/**
 * Control State Module
 *
 * Manages global control state for the ShieldCortex system.
 * Handles pause/resume for memory creation and kill switch lockdown.
 *
 * Kill switch is a stronger state than pause — it blocks ALL operations
 * except forensic tools (audit, status, scan, resume).
 */

import { logIronDomeAudit } from '../defence/iron-dome/audit.js';
import { getDatabase, isDatabaseInitialized } from '../database/init.js';

// ── Types ──

export type ControlMode = 'active' | 'paused' | 'kill_switch';

export type OperationKind =
  | 'memory_read'
  | 'memory_write'
  | 'graph'
  | 'consolidation'
  | 'config'
  | 'status'
  | 'audit'
  | 'scan'
  | 'resume'
  | 'emergency_stop';

export interface KillSwitchMeta {
  triggeredAt: string;
  source: 'kill_phrase' | 'manual' | 'mcp_tool';
  phrase?: string;
  reason?: string;
  sourceIdentifier?: string;
  memoryCountAtTrigger?: number;
}

export class KillSwitchError extends Error {
  constructor(public meta: KillSwitchMeta | null) {
    super('Kill switch active — operation blocked');
    this.name = 'KillSwitchError';
  }
}

// ── Lockdown Policy ──

const ALLOWED_DURING_LOCKDOWN: ReadonlySet<OperationKind> = new Set([
  'status',
  'audit',
  'scan',
  'resume',
  'emergency_stop',
]);

// ── State ──

const startTime = Date.now();
let mode: ControlMode = 'active';
let killSwitchMeta: KillSwitchMeta | null = null;

// ── Cross-process persistence (control_state table, single row id=1) ──
//
// In a normal install the MCP server and the dashboard API server are SEPARATE
// processes. Keeping kill-switch / pause state only in module memory meant a
// dashboard activation never reached the MCP process. The control_state row is
// the single source of truth: mutators WRITE it, gated reads REFRESH from it
// (through a short TTL cache so we don't hit SQLite on every gated op). The
// in-memory `mode` / `killSwitchMeta` stay as the cache. Every DB access here
// is best-effort: a missing / uninitialised DB or any error falls back to the
// current in-memory behaviour and NEVER throws into callers.
//
// Worst-case propagation delay of another process's change to this process is
// `cacheTtlMs` (~1s) — acceptable for memory-write gating, not for sub-second
// guarantees. Mutators force a fresh read first (refreshControlState(true)), so
// cross-process precedence checks never act on a stale cached mode.

let lastRead = 0;
const cacheTtlMs = 1000;

/**
 * Persist the current in-memory control state to the single control_state row.
 * Best-effort: silently no-ops if the DB is uninitialised and never throws.
 */
function persistControlState(): void {
  if (!isDatabaseInitialized()) return;
  try {
    getDatabase()
      .prepare(
        `INSERT INTO control_state (id, mode, meta_json, updated_at)
         VALUES (1, ?, ?, ?)
         ON CONFLICT(id) DO UPDATE SET
           mode = excluded.mode,
           meta_json = excluded.meta_json,
           updated_at = excluded.updated_at`,
      )
      .run(
        mode,
        killSwitchMeta ? JSON.stringify(killSwitchMeta) : null,
        new Date().toISOString(),
      );
    // Our cache is now authoritative for this write — avoid an immediate
    // redundant read clobbering it within the TTL window.
    lastRead = Date.now();
  } catch (err) {
    // Never let persistence break a control operation — but a silent failure
    // here means a dashboard "kill switch" never reaches the MCP process while
    // the dashboard reports success. Surface it (still swallow, never throw).
    console.error('[shieldcortex] failed to persist control state:', err);
  }
}

const VALID_MODES: ReadonlySet<string> = new Set(['active', 'paused', 'kill_switch']);

/**
 * Refresh the in-memory control state from the control_state row, subject to a
 * short TTL so gated ops do ≤1 SQLite read per second rather than one per call.
 * If the DB is uninitialised, the row is absent, or any error occurs, the
 * existing in-memory values are kept (we never clobber to a wrong state).
 */
function loadControlState(): void {
  if (!isDatabaseInitialized()) return;
  const now = Date.now();
  if (now - lastRead <= cacheTtlMs) return;
  // Mark as read up front so a transient error doesn't hammer SQLite every call.
  lastRead = now;
  try {
    const row = getDatabase()
      .prepare('SELECT mode, meta_json FROM control_state WHERE id = 1')
      .get() as { mode: string; meta_json: string | null } | undefined;
    if (!row) return; // no row yet — keep in-memory state
    // Fail-closed: a corrupted / unknown mode must NOT disable lockdown. Keep
    // the prior in-memory state rather than assigning garbage (which would make
    // assertOperationAllowed fail OPEN for any non-'kill_switch' value).
    if (!VALID_MODES.has(row.mode)) {
      console.error(`[shieldcortex] ignoring invalid control_state mode: ${JSON.stringify(row.mode)}`);
      return;
    }
    mode = row.mode as ControlMode;
    killSwitchMeta = row.meta_json ? (JSON.parse(row.meta_json) as KillSwitchMeta) : null;
  } catch {
    // Keep current in-memory values on any read/parse failure.
  }
}

/**
 * Force-or-TTL refresh of the in-memory control state from the row.
 *
 * Mutators (pause/resume/activate/deactivate) call this with force=true BEFORE
 * their precedence checks so they never act on a stale cached `mode`. Without
 * it, process B calling resume() within the TTL after process A activated the
 * kill switch would see its stale in-memory 'active', pass the guard, and write
 * 'active' — silently clearing A's kill switch. Mutators are rare, so the
 * forced DB read is fine. A forced reload with no DB still no-ops (loadControlState
 * guards on isDatabaseInitialized), preserving the uninitialised-DB fallback.
 */
function refreshControlState(force = false): void {
  if (force) lastRead = 0;
  loadControlState();
}

// ── Pause (soft — memory writes only) ──

export function isPaused(): boolean {
  loadControlState();
  return mode === 'paused' || mode === 'kill_switch';
}

export function pause(): void {
  refreshControlState(true); // see current row before the precedence check
  if (mode === 'kill_switch') return; // kill switch takes precedence
  mode = 'paused';
  console.log('[shieldcortex] Memory creation PAUSED');
  persistControlState();
}

export function resume(): void {
  refreshControlState(true); // see current row before the precedence check
  if (mode === 'kill_switch') return; // must use deactivateKillSwitch
  mode = 'active';
  console.log('[shieldcortex] Memory creation RESUMED');
  persistControlState();
}

// ── Kill Switch (hard — blocks everything except forensics) ──

export function isKillSwitchActive(): boolean {
  loadControlState();
  return mode === 'kill_switch';
}

export function getKillSwitchMeta(): KillSwitchMeta | null {
  loadControlState();
  return killSwitchMeta;
}

export function activateKillSwitch(meta: Omit<KillSwitchMeta, 'triggeredAt'>): void {
  refreshControlState(true); // see current row before the precedence check
  if (mode === 'kill_switch') return; // already active, idempotent

  const fullMeta: KillSwitchMeta = {
    ...meta,
    triggeredAt: new Date().toISOString(),
  };

  mode = 'kill_switch';
  killSwitchMeta = fullMeta;
  persistControlState();

  console.log(`[shieldcortex] KILL SWITCH ACTIVATED — source: ${meta.source}${meta.phrase ? `, phrase: "${meta.phrase}"` : ''}`);

  // Audit log
  try {
    logIronDomeAudit({
      action: 'kill_switch_activated',
      allowed: false,
      reason: `Kill switch activated. Source: ${meta.source}.${meta.phrase ? ` Phrase: "${meta.phrase}".` : ''}${meta.reason ? ` Reason: ${meta.reason}.` : ''} Memories: ${meta.memoryCountAtTrigger ?? 'unknown'}.`,
    });
  } catch {
    // Audit logging must never break kill switch activation
  }

  // Cross-process event + cloud alert are wired via events.ts
  // Import lazily to avoid circular deps
  try {
    import('../api/events.js').then(({ emitKillSwitchActivated }) => {
      emitKillSwitchActivated(fullMeta);
    }).catch(() => {});
  } catch {
    // Best-effort
  }

  try {
    import('../cloud/sync.js').then(({ sendKillSwitchAlert }) => {
      sendKillSwitchAlert(fullMeta);
    }).catch(() => {});
  } catch {
    // Best-effort
  }
}

export function deactivateKillSwitch(reason: string): void {
  refreshControlState(true); // see current row before the precedence check
  if (mode !== 'kill_switch') return;

  const previousMeta = killSwitchMeta;
  mode = 'active';
  killSwitchMeta = null;
  persistControlState();

  console.log(`[shieldcortex] Kill switch deactivated — reason: ${reason}`);

  try {
    logIronDomeAudit({
      action: 'kill_switch_deactivated',
      allowed: true,
      reason: `Kill switch deactivated. Reason: ${reason}. Was active since: ${previousMeta?.triggeredAt ?? 'unknown'}.`,
    });
  } catch {
    // Audit logging must never break deactivation
  }

  try {
    import('../api/events.js').then(({ emitKillSwitchDeactivated }) => {
      emitKillSwitchDeactivated({ reason, previousMeta });
    }).catch(() => {});
  } catch {
    // Best-effort
  }
}

// ── Central Policy Enforcement ──

/**
 * Assert that an operation is allowed under the current control mode.
 * Throws KillSwitchError if the operation is blocked.
 */
export function assertOperationAllowed(kind: OperationKind): void {
  loadControlState();
  if (mode !== 'kill_switch') return;
  if (ALLOWED_DURING_LOCKDOWN.has(kind)) return;
  throw new KillSwitchError(killSwitchMeta);
}

// ── Status ──

export function getControlStatus(): {
  mode: ControlMode;
  paused: boolean;
  killSwitchActive: boolean;
  killSwitchMeta: KillSwitchMeta | null;
  uptime: number;
  uptimeFormatted: string;
} {
  loadControlState();
  const uptime = Date.now() - startTime;

  const seconds = Math.floor(uptime / 1000);
  const minutes = Math.floor(seconds / 60);
  const hours = Math.floor(minutes / 60);
  const days = Math.floor(hours / 24);

  let uptimeFormatted: string;
  if (days > 0) {
    uptimeFormatted = `${days}d ${hours % 24}h ${minutes % 60}m`;
  } else if (hours > 0) {
    uptimeFormatted = `${hours}h ${minutes % 60}m ${seconds % 60}s`;
  } else if (minutes > 0) {
    uptimeFormatted = `${minutes}m ${seconds % 60}s`;
  } else {
    uptimeFormatted = `${seconds}s`;
  }

  return {
    mode,
    paused: mode === 'paused' || mode === 'kill_switch',
    killSwitchActive: mode === 'kill_switch',
    killSwitchMeta,
    uptime,
    uptimeFormatted,
  };
}

// ── Test-only hooks ──
//
// These exist solely so cross-process behaviour can be exercised without a real
// >1s sleep. They are not part of the public API.

/** Force the next gated read to re-query the control_state row (bypass TTL). */
export function __refreshControlStateForTest(): void {
  refreshControlState(true);
}
