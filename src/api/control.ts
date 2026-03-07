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

// ── Pause (soft — memory writes only) ──

export function isPaused(): boolean {
  return mode === 'paused' || mode === 'kill_switch';
}

export function pause(): void {
  if (mode === 'kill_switch') return; // kill switch takes precedence
  mode = 'paused';
  console.log('[shieldcortex] Memory creation PAUSED');
}

export function resume(): void {
  if (mode === 'kill_switch') return; // must use deactivateKillSwitch
  mode = 'active';
  console.log('[shieldcortex] Memory creation RESUMED');
}

// ── Kill Switch (hard — blocks everything except forensics) ──

export function isKillSwitchActive(): boolean {
  return mode === 'kill_switch';
}

export function getKillSwitchMeta(): KillSwitchMeta | null {
  return killSwitchMeta;
}

export function activateKillSwitch(meta: Omit<KillSwitchMeta, 'triggeredAt'>): void {
  if (mode === 'kill_switch') return; // already active, idempotent

  const fullMeta: KillSwitchMeta = {
    ...meta,
    triggeredAt: new Date().toISOString(),
  };

  mode = 'kill_switch';
  killSwitchMeta = fullMeta;

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
  if (mode !== 'kill_switch') return;

  const previousMeta = killSwitchMeta;
  mode = 'active';
  killSwitchMeta = null;

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
    paused: isPaused(),
    killSwitchActive: isKillSwitchActive(),
    killSwitchMeta,
    uptime,
    uptimeFormatted,
  };
}
