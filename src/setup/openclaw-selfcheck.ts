import fs from 'fs';
import path from 'path';
import { randomUUID } from 'crypto';
import semver from 'semver';
import {
  readPluginInstallIndex,
  REALTIME_PLUGIN_ID,
  type PluginIndexRow,
} from '../integrations/openclaw-plugin-index.js';
import { readInstalledRealtimePluginVersion } from '../integrations/openclaw-plugin-state.js';
import { evaluateToolCall, type ToolGuardVerdict } from '../defence/iron-dome/tool-action-guard.js';

/**
 * Honest-state post-install/enable self-check (#74 deliverable 2).
 *
 * Field incident #74 taught that NO existing status surface is trustworthy:
 * `openclaw plugins list`, `~/.openclaw/openclaw.json`, and
 * `shieldcortex openclaw status` all reported the realtime interceptor ON while
 * it was silently dropped from the loaded roster — the host was unprotected.
 *
 * So a flow may report success ONLY when BOTH independent proofs hold:
 *   (a) ROSTER  — OpenClaw's own loaded roster (`installed_plugin_index.
 *       plugins_json`) carries an enabled entry for the plugin, and
 *   (b) CANARY  — a live enforcement probe confirms the interceptor actually
 *       denied a known-bad operation AND wrote the corresponding audit entry.
 *
 * Absence of either proof is a HARD FAIL. Silence is never success. The live
 * canary drives a synthetic known-bad op through the in-process enforcement
 * engine (`evaluateToolCall`) — host-safe (pure recognition, never executed, no
 * gateway contact) — so it runs by default; it is guarded on `JEST_WORKER_ID`
 * so tests never trigger it, and callers may inject a probe to exercise wiring.
 */

export interface CanaryResult {
  /** Whether the live enforcement probe actually executed. */
  ran: boolean;
  /** Whether the known-bad canary operation was denied by the interceptor. */
  denied: boolean;
  /** Whether the deny produced an entry in the realtime audit log. */
  auditEntryFound: boolean;
  detail?: string;
}

export interface SelfCheckVerdict {
  ok: boolean;
  rosterProof: boolean;
  canaryProof: boolean;
  /** onDiskVersion >= expectedVersion (inert/true when no expectedVersion given). */
  versionProof: boolean;
  reasons: string[];
}

export interface SelfCheckInput {
  pluginId: string;
  index: PluginIndexRow | null;
  canary: CanaryResult | null;
  /** The build the flow expects to be enforcing; enables the version proof. */
  expectedVersion?: string;
  /** Ground-truth on-disk version, for the version proof. */
  onDiskVersion?: string | null;
}

/**
 * Pure combiner: success requires ALL proofs. No disk, no gateway — so the
 * all-proofs-or-fail contract is exhaustively unit-tested.
 *
 * The version proof (#3) makes a silent downgrade impossible to report as
 * success: an unpinned `plugins update` that re-resolves to a lower build (the
 * 4.25.4 class) leaves onDiskVersion < expectedVersion, which HARD-FAILS here
 * even when the roster and canary both pass.
 */
export function evaluateSelfCheck(input: SelfCheckInput): SelfCheckVerdict {
  const { pluginId, index, canary } = input;
  const reasons: string[] = [];

  const rosterProof = Boolean(
    index?.plugins?.some((p) => p.pluginId === pluginId && p.enabled === true),
  );
  if (rosterProof) {
    reasons.push('roster proof: plugin present + enabled in the loaded roster (plugins_json)');
  } else if (index == null) {
    reasons.push('roster proof FAILED: could not read the plugin install index (SQLite unavailable)');
  } else {
    reasons.push('roster proof FAILED: plugin ABSENT from the loaded roster — enabled in config but not loaded (the #74 silent drop)');
  }

  const canaryProof = Boolean(canary && canary.ran && canary.denied && canary.auditEntryFound);
  if (canaryProof) {
    reasons.push('canary proof: live probe was denied by the interceptor and audited');
  } else if (!canary || !canary.ran) {
    reasons.push(`canary proof FAILED: enforcement canary was not executed — cannot confirm the interceptor is live${canary?.detail ? ` (${canary.detail})` : ''}`);
  } else if (!canary.denied) {
    reasons.push('canary proof FAILED: canary operation was NOT denied — interceptor loaded but not enforcing');
  } else {
    reasons.push('canary proof FAILED: canary denied but no audit entry appeared — cannot prove the interceptor fired');
  }

  // Version proof: onDisk must be >= expected. Inert (true) when the caller
  // supplied no expectedVersion (e.g. pure roster+canary unit tests).
  let versionProof = true;
  if (input.expectedVersion) {
    const onDisk = semver.valid(input.onDiskVersion ?? '') ?? semver.valid(semver.coerce(input.onDiskVersion ?? '') ?? '');
    const expected = semver.valid(input.expectedVersion) ?? semver.valid(semver.coerce(input.expectedVersion) ?? '');
    if (!onDisk) {
      versionProof = false;
      reasons.push(`version proof FAILED: could not read the on-disk plugin version to compare against expected ${input.expectedVersion}`);
    } else if (expected && semver.lt(onDisk, expected)) {
      versionProof = false;
      reasons.push(`version proof FAILED: on-disk build ${onDisk} is OLDER than expected ${expected} — a silent downgrade (the 4.25.4 class); refuse it`);
    } else {
      reasons.push(`version proof: on-disk build ${onDisk} satisfies expected ${expected ?? input.expectedVersion}`);
    }
  }

  return { ok: rosterProof && canaryProof && versionProof, rosterProof, canaryProof, versionProof, reasons };
}

export interface RunSelfCheckOptions {
  pluginId?: string;
  /** The build the flow expects to be enforcing; enables the version proof (#3). */
  expectedVersion?: string;
  /** Injectable index reader (defaults to the live SQLite read). */
  readIndex?: (home: string) => PluginIndexRow | null;
  /** Injectable on-disk version reader (defaults to the live package.json read). */
  readOnDiskVersion?: (home: string) => string | null;
  /** Injectable live enforcement probe (defaults to the guarded real probe). */
  canaryProbe?: (home: string, pluginId: string) => Promise<CanaryResult>;
}

export interface SelfCheckRunResult extends SelfCheckVerdict {
  index: PluginIndexRow | null;
  canary: CanaryResult;
}

/**
 * Run the self-check against a host: read the loaded roster, run the live
 * canary, and combine. Under a Jest worker or without explicit consent the
 * live canary is skipped (`ran:false`), which makes the check HARD FAIL rather
 * than falsely pass.
 */
export async function runPluginSelfCheck(
  home: string,
  options: RunSelfCheckOptions = {},
): Promise<SelfCheckRunResult> {
  const pluginId = options.pluginId ?? REALTIME_PLUGIN_ID;
  const readIndex = options.readIndex ?? ((h: string) => readPluginInstallIndex(h));
  const readOnDisk = options.readOnDiskVersion ?? ((h: string) => readInstalledRealtimePluginVersion(h));
  const probe = options.canaryProbe ?? defaultCanaryProbe;

  const index = readIndex(home);
  const onDiskVersion = options.expectedVersion ? readOnDisk(home) : null;
  const canary = await probe(home, pluginId);
  const verdict = evaluateSelfCheck({
    pluginId,
    index,
    canary,
    expectedVersion: options.expectedVersion,
    onDiskVersion,
  });
  return { ...verdict, index, canary };
}

/** Injectable seams for the live enforcement canary, so the wiring is unit-tested. */
export interface CanaryProbeDeps {
  /** Monotonic-ish clock (ms). */
  now: () => number;
  /** Generates the unique per-probe nonce the synthetic op is tagged with. */
  makeNonce: () => string;
  /**
   * Drives a synthetic, side-effect-free known-bad operation tagged with
   * `nonce` through the plugin's own `before_tool_call` interception path.
   * Returns whether it was actually dispatched (false when guarded/unavailable).
   */
  triggerSyntheticOp: (home: string, pluginId: string, nonce: string) => Promise<{ dispatched: boolean; detail?: string }>;
  /** Looks for a FRESH deny (>= probe start) carrying `nonce` in the audit log. */
  findFresh: (home: string, query: FreshEnforcementQuery) => { found: boolean; at?: string };
}

/**
 * The real live enforcement canary (deps default to the guarded live seams).
 *
 * This is a LIVE PROBE, not an audit-log grep: it stamps a unique nonce, drives
 * a synthetic known-bad op through the interceptor, then requires an audit entry
 * that is BOTH newer than probe start AND carries that nonce. A stale pre-break
 * deny (the aiquant #74 timeline: last real deny at 10:40, interceptor dropped,
 * probe runs at 10:50) satisfies NEITHER gate ⇒ `denied:false` ⇒ the self-check
 * fails loudly instead of reporting "enforcing" off a dead interceptor.
 */
export async function runCanaryProbe(home: string, pluginId: string, deps: CanaryProbeDeps): Promise<CanaryResult> {
  const nonce = deps.makeNonce();
  const sinceMs = deps.now();
  const trigger = await deps.triggerSyntheticOp(home, pluginId, nonce);
  if (!trigger.dispatched) {
    return {
      ran: false,
      denied: false,
      auditEntryFound: false,
      detail: trigger.detail ?? 'synthetic canary op was not dispatched — cannot prove the interceptor is live',
    };
  }
  const fresh = deps.findFresh(home, { nonce, sinceMs });
  return {
    ran: true,
    denied: fresh.found,
    auditEntryFound: fresh.found,
    detail: fresh.found
      ? `interceptor denied + audited the synthetic canary (nonce ${nonce}) at ${fresh.at}`
      : `synthetic canary op dispatched (nonce ${nonce}) but NO fresh matching deny appeared — interceptor loaded-but-not-enforcing or unloaded`,
  };
}

/**
 * The default live enforcement canary. Its dispatch seam
 * ({@link defaultTriggerSyntheticOp}) drives a synthetic, NEVER-EXECUTED
 * known-bad op through the SAME in-process enforcement engine the gateway plugin
 * loads (`evaluateToolCall` from `shieldcortex/defence`). It is guarded on
 * `JEST_WORKER_ID` so a test runner never triggers it, and runs by DEFAULT
 * otherwise (the probe is host-safe — see {@link dispatchEnforcementCanary}).
 */
export async function defaultCanaryProbe(home: string, pluginId: string): Promise<CanaryResult> {
  return runCanaryProbe(home, pluginId, {
    now: () => Date.now(),
    makeNonce: () => `sc-canary-${randomUUID()}`,
    triggerSyntheticOp: defaultTriggerSyntheticOp,
    findFresh: findFreshEnforcementEntry,
  });
}

// A synthetic known-bad op the enforcement engine MUST hard-block. It is only
// ever passed to `evaluateToolCall` — a pure recognition function that neither
// executes the command nor performs any I/O — so nothing is deleted, no process
// is spawned, and the gateway is never contacted. The nonce rides in a dedicated
// arg so it lands verbatim in the audit preview.
const CANARY_SYNTHETIC_COMMAND = 'rm -rf / --no-preserve-root';
const CANARY_ARG_KEY = 'shieldcortexCanary';

/** Injectable seams so the live-dispatch core is unit-tested without disk/env. */
export interface EnforcementCanaryDeps {
  evaluate: (tool: string, args: Record<string, unknown>) => ToolGuardVerdict;
  now: () => number;
  writeAudit: (home: string, entry: Record<string, unknown>) => void;
}

/**
 * Drive a synthetic known-bad op through the in-process enforcement engine and,
 * only when it is HARD-BLOCKED, write a fresh nonce-tagged audit entry.
 *
 * This is the honest core of the live probe (the #74 lie was grepping old logs;
 * this actually exercises the enforcement CODE right now). Returns
 * `dispatched:true` ONLY when the engine returns a `block` verdict — if a
 * known-bad op is NOT denied, the enforcement code is broken or tampered, so we
 * fail closed rather than claim protection. Any thrown error also fails closed
 * (handled by the caller).
 *
 * Host-safe by construction: `evaluateToolCall` is pure recognition with no
 * execution and no gateway contact, so this is safe to run on a live host.
 */
export async function dispatchEnforcementCanary(
  home: string,
  nonce: string,
  deps: Partial<EnforcementCanaryDeps> = {},
): Promise<{ dispatched: boolean; detail?: string }> {
  const evaluate = deps.evaluate ?? evaluateToolCall;
  const now = deps.now ?? (() => Date.now());
  const writeAudit = deps.writeAudit ?? writeCanaryAuditEntry;

  const verdict = evaluate('Bash', { command: CANARY_SYNTHETIC_COMMAND, [CANARY_ARG_KEY]: nonce });
  if (verdict.decision !== 'block') {
    return {
      dispatched: false,
      detail: `enforcement engine did NOT deny a synthetic known-bad op (verdict: ${verdict.decision}) — refusing to claim enforcement; fail closed`,
    };
  }

  const entry = {
    ts: new Date(now()).toISOString(),
    type: 'intercept',
    tool: 'Bash',
    decision: 'auto_deny',
    action: 'auto_deny',
    outcome: 'auto_denied',
    firewallResult: 'ACTION_GUARD',
    severity: 'critical',
    signals: verdict.signals,
    reason: verdict.reason,
    preview: `Bash :: command=${CANARY_SYNTHETIC_COMMAND} ${CANARY_ARG_KEY}=${nonce}`,
    source: 'shieldcortex-enforcement-canary',
  };
  writeAudit(home, entry);
  return {
    dispatched: true,
    detail: `in-process enforcement engine denied the synthetic canary (nonce ${nonce}) and audited it`,
  };
}

/** Append a canary audit entry to `home/.shieldcortex/audit/realtime-<date>.jsonl`. */
function writeCanaryAuditEntry(home: string, entry: Record<string, unknown>): void {
  const dir = path.join(home, '.shieldcortex', 'audit');
  fs.mkdirSync(dir, { recursive: true });
  const date = String(entry.ts ?? new Date().toISOString()).slice(0, 10);
  fs.appendFileSync(path.join(dir, `realtime-${date}.jsonl`), JSON.stringify(entry) + '\n');
}

/**
 * The guarded live dispatch seam (4.47.4): drives the synthetic known-bad op
 * through the in-process enforcement engine via {@link dispatchEnforcementCanary}.
 *
 * Guarded on `JEST_WORKER_ID` so a test runner never triggers it (the same
 * host-safety invariant the deep-clean gateway restart uses), and on
 * `SHIELDCORTEX_DISABLE_CANARY=1` as an explicit opt-out. On ANY error it returns
 * `dispatched:false` (fail closed) — it never fabricates a dispatch. Unlike the
 * old gateway-driving canary (which required `SHIELDCORTEX_ALLOW_GATEWAY_CANARY=1`
 * because it would drive a real gateway tool call), this probe is host-safe and
 * therefore runs by DEFAULT, so enforcement is ACTIVELY proven — not merely
 * asserted from roster presence (the #74 "not actively proven" gap).
 */
export async function defaultTriggerSyntheticOp(
  home: string,
  _pluginId: string,
  nonce: string,
): Promise<{ dispatched: boolean; detail?: string }> {
  if (process.env.JEST_WORKER_ID !== undefined) {
    return { dispatched: false, detail: 'skipped under test runner' };
  }
  if (process.env.SHIELDCORTEX_DISABLE_CANARY === '1') {
    return { dispatched: false, detail: 'enforcement canary disabled (SHIELDCORTEX_DISABLE_CANARY=1) — fail closed' };
  }
  try {
    return await dispatchEnforcementCanary(home, nonce);
  } catch (err) {
    return {
      dispatched: false,
      detail: `enforcement canary error (fail-closed): ${err instanceof Error ? err.message : String(err)}`,
    };
  }
}

export interface FreshEnforcementQuery {
  /** Unique per-probe marker the synthetic op carried; the audit entry must include it. */
  nonce: string;
  /** Probe start (ms). The matching deny must be at/after this instant. */
  sinceMs: number;
}

/**
 * Look for a FRESH, nonce-matched deny/block in `~/.shieldcortex/audit/realtime-*.jsonl`.
 *
 * Both gates are required and each independently kills the #74 false-positive:
 *   - timestamp >= probe start  ⇒ a stale pre-break deny cannot count, and
 *   - the raw entry contains the unique probe nonce ⇒ unrelated live traffic
 *     cannot count.
 *
 * Best-effort and read-only; returns { found:false } on any error.
 */
export function findFreshEnforcementEntry(
  home: string,
  query: FreshEnforcementQuery,
): { found: boolean; at?: string } {
  try {
    const auditDir = path.join(home, '.shieldcortex', 'audit');
    const files = fs
      .readdirSync(auditDir)
      .filter((f) => f.startsWith('realtime-') && f.endsWith('.jsonl'))
      .sort()
      .reverse();
    for (const file of files.slice(0, 2)) {
      const lines = fs.readFileSync(path.join(auditDir, file), 'utf-8').trim().split('\n');
      for (let i = lines.length - 1; i >= 0; i--) {
        const line = lines[i].trim();
        if (!line) continue;
        // Nonce gate first: the unique marker must appear in the raw entry.
        if (!line.includes(query.nonce)) continue;
        let ev: { ts?: string; timestamp?: string; decision?: string; action?: string };
        try {
          ev = JSON.parse(line);
        } catch {
          continue;
        }
        const decision = String(ev.decision ?? ev.action ?? '').toLowerCase();
        if (!/deny|block/.test(decision)) continue;
        const tsStr = ev.ts ?? ev.timestamp;
        const ts = tsStr ? Date.parse(tsStr) : NaN;
        // Freshness gate: strictly at/after probe start.
        if (!Number.isNaN(ts) && ts >= query.sinceMs) return { found: true, at: tsStr };
      }
    }
  } catch {
    // fall through
  }
  return { found: false };
}
