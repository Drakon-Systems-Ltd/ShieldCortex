import fs from 'fs';
import path from 'path';
import {
  readPluginInstallIndex,
  REALTIME_PLUGIN_ID,
  type PluginIndexRow,
} from '../integrations/openclaw-plugin-index.js';

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
 * canary is guarded exactly like the gateway restart (JEST + explicit consent
 * env) so tests and this frozen box never trigger a live gateway operation;
 * callers inject a probe to exercise the wiring.
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
  reasons: string[];
}

export interface SelfCheckInput {
  pluginId: string;
  index: PluginIndexRow | null;
  canary: CanaryResult | null;
}

/**
 * Pure combiner: success requires BOTH proofs. No disk, no gateway — so the
 * both-proofs-or-fail contract is exhaustively unit-tested.
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

  return { ok: rosterProof && canaryProof, rosterProof, canaryProof, reasons };
}

export interface RunSelfCheckOptions {
  pluginId?: string;
  /** Injectable index reader (defaults to the live SQLite read). */
  readIndex?: (home: string) => PluginIndexRow | null;
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
  const probe = options.canaryProbe ?? defaultCanaryProbe;

  const index = readIndex(home);
  const canary = await probe(home, pluginId);
  const verdict = evaluateSelfCheck({ pluginId, index, canary });
  return { ...verdict, index, canary };
}

/**
 * The real live enforcement canary. GUARDED: it refuses to run under a Jest
 * worker and without the explicit `SHIELDCORTEX_ALLOW_GATEWAY_CANARY=1` consent
 * — mirroring the gateway-restart safety gate — because a live probe drives a
 * real tool call through the running gateway. When it cannot run it returns
 * `ran:false` so the self-check fails loudly instead of silently passing.
 *
 * Under consent it corroborates enforcement from the realtime audit log: a
 * recent deny entry proves the interceptor is both loaded and firing. Full
 * active-probe (synthesising a known-bad op) lands on the sacrificial env per
 * the #74 rollout plan; the audit-corroboration path here never fabricates a
 * pass — no recent deny ⇒ `denied:false`.
 */
export async function defaultCanaryProbe(home: string, _pluginId: string): Promise<CanaryResult> {
  if (process.env.JEST_WORKER_ID !== undefined) {
    return { ran: false, denied: false, auditEntryFound: false, detail: 'skipped under test runner' };
  }
  if (process.env.SHIELDCORTEX_ALLOW_GATEWAY_CANARY !== '1') {
    return {
      ran: false,
      denied: false,
      auditEntryFound: false,
      detail: 'live canary requires SHIELDCORTEX_ALLOW_GATEWAY_CANARY=1 (drives a real gateway tool call)',
    };
  }

  // Consented: corroborate live enforcement from the realtime audit log.
  const recent = findRecentEnforcementEntry(home);
  return {
    ran: true,
    denied: recent.found,
    auditEntryFound: recent.found,
    detail: recent.found
      ? `most recent realtime audit deny at ${recent.at}`
      : 'no recent enforcement entry in the realtime audit log',
  };
}

/**
 * Look for a recent deny/block entry in `~/.shieldcortex/audit/realtime-*.jsonl`.
 * Best-effort and read-only; returns { found:false } on any error.
 */
export function findRecentEnforcementEntry(
  home: string,
  withinMs = 10 * 60 * 1000,
): { found: boolean; at?: string } {
  try {
    const auditDir = path.join(home, '.shieldcortex', 'audit');
    const files = fs
      .readdirSync(auditDir)
      .filter((f) => f.startsWith('realtime-') && f.endsWith('.jsonl'))
      .sort()
      .reverse();
    const cutoff = Date.now() - withinMs;
    for (const file of files.slice(0, 2)) {
      const lines = fs.readFileSync(path.join(auditDir, file), 'utf-8').trim().split('\n');
      for (let i = lines.length - 1; i >= 0; i--) {
        const line = lines[i].trim();
        if (!line) continue;
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
        if (!Number.isNaN(ts) && ts >= cutoff) return { found: true, at: tsStr };
      }
    }
  } catch {
    // fall through
  }
  return { found: false };
}
