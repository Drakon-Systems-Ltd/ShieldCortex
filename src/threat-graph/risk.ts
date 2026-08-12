/**
 * Threat-graph risk model (docs/design/2026-08-11-threat-graph.md, Loop 1).
 *
 * risk(t) = 1 - exp( -Σᵢ wᵢ · 2^(-(t - tᵢ)/H) )
 *
 * The exponent sum is stored per source, referenced to a ledger timestamp,
 * and folded incrementally as events project. It is a pure function of ledger
 * rows (weights + timestamps) — deterministic, and therefore safe to keep in
 * source-node attrs (which canonicalDump covers). The DECAYED output is
 * wall-clock-relative and lives only in the source_risk table, recomputed by
 * the sweep; it is deliberately outside the determinism contract.
 *
 * Rebase identity: S referenced to ref' equals S(ref) · 2^(-(ref'-ref)/H), so
 * the sum can be re-anchored to each new event's timestamp exactly, and the
 * final risk at any `now` is invariant to the choice of reference.
 *
 * Accrual is rate-capped per source (≤ RATE_CAP weight per rolling window):
 * one identity cannot saturate risk in a burst, which bounds a victim-name
 * poisoning campaign (see Loop 2's attestation gate for the other half).
 */

import { getDatabase } from '../database/init.js';
import { cachedStmt } from './shared.js';

export const RISK_WEIGHTS = { BLOCK: 1.0, QUARANTINE: 0.5, HIGH_ANOMALY_ALLOW: 0.1 } as const;
export const DEFAULT_HALF_LIFE_MS = 14 * 24 * 60 * 60 * 1000;
export const DEFAULT_ANOMALY_THRESHOLD = 0.7;
export const RATE_CAP = 2.0;
export const RATE_WINDOW_MS = 24 * 60 * 60 * 1000;
const COUNTER_WINDOW_MS = 28 * 24 * 60 * 60 * 1000;

export interface EventWeightInput {
  verdict: 'ALLOW' | 'BLOCK' | 'QUARANTINE';
  anomaly: number;
  pipelineError: boolean;
  anomalyThreshold?: number;
}

/** Per-event severity weight. pipeline_error (the fail-closed handler's own
 * BLOCK rows) is zero so a wedged install can't inflate anyone's risk. */
export function eventWeight(input: EventWeightInput): number {
  if (input.pipelineError) return 0;
  if (input.verdict === 'BLOCK') return RISK_WEIGHTS.BLOCK;
  if (input.verdict === 'QUARANTINE') return RISK_WEIGHTS.QUARANTINE;
  const threshold = input.anomalyThreshold ?? DEFAULT_ANOMALY_THRESHOLD;
  if (input.verdict === 'ALLOW' && input.anomaly >= threshold) return RISK_WEIGHTS.HIGH_ANOMALY_ALLOW;
  return 0;
}

export interface RiskState {
  sum: number;
  refTs: number;
  windowStart: number;
  windowWeight: number;
}

export interface FoldOptions {
  halfLifeMs: number;
  rateCap: number;
  rateWindowMs: number;
}

/**
 * Fold one weighted event into the running state. Pure; callers skip this
 * entirely when the weight is 0 (a zero-weight fold is a no-op for the
 * eventual risk, so the common ALLOW row never touches risk state).
 */
export function foldEvent(
  prev: RiskState | null,
  eventTsMs: number,
  weight: number,
  opts: FoldOptions,
): RiskState {
  if (!prev) {
    const allowed = Math.min(weight, opts.rateCap);
    return { sum: allowed, refTs: eventTsMs, windowStart: eventTsMs, windowWeight: allowed };
  }

  // Rate window: reset when the event falls outside the current window (or
  // before it — a late-arriving earlier row opens its own window).
  let windowStart = prev.windowStart;
  let windowWeight = prev.windowWeight;
  if (eventTsMs - windowStart >= opts.rateWindowMs || eventTsMs < windowStart) {
    windowStart = eventTsMs;
    windowWeight = 0;
  }
  const allowed = Math.min(weight, Math.max(0, opts.rateCap - windowWeight));
  windowWeight += allowed;

  const H = opts.halfLifeMs;
  let sum: number;
  let refTs: number;
  if (eventTsMs >= prev.refTs) {
    sum = prev.sum * Math.pow(2, -(eventTsMs - prev.refTs) / H) + allowed;
    refTs = eventTsMs;
  } else {
    sum = prev.sum + allowed * Math.pow(2, -(prev.refTs - eventTsMs) / H);
    refTs = prev.refTs;
  }
  return { sum, refTs, windowStart, windowWeight };
}

/** Decay the stored sum to `now` and squash to [0,1). */
export function decayedRisk(sum: number, refTsMs: number, nowMs: number, halfLifeMs: number): number {
  if (sum <= 0) return 0;
  const decayed = sum * Math.pow(2, -Math.max(0, nowMs - refTsMs) / halfLifeMs);
  return 1 - Math.exp(-decayed);
}

export interface RiskSweepOptions {
  /** Wall clock (ms) — injectable for tests; NOT written into attrs. */
  nowMs: number;
  halfLifeMs?: number;
}

export interface RiskSweepResult {
  sources: number;
}

interface SourceNodeRow {
  key: string;
  attrs: string;
}

/**
 * Recompute source_risk for every source node: decayed risk from the node's
 * stored exponent sum, plus 28-day windowed counters and the current
 * attestation state, from the audit ledger.
 *
 * Runs every projector pass (the idle sweep), so a source that misbehaved and
 * went quiet actually heals on schedule rather than freezing at peak risk.
 * Bounded by |sources| (hard-capped at 5,000).
 */
export function runRiskSweep(options: RiskSweepOptions): RiskSweepResult {
  const db = getDatabase();
  const H = options.halfLifeMs ?? DEFAULT_HALF_LIFE_MS;
  const windowStartIso = new Date(options.nowMs - COUNTER_WINDOW_MS).toISOString();

  const nodes = db.prepare(
    "SELECT key, attrs FROM threat_nodes WHERE kind = 'source' AND key != 'overflow'"
  ).all() as SourceNodeRow[];

  const upsert = cachedStmt(`
    INSERT INTO source_risk (
      source_key, risk, attested, block_count_28d, quarantine_count_28d,
      scan_count_28d, updated_at
    ) VALUES (@key, @risk, @attested, @block, @quarantine, @scan, @updated)
    ON CONFLICT(source_key) DO UPDATE SET
      risk = @risk, attested = @attested, block_count_28d = @block,
      quarantine_count_28d = @quarantine, scan_count_28d = @scan, updated_at = @updated
  `);

  // Counters + attestation come from the raw type/identifier the node was
  // built from (stored in attrs so a truncated node key can't misquery).
  const counterStmt = cachedStmt(`
    SELECT firewall_result, COUNT(*) AS c
    FROM defence_audit
    WHERE source_type = ? AND source_identifier = ? AND timestamp >= ?
    GROUP BY firewall_result
  `);
  const attestStmt = cachedStmt(`
    SELECT source_attested FROM defence_audit
    WHERE source_type = ? AND source_identifier = ? AND source_attested IS NOT NULL
    ORDER BY id DESC LIMIT 1
  `);

  const nowIso = new Date(options.nowMs).toISOString();

  const sweep = db.transaction(() => {
    for (const node of nodes) {
      let attrs: Record<string, unknown>;
      try {
        attrs = JSON.parse(node.attrs) as Record<string, unknown>;
      } catch {
        continue; // corrupt attrs surface via the projector's own guard
      }

      const sum = typeof attrs.risk_sum === 'number' ? attrs.risk_sum : 0;
      const refTs = typeof attrs.risk_ref_ts === 'string' ? Date.parse(attrs.risk_ref_ts) : options.nowMs;
      const risk = decayedRisk(sum, refTs, options.nowMs, H);

      const srcType = typeof attrs.src_type === 'string' ? attrs.src_type : node.key.split(':')[0];
      const srcId = typeof attrs.src_id === 'string' ? attrs.src_id : node.key.slice(node.key.indexOf(':') + 1);

      const counts = counterStmt.all(srcType, srcId, windowStartIso) as Array<{ firewall_result: string; c: number }>;
      let block = 0, quarantine = 0, scan = 0;
      for (const row of counts) {
        scan += row.c;
        if (row.firewall_result === 'BLOCK') block = row.c;
        else if (row.firewall_result === 'QUARANTINE') quarantine = row.c;
      }

      // Latest-non-null attestation wins: an attacker declaring (unattested)
      // rows under a victim's name flips attested to 0, which turns the trust
      // modifier OFF for that source — fail-safe, never wrongly-on.
      const attestRow = attestStmt.get(srcType, srcId) as { source_attested: number } | undefined;
      const attested = attestRow?.source_attested === 1 ? 1 : 0;

      upsert.run({
        key: node.key, risk, attested, block, quarantine, scan, updated: nowIso,
      });
    }
  });
  sweep.immediate();

  return { sources: nodes.length };
}
