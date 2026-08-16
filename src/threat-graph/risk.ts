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

import { getDatabase, isDatabaseInitialized } from '../database/init.js';
import type { DefenceSource } from '../defence/types.js';
import { logAudit } from '../defence/audit/logger.js';
import { inferSourceFromEnvironment } from '../defence/trust/env-detector.js';
import { cachedStmt } from './shared.js';
import { sourceKey } from './keys.js';

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

  // Rate window: tumble FORWARD only. A new window opens only when an event
  // lands at/after windowStart + rateWindowMs; an earlier-timestamped row
  // (out-of-order id/timestamp, or a backward clock step — NTP, VM resume,
  // sleep) accumulates into the current window against the cap, never gets a
  // fresh allowance. Resetting on `eventTsMs < windowStart` was a full bypass:
  // a descending-timestamp burst re-armed the cap every row.
  let windowStart = prev.windowStart;
  let windowWeight = prev.windowWeight;
  if (eventTsMs >= windowStart + opts.rateWindowMs) {
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

// ── Loop 2: the advisory trust modifier ──────────────────────────────────────

export type TrustModifierMode = 'off' | 'advisory' | 'enforce';

/** Max trust a fully-burned source can lose. */
export const RISK_TRUST_CAP = 0.3;
/** Risk-to-trust-penalty scale. SCALE = CAP so risk∈[0,1] can't exceed the cap
 * today; the cap is belt-and-braces for a future SCALE increase. */
export const RISK_TRUST_SCALE = 0.3;

export interface RiskModifierResult {
  /** Amount to subtract from base trust (0 when not applicable). */
  modifier: number;
  /** True only in enforce mode with a non-zero modifier. */
  applied: boolean;
}

/**
 * Compute the trust modifier for a source — the ONE hot-path read.
 *
 * Contract (design doc invariant 4 + Loop 2):
 *  - O(1) primary-key read of source_risk via the shared sourceKey() (same
 *    normalisation as the projector, or long identifiers miss their row);
 *  - guarded by isDatabaseInitialized() and wrapped so ANY error yields
 *    modifier 0 — a graph fault must never reach the pipeline's fail-closed
 *    handler and turn a stale checkpoint into a blocked scan;
 *  - gated on attestation: an unattested identity (including an attacker
 *    spoofing a victim's name, which resolves unattested) yields 0 — spoofing
 *    can only switch enforcement OFF;
 *  - subtraction only (additive-tightening): never raises trust.
 */
export function computeRiskModifier(source: DefenceSource, mode: TrustModifierMode): RiskModifierResult {
  if (mode === 'off') return { modifier: 0, applied: false };
  if (!isDatabaseInitialized()) return { modifier: 0, applied: false };

  try {
    const key = sourceKey(source.type, source.identifier);
    let row = cachedStmt('SELECT risk, attested FROM source_risk WHERE source_key = ?')
      .get(key) as { risk: number; attested: number } | undefined;

    // #307 — overflowed identities have no own source_risk row. Use the overflow
    // bucket's risk, but THIS source's latest-non-null attestation (unattested
    // overflow traffic must not tighten).
    if (!row) {
      const ownNode = cachedStmt("SELECT 1 AS ok FROM threat_nodes WHERE kind = 'source' AND key = ?")
        .get(key) as { ok: number } | undefined;
      if (!ownNode) {
        const overflow = cachedStmt("SELECT risk FROM source_risk WHERE source_key = 'overflow'")
          .get() as { risk: number } | undefined;
        if (overflow && overflow.risk > 0) {
          const attestRow = cachedStmt(`
            SELECT source_attested FROM defence_audit
            WHERE source_type = ? AND source_identifier = ? AND source_attested IS NOT NULL
            ORDER BY id DESC LIMIT 1
          `).get(source.type, source.identifier) as { source_attested: number } | undefined;
          if (attestRow?.source_attested === 1) {
            row = { risk: overflow.risk, attested: 1 };
          }
        }
      }
    }

    if (!row || row.attested !== 1 || row.risk <= 0) return { modifier: 0, applied: false };

    const modifier = Math.min(row.risk * RISK_TRUST_SCALE, RISK_TRUST_CAP);
    return { modifier, applied: mode === 'enforce' && modifier > 0 };
  } catch {
    // Fail-to-zero: the base pipeline is fail-closed; the modifier is not
    // allowed to make a graph error cost a scan.
    return { modifier: 0, applied: false };
  }
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
    "SELECT key, attrs FROM threat_nodes WHERE kind = 'source'"
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
      AND (operation IS NULL OR operation != 'review')
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

// ── Operator dispute (invariant 3's only loosening) ──────────────────────────

export interface ResetSourceResult {
  found: boolean;
}

/** Structured reset payload carried in the review row's reason (so a rebuild
 * can parse it deterministically regardless of key/username characters). */
export interface RiskResetPayload {
  kind: 'risk_reset';
  source_key: string;
  reviewed_by: string;
}

/** Parse a review row's reason; returns the reset payload or null. */
export function parseRiskReset(reason: string | null): RiskResetPayload | null {
  if (!reason || reason[0] !== '{') return null;
  try {
    const p = JSON.parse(reason) as Partial<RiskResetPayload>;
    if (p.kind === 'risk_reset' && typeof p.source_key === 'string') {
      return { kind: 'risk_reset', source_key: p.source_key, reviewed_by: String(p.reviewed_by ?? '') };
    }
  } catch { /* not JSON */ }
  return null;
}

/**
 * Clear a source's accrued exponent sum and zero its source_risk row. NO
 * transaction wrapper — safe to call inside the projector's batch txn (so a
 * rebuild reproduces the reset) and inside resetSourceRisk's own txn.
 * `nowIso` freshens source_risk.updated_at so the doctor sweep-age is honest.
 */
export function applyRiskReset(key: string, nowIso: string): boolean {
  const db = getDatabase();
  const node = db.prepare("SELECT id, attrs FROM threat_nodes WHERE kind = 'source' AND key = ?")
    .get(key) as { id: number; attrs: string } | undefined;
  const riskRow = db.prepare('SELECT source_key FROM source_risk WHERE source_key = ?').get(key);
  if (!node && !riskRow) return false;

  if (node) {
    let attrs: Record<string, unknown>;
    try { attrs = JSON.parse(node.attrs) as Record<string, unknown>; } catch { attrs = {}; }
    delete attrs.risk_sum;
    delete attrs.risk_ref_ts;
    delete attrs.risk_win_start;
    delete attrs.risk_win_weight;
    db.prepare('UPDATE threat_nodes SET attrs = ? WHERE id = ?').run(JSON.stringify(attrs), node.id);
  }
  db.prepare('UPDATE source_risk SET risk = 0, updated_at = ? WHERE source_key = ?').run(nowIso, key);
  return true;
}

/**
 * Reset a source's accumulated risk — the operator's dispute path for a
 * risk-poisoned identity (design doc Loop 2). Clears the live graph state AND
 * records an operation='review' row carrying a structured risk_reset payload,
 * which the projector consumes on replay — so the reset survives a rebuild or
 * a projector-version bump (invariant 3: a rebuild reproduces it). Narrow
 * (one source), human-authored, self-expiring: risk re-accrues if the source
 * keeps misbehaving.
 */
export function resetSourceRisk(key: string, opts: { reviewedBy: string }): ResetSourceResult {
  const db = getDatabase();
  const nowIso = new Date().toISOString();

  const found = db.transaction(() => applyRiskReset(key, nowIso)).immediate();
  if (!found) return { found: false };

  try {
    // #305 — reviewedBy is annotation; the row identity is host-derived.
    const reviewer = inferSourceFromEnvironment().source;
    logAudit({
      memory_id: null,
      project: null,
      timestamp: nowIso,
      source_type: reviewer.type,
      source_identifier: reviewer.identifier,
      trust_score: 0.9,
      sensitivity_level: 'INTERNAL',
      firewall_result: 'ALLOW',
      operation: 'review',
      anomaly_score: 0,
      threat_indicators: '[]',
      blocked_patterns: '[]',
      reason: JSON.stringify({ kind: 'risk_reset', source_key: key, reviewed_by: opts.reviewedBy } satisfies RiskResetPayload),
      fragmentation_score: null,
      pipeline_duration_ms: null,
    });
  } catch {
    // Audit logging must never break the reset itself.
  }

  return { found: true };
}
