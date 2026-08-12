/**
 * Operator allowance state machine (design doc Loop 3). Pure — a deterministic
 * function of the ledger's quarantine_decision rows, stored in the `allows`
 * edge's attrs so a rebuild reproduces every allowance.
 *
 * An allowance is keyed (source, pattern) — a DETECTOR class, not a payload.
 * It activates only on N qualifying approvals (distinct days AND distinct
 * content hashes, individually reviewed), and consumption (auto-release) is
 * further gated on near-duplicate match to an approved exemplar, so the scope
 * never becomes a tunnel. Revocation is remembered; a second revocation
 * disables the pair for good.
 */

import { getDatabase, isDatabaseInitialized } from '../database/init.js';
import { logAudit } from '../defence/audit/logger.js';

const DAY_MS = 24 * 60 * 60 * 1000;
const BASE_N = 3;
const BASE_WINDOW_DAYS = 30;

export interface ApprovalRecord {
  day: string;   // 'YYYY-MM-DD' (ledger-derived)
  hash: string;  // normalised content hash
  ts: string;    // ISO timestamp (ledger-derived)
}

export interface AllowanceState {
  approvals: ApprovalRecord[]; // non-bulk, deduped by hash, within the window
  exemplars: string[];         // hashes that earned the current active allowance
  active: boolean;
  expires: string | null;      // ISO; allowance valid until this while active
  strikes: number;             // revocations remembered
  disabled: boolean;           // ≥2 strikes → annotation-only forever
}

export function freshAllowance(): AllowanceState {
  return { approvals: [], exemplars: [], active: false, expires: null, strikes: 0, disabled: false };
}

/** Thresholds scale with strikes: base 3/30d, after one strike 6/60d. */
function thresholds(strikes: number): { n: number; windowMs: number } {
  const factor = strikes + 1; // 0 strikes → ×1, 1 strike → ×2
  return { n: BASE_N * factor, windowMs: BASE_WINDOW_DAYS * factor * DAY_MS };
}

export interface DecisionEvent {
  ts: string;
  day: string;
  hash: string;
  bulk: boolean;
}

/**
 * Fold one approval. Bulk approvals and decisions on a disabled pair are
 * no-ops. Near-dups (same hash) count once. Activates when the window holds
 * ≥N approvals spanning ≥N distinct days with ≥N distinct hashes.
 */
export function applyApproval(state: AllowanceState, ev: DecisionEvent): AllowanceState {
  if (ev.bulk || state.disabled) return state;
  const { n, windowMs } = thresholds(state.strikes);
  const nowMs = Date.parse(ev.ts);

  // Prune out-of-window approvals, then add this one (deduped by hash).
  const kept = state.approvals.filter((a) => nowMs - Date.parse(a.ts) < windowMs);
  const next = kept.some((a) => a.hash === ev.hash)
    ? kept
    : [...kept, { day: ev.day, hash: ev.hash, ts: ev.ts }];

  const distinctHashes = new Set(next.map((a) => a.hash));
  const distinctDays = new Set(next.map((a) => a.day));
  const qualifies = distinctHashes.size >= n && distinctDays.size >= n;

  if (qualifies) {
    return {
      ...state,
      approvals: next,
      active: true,
      exemplars: [...distinctHashes],
      expires: new Date(nowMs + windowMs).toISOString(),
    };
  }
  return { ...state, approvals: next };
}

/**
 * Fold one rejection: revoke immediately and record a strike; re-earning then
 * requires the higher threshold. A second strike disables the pair for good.
 * Approvals are cleared so the pair must be re-earned from scratch.
 */
export function applyRejection(state: AllowanceState, ev: { ts: string }): AllowanceState {
  // A reject with no allowance history at all is noise — nothing to revoke.
  if (state.approvals.length === 0 && !state.active && state.strikes === 0) return state;
  const strikes = state.strikes + 1;
  return {
    approvals: [],
    exemplars: [],
    active: false,
    expires: null,
    strikes,
    disabled: strikes >= 2,
  };
}

export function isAllowanceActive(state: AllowanceState, nowMs: number): boolean {
  return (
    state.active &&
    !state.disabled &&
    state.expires !== null &&
    Date.parse(state.expires) > nowMs
  );
}

/** Whether a content hash matches one of the exemplars that earned the
 * allowance — the near-duplicate gate for auto-release. */
export function matchesExemplar(state: AllowanceState, hash: string): boolean {
  return state.exemplars.includes(hash);
}

// ── Auto-release consumption (DB) ────────────────────────────────────────────

const DEFAULT_DAILY_CAP = 20;

export interface AutoReleaseQuery {
  sourceKey: string;
  /** The COMPLETE detection set (blocked_patterns ∪ threat_indicators) —
   * EVERY entry must have an active allowance. A subset lets an item with an
   * unlisted detection slip through. */
  patterns: string[];
  contentHash: string;
  nowMs: number;
  /** Resolved verdict. Auto-release NEVER admits a BLOCK — fails closed unless
   * this is exactly 'QUARANTINE' (invariant 2: never downgrade a verdict). */
  verdict: 'ALLOW' | 'BLOCK' | 'QUARANTINE';
  dailyCap?: number;
}

export interface AutoReleaseResult {
  release: boolean;
  reason?: string;
}

/**
 * Decide whether a would-be-quarantined item may be auto-released. Fails
 * CLOSED (release:false) on any doubt or error — auto-release is the loosening,
 * so a fault must never admit content. Requires: at least one detection; EVERY
 * detection pattern has an ACTIVE allowance for the source whose exemplars
 * include this content hash; and the source is under its per-day cap.
 */
export function shouldAutoRelease(q: AutoReleaseQuery): AutoReleaseResult {
  if (!isDatabaseInitialized()) return { release: false };
  // BLOCK is never auto-released — invariant 2. Fail closed on anything but
  // an exact QUARANTINE.
  if (q.verdict !== 'QUARANTINE') return { release: false, reason: 'verdict is not QUARANTINE' };
  if (q.patterns.length === 0) return { release: false, reason: 'no detection to release against' };
  const cap = q.dailyCap ?? DEFAULT_DAILY_CAP;

  try {
    const db = getDatabase();
    const stmt = db.prepare(`
      SELECT e.attrs FROM threat_edges e
      JOIN threat_nodes s ON s.id = e.src
      JOIN threat_nodes p ON p.id = e.dst
      WHERE e.predicate = 'allows' AND s.kind = 'source' AND s.key = ? AND p.kind = 'pattern' AND p.key = ?
    `);
    for (const pattern of q.patterns) {
      const row = stmt.get(q.sourceKey, pattern) as { attrs: string } | undefined;
      if (!row) return { release: false, reason: `no allowance for ${pattern}` };
      let state: AllowanceState;
      try { state = JSON.parse(row.attrs) as AllowanceState; } catch { return { release: false }; }
      if (!isAllowanceActive(state, q.nowMs)) return { release: false, reason: `allowance inactive for ${pattern}` };
      if (!matchesExemplar(state, q.contentHash)) return { release: false, reason: `content not a near-dup for ${pattern}` };
    }

    const dayStart = new Date(q.nowMs);
    dayStart.setUTCHours(0, 0, 0, 0);
    const count = (db.prepare(`
      SELECT COUNT(*) AS c FROM defence_audit
      WHERE source_type = 'auto_release' AND source_identifier = ?
        AND threat_indicators LIKE '%auto_released%' AND timestamp >= ?
    `).get(q.sourceKey, dayStart.toISOString()) as { c: number }).c;
    if (count >= cap) return { release: false, reason: `per-day auto-release cap (${cap}) reached` };

    return { release: true };
  } catch {
    return { release: false };
  }
}

export interface AllowanceSummary {
  source_key: string;
  pattern: string;
  active: boolean;
  disabled: boolean;
  strikes: number;
  expires: string | null;
  exemplars: number;
}

/** List allowance edges for the tool / CLI / annotation surface. `nowMs`
 * decides the live active flag (expiry-aware). */
export function listAllowances(nowMs: number, limit = 200): AllowanceSummary[] {
  if (!isDatabaseInitialized()) return [];
  const rows = getDatabase().prepare(`
    SELECT s.key AS source_key, p.key AS pattern, e.attrs
    FROM threat_edges e
    JOIN threat_nodes s ON s.id = e.src
    JOIN threat_nodes p ON p.id = e.dst
    WHERE e.predicate = 'allows'
    ORDER BY e.last_seen DESC LIMIT ?
  `).all(limit) as Array<{ source_key: string; pattern: string; attrs: string }>;

  const out: AllowanceSummary[] = [];
  for (const r of rows) {
    let st: AllowanceState;
    try { st = JSON.parse(r.attrs) as AllowanceState; } catch { continue; }
    out.push({
      source_key: r.source_key,
      pattern: r.pattern,
      active: isAllowanceActive(st, nowMs),
      disabled: st.disabled,
      strikes: st.strikes,
      expires: st.expires,
      exemplars: st.exemplars.length,
    });
  }
  return out;
}

/** Ledger ONE auto-release per released item (not per pattern) for
 * after-the-fact review and the per-source per-day cap. */
export function recordAutoRelease(a: { sourceKey: string; patterns: string[]; contentHash: string; nowMs: number }): void {
  try {
    logAudit({
      memory_id: null,
      project: null,
      timestamp: new Date(a.nowMs).toISOString(),
      source_type: 'auto_release',
      source_identifier: a.sourceKey,
      trust_score: 0.9,
      sensitivity_level: 'INTERNAL',
      firewall_result: 'ALLOW',
      operation: 'review',
      anomaly_score: 0,
      threat_indicators: JSON.stringify(['auto_released']),
      blocked_patterns: '[]',
      reason: JSON.stringify({ kind: 'auto_release', source_key: a.sourceKey, patterns: a.patterns, content_hash: a.contentHash }),
      fragmentation_score: null,
      pipeline_duration_ms: null,
    });
  } catch {
    // Recording must never break the release path.
  }
}
