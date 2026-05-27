/**
 * Recall result ranking helpers.
 *
 * v4.23.0 — FTS rank primary, raw salience tiebreaker (fixed: high-salience-
 * but-off-topic memories bubbling to the top of the per-prompt recall preamble).
 *
 * v4.25.0 — tiebreaker now uses *effective* salience instead of raw:
 *   recency × access × pin × downvote_penalty. See scripts/lib/salience.mjs.
 *   The DB column stays untouched — this is a read-time computation only.
 *
 * SQLite FTS5 BM25 ranks are negative numbers — more negative = more
 * relevant. So `a.rank - b.rank` (ascending) puts the most-relevant result
 * first. Rows from the category-boost fallback path don't carry a `rank`
 * field; they sort below all FTS results.
 */

import { computeEffectiveSalience } from './salience.mjs';

/**
 * Sort comparator for memory recall results.
 *
 * Behaviour:
 * - Both rows have `rank` (FTS results): lower rank wins (more relevant)
 * - Only one has `rank`: that one wins (FTS beats category-only fallback)
 * - Neither has `rank` (or tied): higher *effective* salience wins
 *
 * Stable behaviour for equal-rank-equal-salience: original order preserved
 * (Array.prototype.sort in modern engines is stable).
 *
 * @param {{ rank?: number, salience?: number, last_accessed?: string, access_count?: number, pinned?: number, downvote_count?: number }} a
 * @param {{ rank?: number, salience?: number, last_accessed?: string, access_count?: number, pinned?: number, downvote_count?: number }} b
 * @returns {number} negative if a comes first, positive if b comes first
 */
// A row carries the v4.25 salience-formula inputs only when the SELECT
// projected pinned/access_count/last_accessed/downvote_count. Older call
// sites and recall-rank tests pass rows with just {id, rank, salience} —
// for those, fall back to raw salience comparison (v4.23 behaviour).
function hasSalienceFormulaInputs(row) {
  return (
    row.access_count !== undefined ||
    row.last_accessed !== undefined ||
    row.pinned !== undefined ||
    row.downvote_count !== undefined
  );
}

export function compareRecallResults(a, b) {
  const aHasRank = typeof a.rank === 'number' && Number.isFinite(a.rank);
  const bHasRank = typeof b.rank === 'number' && Number.isFinite(b.rank);

  if (aHasRank && bHasRank) {
    if (a.rank !== b.rank) return a.rank - b.rank;
    // Same rank → tiebreaker
  } else if (aHasRank !== bHasRank) {
    return aHasRank ? -1 : 1;
  }
  // v4.25.0: effective salience if both rows carry the formula inputs.
  // Otherwise (legacy or test rows) preserve v4.23 raw-salience behaviour.
  if (hasSalienceFormulaInputs(a) && hasSalienceFormulaInputs(b)) {
    return computeEffectiveSalience(b) - computeEffectiveSalience(a);
  }
  return (b.salience ?? 0) - (a.salience ?? 0);
}
