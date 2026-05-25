/**
 * Recall result ranking helpers (v4.23.0).
 *
 * Field context (edith, jarvis 2026-05-24): the UserPromptSubmit recall hook
 * was filtering candidates by FTS5 keyword match but then doing a final sort
 * by RAW salience, discarding the relevance signal. Result: high-salience-
 * but-off-topic memories bubbled to the top of the per-prompt recall preamble
 * ("Decision: that path for the rest of this conversation"-style fragments).
 *
 * v4.23.0 picks the simplest of the three candidate approaches (A in the
 * v4.22.0 plan): **FTS rank is primary, raw salience is the tiebreaker**.
 *
 * SQLite FTS5 BM25 ranks are negative numbers — more negative = more
 * relevant. So `a.rank - b.rank` (ascending) puts the most-relevant result
 * first. Rows from the category-boost fallback path don't carry a `rank`
 * field; they sort below all FTS results.
 */

/**
 * Sort comparator for memory recall results.
 *
 * Behaviour:
 * - Both rows have `rank` (FTS results): lower rank wins (more relevant)
 * - Only one has `rank`: that one wins (FTS beats category-only fallback)
 * - Neither has `rank` (or tied): higher salience wins
 *
 * Stable behaviour for equal-rank-equal-salience: original order preserved
 * (Array.prototype.sort in modern engines is stable).
 *
 * @param {{ rank?: number, salience?: number }} a
 * @param {{ rank?: number, salience?: number }} b
 * @returns {number} negative if a comes first, positive if b comes first
 */
export function compareRecallResults(a, b) {
  const aHasRank = typeof a.rank === 'number' && Number.isFinite(a.rank);
  const bHasRank = typeof b.rank === 'number' && Number.isFinite(b.rank);

  if (aHasRank && bHasRank) {
    if (a.rank !== b.rank) return a.rank - b.rank;
    // Same rank → tiebreaker
  } else if (aHasRank !== bHasRank) {
    return aHasRank ? -1 : 1;
  }
  // Neither has rank (both from category fallback), or tied rank → salience
  return (b.salience ?? 0) - (a.salience ?? 0);
}
