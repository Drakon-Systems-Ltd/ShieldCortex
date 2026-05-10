/**
 * Pure scoring functions for the LongMemEval-S harness.
 *
 * Kept side-effect free + dependency free so they can be unit-tested
 * without standing up a database or loading the dataset. The runner
 * supplies retrieved-session-id arrays + gold-session-id sets; these
 * fns return the metric numbers.
 */

import type { EngineScorecard, QuestionResult } from './types.js';

/**
 * Recall @ k: fraction of questions that have at least one retrieved
 * session in their gold set within the top-k retrieved positions.
 *
 * Note: we operate on *session ids*, not memory ids. A question with
 * 5 retrieved memories all from the same gold session counts as one
 * hit, not five — that's the metric LongMemEval reports.
 */
export function recallAtK(
  retrievedSessionIds: readonly string[],
  goldSessionIds: ReadonlySet<string>,
  k: number,
): number {
  if (k <= 0) return 0;
  if (goldSessionIds.size === 0) return 0;
  const top = retrievedSessionIds.slice(0, k);
  return top.some((id) => goldSessionIds.has(id)) ? 1 : 0;
}

/**
 * Reciprocal rank: 1 / (1-indexed position of first gold hit).
 * Returns 0 when no gold session appears anywhere in retrievedSessionIds.
 */
export function reciprocalRank(
  retrievedSessionIds: readonly string[],
  goldSessionIds: ReadonlySet<string>,
): number {
  if (goldSessionIds.size === 0) return 0;
  for (let i = 0; i < retrievedSessionIds.length; i++) {
    if (goldSessionIds.has(retrievedSessionIds[i])) {
      return 1 / (i + 1);
    }
  }
  return 0;
}

/**
 * 1-indexed rank of first gold hit within retrievedSessionIds, or null
 * if none. Used for `QuestionResult.first_hit_rank` so we can show
 * per-question diffs in the scorecard.
 */
export function firstHitRank(
  retrievedSessionIds: readonly string[],
  goldSessionIds: ReadonlySet<string>,
): number | null {
  for (let i = 0; i < retrievedSessionIds.length; i++) {
    if (goldSessionIds.has(retrievedSessionIds[i])) return i + 1;
  }
  return null;
}

/**
 * Reduce a list of `QuestionResult`s into an `EngineScorecard`. Pure —
 * the runner is responsible for measuring `duration_ms` and tagging
 * the engine.
 */
export function summarise(
  perQuestion: readonly QuestionResult[],
  engine: 'rrf' | 'legacy',
  durationMs: number,
): EngineScorecard {
  const n = perQuestion.length;
  if (n === 0) {
    return {
      engine,
      question_count: 0,
      recall_at_5: 0,
      recall_at_10: 0,
      mrr: 0,
      per_question: [],
      duration_ms: durationMs,
    };
  }

  let r5 = 0;
  let r10 = 0;
  let mrr = 0;
  for (const q of perQuestion) {
    const rank = q.first_hit_rank;
    if (rank !== null) {
      if (rank <= 5) r5++;
      if (rank <= 10) r10++;
      mrr += 1 / rank;
    }
  }

  return {
    engine,
    question_count: n,
    recall_at_5: r5 / n,
    recall_at_10: r10 / n,
    mrr: mrr / n,
    per_question: [...perQuestion],
    duration_ms: durationMs,
  };
}
