/**
 * Unit tests for the LongMemEval scoring functions. Pure code — no DB,
 * no fixture files.
 */
import { describe, expect, it } from '@jest/globals';
import {
  recallAtK,
  reciprocalRank,
  firstHitRank,
  summarise,
} from '../../benchmark/longmemeval/score.js';
import type { QuestionResult } from '../../benchmark/longmemeval/types.js';

const gold = (...ids: string[]) => new Set(ids);

describe('recallAtK', () => {
  it('returns 1 when a gold session is in top-k', () => {
    expect(recallAtK(['s1', 's2', 's3'], gold('s2'), 5)).toBe(1);
  });

  it('returns 0 when no gold session appears in top-k', () => {
    expect(recallAtK(['s1', 's2', 's3'], gold('s9'), 5)).toBe(0);
  });

  it('respects k — gold at position k+1 does not count', () => {
    expect(recallAtK(['s1', 's2', 's3', 's-gold'], gold('s-gold'), 3)).toBe(0);
    expect(recallAtK(['s1', 's2', 's3', 's-gold'], gold('s-gold'), 4)).toBe(1);
  });

  it('returns 0 for empty gold set', () => {
    expect(recallAtK(['s1', 's2'], gold(), 5)).toBe(0);
  });

  it('returns 0 when k <= 0', () => {
    expect(recallAtK(['s1'], gold('s1'), 0)).toBe(0);
    expect(recallAtK(['s1'], gold('s1'), -1)).toBe(0);
  });

  it('counts a single hit even if multiple gold sessions match', () => {
    // Recall@k is 0 or 1 per question — multi-hit doesn't go above 1.
    expect(recallAtK(['s1', 's2'], gold('s1', 's2'), 5)).toBe(1);
  });
});

describe('reciprocalRank', () => {
  it('is 1 when first retrieved item is gold', () => {
    expect(reciprocalRank(['s1', 's2'], gold('s1'))).toBe(1);
  });

  it('is 1/2 when first gold hit is at position 2', () => {
    expect(reciprocalRank(['s1', 's2'], gold('s2'))).toBe(0.5);
  });

  it('is 1/3 when first gold hit is at position 3', () => {
    expect(reciprocalRank(['s1', 's2', 's3'], gold('s3'))).toBeCloseTo(1 / 3, 6);
  });

  it('is 0 when no gold session appears', () => {
    expect(reciprocalRank(['s1', 's2'], gold('s9'))).toBe(0);
  });

  it('takes the first hit even if later positions are also gold', () => {
    expect(reciprocalRank(['s1', 's2', 's3'], gold('s2', 's3'))).toBe(0.5);
  });

  it('is 0 for empty gold set', () => {
    expect(reciprocalRank(['s1', 's2'], gold())).toBe(0);
  });
});

describe('firstHitRank', () => {
  it('returns 1-indexed rank of the first hit', () => {
    expect(firstHitRank(['s1', 's2', 's3'], gold('s2'))).toBe(2);
  });

  it('returns null when nothing matches', () => {
    expect(firstHitRank(['s1', 's2'], gold('s9'))).toBeNull();
  });

  it('returns null for empty retrieval list', () => {
    expect(firstHitRank([], gold('s1'))).toBeNull();
  });
});

describe('summarise', () => {
  const baseResult = (
    id: string,
    rank: number | null,
    sessionIds: string[] = ['s'],
  ): QuestionResult => ({
    question_id: id,
    retrieved_memory_ids: [],
    retrieved_session_ids: sessionIds,
    first_hit_rank: rank,
    gold_session_count: 1,
  });

  it('zero-question input returns zeros (no NaN)', () => {
    const card = summarise([], 'rrf', 0);
    expect(card.recall_at_5).toBe(0);
    expect(card.recall_at_10).toBe(0);
    expect(card.mrr).toBe(0);
    expect(card.question_count).toBe(0);
  });

  it('all hits within top-5 → R@5 = 1.0', () => {
    const card = summarise(
      [baseResult('q1', 1), baseResult('q2', 3), baseResult('q3', 5)],
      'rrf',
      100,
    );
    expect(card.recall_at_5).toBe(1);
    expect(card.recall_at_10).toBe(1);
    expect(card.question_count).toBe(3);
    expect(card.duration_ms).toBe(100);
    expect(card.engine).toBe('rrf');
  });

  it('hits beyond top-5 contribute to R@10 only', () => {
    const card = summarise(
      [baseResult('q1', 8), baseResult('q2', 11), baseResult('q3', 3)],
      'legacy',
      50,
    );
    // q1 (rank 8): R@5 miss, R@10 hit
    // q2 (rank 11): R@5 miss, R@10 miss
    // q3 (rank 3): both hit
    expect(card.recall_at_5).toBeCloseTo(1 / 3, 6);
    expect(card.recall_at_10).toBeCloseTo(2 / 3, 6);
  });

  it('null first_hit_rank contributes 0 to MRR', () => {
    const card = summarise([baseResult('q1', 1), baseResult('q2', null)], 'rrf', 0);
    expect(card.mrr).toBeCloseTo((1 + 0) / 2, 6);
  });

  it('MRR matches manual calculation', () => {
    const card = summarise(
      [baseResult('q1', 1), baseResult('q2', 2), baseResult('q3', 4)],
      'rrf',
      0,
    );
    const expected = (1 + 1 / 2 + 1 / 4) / 3;
    expect(card.mrr).toBeCloseTo(expected, 6);
  });

  it('returns immutable copy of per_question (not the original ref)', () => {
    const inputs: QuestionResult[] = [baseResult('q1', 1)];
    const card = summarise(inputs, 'rrf', 0);
    expect(card.per_question).not.toBe(inputs);
    expect(card.per_question[0]).toEqual(inputs[0]);
  });
});
