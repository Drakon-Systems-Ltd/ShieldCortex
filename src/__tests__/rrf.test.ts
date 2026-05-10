/**
 * Tests for Reciprocal Rank Fusion (RRF).
 *
 * RRF is a rank-based fusion method for combining multiple retrievers
 * (e.g. BM25, vector, graph) into a single score that's robust to
 * heterogeneous score scales between retrievers.
 *
 *   score(d) = Σ_i  w_i / (k + rank_i(d))
 *
 * where rank_i(d) is the 1-indexed rank of document d in retriever i,
 * w_i is the optional weight for retriever i (default 1), and k is a
 * smoothing constant (Cormack et al. 2009 use 60).
 */

import { describe, it, expect } from '@jest/globals';

describe('reciprocalRankFusion', () => {
  it('returns empty array when given no rank lists', async () => {
    const { reciprocalRankFusion } = await import('../memory/ranker/rrf.js');
    expect(reciprocalRankFusion([])).toEqual([]);
  });

  it('returns empty array when every rank list is empty', async () => {
    const { reciprocalRankFusion } = await import('../memory/ranker/rrf.js');
    expect(
      reciprocalRankFusion([
        { name: 'fts', ids: [] },
        { name: 'vector', ids: [] },
      ]),
    ).toEqual([]);
  });

  it('scores a single id from a single retriever as 1 / (k + 1)', async () => {
    const { reciprocalRankFusion } = await import('../memory/ranker/rrf.js');
    const results = reciprocalRankFusion([{ name: 'fts', ids: [42] }], { k: 60 });
    expect(results).toHaveLength(1);
    expect(results[0].id).toBe(42);
    expect(results[0].score).toBeCloseTo(1 / 61, 10);
    expect(results[0].contributions).toEqual([{ name: 'fts', rank: 1, weighted: 1 / 61 }]);
  });

  it('preserves order within a single retriever and produces monotonically decreasing scores', async () => {
    const { reciprocalRankFusion } = await import('../memory/ranker/rrf.js');
    const results = reciprocalRankFusion([{ name: 'fts', ids: [10, 20, 30, 40] }]);
    expect(results.map((r) => r.id)).toEqual([10, 20, 30, 40]);
    for (let i = 0; i < results.length - 1; i++) {
      expect(results[i].score).toBeGreaterThan(results[i + 1].score);
    }
  });

  it('sums contributions from multiple retrievers that find the same id', async () => {
    const { reciprocalRankFusion } = await import('../memory/ranker/rrf.js');
    const results = reciprocalRankFusion(
      [
        { name: 'fts', ids: [7] },
        { name: 'vector', ids: [7] },
      ],
      { k: 60 },
    );
    expect(results).toHaveLength(1);
    expect(results[0].id).toBe(7);
    // Both retrievers rank id 7 first → score = 1/(60+1) + 1/(60+1) = 2/61
    expect(results[0].score).toBeCloseTo(2 / 61, 10);
    expect(results[0].contributions).toEqual([
      { name: 'fts', rank: 1, weighted: 1 / 61 },
      { name: 'vector', rank: 1, weighted: 1 / 61 },
    ]);
  });

  it('ranks the union of ids across all retrievers', async () => {
    const { reciprocalRankFusion } = await import('../memory/ranker/rrf.js');
    const results = reciprocalRankFusion([
      { name: 'fts', ids: [1, 2] },
      { name: 'vector', ids: [3, 4] },
      { name: 'graph', ids: [5] },
    ]);
    // 1, 2, 3, 4, 5 should all appear (in some order)
    expect(new Set(results.map((r) => r.id))).toEqual(new Set([1, 2, 3, 4, 5]));
  });

  it('promotes ids that appear in multiple retrievers above ids that only appear in one', async () => {
    const { reciprocalRankFusion } = await import('../memory/ranker/rrf.js');
    // Without overlap: A is rank 1 in FTS only; B is rank 2 in FTS but rank 1 in vector.
    // RRF should put B above A because B accumulates contributions from two retrievers.
    const results = reciprocalRankFusion(
      [
        { name: 'fts', ids: [/* A */ 100, /* B */ 200] },
        { name: 'vector', ids: [/* B */ 200, /* C */ 300] },
      ],
      { k: 60 },
    );
    const ids = results.map((r) => r.id);
    const idxA = ids.indexOf(100);
    const idxB = ids.indexOf(200);
    expect(idxB).toBeLessThan(idxA);
  });

  it('respects per-retriever weights', async () => {
    const { reciprocalRankFusion } = await import('../memory/ranker/rrf.js');
    // Same id in two retrievers; vector weight 2× fts weight. Vector contribution
    // should dominate, but the SUM determines final score.
    const results = reciprocalRankFusion(
      [
        { name: 'fts', ids: [1], weight: 1 },
        { name: 'vector', ids: [1], weight: 2 },
      ],
      { k: 60 },
    );
    expect(results[0].score).toBeCloseTo(1 / 61 + 2 / 61, 10);
    expect(results[0].contributions).toEqual([
      { name: 'fts', rank: 1, weighted: 1 / 61 },
      { name: 'vector', rank: 1, weighted: 2 / 61 },
    ]);
  });

  it('weights default to 1 when not provided', async () => {
    const { reciprocalRankFusion } = await import('../memory/ranker/rrf.js');
    const a = reciprocalRankFusion([{ name: 'fts', ids: [9] }]);
    const b = reciprocalRankFusion([{ name: 'fts', ids: [9], weight: 1 }]);
    expect(a[0].score).toBeCloseTo(b[0].score, 12);
  });

  it('uses k=60 by default (Cormack et al)', async () => {
    const { reciprocalRankFusion } = await import('../memory/ranker/rrf.js');
    const results = reciprocalRankFusion([{ name: 'fts', ids: [1] }]);
    expect(results[0].score).toBeCloseTo(1 / 61, 10);
  });

  it('changes k changes the score magnitude but preserves rank order when retrievers agree', async () => {
    const { reciprocalRankFusion } = await import('../memory/ranker/rrf.js');
    const small = reciprocalRankFusion(
      [
        { name: 'fts', ids: [1, 2, 3] },
        { name: 'vector', ids: [1, 2, 3] },
      ],
      { k: 0 },
    );
    const large = reciprocalRankFusion(
      [
        { name: 'fts', ids: [1, 2, 3] },
        { name: 'vector', ids: [1, 2, 3] },
      ],
      { k: 1000 },
    );
    expect(small.map((r) => r.id)).toEqual([1, 2, 3]);
    expect(large.map((r) => r.id)).toEqual([1, 2, 3]);
    expect(small[0].score).toBeGreaterThan(large[0].score);
  });

  it('deduplicates ids that appear more than once within a single rank list (keeps first occurrence)', async () => {
    const { reciprocalRankFusion } = await import('../memory/ranker/rrf.js');
    const results = reciprocalRankFusion([{ name: 'fts', ids: [5, 10, 5, 15] }], { k: 60 });
    // 5 appears at rank 1 and rank 3 — only the rank-1 contribution counts.
    expect(results.map((r) => r.id)).toEqual([5, 10, 15]);
    const five = results.find((r) => r.id === 5)!;
    expect(five.score).toBeCloseTo(1 / 61, 10);
  });

  it('omits empty rank lists from contributions without crashing', async () => {
    const { reciprocalRankFusion } = await import('../memory/ranker/rrf.js');
    const results = reciprocalRankFusion([
      { name: 'fts', ids: [1, 2] },
      { name: 'vector', ids: [] },
      { name: 'graph', ids: [] },
    ]);
    expect(results.map((r) => r.id)).toEqual([1, 2]);
    for (const r of results) {
      expect(r.contributions.every((c) => c.name === 'fts')).toBe(true);
    }
  });

  it('matches a hand-computed three-retriever example', async () => {
    const { reciprocalRankFusion } = await import('../memory/ranker/rrf.js');
    // Three retrievers, k=60, equal weights.
    //   FTS:    [A=1, B=2, C=3]
    //   Vector: [B=1, A=2, D=3]
    //   Graph:  [A=1, D=2]
    // Expected:
    //   A: 1/61 + 1/62 + 1/61 = 0.04935...
    //   B: 1/62 + 1/61          = 0.03252...
    //   C: 1/63                  = 0.01587
    //   D: 1/63 + 1/62           = 0.03200...
    const results = reciprocalRankFusion(
      [
        { name: 'fts', ids: [1, 2, 3] },
        { name: 'vector', ids: [2, 1, 4] },
        { name: 'graph', ids: [1, 4] },
      ],
      { k: 60 },
    );
    const score = (id: number) => results.find((r) => r.id === id)!.score;
    expect(score(1)).toBeCloseTo(1 / 61 + 1 / 62 + 1 / 61, 10);
    expect(score(2)).toBeCloseTo(1 / 62 + 1 / 61, 10);
    expect(score(3)).toBeCloseTo(1 / 63, 10);
    expect(score(4)).toBeCloseTo(1 / 63 + 1 / 62, 10);
    expect(results[0].id).toBe(1);
  });

  it('breaks score ties deterministically (by id ascending) for stable ordering across runs', async () => {
    const { reciprocalRankFusion } = await import('../memory/ranker/rrf.js');
    // Two ids with identical contributions should sort by id ascending so
    // dashboard listings don't shuffle on equal scores.
    const results = reciprocalRankFusion(
      [
        { name: 'fts', ids: [99, 7] },
        { name: 'vector', ids: [7, 99] },
      ],
      { k: 60 },
    );
    expect(results[0].score).toBeCloseTo(results[1].score, 10);
    expect(results[0].id).toBe(7);
    expect(results[1].id).toBe(99);
  });
});
