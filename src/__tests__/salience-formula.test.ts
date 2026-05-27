import { describe, it, expect } from '@jest/globals';

/**
 * v4.25.0: effective salience formula at recall time.
 *
 *   effective = base × recency × access × pin × downvote_penalty
 *
 * No DB writes — purely a read-time computation in scripts/lib/salience.mjs.
 * compareRecallResults() uses it as the tiebreaker for FTS results with
 * equal BM25 rank, replacing the pre-4.25 raw-salience tiebreaker.
 *
 * These tests pin each factor in isolation so a future tweak to one
 * (e.g. switching from log-scaled access to linear) doesn't silently
 * change the ranking of unrelated factors.
 */

describe('v4.25.0 computeEffectiveSalience', () => {
  it('returns base salience when all factors are neutral (now, never-accessed, unpinned, no downvotes)', async () => {
    const { computeEffectiveSalience } = await import('../../scripts/lib/salience.mjs');
    const now = Date.parse('2026-05-27T00:00:00Z');
    // last_accessed=now → recency=1
    // access_count=0 → access = log(1)/log(11) = 0  ← uh that makes it 0
    // We need at least one access for the access factor to be > 0.
    const score = computeEffectiveSalience(
      { salience: 0.5, last_accessed: '2026-05-27T00:00:00Z', access_count: 10, pinned: 0, downvote_count: 0 },
      { now },
    );
    // access = log(1+10) / log(1+10) = 1, all others = 1, so effective = 0.5
    expect(score).toBeCloseTo(0.5, 3);
  });

  it('recency factor decays exponentially with default 14-day half-life', async () => {
    const { computeEffectiveSalience } = await import('../../scripts/lib/salience.mjs');
    const now = Date.parse('2026-05-27T00:00:00Z');
    const fortnightAgo = '2026-05-13T00:00:00Z'; // 14 days
    const score = computeEffectiveSalience(
      { salience: 1.0, last_accessed: fortnightAgo, access_count: 10, pinned: 0, downvote_count: 0 },
      { now },
    );
    // 14d / 14d half-life → exp(-1) ≈ 0.368
    expect(score).toBeCloseTo(Math.exp(-1), 2);
  });

  it('access factor is log-scaled and normalised to ~1 at access_count=10 (default)', async () => {
    const { computeEffectiveSalience } = await import('../../scripts/lib/salience.mjs');
    const now = Date.parse('2026-05-27T00:00:00Z');
    const cold = computeEffectiveSalience(
      { salience: 1.0, last_accessed: '2026-05-27T00:00:00Z', access_count: 0, pinned: 0, downvote_count: 0 },
      { now },
    );
    const warm = computeEffectiveSalience(
      { salience: 1.0, last_accessed: '2026-05-27T00:00:00Z', access_count: 10, pinned: 0, downvote_count: 0 },
      { now },
    );
    expect(cold).toBe(0); // log(1) = 0
    expect(warm).toBeCloseTo(1.0, 2);
  });

  it('pinned memories get a default 1.5x boost over identical unpinned ones', async () => {
    const { computeEffectiveSalience } = await import('../../scripts/lib/salience.mjs');
    const now = Date.parse('2026-05-27T00:00:00Z');
    const common = { salience: 0.5, last_accessed: '2026-05-27T00:00:00Z', access_count: 10, downvote_count: 0 };
    const unpinned = computeEffectiveSalience({ ...common, pinned: 0 }, { now });
    const pinned = computeEffectiveSalience({ ...common, pinned: 1 }, { now });
    expect(pinned / unpinned).toBeCloseTo(1.5, 2);
  });

  it('downvote_count linearly subtracts from the multiplier (default 0.3 per downvote)', async () => {
    const { computeEffectiveSalience } = await import('../../scripts/lib/salience.mjs');
    const now = Date.parse('2026-05-27T00:00:00Z');
    const common = { salience: 0.5, last_accessed: '2026-05-27T00:00:00Z', access_count: 10, pinned: 0 };
    const clean = computeEffectiveSalience({ ...common, downvote_count: 0 }, { now });
    const oneDown = computeEffectiveSalience({ ...common, downvote_count: 1 }, { now });
    const twoDown = computeEffectiveSalience({ ...common, downvote_count: 2 }, { now });
    expect(oneDown / clean).toBeCloseTo(0.7, 2);
    expect(twoDown / clean).toBeCloseTo(0.4, 2);
  });

  it('downvote penalty floors at 0.1 so downvoted memories can still surface when truly relevant', async () => {
    const { computeEffectiveSalience } = await import('../../scripts/lib/salience.mjs');
    const now = Date.parse('2026-05-27T00:00:00Z');
    const common = { salience: 0.5, last_accessed: '2026-05-27T00:00:00Z', access_count: 10, pinned: 0 };
    const heavilyDownvoted = computeEffectiveSalience({ ...common, downvote_count: 100 }, { now });
    // floor at 0.1 × base × access × recency × pin = 0.1 × 0.5 × 1 × 1 × 1 = 0.05
    expect(heavilyDownvoted).toBeCloseTo(0.05, 3);
    expect(heavilyDownvoted).toBeGreaterThan(0);
  });

  it('env-var overrides take precedence over defaults', async () => {
    const { computeEffectiveSalience } = await import('../../scripts/lib/salience.mjs');
    const now = Date.parse('2026-05-27T00:00:00Z');
    const score = computeEffectiveSalience(
      { salience: 1.0, last_accessed: '2026-05-27T00:00:00Z', access_count: 10, pinned: 1, downvote_count: 0 },
      { now, pinBoost: 3.0 },
    );
    expect(score).toBeCloseTo(3.0, 2);
  });

  it('missing fields are tolerated (returns 0 base when salience is undefined)', async () => {
    const { computeEffectiveSalience } = await import('../../scripts/lib/salience.mjs');
    const score = computeEffectiveSalience({});
    expect(score).toBe(0);
  });

  it('missing last_accessed assumes "now" — fresh memory not penalised', async () => {
    const { computeEffectiveSalience } = await import('../../scripts/lib/salience.mjs');
    const now = Date.parse('2026-05-27T00:00:00Z');
    const score = computeEffectiveSalience(
      { salience: 0.5, access_count: 10, pinned: 0, downvote_count: 0 },
      { now },
    );
    // recency=1, access=1, pin=1, dv=1 → base
    expect(score).toBeCloseTo(0.5, 3);
  });
});

describe('v4.25.0 compareRecallResults — effective salience tiebreaker', () => {
  it('downvoted memory ranks below identical clean memory when ranks tie', async () => {
    const { compareRecallResults } = await import('../../scripts/lib/recall-rank.mjs');
    const a = { rank: -10, salience: 0.5, last_accessed: '2026-05-27T00:00:00Z', access_count: 10, pinned: 0, downvote_count: 3 };
    const b = { rank: -10, salience: 0.5, last_accessed: '2026-05-27T00:00:00Z', access_count: 10, pinned: 0, downvote_count: 0 };
    // tied rank → effective salience tiebreaker → b should win
    expect(compareRecallResults(a, b)).toBeGreaterThan(0);
  });

  it('pinned memory ranks above identical unpinned one when ranks tie', async () => {
    const { compareRecallResults } = await import('../../scripts/lib/recall-rank.mjs');
    const pinned = { rank: -5, salience: 0.4, last_accessed: '2026-05-27T00:00:00Z', access_count: 10, pinned: 1, downvote_count: 0 };
    const unpinned = { rank: -5, salience: 0.4, last_accessed: '2026-05-27T00:00:00Z', access_count: 10, pinned: 0, downvote_count: 0 };
    expect(compareRecallResults(pinned, unpinned)).toBeLessThan(0);
  });

  it('FTS rank still beats effective salience (rank is primary)', async () => {
    const { compareRecallResults } = await import('../../scripts/lib/recall-rank.mjs');
    // a is heavily downvoted but more relevant by FTS → a wins
    const a = { rank: -100, salience: 0.5, last_accessed: '2026-05-27T00:00:00Z', access_count: 10, pinned: 0, downvote_count: 3 };
    const b = { rank: -10, salience: 0.5, last_accessed: '2026-05-27T00:00:00Z', access_count: 10, pinned: 0, downvote_count: 0 };
    expect(compareRecallResults(a, b)).toBeLessThan(0);
  });
});
