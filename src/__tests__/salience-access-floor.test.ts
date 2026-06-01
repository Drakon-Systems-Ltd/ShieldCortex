import { describe, it, expect } from '@jest/globals';

/**
 * Task 1 of the memory-quality fix.
 *
 * The `access` factor in computeEffectiveSalience was a 0..1 gate:
 *   access = log1p(access_count) / log1p(accessNorm)
 * For access_count=0 that is log1p(0)/log1p(10) = 0, and because access is a
 * *multiplicative* factor it collapsed the ENTIRE effective salience to 0 for
 * any never-recalled memory. On the live DB ~44% of rows have access_count=0,
 * so all of them tied at 0 and effective-salience ranking did nothing.
 *
 * The fix turns access into a 0.4..1.0 boost (floor env-tunable via
 * SHIELDCORTEX_ACCESS_FLOOR), so access still lifts frequently-used memories
 * but never zeroes a never-accessed one — letting recency/pin/base discriminate.
 */

describe('access floor: never-accessed memories are no longer zeroed', () => {
  it('a fresh, never-accessed memory has effective salience > 0', async () => {
    const { computeEffectiveSalience } = await import('../../scripts/lib/salience.mjs');
    const now = Date.parse('2026-06-01T00:00:00Z');
    const score = computeEffectiveSalience(
      { salience: 0.6, access_count: 0, last_accessed: '2026-06-01T00:00:00Z', pinned: 0, downvote_count: 0 },
      { now },
    );
    expect(score).toBeGreaterThan(0);
  });

  it('recency breaks the tie: a fresh low-base memory outranks a stale high-base one when both are never-accessed', async () => {
    const { computeEffectiveSalience } = await import('../../scripts/lib/salience.mjs');
    const now = Date.parse('2026-06-01T00:00:00Z');
    const fresh = computeEffectiveSalience(
      { salience: 0.6, access_count: 0, last_accessed: '2026-06-01T00:00:00Z', pinned: 0, downvote_count: 0 },
      { now },
    );
    const stale = computeEffectiveSalience(
      // ~3 months ago
      { salience: 1.0, access_count: 0, last_accessed: '2026-03-01T00:00:00Z', pinned: 0, downvote_count: 0 },
      { now },
    );
    expect(fresh).toBeGreaterThan(stale);
  });

  it('SHIELDCORTEX_ACCESS_FLOOR tunes the floor for a never-accessed memory', async () => {
    const { computeEffectiveSalience } = await import('../../scripts/lib/salience.mjs');
    const now = Date.parse('2026-06-01T00:00:00Z');
    const prev = process.env.SHIELDCORTEX_ACCESS_FLOOR;
    process.env.SHIELDCORTEX_ACCESS_FLOOR = '0.5';
    try {
      // base=1, recency=1, access=floor (access_count=0), pin=1, dv=1 → effective = floor
      const score = computeEffectiveSalience(
        { salience: 1.0, access_count: 0, last_accessed: '2026-06-01T00:00:00Z', pinned: 0, downvote_count: 0 },
        { now },
      );
      expect(score).toBeCloseTo(0.5, 3);
    } finally {
      if (prev === undefined) delete process.env.SHIELDCORTEX_ACCESS_FLOOR;
      else process.env.SHIELDCORTEX_ACCESS_FLOOR = prev;
    }
  });
});
