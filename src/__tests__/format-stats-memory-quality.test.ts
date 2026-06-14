import { describe, it, expect } from '@jest/globals';
import { formatStats } from '../tools/context.js';
import type { SalienceDistribution } from '../memory/metrics.js';

/**
 * Phase 0 slice 2: surface the salience-wall instrument through the existing
 * `memory_stats` tool (which renders via formatStats) — no parallel tool.
 */
const baseStats = {
  total: 10, shortTerm: 4, longTerm: 6, episodic: 0,
  byCategory: { architecture: 3, error: 2 }, averageSalience: 0.8,
};

describe('formatStats — Memory Quality section (salience wall)', () => {
  it('appends a Memory Quality section with the wall % and fragment % when a distribution is given', () => {
    const dist: SalienceDistribution = {
      total: 10,
      bands: [],
      wall: { ltmAtOrAbove095: 6, ltmTotal: 6, ltmPct: 100 },
      fragments: { atOrAbove095: 5, pctOfWall: 83 },
      warnings: ['Salience wall: 100% of long-term memories sit at salience ≥0.95 (raw salience has stopped discriminating).'],
    };
    const out = formatStats(baseStats, dist);
    expect(out).toMatch(/Memory Quality/);
    expect(out).toMatch(/100%/);            // wall pct
    expect(out).toMatch(/83%/);             // fragment pct of wall
    expect(out).toMatch(/Salience wall/);   // warning surfaced verbatim
  });

  it('omits the Memory Quality section when no distribution is provided (back-compat)', () => {
    const out = formatStats(baseStats);
    expect(out).not.toMatch(/Memory Quality/);
    expect(out).toMatch(/Memory Statistics/); // existing output intact
  });
});
