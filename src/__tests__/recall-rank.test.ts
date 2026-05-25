import { describe, expect, it } from '@jest/globals';
// @ts-expect-error -- importing a .mjs hook utility
import { compareRecallResults } from '../../scripts/lib/recall-rank.mjs';

/**
 * Unit tests for the v4.23.0 recall result comparator.
 *
 * Pre-v4.23.0 the UserPromptSubmit hook filtered candidates by FTS5 keyword
 * match then did a final sort by raw salience, discarding the relevance
 * signal. Field reports (edith, jarvis 2026-05-24) flagged high-salience-
 * but-off-topic memories bubbling to the top of the recall preamble.
 *
 * Plan A (v4.22.0 plan file): FTS rank primary, salience tiebreaker. The
 * fix is one function — these tests pin its behaviour across the corner
 * cases (FTS vs category fallback, rank ties, missing fields).
 */
describe('compareRecallResults — FTS rank primary, salience tiebreaker', () => {
  function sorted<T>(rows: T[]): T[] {
    return [...rows].sort(compareRecallResults as (a: T, b: T) => number);
  }

  it('orders FTS results by rank ascending (SQLite BM25: more negative = more relevant)', () => {
    const rows = [
      { id: 1, rank: -1.2, salience: 0.5 },
      { id: 2, rank: -5.0, salience: 0.5 },
      { id: 3, rank: -3.0, salience: 0.5 },
    ];
    expect(sorted(rows).map((r) => r.id)).toEqual([2, 3, 1]);
  });

  it('FTS results win over category-fallback results regardless of salience', () => {
    const rows = [
      { id: 'cat-high', salience: 0.9 }, // no rank — category fallback
      { id: 'fts-low', rank: -2.0, salience: 0.3 }, // FTS, low salience
    ];
    expect(sorted(rows).map((r) => r.id)).toEqual(['fts-low', 'cat-high']);
  });

  it('falls back to salience tiebreaker when FTS rank is tied', () => {
    const rows = [
      { id: 'low', rank: -2.0, salience: 0.3 },
      { id: 'high', rank: -2.0, salience: 0.8 },
      { id: 'mid', rank: -2.0, salience: 0.5 },
    ];
    expect(sorted(rows).map((r) => r.id)).toEqual(['high', 'mid', 'low']);
  });

  it('orders category-only rows (no FTS rank) by salience descending', () => {
    const rows = [
      { id: 'a', salience: 0.4 },
      { id: 'b', salience: 0.7 },
      { id: 'c', salience: 0.5 },
    ];
    expect(sorted(rows).map((r) => r.id)).toEqual(['b', 'c', 'a']);
  });

  it('treats missing salience as 0 (sorts to bottom of its group)', () => {
    const rows = [
      { id: 'has', salience: 0.1 },
      { id: 'missing' }, // no salience field
    ];
    expect(sorted(rows).map((r) => r.id)).toEqual(['has', 'missing']);
  });

  it('the edith complaint — high-salience-but-off-topic no longer beats on-topic', () => {
    // Pre-v4.23.0 sort: pure salience → 'off-topic' (0.95) first
    // Post-v4.23.0 sort: 'on-topic' wins because FTS matched
    const rows = [
      { id: 'on-topic', rank: -4.0, salience: 0.4 },
      { id: 'off-topic', salience: 0.95 }, // no FTS match — only via category fallback
    ];
    expect(sorted(rows).map((r) => r.id)).toEqual(['on-topic', 'off-topic']);
  });

  it('does not crash on NaN or Infinity rank values (treats them as missing)', () => {
    const rows = [
      { id: 'nan', rank: NaN, salience: 0.5 },
      { id: 'inf', rank: Infinity, salience: 0.5 },
      { id: 'valid', rank: -2.0, salience: 0.3 },
    ];
    // Only the valid FTS row should be promoted; the others fall back to salience tiebreaker
    expect(sorted(rows)[0]!.id).toBe('valid');
  });

  it('preserves original order when fully tied (stable sort)', () => {
    const rows = [
      { id: 'a', rank: -2.0, salience: 0.5 },
      { id: 'b', rank: -2.0, salience: 0.5 },
      { id: 'c', rank: -2.0, salience: 0.5 },
    ];
    expect(sorted(rows).map((r) => r.id)).toEqual(['a', 'b', 'c']);
  });
});
