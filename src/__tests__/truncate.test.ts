import { describe, expect, it } from '@jest/globals';
// @ts-expect-error -- importing a .mjs hook utility
import { truncatePreservingWords } from '../../scripts/lib/truncate.mjs';

/**
 * Unit tests for the word-boundary-aware truncation helper used by the
 * SessionStart preamble and the UserPromptSubmit recall hook. Field reports
 * (edith, jarvis 2026-05-24) flagged content cut mid-word like "with
 * website-policy URLs added to evidence where m..." — this helper backs off
 * to the last clean boundary within 20 chars of the limit.
 */
describe('truncatePreservingWords', () => {
  it('returns the input unchanged when shorter than the limit', () => {
    expect(truncatePreservingWords('short', 100)).toBe('short');
  });

  it('returns the input unchanged when exactly at the limit', () => {
    const input = 'a'.repeat(50);
    expect(truncatePreservingWords(input, 50)).toBe(input);
  });

  it('backs off to the last space when one exists within lookback range', () => {
    const input = 'the quick brown fox jumps over the lazy dog and never stops';
    const result = truncatePreservingWords(input, 25);
    expect(result).toMatch(/…$/);
    expect(result.length).toBeLessThanOrEqual(26); // 25 chars + 1 ellipsis
    // The tail before the ellipsis must be a complete word from the input
    const beforeEllipsis = result.slice(0, -1).trimEnd();
    const lastSpaceIdx = beforeEllipsis.lastIndexOf(' ');
    const tail = lastSpaceIdx >= 0 ? beforeEllipsis.slice(lastSpaceIdx + 1) : beforeEllipsis;
    expect(input.split(/\s+/)).toContain(tail);
  });

  it('does not produce mid-word cuts (the edith complaint)', () => {
    const input = 'with website-policy URLs added to evidence where machine learning provides clarity';
    const result = truncatePreservingWords(input, 60);
    // Either the input is unchanged (too short) or it ends with …
    if (result !== input) {
      expect(result).toMatch(/…$/);
      // Char before the ellipsis should not be a letter immediately preceded by
      // another letter from a word it sliced through. Easier check: the part
      // before "…" should end at a complete word.
      const beforeEllipsis = result.slice(0, -1).trimEnd();
      const lastSpaceIdx = beforeEllipsis.lastIndexOf(' ');
      const tail = lastSpaceIdx >= 0 ? beforeEllipsis.slice(lastSpaceIdx + 1) : beforeEllipsis;
      // tail should be a real word from the input — i.e. it appears as a
      // whole-word match somewhere in the source text.
      const wordBoundaryRegex = new RegExp(`\\b${tail.replace(/[.*+?^${}()|[\\]\\\\]/g, '\\$&')}\\b`);
      expect(input).toMatch(wordBoundaryRegex);
    }
  });

  it('falls back to a hard cut if no boundary within lookback range', () => {
    // 50 chars of one word — no spaces to fall back to
    const input = 'a'.repeat(50);
    const result = truncatePreservingWords(input, 20);
    expect(result).toBe('aaaaaaaaaaaaaaaaaaaa…');
    expect(result.length).toBe(21);
  });

  it('uses sentence-terminal punctuation as a boundary', () => {
    const input = 'First sentence. Second sentence is way longer to force truncation past the period.';
    const result = truncatePreservingWords(input, 20);
    expect(result).toMatch(/…$/);
    // Should have cut at the period+space, not mid-word
    expect(result).toContain('First sentence');
  });

  it('returns non-strings unchanged (defensive)', () => {
    expect(truncatePreservingWords(undefined, 100)).toBeUndefined();
    expect(truncatePreservingWords(null, 100)).toBeNull();
    expect(truncatePreservingWords(42 as unknown as string, 100)).toBe(42);
  });
});
