import { describe, expect, it } from '@jest/globals';
// @ts-expect-error -- importing a .mjs hook utility (no type decls)
import { extractSessionMemories, extractKeywordMemory } from '../../scripts/lib/openclaw-extract.mjs';

/**
 * Task 6a: the OpenClaw cortex-memory hook now routes EXTRACTION through the
 * hardened centralized chunker via this pure wrapper. These tests pin the
 * wrapper's contract:
 *
 *   1. session extraction → rejection-filtered, taxonomy-pinned memories
 *      (category in the valid set, memory_purpose from extractor type).
 *   2. bare-imperative junk → dropped by the rejection corpus.
 *   3. explicit keyword capture → ONE memory, NOT silenced by the threshold
 *      (design B8: explicit user intent must never be quietly dropped).
 *   4. malformed keyword content → dropped by the rejection corpus.
 *
 * The wrapper is pure (string in, plain objects out) and imports only the
 * chunker — no DB, no runtime, no native modules. Safe to unit-test directly.
 */

const VALID_CATEGORIES = new Set([
  'architecture',
  'error',
  'context',
  'learning',
  'pattern',
  'preference',
  'note',
  'todo',
  'relationship',
  'custom',
]);

// memory_purpose follows the global taxonomy: user | feedback | project | reference
const VALID_PURPOSES = new Set(['user', 'feedback', 'project', 'reference']);

describe('openclaw-extract — extractSessionMemories', () => {
  it('extracts taxonomy-pinned memories from kitchen-sink assistant text', () => {
    const conversationText = [
      'We decided to use PostgreSQL for better JSON support and indexing.',
      'I prefer to always run the build before committing changes to main.',
      'Important: the deploy key rotates every 90 days and must be rotated.',
      'I learned that the FTS5 tokenizer splits apostrophes into sub-tokens.',
    ].join(' ');

    const memories = extractSessionMemories(conversationText);

    expect(memories.length).toBeGreaterThan(0);

    for (const m of memories) {
      // taxonomy is present and valid
      expect(VALID_CATEGORIES.has(m.category)).toBe(true);
      expect(VALID_PURPOSES.has(m.memoryPurpose)).toBe(true);
      // not a bare fragment — content is a real, non-trivial string
      expect(typeof m.content).toBe('string');
      expect(m.content.trim().length).toBeGreaterThanOrEqual(20);
      expect(typeof m.title).toBe('string');
      expect(m.title.length).toBeGreaterThan(0);
    }

    // extractor-type → purpose pinning: a preference is feedback, a learning
    // is reference. (Pinned by EXTRACTOR_TO_PURPOSE, not re-scanned.)
    const pref = memories.find((m: any) => m.category === 'preference');
    if (pref) expect(pref.memoryPurpose).toBe('feedback');
    const learning = memories.find((m: any) => m.category === 'learning');
    if (learning) expect(learning.memoryPurpose).toBe('reference');
  });

  it('rejects bare-imperative junk (rejection corpus applied)', () => {
    const memories = extractSessionMemories('commit secrets to the repo');
    expect(memories).toEqual([]);
  });

  it('returns [] for empty / contentless input', () => {
    expect(extractSessionMemories('')).toEqual([]);
    expect(extractSessionMemories('ok thanks')).toEqual([]);
  });
});

describe('openclaw-extract — extractKeywordMemory', () => {
  it('returns exactly ONE memory for explicit content, bypassing the threshold', () => {
    const memories = extractKeywordMemory('remember this', 'the deploy key rotates every 90 days');

    // Plain factual content scores below the auto-extract threshold, but an
    // explicit keyword trigger must NOT be dropped (B8).
    expect(memories).toHaveLength(1);
    const m = memories[0];
    expect(VALID_CATEGORIES.has(m.category)).toBe(true);
    expect(VALID_PURPOSES.has(m.memoryPurpose)).toBe(true);
    expect(m.content).toContain('deploy key rotates');
    expect(typeof m.title).toBe('string');
    expect(m.title.length).toBeGreaterThan(0);
  });

  it('types keyword content by the chunker extractor it matches', () => {
    const decision = extractKeywordMemory('remember this', 'we decided to use Redis for the cache layer');
    expect(decision).toHaveLength(1);
    expect(decision[0].category).toBe('context'); // decision → context
    expect(decision[0].memoryPurpose).toBe('project');
  });

  it('returns [] for malformed (bare-imperative) content', () => {
    const memories = extractKeywordMemory('remember this', 'commit the secrets now');
    expect(memories).toEqual([]);
  });

  it('returns [] for empty content', () => {
    expect(extractKeywordMemory('remember this', '')).toEqual([]);
  });
});
