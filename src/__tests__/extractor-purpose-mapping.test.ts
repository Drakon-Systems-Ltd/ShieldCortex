import { describe, it, expect } from '@jest/globals';

/**
 * v4.25.0: deterministic taxonomy.
 *
 * Pre-4.25 every auto-extracted memory ended up with `category` chosen by
 * a keyword scan over the captured text (suggestCategory) and `memory_purpose`
 * left at the schema default 'project'. That produced two pathologies:
 *
 *   - An "important-note" extractor capture would land with category='error'
 *     whenever the captured text happened to mention "bug" / "fail" / etc.
 *   - All hook-written memories looked identical to user-typed memories at
 *     the SQL level (memory_purpose='project', source_kind='user'),
 *     making `inspect last-precompact`-style introspection impossible.
 *
 * v4.25 fixes the first by pinning category to extractorType via
 * EXTRACTOR_TO_CATEGORY, and the second by also carrying memoryPurpose
 * through to the save path (save-memory.mjs).
 *
 * These tests pin the mapping so a regex extractor renamed without
 * updating the maps fails loudly here.
 */

describe('v4.25.0 extractor → memory_purpose + category mapping', () => {
  it('every in-tree extractorType maps to a valid memory_purpose', async () => {
    const { EXTRACTOR_TO_PURPOSE, FULL_EXTRACTORS } = await import(
      '../../scripts/lib/extract-memorable-segments.mjs'
    );
    const validPurposes = new Set(['user', 'feedback', 'project', 'reference']);
    for (const extractor of FULL_EXTRACTORS) {
      const purpose = EXTRACTOR_TO_PURPOSE[extractor.name];
      expect(purpose).toBeDefined();
      expect(validPurposes.has(purpose)).toBe(true);
    }
  });

  it('every in-tree extractorType maps to a valid category', async () => {
    const { EXTRACTOR_TO_CATEGORY, FULL_EXTRACTORS } = await import(
      '../../scripts/lib/extract-memorable-segments.mjs'
    );
    const validCategories = new Set([
      'architecture', 'pattern', 'preference', 'error', 'context',
      'learning', 'todo', 'note', 'relationship', 'custom',
    ]);
    for (const extractor of FULL_EXTRACTORS) {
      const category = EXTRACTOR_TO_CATEGORY[extractor.name];
      expect(category).toBeDefined();
      expect(validCategories.has(category)).toBe(true);
    }
  });

  it('preference captures get purpose=feedback (not project)', async () => {
    const { extractMemorableSegments, processSegments } = await import(
      '../../scripts/lib/extract-memorable-segments.mjs'
    );
    // "include" is not in BARE_IMPERATIVE_VERBS so the capture survives.
    const text = 'Always include a sign-off line on every commit going forward.';
    const segments = extractMemorableSegments(text);
    const processed = processSegments(segments, 0.1);
    const pref = processed.find((s: any) => s.extractorType === 'preference');
    expect(pref).toBeDefined();
    expect(pref!.memoryPurpose).toBe('feedback');
    expect(pref!.category).toBe('preference');
  });

  it('decision captures get purpose=project and category=context (not keyword-driven)', async () => {
    const { extractMemorableSegments, processSegments } = await import(
      '../../scripts/lib/extract-memorable-segments.mjs'
    );
    // Text mentions "bug" — pre-4.25 keyword-driven suggestCategory would
    // have returned 'error'. Pinning to extractorType returns 'context'.
    // "we" is not in the rejection list so the capture survives.
    const text = 'We decided we would ship the bug-fix release today after final QA.';
    const segments = extractMemorableSegments(text);
    const processed = processSegments(segments, 0.1);
    const decision = processed.find((s: any) => s.extractorType === 'decision');
    expect(decision).toBeDefined();
    expect(decision!.memoryPurpose).toBe('project');
    expect(decision!.category).toBe('context');
  });

  it('learning captures get purpose=reference (reusable knowledge)', async () => {
    const { extractMemorableSegments, processSegments } = await import(
      '../../scripts/lib/extract-memorable-segments.mjs'
    );
    const text = 'Learned that SQLite FTS5 requires explicit escaping of hyphens.';
    const segments = extractMemorableSegments(text);
    const processed = processSegments(segments, 0.1);
    const learning = processed.find((s: any) => s.extractorType === 'learning');
    expect(learning).toBeDefined();
    expect(learning!.memoryPurpose).toBe('reference');
    expect(learning!.category).toBe('learning');
  });

  it('important-note captures get category=note (NOT error, even if text mentions error)', async () => {
    const { extractMemorableSegments, processSegments } = await import(
      '../../scripts/lib/extract-memorable-segments.mjs'
    );
    // Text mentions "error" — pre-4.25 suggestCategory would have
    // returned 'error'. Pinning to extractorType returns 'note'.
    // "rotate" is not in BARE_IMPERATIVE_VERBS so the capture survives.
    const text = 'Important: rotate the encryption key every 90 days even when error logs look fine.';
    const segments = extractMemorableSegments(text);
    const processed = processSegments(segments, 0.1);
    const note = processed.find((s: any) => s.extractorType === 'important-note');
    expect(note).toBeDefined();
    expect(note!.category).toBe('note');
    expect(note!.memoryPurpose).toBe('project');
  });

  it('error-fix captures get category=error and purpose=project', async () => {
    const { extractMemorableSegments, processSegments } = await import(
      '../../scripts/lib/extract-memorable-segments.mjs'
    );
    const text = 'Fixed by adding busy_timeout=10000ms to the SQLite connection.';
    const segments = extractMemorableSegments(text);
    const processed = processSegments(segments, 0.1);
    const fix = processed.find((s: any) => s.extractorType === 'error-fix');
    expect(fix).toBeDefined();
    expect(fix!.category).toBe('error');
    expect(fix!.memoryPurpose).toBe('project');
  });
});
