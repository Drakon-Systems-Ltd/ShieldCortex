import { describe, it, expect } from '@jest/globals';

/**
 * v4.24.3 regression: Jarvis (running 4.20.0 production) reported recall
 * snippets truncated mid-clause, with literal `\n` escapes leaking through
 * and useless mid-sentence headlines. Examples from the field:
 *
 *   Decision: python3 /home/ubuntu/clawd/scripts/beautyhair_colo...
 *   Decision: the 7-day window unless overridden.\n\nsales@ inbo...
 *   Preference: ran one; likely missing on hero/gallery shots\n• L...
 *
 * Root cause confirmed in extract-memorable-segments.mjs:231-292 — the
 * regex captures used `.{15,200}` (fixed-character window after a keyword)
 * with no sentence-boundary awareness, and the headline was the first 50
 * chars of the captured group, regardless of where the sentence ended.
 *
 * The fix:
 *   1. Capture groups changed to `[^.!?\n]{15,200}[.!?]?` — stop at the
 *      first sentence terminator, fall back to the 200-char cap.
 *   2. New extractFirstSentence helper produces the headline.
 *   3. defensiveUnescape strips literal `\n` / `\t` / `\r` JSON-escape
 *      leaks before regex matching.
 *
 * These tests pin the new behaviour so a future "let's go back to greedy
 * captures" regression can't silently land.
 */

describe('v4.24.3 sentence-bounded extraction', () => {
  it('decision captures stop at a sentence terminator', async () => {
    const { extractMemorableSegments } = await import('../../scripts/lib/extract-memorable-segments.mjs');
    const text =
      'I decided to use Postgres for JSON support. The team agreed last week. ' +
      'Next we will tune the indexes.';
    const segments = extractMemorableSegments(text);
    const decisions = segments.filter((s) => s.extractorType === 'decision');
    expect(decisions.length).toBeGreaterThan(0);
    // Captured content should end at the first sentence terminator, NOT
    // bleed into "The team agreed last week."
    for (const d of decisions) {
      expect(d.content).not.toContain('The team agreed');
    }
  });

  it('headline is the first complete sentence of the capture, not a 50-char slice', async () => {
    const { extractMemorableSegments } = await import('../../scripts/lib/extract-memorable-segments.mjs');
    const text =
      'We decided to use python3 /home/ubuntu/clawd/scripts/beautyhair_colour_rank_summary.py ' +
      'and send Michael the concise summary. Then we will rotate the report weekly.';
    const segments = extractMemorableSegments(text);
    const decision = segments.find((s) => s.extractorType === 'decision');
    expect(decision).toBeDefined();
    // Old behaviour: title = "Decision: use python3 /home/ubuntu/clawd/scrip..."
    // New behaviour: title ends at the FIRST sentence terminator OR within
    // a sensible 80-char headline, without trailing ellipsis.
    expect(decision!.title.startsWith('Decision: ')).toBe(true);
    // Headline must not contain the second sentence.
    expect(decision!.title).not.toContain('Then we will');
    // Headline must not contain mid-sentence cut-off ellipsis ("colo...")
    // that the old slicer produced.
    expect(decision!.title).not.toMatch(/\b(colo|beautyhai|summar)\.\.\.\s*$/);
  });

  it('strips literal \\n / \\t / \\r escape leaks before matching', async () => {
    const { extractMemorableSegments } = await import('../../scripts/lib/extract-memorable-segments.mjs');
    // Simulate a JSON-encoded fragment whose inner string was double-stringified
    // upstream: literal backslash-n appears in the source text.
    const text =
      'We decided to wait 7 days unless overridden.\\n\\nsales@ inbox is now lean.';
    const segments = extractMemorableSegments(text);
    const decision = segments.find((s) => s.extractorType === 'decision');
    expect(decision).toBeDefined();
    // The literal `\n` should be unescaped → real newlines → the regex
    // stops at the first one. The captured content must NOT contain
    // either the literal `\n` characters or the "sales@" tail.
    expect(decision!.content).not.toContain('\\n');
    expect(decision!.content).not.toContain('sales@');
  });

  it('still extracts the full sentence when no terminator is nearby (200-char cap)', async () => {
    const { extractMemorableSegments } = await import('../../scripts/lib/extract-memorable-segments.mjs');
    // 180+ char sentence with no terminator — falls back to char cap.
    const text =
      'We decided to use a multi-step rollout strategy with canary deployments ' +
      'feature flags retries with exponential backoff and per-team dashboards for observability';
    const segments = extractMemorableSegments(text);
    const decision = segments.find((s) => s.extractorType === 'decision');
    expect(decision).toBeDefined();
    // Content should include the meaningful tail.
    expect(decision!.content).toContain('canary deployments');
    expect(decision!.content.length).toBeLessThanOrEqual(500); // existing body cap
  });

  it('does not cut a clean sentence mid-word at the headline cap', async () => {
    const { extractMemorableSegments } = await import('../../scripts/lib/extract-memorable-segments.mjs');
    // One complete ~100-char sentence (terminated) — longer than the old 80-char
    // headline cap, so the old `slice(0, 80)` chopped it mid-word ("...session to").
    const sentence =
      'We decided to migrate the entire authentication subsystem onto short-lived ' +
      'rotating session tokens this quarter.';
    const segments = extractMemorableSegments(sentence);
    const decision = segments.find((s) => s.extractorType === 'decision');
    expect(decision).toBeDefined();
    const headline = decision!.title.replace(/^Decision: /, '');
    // The headline is a prefix of the captured content...
    const core = headline.replace(/…$/, '').trimEnd();
    expect(decision!.content.startsWith(core)).toBe(true);
    // ...and wherever it stops, the next source char must be a word boundary —
    // never mid-word. (end-of-content counts as a clean stop.)
    const nextChar = decision!.content.charAt(core.length);
    expect(nextChar === '' || /[\s.!?,;:]/.test(nextChar)).toBe(true);
  });

  it('preference captures stop at a sentence terminator', async () => {
    const { extractMemorableSegments } = await import('../../scripts/lib/extract-memorable-segments.mjs');
    const text =
      'Always commit with a sign-off line. Never push to main on Fridays.';
    const segments = extractMemorableSegments(text);
    const prefs = segments.filter((s) => s.extractorType === 'preference');
    expect(prefs.length).toBeGreaterThan(0);
    // The "always" capture must not bleed into "Never push to main".
    const always = prefs.find((p) => p.content.toLowerCase().includes('sign-off'));
    expect(always).toBeDefined();
    expect(always!.content).not.toContain('Never push');
  });
});
