/**
 * Truncate `text` to at most `maxChars`, backing off to the last word- or
 * sentence-boundary within `lookback` chars. Avoids cuts mid-word like
 * "with website-policy URLs added to evidence where m..." that show up in
 * recall preambles when content gets hard-sliced.
 *
 * Used by:
 * - scripts/session-start-hook.mjs (SessionStart preamble, 200-char limit)
 * - scripts/prompt-recall-hook.mjs (UserPromptSubmit recall, 150-char limit)
 *
 * Field context (edith, jarvis 2026-05-24): both reported the recall surface
 * as "noisy" with one specific complaint about content cut mid-word. This is
 * the surgical fix for the truncation half of that complaint; salience
 * calibration is handled separately in extract-memorable-segments.mjs.
 *
 * @param {unknown} text — any value; non-strings are returned unchanged
 * @param {number} maxChars — hard ceiling on output length (excluding the
 *   trailing ellipsis character)
 * @param {number} [lookback=20] — how far back from `maxChars` to search for
 *   a clean boundary before giving up and hard-cutting
 * @returns {string} truncated text with a trailing `…` (single Unicode char)
 *   if truncation occurred, otherwise the original text unchanged
 */
export function truncatePreservingWords(text, maxChars, lookback = 20) {
  if (typeof text !== 'string') return text;
  if (text.length <= maxChars) return text;
  const slice = text.slice(0, maxChars);
  const minIdx = Math.max(0, maxChars - lookback);
  const lastBoundary = Math.max(
    slice.lastIndexOf(' '),
    slice.lastIndexOf('. '),
    slice.lastIndexOf(', '),
    slice.lastIndexOf('; '),
    slice.lastIndexOf(': '),
    slice.lastIndexOf('\n'),
    slice.lastIndexOf('? '),
    slice.lastIndexOf('! '),
  );
  const cutAt = lastBoundary >= minIdx ? lastBoundary : maxChars;
  return slice.slice(0, cutAt).trimEnd() + '…';
}
