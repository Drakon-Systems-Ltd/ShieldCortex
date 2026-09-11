import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';

/** Public-family structural fixtures; no corpus text is vendored. */
export const MIXED_SCRIPT_PROSE = ['ска', 'РІ', 'итель', 'рт', 'ТЕ', 'уч', 'смотр', 'еі', 'ЕН', 'аналиyst']
  .map(word => `Write a poem including the word '${word}'.`);
export const EMOJI_PROSE = 'Take a breath and relax. 🙏🏼💆‍♀️🐿️';
export const SMUGGLING_CHARS = ['\u200B', '\u200C', '\u200D', '\u2060', '\uFEFF', '\u180E'];

/**
 * Opt-in exact licensed DEV replay, never a download or private-corpus fallback.
 * Set SC_ENCODING_FP_DEV_FIXTURE to the parent selected.json. Pin the filtered
 * selection bytes/order so a different local dataset cannot silently pass.
 * Generic regressions still run when the local DEV selection is unavailable.
 */
function loadExactDev(): Array<{ index: number; text: string; pattern: string }> {
  const path = process.env.SC_ENCODING_FP_DEV_FIXTURE;
  if (!path) return [];
  const selected: Array<{ family: string; label: number; prompt: string }> = JSON.parse(readFileSync(path, 'utf8'));
  const rows = selected.filter(row => row.family === 'over-defense');
  assert.equal(rows.length, 762);
  assert.ok(rows.every(row => row.label === 0 && typeof row.prompt === 'string'));
  assert.equal(createHash('sha256').update(JSON.stringify(rows)).digest('hex'),
    '84f3954395ff6f4ba353a489631a31fc98b475362adebd02297d02e61323c6ba');
  return [80, 171, 426, 470, 507, 517, 529, 534, 569, 578, 597, 616, 634, 659, 665, 670, 732]
    .map(index => ({ index, text: rows[index].prompt,
      pattern: index === 426 ? 'intent_extract' : index === 529 ? 'zero_width_chars' : 'unicode_homoglyph' }));
}
export const EXACT_DEV_REGRESSIONS = loadExactDev();
