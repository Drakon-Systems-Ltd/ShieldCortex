/**
 * Closed whole-note preference grammar G (SCN-010 part C, design scn-010c §3).
 *
 * `isClosedPreferenceNote(text)` is true ONLY when the entire input, after
 * trimming ASCII whitespace at its ends, is exactly one sentence of G: a
 * one-sentence style preference built from closed word lists with no
 * control-bearing word in any slot. Anything else (a second sentence, an extra
 * clause or word, a title line, a newline, any character outside
 * `[A-Za-z0-9 ,.'-]`, a run of spaces, an internal full stop, more than 160
 * characters) fails the parse.
 *
 * This is a CLOSED-world, POSITIVE parse. It never asks whether anything
 * hostile is present, and nothing that consumes it may depend on another
 * detector being quiet. That is the lesson of SCN-010's deleted M4 ("relax
 * unless something bad is present"): the attacker controls what is present,
 * and a harmless preference grafted onto an order defeated it. A graft here is
 * a second sentence or extra words, so it cannot parse, and a note that does
 * parse is nothing but a closed-vocabulary style preference: no payload.
 *
 * Grammar (case-insensitive letters; optional single final `.`):
 *   T1 := FRAME `,`? ` always ` STYLEVERB ` ` STYLE ( ` ` SCOPE )?
 *   T2 := `when the user asks for ` ARTICLE ` ` ARTIFACT `, ` ACTION
 *   STYLE  := LOCALE ` English` ( ` spelling` )? | STYLES_FIXED
 *   SCOPE  := SCOPE_PREPOSITION ` ` ( `all ` )? DOC_NOUN
 *   ACTION := `keep it ` KEEP ` ` UNIT | ACTIONS_FIXED | `reply in ` STYLE
 *   KEEP   := ( `to` | `within` ) ` ` NUM | `under ` NUM_ABOVE_ONE
 *   NUM    := NUMBER_WORD | [1-9][0-9]?   (1..99, no zero, no leading zero)
 *   NUM_ABOVE_ONE := NUMBER_WORD except `one` | 2..99
 *
 * A count must admit a non-empty answer: `to 0`, `to 00`, `to 05` and
 * `under one` / `under 1` ask for nothing, which is suppressing the artifact,
 * not choosing its style.
 *
 * Widening G (a new slot value, a second sentence, a title) is a new grammar
 * version and needs review; it is never an open-world test.
 *
 * Cost: the trim is an index walk, the 160-character cap is checked before
 * any regex runs, and every regex is fully anchored with no unbounded run, so
 * the parse is linear in the input and constant after the cap.
 */

export const PREFERENCE_NOTE_MAX_LENGTH = 160;

const freeze = (words: string[]): readonly string[] => Object.freeze(words);

export const PREFERENCE_NOTE_FRAMES = freeze(['from now on', 'going forward', 'in future']);
export const PREFERENCE_NOTE_STYLE_VERBS = freeze(['use', 'write in', 'reply in', 'respond in', 'answer in']);
export const PREFERENCE_NOTE_LOCALES = freeze(['British', 'UK', 'American', 'US', 'Australian', 'Canadian', 'Irish']);
export const PREFERENCE_NOTE_STYLES_FIXED = freeze(['plain English', 'metric units', 'the 24-hour clock', 'Celsius']);
export const PREFERENCE_NOTE_SCOPE_PREPOSITIONS = freeze(['in', 'for']);
export const PREFERENCE_NOTE_DOC_NOUNS = freeze([
  'replies', 'responses', 'answers', 'messages', 'emails', 'documents', 'summaries', 'drafts', 'notes',
]);
export const PREFERENCE_NOTE_ARTICLES = freeze(['a', 'an']);
export const PREFERENCE_NOTE_ARTIFACTS = freeze([
  'summary', 'recap', 'overview', 'update', 'status update', 'translation', 'draft', 'list', 'explanation',
]);
export const PREFERENCE_NOTE_KEEP_PREPOSITIONS = freeze(['to', 'under', 'within']);
export const PREFERENCE_NOTE_NUMBER_WORDS = freeze([
  'one', 'two', 'three', 'four', 'five', 'six', 'seven', 'eight', 'nine', 'ten',
]);
export const PREFERENCE_NOTE_UNITS = freeze(['bullet points', 'bullets', 'sentences', 'paragraphs', 'lines', 'words']);
export const PREFERENCE_NOTE_ACTIONS_FIXED = freeze(['keep it short', 'keep it brief', 'use bullet points']);

/** A non-capturing alternation of literal phrases (single spaces are literal). */
const alt = (words: readonly string[]): string =>
  `(?:${words.map((w) => w.replace(/[.*+?^${}()|[\]\\-]/g, '\\$&')).join('|')})`;

const STYLE = `(?:${alt(PREFERENCE_NOTE_LOCALES)} English(?: spelling)?|${alt(PREFERENCE_NOTE_STYLES_FIXED)})`;
const SCOPE = `${alt(PREFERENCE_NOTE_SCOPE_PREPOSITIONS)} (?:all )?${alt(PREFERENCE_NOTE_DOC_NOUNS)}`;
// Counts admit a non-empty answer (review r2 SF1): digits 1..99 with no zero
// and no leading zero; the strict `under` needs at least two.
const STRICT_KEEP_PREPOSITION = 'under';
const NUM = `(?:${alt(PREFERENCE_NOTE_NUMBER_WORDS)}|[1-9][0-9]?)`;
const NUM_ABOVE_ONE = `(?:${alt(PREFERENCE_NOTE_NUMBER_WORDS.filter((w) => w !== 'one'))}|[2-9]|[1-9][0-9])`;
const KEEP = `(?:${alt(PREFERENCE_NOTE_KEEP_PREPOSITIONS.filter((p) => p !== STRICT_KEEP_PREPOSITION))} ${NUM}`
  + `|${STRICT_KEEP_PREPOSITION} ${NUM_ABOVE_ONE})`;
const ACTION = `(?:keep it ${KEEP} ${alt(PREFERENCE_NOTE_UNITS)}`
  + `|${alt(PREFERENCE_NOTE_ACTIONS_FIXED)}|reply in ${STYLE})`;

// Built once at load. Plain `i` flag (no scoped modifier): the charset check
// below has already limited the input to ASCII, so case folding is ASCII-only.
const T1 = new RegExp(
  `^${alt(PREFERENCE_NOTE_FRAMES)},? always ${alt(PREFERENCE_NOTE_STYLE_VERBS)} ${STYLE}(?: ${SCOPE})?$`,
  'i',
);
const T2 = new RegExp(
  `^when the user asks for ${alt(PREFERENCE_NOTE_ARTICLES)} ${alt(PREFERENCE_NOTE_ARTIFACTS)}, ${ACTION}$`,
  'i',
);

const CHARSET = /^[A-Za-z0-9 ,.'-]+$/;

/** ASCII space, tab, CR, LF. Every other edge character fails the charset. */
function isTrimmable(code: number): boolean {
  return code === 0x20 || code === 0x09 || code === 0x0d || code === 0x0a;
}

/**
 * True only when the WHOLE input is exactly one sentence of grammar G.
 * Pure; no state; never throws (a non-string is not a note).
 */
export function isClosedPreferenceNote(text: string): boolean {
  if (typeof text !== 'string') return false;
  let start = 0;
  let end = text.length;
  while (start < end && isTrimmable(text.charCodeAt(start))) start += 1;
  while (end > start && isTrimmable(text.charCodeAt(end - 1))) end -= 1;
  const length = end - start;
  if (length === 0 || length > PREFERENCE_NOTE_MAX_LENGTH) return false;

  const note = text.slice(start, end);
  if (!CHARSET.test(note)) return false;
  if (note.includes('  ')) return false;
  const stop = note.indexOf('.');
  if (stop !== -1 && stop !== note.length - 1) return false;

  const sentence = stop === -1 ? note : note.slice(0, -1);
  return T1.test(sentence) || T2.test(sentence);
}
