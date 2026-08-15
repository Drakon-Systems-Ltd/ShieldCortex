/**
 * Instruction-text normalisation (issue #204, Stage 1)
 *
 * A shared pre-match fold used by BOTH regex tiers — the memory firewall's
 * `detectInstructions()` and Iron Dome's `scanForInjection()`. Before #204 the
 * two paths normalised differently (the firewall folded confusables, the
 * scanner folded nothing), so the same payload could be caught by one and
 * walked past the other. One helper, both callers.
 *
 * What it closes: the cosmetic-mangle class of evasion, where the English is
 * unchanged and only the bytes move —
 *
 *   Ig<ZWSP>nore all previous instructions   (zero-width / bidi marks)
 *   ignorе all previous instructions          (Cyrillic е homoglyph)
 *   Ignore,,, all... previous;;; instructions (punctuation runs)
 *   Ign0r3 4ll pr3vi0us in5truction5          (classic leet)
 *
 * Two deliberate limits, both load-bearing:
 *
 *  1. Leet folding is an ADDITIONAL variant, never a replacement. Rewriting
 *     digits in place would destroy plain-ASCII matches and mangle ordinary
 *     text (`port 443`, `v1.0.5`). Callers test the original first.
 *  2. The digit `1` is NOT mapped. It reads as both `i` and `l`, and mapping it
 *     turns every version string and identifier into a new token to false-match
 *     against. The classic set (0/3/4/5/7/@) carries the real payloads.
 *
 * The variant budget is capped at 3 (original + normalised + leet) so the
 * per-scan cost stays bounded on large inputs.
 */

import { foldConfusables } from './confusables.js';

/**
 * Zero-width and bidirectional formatting characters. These render as nothing
 * (or as pure layout) but break every ASCII regex they are wedged into.
 *   U+180E  Mongolian vowel separator
 *   U+200B–U+200F  ZWSP, ZWNJ, ZWJ, LRM, RLM
 *   U+202A–U+202E  bidi embedding / override
 *   U+2060–U+2064  word joiner + invisible operators
 *   U+2066–U+2069  bidi isolates
 *   U+FEFF  BOM / zero-width no-break space
 */
const ZERO_WIDTH_AND_BIDI = /[\u180E\u200B-\u200F\u202A-\u202E\u2060-\u2064\u2066-\u2069\uFEFF]/g;

/**
 * Runs of 2+ sentence punctuation sitting between word characters (or between a
 * word and the following space). `Ignore,,, all` and `Ignore,,,all` both fold to
 * `Ignore all`. Single punctuation marks are left alone — collapsing those would
 * rewrite ordinary prose and abbreviations for no detection gain.
 */
const PUNCTUATION_RUN = /(?<=\w)[,.;:!?]{2,}(?=\s|\w|$)/g;

/** Classic injection leet. `1` is intentionally absent — see the header note. */
const LEET_MAP: Record<string, string> = {
  '0': 'o',
  '3': 'e',
  '4': 'a',
  '5': 's',
  '7': 't',
  '@': 'a',
};

function isLatinLetter(ch: string | undefined): boolean {
  return ch !== undefined && /[A-Za-z]/.test(ch);
}

/**
 * Fold the classic leet substitutions, but only where the character sits next to
 * a Latin letter — i.e. inside a word. That guard is what keeps `port 443`,
 * `retries 3 times` and `v1.0.5` untouched while still recovering `Ign0r3`.
 *
 * Adjacency is evaluated against the input string, so a run like `4ll` folds on
 * the letter to its right and `in5truction5` on the letter to its left.
 */
export function foldLeetSpeak(input: string): string {
  let out = '';
  for (let i = 0; i < input.length; i++) {
    const ch = input[i];
    const mapped = LEET_MAP[ch];
    if (mapped !== undefined && (isLatinLetter(input[i - 1]) || isLatinLetter(input[i + 1]))) {
      out += mapped;
    } else {
      out += ch;
    }
  }
  return out;
}

/**
 * Full normalisation fold for matching. Order matters:
 *   1. strip zero-width / bidi marks (they hide between any two characters)
 *   2. NFKC + cross-script confusable fold (existing `foldConfusables`)
 *   3. collapse punctuation runs between words
 *   4. collapse whitespace and trim
 *
 * Leet folding is NOT applied here — see `instructionMatchVariants`.
 */
export function normalizeInstructionText(input: string): string {
  return foldConfusables(input.replace(ZERO_WIDTH_AND_BIDI, ''))
    .replace(PUNCTUATION_RUN, ' ')
    .replace(/\s+/g, ' ')
    .trim();
}

/**
 * The (at most 3) strings a pattern should be tested against: the original, the
 * normalised fold, and the leet fold of the normalised copy. Duplicates are
 * dropped, and the original is always first so an un-mangled payload matches on
 * the cheapest pass with its span intact.
 */
export function instructionMatchVariants(input: string): string[] {
  const variants = [input];

  const normalised = normalizeInstructionText(input);
  if (normalised !== input) variants.push(normalised);

  const leetFolded = foldLeetSpeak(normalised);
  if (leetFolded !== normalised && !variants.includes(leetFolded)) variants.push(leetFolded);

  return variants;
}
