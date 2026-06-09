/**
 * Unicode Confusable Folding
 *
 * Cross-script homoglyph attacks swap a single Latin letter for an
 * identical-looking glyph from another script (e.g. Cyrillic `е` U+0435 for
 * Latin `e`), so `ignorе all previous instructions` reads as English but never
 * matches an ASCII regex. `foldConfusables` normalises such text back to its
 * Latin skeleton so the instruction detector can match the real intent.
 *
 * Two stages:
 *   1. NFKC normalisation — folds fullwidth forms, many mathematical
 *      alphanumerics, ligatures, etc. down to their ASCII compatibility forms.
 *   2. A curated cross-script lookalike table — the high-frequency Cyrillic and
 *      Greek glyphs that NFKC does NOT touch (NFKC preserves script identity for
 *      these). This is deliberately NOT exhaustive: it targets the glyphs that
 *      actually show up in homoglyph injection attacks, not the full Unicode
 *      confusables database.
 */

// Cyrillic → Latin. The lowercase codepoints here are the same set used by
// CYRILLIC_HOMOGLYPHS in encoding-detector.ts (the run that already drives the
// homoglyph flag); the uppercase set extends it for capitalised attack text.
const CYRILLIC_TO_LATIN: Record<string, string> = {
  'а': 'a', // а
  'е': 'e', // е
  'о': 'o', // о
  'р': 'p', // р
  'с': 'c', // с
  'у': 'y', // у
  'х': 'x', // х
  'А': 'A', // А
  'В': 'B', // В
  'Е': 'E', // Е
  'К': 'K', // К
  'М': 'M', // М
  'Н': 'H', // Н
  'О': 'O', // О
  'Р': 'P', // Р
  'С': 'C', // С
  'Т': 'T', // Т
  'У': 'Y', // У
  'Х': 'X', // Х
};

// Greek → Latin. Only the high-frequency lookalikes; lowercase Greek mostly
// does not resemble Latin (α/β/γ are distinct) so we cover lowercase omicron
// plus the capital letters that are visually identical to Latin capitals.
const GREEK_TO_LATIN: Record<string, string> = {
  'ο': 'o', // ο  lowercase omicron
  'Α': 'A', // Α
  'Β': 'B', // Β
  'Ε': 'E', // Ε
  'Ζ': 'Z', // Ζ
  'Η': 'H', // Η
  'Ι': 'I', // Ι
  'Κ': 'K', // Κ
  'Μ': 'M', // Μ
  'Ν': 'N', // Ν
  'Ο': 'O', // Ο
  'Ρ': 'P', // Ρ
  'Τ': 'T', // Τ
  'Υ': 'Y', // Υ
  'Χ': 'X', // Χ
};

const CONFUSABLE_MAP: Record<string, string> = {
  ...CYRILLIC_TO_LATIN,
  ...GREEK_TO_LATIN,
};

/**
 * Fold a string to its Latin skeleton: NFKC first, then map curated
 * cross-script confusables to their Latin lookalikes.
 */
export function foldConfusables(s: string): string {
  const normalised = s.normalize('NFKC');
  let out = '';
  for (const ch of normalised) {
    out += CONFUSABLE_MAP[ch] ?? ch;
  }
  return out;
}

/**
 * True when a cross-script confusable substitution changed something beyond
 * what plain NFKC normalisation does — i.e. one of the curated Cyrillic/Greek
 * glyphs was present and got folded to a different Latin letter. Genuine
 * NFKC-only changes (fullwidth, ligatures) do NOT count.
 */
export function hasConfusables(s: string): boolean {
  return foldConfusables(s) !== s.normalize('NFKC');
}
