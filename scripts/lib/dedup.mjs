/**
 * Pure, synchronous near-duplicate detection for the hook write path.
 *
 * No DB, no native deps, no dist dependency — this lets the hook writer
 * (save-memory.mjs) dedup even in a dev workspace where `dist/` hasn't been
 * built. It is deliberately a .mjs sibling rather than an import of
 * dist/memory/similarity.js so the write path never gains a build dependency.
 *
 * The Jaccard algorithm below MIRRORS src/memory/similarity.ts:tokenize/
 * jaccardSimilarity so the write-path gate and the consolidate/contradiction
 * paths agree on what "similar" means. Keep them in lockstep if either moves.
 *
 * NOTE (future convergence): hooks/openclaw/cortex-memory/handler.ts has its
 * own `inspectNovelty` Jaccard gate. This module is the candidate convergence
 * point for all three, but the handler is intentionally left untouched here.
 */

/**
 * Tokenize text into a set of normalized words.
 * Lowercase, strip punctuation to whitespace, split on whitespace, drop words
 * of length <= 2. Mirrors src/memory/similarity.ts:tokenize exactly.
 *
 * @param {string} text
 * @returns {Set<string>}
 */
export function tokenize(text) {
  return new Set(
    String(text ?? '')
      .toLowerCase()
      .replace(/[^\w\s]/g, ' ') // punctuation -> space
      .split(/\s+/)
      .filter((word) => word.length > 2), // drop very short words (and empties)
  );
}

/**
 * Jaccard similarity between two texts: |A ∩ B| / |A ∪ B|.
 * Mirrors src/memory/similarity.ts:jaccardSimilarity (two empty token sets => 1.0).
 *
 * @param {string} textA
 * @param {string} textB
 * @returns {number} 0..1
 */
export function jaccardSimilarity(textA, textB) {
  const setA = tokenize(textA);
  const setB = tokenize(textB);

  if (setA.size === 0 && setB.size === 0) return 1.0;
  if (setA.size === 0 || setB.size === 0) return 0.0;

  let intersection = 0;
  for (const word of setA) {
    if (setB.has(word)) intersection++;
  }

  const union = setA.size + setB.size - intersection;
  return intersection / union;
}

/**
 * Decide whether `candidate` is a near-duplicate of `existing`.
 *
 * Two-stage to keep cost down and avoid false merges:
 *   1. Title-Jaccard PRE-GATE — only consider pairs whose titles already
 *      overlap (>= titleJaccard). If titles are unrelated we never compute
 *      content similarity. This both bounds work and stops two genuinely
 *      different notes that happen to reuse a few content words from merging.
 *   2. Combined score — content*0.6 + title*0.4, matching the weighting in
 *      src/memory/consolidate.ts (~L603-613). >= combinedThreshold => dup.
 *
 * @param {{title: string, content: string}} candidate — the incoming write
 * @param {{title: string, content: string}} existing  — a stored row
 * @param {{titleJaccard: number, combinedThreshold: number}} thresholds
 * @returns {{ duplicate: boolean, combined: number, titleSim: number }}
 */
export function isNearDuplicate(candidate, existing, { titleJaccard, combinedThreshold }) {
  // Empty-title guard: jaccardSimilarity() (faithful to similarity.ts) returns
  // 1.0 for two empty token sets, but for a dedup PRE-GATE that's a false
  // match — two titles that tokenize to nothing (e.g. "A", "PC", a bare digit)
  // carry no overlap signal and must NOT auto-pass the gate. Require real title
  // tokens on both sides before trusting titleSim.
  const candTitleTokens = tokenize(candidate.title);
  const existTitleTokens = tokenize(existing.title);
  if (candTitleTokens.size === 0 || existTitleTokens.size === 0) {
    return { duplicate: false, combined: 0, titleSim: 0 };
  }

  const titleSim = jaccardSimilarity(candidate.title, existing.title);

  // Pre-gate: unrelated titles short-circuit before any content work.
  if (titleSim < titleJaccard) {
    return { duplicate: false, combined: 0, titleSim };
  }

  const contentSim = jaccardSimilarity(candidate.content, existing.content);
  const combined = contentSim * 0.6 + titleSim * 0.4;

  return { duplicate: combined >= combinedThreshold, combined, titleSim };
}
