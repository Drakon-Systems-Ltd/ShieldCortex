/**
 * Recall relevance gate (P4, B9 design).
 *
 * The per-turn UserPromptSubmit recall hook runs an FTS5 OR-of-terms query.
 * FTS5 happily returns a row that matches just ONE common term out of six —
 * which is how off-topic, high-salience memories ended up injected every turn
 * ("same 5 every turn, none relevant" — EDITH, 2026-05). A relative BM25 floor
 * alone does NOT fix this: a "what is the weather today" query still returns
 * five hits within 35% of the best rank.
 *
 * The load-bearing discriminator is TERM-COVERAGE: how many DISTINCT query
 * terms a row actually matches. A 1-of-6-terms OR-match is noise; a real match
 * covers multiple terms.
 *
 * Two-stage gate:
 *   1. TERM-COVERAGE (primary). Keep iff
 *        matchedTerms >= minTermMatches
 *        OR (totalQueryTerms <= minTermMatches AND matchedTerms === totalQueryTerms)
 *      — i.e. a multi-term match, OR a terse prompt that was matched in full.
 *      So a 1-of-6 match drops; a 2-of-2 terse match keeps.
 *   2. RELATIVE BM25 FLOOR (secondary). Among coverage survivors that carry an
 *      FTS `rank`, drop rows weaker than `relFactor` of this query's best rank.
 *      SQLite bm25 ranks are negative; more negative = more relevant, so the
 *      floor is `best * relFactor` (less negative) and we drop `rank > floor`.
 *      Rows WITHOUT a `rank` (category-boost path) have no FTS rank and are
 *      exempt from the BM25 floor — but are STILL subject to term-coverage.
 *
 * Pure: no DB, no env reads, no mutation of inputs. The caller resolves all
 * options (mirror the pickNumber/env pattern in salience.mjs at the call site).
 */

/**
 * Count how many DISTINCT query terms appear in the given text, matched
 * case-insensitively on word-ish boundaries (NOT substring — "schema" must
 * not match inside "schematics"). A term made entirely of non-word characters
 * after lowercasing is skipped.
 *
 * @param {string} text
 * @param {string[]} queryTerms
 * @returns {number}
 */
function countMatchedTerms(text, queryTerms) {
  const haystack = String(text || '').toLowerCase();
  let matched = 0;
  const seen = new Set();
  for (const raw of queryTerms) {
    const term = String(raw || '').toLowerCase();
    if (!term || seen.has(term)) continue;
    seen.add(term);
    // Word-ish boundary: the term must be bounded by a non-word-char (or
    // string edge) on both sides. Escape regex metacharacters in the term.
    const escaped = term.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
    const re = new RegExp(`(^|[^\\p{L}\\p{N}_])${escaped}([^\\p{L}\\p{N}_]|$)`, 'u');
    if (re.test(haystack)) matched += 1;
  }
  return matched;
}

/**
 * Apply the term-coverage + relative-BM25 relevance gate to a set of recall
 * candidate rows.
 *
 * @param {Array<{ id?: any, title?: string, content?: string, rank?: number }>} rows
 * @param {{
 *   queryTerms: string[],
 *   minTermMatches?: number,
 *   relFactor?: number,
 *   maxBm25?: number | null,
 * }} opts
 * @returns {{ kept: any[], dropped: Array<{ row: any, reason: 'below_term_coverage' | 'below_relevance_floor' }> }}
 */
export function filterByRelevance(rows, opts = {}) {
  const list = Array.isArray(rows) ? rows : [];
  const queryTerms = Array.isArray(opts.queryTerms) ? opts.queryTerms : [];
  const minTermMatches =
    typeof opts.minTermMatches === 'number' && Number.isFinite(opts.minTermMatches)
      ? opts.minTermMatches
      : 2;
  const relFactor =
    typeof opts.relFactor === 'number' && Number.isFinite(opts.relFactor) ? opts.relFactor : 0.35;
  // Absolute BM25 floor is OPT-IN: null/undefined (the default) means "no
  // absolute dreg cut". It has no safe cross-corpus default — on a small/new
  // FTS index real bm25 ranks are tiny (~-1e-6), so an absolute floor like
  // -0.5 would drop even a perfect full-coverage match the moment an operator
  // turns on enforce mode. Only honour it when an explicit numeric value is
  // passed; the relative floor + term-coverage do the gating otherwise.
  const maxBm25 =
    typeof opts.maxBm25 === 'number' && Number.isFinite(opts.maxBm25) ? opts.maxBm25 : null;

  // Distinct, non-empty query terms (lowercased) — defines totalQueryTerms.
  const distinctTerms = [];
  const seenTerm = new Set();
  for (const raw of queryTerms) {
    const t = String(raw || '').toLowerCase();
    if (t && !seenTerm.has(t)) {
      seenTerm.add(t);
      distinctTerms.push(t);
    }
  }
  const totalQueryTerms = distinctTerms.length;

  // With no usable query terms there is nothing to gate on — keep everything
  // (defensive; the hook short-circuits before calling us in that case).
  if (totalQueryTerms === 0) {
    return { kept: [...list], dropped: [] };
  }

  const dropped = [];

  // ── Stage 1: term coverage ────────────────────────────────────────────
  const coverageSurvivors = [];
  for (const row of list) {
    const text = `${row && row.title ? row.title : ''} ${row && row.content ? row.content : ''}`;
    const matchedTerms = countMatchedTerms(text, distinctTerms);
    const multiTerm = matchedTerms >= minTermMatches;
    const terseFullMatch = totalQueryTerms <= minTermMatches && matchedTerms === totalQueryTerms;
    if (multiTerm || terseFullMatch) {
      coverageSurvivors.push(row);
    } else {
      dropped.push({ row, reason: 'below_term_coverage' });
    }
  }

  // ── Stage 2: relative BM25 floor (only over rows carrying an FTS rank) ──
  const ranked = coverageSurvivors.filter(
    (r) => typeof r.rank === 'number' && Number.isFinite(r.rank),
  );
  // best = most-negative (most relevant) rank among survivors.
  let best = null;
  for (const r of ranked) {
    if (best === null || r.rank < best) best = r.rank;
  }
  // Relative floor: drop ranked rows weaker (greater, i.e. less negative) than
  // best * relFactor. Only meaningful when best is negative (normal BM25).
  const relativeFloor = best !== null && best < 0 ? best * relFactor : null;

  const kept = [];
  for (const row of coverageSurvivors) {
    const hasRank = typeof row.rank === 'number' && Number.isFinite(row.rank);
    if (hasRank) {
      // Absolute dreg cut: a rank weaker than maxBm25 is noise regardless of
      // the relative floor (guards a query where even the best hit is weak).
      if (maxBm25 !== null && row.rank > maxBm25) {
        dropped.push({ row, reason: 'below_relevance_floor' });
        continue;
      }
      if (relativeFloor !== null && row.rank > relativeFloor) {
        dropped.push({ row, reason: 'below_relevance_floor' });
        continue;
      }
    }
    // No rank (category-boost) → exempt from the BM25 floor, already passed
    // term coverage. Or a ranked row at/under the floor.
    kept.push(row);
  }

  return { kept, dropped };
}

/**
 * Extract the distinct FTS query terms from a raw prompt, using the SAME
 * normalisation the hook's escapeFts5 applies before the OR-join (strip FTS5
 * operators, drop boolean keywords, split on whitespace, keep words longer
 * than two chars, cap at six). Exposed here so the relevance gate and the FTS
 * query agree on exactly which terms count.
 *
 * @param {string} query
 * @returns {string[]} up to 6 distinct lowercased terms
 */
export function extractQueryTerms(query) {
  const words = String(query || '')
    .replace(/[*(){}[\]<>~^"]/g, ' ')
    .replace(/\b(AND|OR|NOT|NEAR)\b/gi, '')
    .split(/\s+/)
    .filter((w) => w.length > 2);
  // Dedup BEFORE the cap so repeated early terms don't crowd out distinct
  // later ones (e.g. "drizzle drizzle drizzle migration migration rollback
  // schema postgres journal" → up to 6 DISTINCT terms, not 3). First
  // occurrence wins (order preserved); the slice then keeps the first 6.
  const out = [];
  const seen = new Set();
  for (const w of words) {
    const lw = w.toLowerCase();
    if (!seen.has(lw)) {
      seen.add(lw);
      out.push(lw);
    }
    if (out.length >= 6) break;
  }
  return out;
}
