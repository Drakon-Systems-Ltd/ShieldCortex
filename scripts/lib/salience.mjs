/**
 * Effective salience computation (v4.25.0).
 *
 * Pre-4.25 the recall hook ranked tied FTS results by raw `salience` only.
 * That ignored real signal: a memory that was last accessed 3 months ago
 * carries less weight than a memory accessed yesterday; a pinned memory
 * deserves more weight than an identical unpinned one; a memory the user
 * downvoted via `shieldcortex memory downvote <id>` should be demoted.
 *
 * Formula:
 *   effective = base × recency × access × pin × downvote_penalty
 *
 *   recency           = exp(-Δt_days / halfLifeDays)        // decay
 *   access            = accessFloor + (1 - accessFloor) × log(1 + access_count) / log(1 + accessNorm)
 *   pin               = pinned ? pinBoost : 1
 *   downvote_penalty  = max(0.1, 1 - downvoteDecay × downvote_count)
 *
 * v4.47.x (issue #120): a CONTENT-CLASS factor is folded in on top —
 * transactional/status noise (cron run tallies, retry logs, delivery
 * confirmations) is penalised and consequence content (decision, root-cause,
 * preference, doctrine) is boosted. Frequency (the raw-salience ratchet) and
 * recency are load-independent of consequence, so without this a re-extracted
 * status line out-ranks a three-week-old root-cause finding. See
 * scripts/lib/content-class.mjs.
 *
 * All constants are env-var-tunable (no recompile needed for field tuning).
 *
 * The function returns the *multiplier-adjusted* salience. The base salience
 * column in SQLite stays untouched — this is a read-time computation.
 *
 * @param {{
 *   salience?: number,
 *   last_accessed?: string | null,
 *   access_count?: number | null,
 *   pinned?: number | boolean | null,
 *   downvote_count?: number | null
 * }} memory
 * @param {{
 *   halfLifeDays?: number,
 *   accessNorm?: number,
 *   accessFloor?: number,
 *   pinBoost?: number,
 *   downvoteDecay?: number,
 *   now?: number,
 * }} [opts]
 * @returns {number}
 */
import { contentClassFactor } from './content-class.mjs';

// Resolve a numeric tuning constant from opts (explicit override), then
// SHIELDCORTEX_* env var, then the documented default. Returns the default
// if either of the first two is NaN — we never want a typo'd env var to
// silently zero out a multiplier.
function pickNumber(override, envName, fallback) {
  if (typeof override === 'number' && Number.isFinite(override)) return override;
  const fromEnv = Number(process.env[envName]);
  if (Number.isFinite(fromEnv) && fromEnv !== 0) return fromEnv;
  return fallback;
}

// Function words a capture begins or ends on when it was sliced mid-clause.
// Mirrors the extractor's DANGLING_TAIL vocabulary
// (scripts/lib/extract-memorable-segments.mjs) — a closed grammatical class,
// not business logic, so the small duplication is deliberate: importing the
// ~29 KB extractor module into this read-time hot path (runs on every recall /
// prompt) isn't worth the coupling or parse cost.
const FRAGMENT_FUNCTION_WORDS = new Set([
  'and', 'or', 'but', 'nor', 'the', 'a', 'an', 'to', 'of', 'in', 'on', 'at',
  'by', 'for', 'with', 'without', 'from', 'as', 'is', 'are', 'was', 'were',
  'be', 'been', 'that', 'which', 'who', 'whose', 'because', 'so', 'if', 'when',
  'while', 'than', 'then', 'into', 'onto', 'over', 'under', 'via', 'per',
  'about', 'after', 'before', 'between', 'during',
]);

function normaliseWord(w) {
  return w.toLowerCase().replace(/[^a-z']/g, '');
}

// First / last word carrying letters, skipping pure-punctuation tokens
// (em-dashes, markdown bullets, stray brackets) so "— the daily check" reads
// as first-word "the".
function edgeWords(text) {
  const tokens = text.split(/\s+/);
  let first = '';
  for (const t of tokens) { const c = normaliseWord(t); if (c) { first = c; break; } }
  let last = '';
  for (let i = tokens.length - 1; i >= 0; i--) { const c = normaliseWord(tokens[i]); if (c) { last = c; break; } }
  return { first, last };
}

/**
 * Read-time completeness signal. Returns 1 for a self-contained capture, or
 * `fragmentFactor` (<1) for one sliced mid-clause:
 *   - BEGINS on a *lowercase* function word — cut before the clause started
 *     ("the resources this year"). The lowercase test is load-bearing: a real
 *     sentence opening "The fix was…" is complete and must NOT be penalised.
 *   - ENDS on a function word with no terminal punctuation — cut after
 *     ("…the normalisation step after the").
 *
 * Recomputed from the (stable) content on every call, so the salience ratchet
 * (reinforcement / consolidation only ever ADD) cannot erase it. Re-ranks
 * only — floored above 0, never drops a memory (cf. the downvote floor).
 *
 * @param {unknown} content
 * @param {number} fragmentFactor
 * @returns {number} 1 (complete) or fragmentFactor (fragment)
 */
function contentCompletenessFactor(content, fragmentFactor) {
  if (typeof content !== 'string') return 1;
  const t = content.trim();
  if (!t) return 1;
  const { first, last } = edgeWords(t);
  const firstLetter = t.match(/[A-Za-z]/);
  const firstIsLower = !!firstLetter && firstLetter[0] >= 'a' && firstLetter[0] <= 'z';
  const startsMidClause = firstIsLower && FRAGMENT_FUNCTION_WORDS.has(first);
  const endsMidClause = !/[.!?]["')\]]?$/.test(t) && FRAGMENT_FUNCTION_WORDS.has(last);
  return startsMidClause || endsMidClause ? fragmentFactor : 1;
}

export function computeEffectiveSalience(memory, opts = {}) {
  const halfLifeDays = pickNumber(opts.halfLifeDays, 'SHIELDCORTEX_SALIENCE_HALF_LIFE_DAYS', 14);
  const accessNorm = pickNumber(opts.accessNorm, 'SHIELDCORTEX_SALIENCE_ACCESS_NORM', 10);
  const pinBoost = pickNumber(opts.pinBoost, 'SHIELDCORTEX_SALIENCE_PIN_BOOST', 1.5);
  const downvoteDecay = pickNumber(opts.downvoteDecay, 'SHIELDCORTEX_SALIENCE_DOWNVOTE_DECAY', 0.3);
  const accessFloor = pickNumber(opts.accessFloor, 'SHIELDCORTEX_ACCESS_FLOOR', 0.4);
  // Fragment captures rank at fragmentFactor× a complete fact of equal recency
  // /access. Default 0.5 halves them — enough to sink below complete facts in
  // the candidate pool without excluding a genuinely-relevant one outright.
  const fragmentFactor = pickNumber(opts.fragmentFactor, 'SHIELDCORTEX_SALIENCE_FRAGMENT_FACTOR', 0.5);
  // Content-class weights (issue #120): transactional/status content is
  // penalised, consequence content (decision/root-cause/preference/doctrine) is
  // boosted. Kept < the completeness swing individually but multiplicative with
  // it, so a complete consequence fact dominates a fragmentary status line.
  const classBoost = pickNumber(opts.classBoost, 'SHIELDCORTEX_SALIENCE_CLASS_BOOST', 1.3);
  const classPenalty = pickNumber(opts.classPenalty, 'SHIELDCORTEX_SALIENCE_CLASS_PENALTY', 0.35);
  const now = opts.now ?? Date.now();

  const base = typeof memory.salience === 'number' ? memory.salience : 0;

  // Recency: exp(-Δt_days / halfLife). last_accessed missing → assume "now"
  // (a brand-new memory should not be penalised for never having been read).
  let recency = 1;
  if (memory.last_accessed) {
    const lastMs = Date.parse(memory.last_accessed);
    if (Number.isFinite(lastMs)) {
      const deltaDays = Math.max(0, (now - lastMs) / 86_400_000);
      recency = Math.exp(-deltaDays / halfLifeDays);
    }
  }

  // Access: log-scaled boost, NOT a gate. Floored at accessFloor so a
  // never-accessed memory (access_count=0, ~44% of the live DB) keeps a
  // non-zero multiplier instead of collapsing the whole product to 0.
  // access_count=0 → accessFloor; access_count=accessNorm → ~1.0.
  const accessCount = Math.max(0, Number(memory.access_count) || 0);
  const access = accessFloor + (1 - accessFloor) * (Math.log1p(accessCount) / Math.log1p(accessNorm));

  // Pin: SQLite stores boolean as 0/1.
  const pin = memory.pinned ? pinBoost : 1;

  // Downvote: each downvote lops downvoteDecay off the multiplier, floored
  // at 0.1 so a 4×-downvoted memory can still surface when truly relevant.
  const downvotes = Math.max(0, Number(memory.downvote_count) || 0);
  const downvotePenalty = Math.max(0.1, 1 - downvoteDecay * downvotes);

  // Completeness: derived fresh from content each call so the raw-salience
  // ratchet can't erase it (v4.33.1). Neutral (1) when no content is supplied,
  // preserving v4.25 caller behaviour.
  const completeness = contentCompletenessFactor(memory.content, fragmentFactor);

  // Content class: derived fresh from content each call (ratchet-proof, like
  // completeness). Neutral (1) when no content is supplied, preserving v4.25
  // caller behaviour.
  const contentClass =
    typeof memory.content === 'string'
      ? contentClassFactor(memory.content, { boost: classBoost, penalty: classPenalty })
      : 1;

  return base * recency * access * pin * downvotePenalty * completeness * contentClass;
}
