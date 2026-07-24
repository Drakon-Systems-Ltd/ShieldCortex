/**
 * Content-class weighting (issue #120).
 *
 * Recall used to rank almost entirely on frequency (raw-salience ratchet) and
 * recency. Both are load-independent of *consequence*: a cron run-tally that
 * gets re-extracted every session ratchets to salience 1.0 and, being freshly
 * touched, out-ranks a three-week-old root-cause finding that only mattered
 * once. On the Jarvis box the SessionStart preamble surfaced three transactional
 * fragments at 100% salience while an OAuth root-cause and a fleet-billing
 * doctrine sat below the fold.
 *
 * The fix is a CONTENT-CLASS signal, recomputed from the (stable) content on
 * every rank so the salience ratchet can't erase it — the same philosophy as
 * the read-time completeness factor in salience.mjs.
 *
 *   'transactional' — run tallies ("0, reran 0, blocked 2"), counters,
 *      delivery confirmations ("12 delivered, 0 bounced"), retry / escalation
 *      logs ("re-escalated … every ~6h", "cron: job interrupted"). Zero forward
 *      value; demoted (and rejected outright at capture time).
 *   'consequence'   — decision, root-cause, preference, doctrine. The durable
 *      facts recall exists to surface; promoted.
 *   'neutral'       — ordinary complete facts. Weight unchanged.
 *
 * Pure + dependency-free so both the read-time hot path (salience.mjs, runs on
 * every recall / prompt) and the capture path (extract-memorable-segments.mjs)
 * share one vocabulary without either importing the other.
 */

// ── Transactional / status tells ───────────────────────────────────────────
// A status report keys on NUMBER+STATUS-VERB shapes and machine log phrasing,
// NOT on the mere presence of a digit — "retries failed operations 3 times" is
// a doctrine and "sentinel fires every 30 minutes" is a schedule, neither is a
// run tally. The count-word list is deliberately narrow (delivery / queue /
// sync verbs) so ordinary facts that happen to contain a number or a common
// verb like "failed" / "ran" are not swept up.
const STATUS_COUNT_WORDS =
  'sent|reran|re-ran|blocked|skipped|queued|delivered|bounced|' +
  'synced|retried|succeeded|errored|dropped|flushed|processed';

const TRANSACTIONAL_PATTERNS = [
  // Run tally: a bare number adjacent to a status/count word, in either order.
  // "0, reran 0, blocked 2" / "12 delivered" / "3 queued" / "blocked: 2".
  new RegExp(`\\b\\d+\\s+(?:${STATUS_COUNT_WORDS})\\b`, 'i'),
  new RegExp(`\\b(?:${STATUS_COUNT_WORDS})[:\\s]+\\d+\\b`, 'i'),
  // The comma-run-tally opener specifically ("0, reran 0, blocked 2.").
  /^\s*\d+\s*,\s*[a-z-]+\s+\d+/i,
  // Delivery / job confirmations and interruptions.
  /\b(?:successfully\s+(?:sent|delivered|synced|posted|completed)|(?:sent|delivered|posted|synced)\s+successfully|(?:sync|job|run|backup|briefing|cron)\s+(?:completed|finished|succeeded|interrupted|failed|skipped))\b/i,
  /\bcron:\s/i,
  /\bjob\s+interrupted\b/i,
  /\bgateway\s+restart\b/i,
  // Retry / escalation logs.
  /\bre-?escalat/i,
  /\blast\s+run\s+(?:as|was|=)\b/i,
];

// ── Consequence tells ───────────────────────────────────────────────────────
// Distinctive, high-confidence markers only. Bare "chose"/"chosen" is
// deliberately EXCLUDED — it reads as an ordinary fact ("PostgreSQL chosen for
// JSONB support") as often as a decision, and boosting it would disturb the
// calibrated neutral baseline. Decisions are surfaced by their explicit
// decision verbs instead.
const CONSEQUENCE_PATTERNS = [
  // Decision.
  /\b(?:we\s+)?decided\b/i,
  /\bdecision\b/i,
  /\b(?:opted\s+(?:for|to)|settled\s+on|going\s+with|will\s+use)\b/i,
  // Root-cause.
  /\broot\s+cause\b/i,
  /\bcaused\s+by\b/i,
  /\bthe\s+(?:fix|bug|issue|problem|root\s+cause)\s+(?:is|was)\b/i,
  // Preference.
  /\b(?:prefers?|preferred|preference|mandat(?:e|ed|ory))\b/i,
  /\bby\s+(?:convention|policy|design)\b/i,
  /\b(?:must|should)\s+(?:always|never)\b/i,
  // Doctrine.
  /\b(?:doctrine|principle|invariant|zeroth\s+law|rule\s+of\s+thumb)\b/i,
];

/**
 * Classify a snippet's content class. Transactional wins over consequence when
 * both fire — a status line that happens to mention a "decision" is still a
 * status line, and the whole point is to keep housekeeping noise down.
 *
 * @param {unknown} text
 * @returns {'transactional' | 'consequence' | 'neutral'}
 */
export function classifyContentClass(text) {
  if (typeof text !== 'string' || !text.trim()) return 'neutral';
  if (TRANSACTIONAL_PATTERNS.some((rx) => rx.test(text))) return 'transactional';
  if (CONSEQUENCE_PATTERNS.some((rx) => rx.test(text))) return 'consequence';
  return 'neutral';
}

/**
 * Salience multiplier for a snippet's content class. Re-ranks only — the
 * penalty is floored above 0 by construction (callers pass a positive penalty),
 * so a transactional memory can still surface when it's genuinely the best
 * match, it just never out-ranks a consequence fact on frequency/recency alone.
 *
 * @param {unknown} text
 * @param {{ boost?: number, penalty?: number }} [opts]
 * @returns {number} penalty (transactional), boost (consequence), or 1 (neutral)
 */
export function contentClassFactor(text, opts = {}) {
  const boost = typeof opts.boost === 'number' && Number.isFinite(opts.boost) ? opts.boost : 1.3;
  const penalty =
    typeof opts.penalty === 'number' && Number.isFinite(opts.penalty) ? opts.penalty : 0.35;
  const cls = classifyContentClass(text);
  if (cls === 'transactional') return penalty;
  if (cls === 'consequence') return boost;
  return 1;
}
