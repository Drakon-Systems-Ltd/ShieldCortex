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
 *   access            = log(1 + access_count) / log(1 + accessNorm)
 *   pin               = pinned ? pinBoost : 1
 *   downvote_penalty  = max(0.1, 1 - downvoteDecay × downvote_count)
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
 *   pinBoost?: number,
 *   downvoteDecay?: number,
 *   now?: number,
 * }} [opts]
 * @returns {number}
 */
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

export function computeEffectiveSalience(memory, opts = {}) {
  const halfLifeDays = pickNumber(opts.halfLifeDays, 'SHIELDCORTEX_SALIENCE_HALF_LIFE_DAYS', 14);
  const accessNorm = pickNumber(opts.accessNorm, 'SHIELDCORTEX_SALIENCE_ACCESS_NORM', 10);
  const pinBoost = pickNumber(opts.pinBoost, 'SHIELDCORTEX_SALIENCE_PIN_BOOST', 1.5);
  const downvoteDecay = pickNumber(opts.downvoteDecay, 'SHIELDCORTEX_SALIENCE_DOWNVOTE_DECAY', 0.3);
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

  // Access: log-scaled, normalised so access_count=accessNorm produces ~1.0.
  const accessCount = Math.max(0, Number(memory.access_count) || 0);
  const access = Math.log1p(accessCount) / Math.log1p(accessNorm);

  // Pin: SQLite stores boolean as 0/1.
  const pin = memory.pinned ? pinBoost : 1;

  // Downvote: each downvote lops downvoteDecay off the multiplier, floored
  // at 0.1 so a 4×-downvoted memory can still surface when truly relevant.
  const downvotes = Math.max(0, Number(memory.downvote_count) || 0);
  const downvotePenalty = Math.max(0.1, 1 - downvoteDecay * downvotes);

  return base * recency * access * pin * downvotePenalty;
}
