/**
 * Session-start context ordering helpers.
 *
 * The boot preamble used to order high-priority memories by raw
 * `salience DESC, last_accessed DESC`. Because ~80% of rows sit at raw
 * salience=1.0 (the "wall"), that ordering was an 80% tie and effectively
 * random. Ranking by *effective* salience (recency × access × pin ×
 * downvote_penalty — see scripts/lib/salience.mjs) lets fresh/relevant
 * memories rank above stale 1.0 ones.
 *
 * Kept pure + side-effect-free so it's unit-testable without importing the
 * hook entrypoint (which runs a stdin/process.exit IIFE at module load).
 */

import { computeEffectiveSalience } from './salience.mjs';

/**
 * Sort memories by effective salience, highest first. Returns a new array;
 * the input is not mutated. `opts` is passed through to
 * computeEffectiveSalience so tests can inject a deterministic `now`.
 *
 * @param {Array<object>} memories
 * @param {object} [opts] - forwarded to computeEffectiveSalience (e.g. { now })
 * @returns {Array<object>}
 */
export function orderByEffectiveSalience(memories, opts = {}) {
  return [...memories].sort(
    (a, b) => computeEffectiveSalience(b, opts) - computeEffectiveSalience(a, opts),
  );
}
