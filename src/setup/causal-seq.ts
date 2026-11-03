/**
 * #977 review — causal ordering for "did this restart load that change?".
 *
 * Wall-clock milliseconds cannot order two events that land in the same
 * millisecond: a change and the restart right after it compare equal, and no
 * choice of `<` / `<=` is right for both orders. Every event that needs
 * ordering takes a ticket from this one process-wide counter instead; tickets
 * are strictly increasing, so the earlier event always holds the smaller one.
 * Pure and dependency-free.
 */
let seq = 0;

/** The next ticket: strictly greater than every ticket handed out before it. */
export function nextCausalSeq(): number {
  seq += 1;
  return seq;
}
