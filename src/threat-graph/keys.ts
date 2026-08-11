/**
 * Pure key derivation for the threat graph — deliberately DB-free so the
 * defence pipeline's hot path (Phase B's source_risk read) can import it
 * without dragging in database modules. shared.ts imports database/init and
 * must never be imported from pipeline code; this module may be.
 *
 * Single source of truth: the projector's node keying and the hot-path
 * lookup MUST derive keys identically, or long identifiers silently read no
 * risk row (modifier 0 forever).
 */

/** Max identifier length contributing to source-node identity. */
export const SOURCE_KEY_MAX_LENGTH = 200;

export function sourceKey(
  sourceType: string,
  identifier: string,
  cap: number = SOURCE_KEY_MAX_LENGTH,
): string {
  return `${sourceType}:${identifier.slice(0, cap)}`;
}
