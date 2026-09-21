/**
 * Read-side sensitivity isolation (#542).
 *
 * The product ladder is PUBLIC / INTERNAL / CONFIDENTIAL / RESTRICTED. A stored
 * row can still carry another label: `SECRET` is preserved (never lowered) by
 * the store merge ladder and the hook writers, and a row written by an older or
 * foreign client may carry anything. Every reader-side gate used to test
 * `=== 'RESTRICTED'`, so such a row fell through to the shared branch — a label
 * that outranks RESTRICTED in the merge ladder read like CONFIDENTIAL.
 *
 * `isIsolatedSensitivity` is the single answer for readers: a label is isolated
 * (handled exactly like RESTRICTED for access checks, display redaction, recall
 * redaction and prompt injection) when it is RESTRICTED, SECRET, or anything
 * that is not one of the three shared tiers. Only an ABSENT label (null,
 * undefined, blank) is not isolated: unlabelled rows are INTERNAL by convention
 * (`COALESCE(sensitivity_level, 'INTERNAL')` everywhere else) and failing
 * closed on them would hide most of a store. Case and surrounding whitespace
 * are ignored so `restricted` cannot slip past a case-sensitive comparison.
 *
 * Whether `SECRET` becomes a real tier or is normalised to RESTRICTED at write
 * is a separate decision (#542, options 1/2); both outcomes keep this true.
 */

/** The tiers a non-owner, non-operator caller may be allowed to read. */
export const SHARED_SENSITIVITY_LEVELS: ReadonlySet<string> = new Set(['PUBLIC', 'INTERNAL', 'CONFIDENTIAL']);

/** Trimmed, upper-cased label; `null` when the row carries no label at all. */
export function normaliseSensitivityLabel(level: unknown): string | null {
  if (level == null) return null;
  const label = String(level).trim().toUpperCase();
  return label === '' ? null : label;
}

/**
 * True when a row must be treated as RESTRICTED by every reader: RESTRICTED,
 * SECRET, or any label outside the shared tiers (fail closed on the unknown).
 */
export function isIsolatedSensitivity(level: unknown): boolean {
  const label = normaliseSensitivityLabel(level);
  if (label === null) return false;
  return !SHARED_SENSITIVITY_LEVELS.has(label);
}

/**
 * SQL predicate equivalent to `!isIsolatedSensitivity(<column>)` for the
 * counting queries that mirror the injection gate. NULL and blank labels count
 * as INTERNAL, exactly as the TypeScript helper treats them.
 */
export function sharedSensitivitySqlPredicate(column = 'sensitivity_level'): string {
  const tiers = [...SHARED_SENSITIVITY_LEVELS].map((t) => `'${t}'`).join(', ');
  return `UPPER(TRIM(COALESCE(NULLIF(TRIM(${column}), ''), 'INTERNAL'))) IN (${tiers})`;
}
