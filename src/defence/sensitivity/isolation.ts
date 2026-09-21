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

/**
 * The code points `String.prototype.trim` strips (ECMAScript WhiteSpace plus
 * LineTerminator). SQLite's one-argument `TRIM` strips U+0020 only, so a label
 * of `"\tINTERNAL\n"` was injectable to the TypeScript gate and invisible to
 * the SQL count that claims to mirror it (#545 review). The SQL predicate
 * passes this exact set to two-argument `TRIM`, so both sides strip the same
 * characters; the differential test walks every one of them.
 */
export const LABEL_WHITESPACE_CODE_POINTS: readonly number[] = Object.freeze([
  0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x20, 0xa0, 0x1680,
  0x2000, 0x2001, 0x2002, 0x2003, 0x2004, 0x2005, 0x2006, 0x2007, 0x2008, 0x2009, 0x200a,
  0x2028, 0x2029, 0x202f, 0x205f, 0x3000, 0xfeff,
]);

/**
 * ASCII-only upper-casing, the same mapping as SQLite's built-in `UPPER`.
 * `toUpperCase` is Unicode-aware: it turns `ınternal` (dotless i) into
 * `INTERNAL`, a shared tier, while SQL keeps it an unknown label. Unknown must
 * stay unknown on both sides, so neither side folds beyond a-z.
 */
function asciiUpper(s: string): string {
  return s.replace(/[a-z]+/g, (m) => m.toUpperCase());
}

/** Trimmed, ASCII-upper-cased label; `null` when the row carries no label at all. */
export function normaliseSensitivityLabel(level: unknown): string | null {
  if (level == null) return null;
  const label = asciiUpper(String(level).trim());
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
 * as INTERNAL, exactly as the TypeScript helper treats them. Whitespace is the
 * `LABEL_WHITESPACE_CODE_POINTS` set and case folding is ASCII-only on both
 * sides (SQLite's built-in `UPPER`; a build with the ICU extension loaded
 * would fold more and is not what ShieldCortex ships).
 */
export function sharedSensitivitySqlPredicate(column = 'sensitivity_level'): string {
  const tiers = [...SHARED_SENSITIVITY_LEVELS].map((t) => `'${t}'`).join(', ');
  const ws = `char(${LABEL_WHITESPACE_CODE_POINTS.join(',')})`;
  return `UPPER(COALESCE(NULLIF(TRIM(${column}, ${ws}), ''), 'INTERNAL')) IN (${tiers})`;
}
