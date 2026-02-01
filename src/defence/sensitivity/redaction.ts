/**
 * Content redaction utilities.
 */

import type { SensitivityLevel } from '../types.js';
import { RESTRICTED_PATTERNS, CONFIDENTIAL_PATTERNS } from './patterns.js';

/**
 * Replace all RESTRICTED pattern matches with [REDACTED].
 */
export function redactContent(content: string): string {
  let result = content;

  for (const { pattern } of RESTRICTED_PATTERNS) {
    // Clone the regex to avoid shared lastIndex state
    const re = new RegExp(pattern.source, pattern.flags);
    result = result.replace(re, '[REDACTED]');
  }

  return result;
}

/**
 * Partially mask a string: show first and last characters, mask the middle.
 * For strings <= 4 chars, mask everything.
 */
function partialMask(value: string): string {
  if (value.length <= 4) return '*'.repeat(value.length);
  return value[0] + '*'.repeat(value.length - 2) + value[value.length - 1];
}

/**
 * Redact content appropriate to its sensitivity level.
 *
 * - RESTRICTED: fully redact all restricted patterns
 * - CONFIDENTIAL: partially mask confidential patterns (show first/last chars)
 * - INTERNAL / PUBLIC: return as-is
 */
export function redactForDisplay(
  content: string,
  level: SensitivityLevel,
): string {
  if (level === 'RESTRICTED') {
    return redactContent(content);
  }

  if (level === 'CONFIDENTIAL') {
    let result = content;
    for (const { pattern } of CONFIDENTIAL_PATTERNS) {
      const re = new RegExp(pattern.source, pattern.flags);
      result = result.replace(re, (match) => partialMask(match));
    }
    return result;
  }

  return content;
}
