/**
 * Sensitivity classification and redaction.
 */

import type { SensitivityClassification } from '../types.js';
import { classifyContent } from './classifier.js';
import { toPublicSensitivity, type PreciseSensitivityClassification } from './tier.js';

export { redactContent, redactForDisplay, redactForDisplayTier } from './redaction.js';
export { classifyContent } from './classifier.js';
export { PII_KINDS, detectPII, redactPII, isPIIRedactionEnabled, redactForPersistence, redactJsonForPersistence, hasRedactionToken } from './pii.js';
export type { PIIFinding, PIIKind, PIIRedactionResult, PersistableFields, PersistenceRedaction } from './pii.js';

/**
 * Classify content sensitivity — convenience wrapper around classifyContent.
 */
export function classifySensitivity(
  content: string,
  title: string,
): SensitivityClassification {
  return toPublicSensitivity(classifyContent(content, title));
}

/**
 * INTERNAL: the precise classification (`level` may be PERSONAL). Used by the
 * library's own writers, gates and wire serializers. Not re-exported from any
 * package entry point.
 */
export function classifySensitivityPrecise(
  content: string,
  title: string,
): PreciseSensitivityClassification {
  return classifyContent(content, title);
}
