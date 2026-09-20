/**
 * Sensitivity classification and redaction.
 */

import type { SensitivityClassification } from '../types.js';
import { classifyContent } from './classifier.js';

export { redactContent, redactForDisplay } from './redaction.js';
export { classifyContent } from './classifier.js';
export { detectPII, redactPII, isPIIRedactionEnabled, redactForPersistence, redactJsonForPersistence, hasRedactionToken } from './pii.js';
export type { PIIFinding, PIIKind, PIIRedactionResult, PersistableFields, PersistenceRedaction } from './pii.js';

/**
 * Classify content sensitivity — convenience wrapper around classifyContent.
 */
export function classifySensitivity(
  content: string,
  title: string,
): SensitivityClassification {
  return classifyContent(content, title);
}
