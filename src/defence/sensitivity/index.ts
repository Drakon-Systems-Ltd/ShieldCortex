/**
 * Sensitivity classification and redaction.
 */

import type { SensitivityClassification } from '../types.js';
import { classifyContent } from './classifier.js';

export { redactContent, redactForDisplay } from './redaction.js';
export { classifyContent } from './classifier.js';

/**
 * Classify content sensitivity — convenience wrapper around classifyContent.
 */
export function classifySensitivity(
  content: string,
  title: string,
): SensitivityClassification {
  return classifyContent(content, title);
}
