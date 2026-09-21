/**
 * Content sensitivity classifier.
 */

import type { SensitivityClassification, SensitivityLevel } from '../types.js';
import {
  RESTRICTED_PATTERNS,
  CONFIDENTIAL_PATTERNS,
  INTERNAL_PATTERNS,
  type SensitivityPattern,
} from './patterns.js';
import { detectPII } from './pii.js';

function matchPatterns(
  text: string,
  patterns: SensitivityPattern[],
): { labels: string[]; maxWeight: number } {
  const labels: string[] = [];
  let maxWeight = 0;

  for (const { pattern, label, weight } of patterns) {
    // Reset lastIndex for global regexes
    pattern.lastIndex = 0;
    if (pattern.test(text)) {
      labels.push(label);
      if (weight > maxWeight) maxWeight = weight;
    }
  }

  return { labels, maxWeight };
}

export function classifyContent(
  content: string,
  title: string,
): SensitivityClassification {
  const text = `${title}\n${content}`;

  const allLabels: string[] = [];
  let level: SensitivityLevel = 'PUBLIC';
  let confidence = 0.5;

  // Check in priority order: RESTRICTED > CONFIDENTIAL > INTERNAL
  const restricted = matchPatterns(text, RESTRICTED_PATTERNS);
  allLabels.push(...restricted.labels);

  const confidential = matchPatterns(text, CONFIDENTIAL_PATTERNS);
  allLabels.push(...confidential.labels);

  const internal = matchPatterns(text, INTERNAL_PATTERNS);
  allLabels.push(...internal.labels);

  if (restricted.labels.length > 0) {
    level = 'RESTRICTED';
    confidence = restricted.maxWeight;
  } else if (confidential.labels.length > 0) {
    level = 'CONFIDENTIAL';
    confidence = confidential.maxWeight;
  } else if (internal.labels.length > 0) {
    level = 'INTERNAL';
    confidence = internal.maxWeight;
  }

  // #510: identifier-grade PII (NI number, SSN, tax id, salary) is at least
  // CONFIDENTIAL. It never raises to RESTRICTED — PII is redacted, not blocked.
  const piiKinds = [...new Set(detectPII(text).filter(f => f.identifier).map(f => f.kind))];
  if (piiKinds.length > 0) {
    allLabels.push(...piiKinds.map(kind => `pii:${kind}`));
    if (level === 'PUBLIC' || level === 'INTERNAL') {
      level = 'CONFIDENTIAL';
      confidence = 0.85;
    }
  }

  return {
    level,
    confidence,
    detectedPatterns: allLabels,
    redactionRequired: level === 'RESTRICTED',
  };
}
