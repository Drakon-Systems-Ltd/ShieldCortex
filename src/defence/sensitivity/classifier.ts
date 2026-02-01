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

  return {
    level,
    confidence,
    detectedPatterns: allLabels,
    redactionRequired: level === 'RESTRICTED',
  };
}
