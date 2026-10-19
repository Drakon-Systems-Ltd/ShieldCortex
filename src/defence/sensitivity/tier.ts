/**
 * #718 precise sensitivity tier. INTERNAL: nothing in this module is
 * re-exported from a package entry point.
 *
 * 5.7.0 added PERSONAL to the exported `SensitivityLevel`, which broke code
 * written against 5.6.0. The public declarations are back to the 5.6.0 shape;
 * the five-value tier lives here. Storage, the audit log, the HTTP scan routes,
 * CLI JSON and Cloud sync keep using it; public in-process returns are
 * projected (PERSONAL → CONFIDENTIAL).
 *
 * PERSONAL sits between INTERNAL and CONFIDENTIAL: personal / family /
 * relationship content that is not a credential or an identifier, but must
 * only ever be recalled into the owner's interactive lane.
 */

import type { SensitivityClassification, SensitivityLevel } from '../types.js';

export type SensitivityTier = SensitivityLevel | 'PERSONAL';

/** The 5.7.0–5.10.5 classification shape, with `level` carrying the precise tier. */
export interface PreciseSensitivityClassification {
  level: SensitivityTier;
  confidence: number;
  detectedPatterns: string[];
  redactionRequired: boolean;
}

/**
 * 5.6.0-compatible projection. PERSONAL → CONFIDENTIAL: the lowest four-value
 * level that keeps every PERSONAL protection (Cloud exclusion, non-interactive
 * lane withholding). Never INTERNAL, which Cloud sync would send by default.
 */
export function projectSensitivityTier(tier: SensitivityTier): SensitivityLevel {
  return tier === 'PERSONAL' ? 'CONFIDENTIAL' : tier;
}

/** Projected copy for public returns. Keeps the classifier's key order; never mutates `p`. */
export function toPublicSensitivity(p: PreciseSensitivityClassification): SensitivityClassification {
  return {
    level: projectSensitivityTier(p.level),
    confidence: p.confidence,
    detectedPatterns: [...p.detectedPatterns],
    redactionRequired: p.redactionRequired,
  };
}
