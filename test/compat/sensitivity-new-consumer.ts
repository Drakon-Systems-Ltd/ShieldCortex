// What a 5.7.0–5.10.5 consumer sees after the 5.x compat restore: the precise
// #718 tier is not public under any name, and PERSONAL is no longer a
// SensitivityLevel (the disclosed source change for that cohort).
import type { SensitivityLevel } from 'shieldcortex/defence';
// @ts-expect-error internal type, never exported
import type { SensitivityTier } from 'shieldcortex/defence';
// @ts-expect-error internal type, never exported
import type { PreciseSensitivityClassification } from 'shieldcortex/defence';
// @ts-expect-error internal type, never exported
import type { PreciseDefencePipelineResult } from 'shieldcortex/defence';
// @ts-expect-error internal type, never exported
import type { PreciseSkillScanResult } from 'shieldcortex/lib';
// @ts-expect-error internal function, never exported
import { classifySensitivityPrecise } from 'shieldcortex/defence';
// @ts-expect-error internal function, never exported
import { runDefencePipelinePrecise } from 'shieldcortex/defence';
// @ts-expect-error internal function, never exported
import { redactForDisplayTier } from 'shieldcortex/defence';
// @ts-expect-error internal function, never exported
import { scanSkillPrecise } from 'shieldcortex/defence';
// @ts-expect-error internal function, never exported
import { toPublicSensitivity } from 'shieldcortex/lib';
// @ts-expect-error internal function, never exported
import { classifySensitivityPrecise as rootPrecise } from 'shieldcortex';
// @ts-expect-error internal function, never exported
import { syncToCloudInternal } from 'shieldcortex/defence';

// The intended break for 5.7+ adopters: a five-key Record no longer compiles.
// @ts-expect-error PERSONAL is not a SensitivityLevel
const five: Record<SensitivityLevel, number> = { PUBLIC: 0, INTERNAL: 1, PERSONAL: 2, CONFIDENTIAL: 3, RESTRICTED: 4 };

// The documented local widening for code that reads stored labels still works.
type StoredLabel = SensitivityLevel | 'PERSONAL';
const stored: StoredLabel = 'PERSONAL';

export const used = [five, stored];
export type Unused = [SensitivityTier, PreciseSensitivityClassification, PreciseDefencePipelineResult, PreciseSkillScanResult,
  typeof classifySensitivityPrecise, typeof runDefencePipelinePrecise, typeof redactForDisplayTier, typeof scanSkillPrecise,
  typeof toPublicSensitivity, typeof rootPrecise, typeof syncToCloudInternal];
