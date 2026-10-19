// An unchanged 5.6.0 consumer. Compiled by run-compat.mjs against the BUILT
// package declarations through `node_modules/shieldcortex` and its `exports`
// map only (no src, no paths). Must pass on 5.6.0 and on this patch; fails on
// 5.7.0–5.10.5, whose exported SensitivityLevel carried PERSONAL.
import type { SensitivityLevel as RootLevel } from 'shieldcortex';
import { classifySensitivity as rootClassify, scanSkillContent as rootScanSkillContent } from 'shieldcortex';
import type { SensitivityLevel as LibLevel, DefencePipelineResultWithVerify } from 'shieldcortex/lib';
import { redactForDisplay as libRedact, scanSkillContent as libScanSkillContent, ShieldCortexGuard as LibGuard } from 'shieldcortex/lib';
import type { SensitivityLevel, SensitivityClassification, SkillScanResult } from 'shieldcortex/defence';
import { classifySensitivity, redactForDisplay, runDefencePipeline, runDefencePipelineWithVerify } from 'shieldcortex/defence';
import type { DefencePipelineResult as ScanResult } from 'shieldcortex/scan';
import { scan, scanText } from 'shieldcortex/scan';
import { ShieldCortexGuard, ShieldCortexGuardedMemoryBridge as IntBridge } from 'shieldcortex/integrations';
import type { GuardedSaveResult as IntSave } from 'shieldcortex/integrations';
import { ShieldCortexGuard as LcGuard } from 'shieldcortex/integrations/langchain';
import type { GuardedSaveResult, ShieldCortexGuardedMemoryBridge } from 'shieldcortex/integrations/universal';

type Equals<A, B> = (<T>() => T extends A ? 1 : 2) extends (<T>() => T extends B ? 1 : 2) ? true : false;
type Assert<T extends true> = T;
type Four = 'PUBLIC' | 'INTERNAL' | 'CONFIDENTIAL' | 'RESTRICTED';

const r1: Record<RootLevel, string> = { PUBLIC: 'a', INTERNAL: 'b', CONFIDENTIAL: 'c', RESTRICTED: 'd' };
const r2: Record<LibLevel, string> = { PUBLIC: 'a', INTERNAL: 'b', CONFIDENTIAL: 'c', RESTRICTED: 'd' };
const r3: Record<SensitivityLevel, string> = { PUBLIC: 'a', INTERNAL: 'b', CONFIDENTIAL: 'c', RESTRICTED: 'd' };
const all: SensitivityLevel[] = ['PUBLIC', 'INTERNAL', 'CONFIDENTIAL', 'RESTRICTED'];

export function label(l: SensitivityLevel): string {
  switch (l) {
    case 'PUBLIC': return 'p';
    case 'INTERNAL': return 'i';
    case 'CONFIDENTIAL': return 'c';
    case 'RESTRICTED': return 'r';
    default: { const n: never = l; return n; }
  }
}

// Reviewer B2(1): keyof of the classification is exactly the four 5.6.0 keys.
const k1: Record<keyof SensitivityClassification, string> = { level: '', confidence: '', detectedPatterns: '', redactionRequired: '' };
const k2: Record<keyof ReturnType<typeof classifySensitivity>, string> = { level: '', confidence: '', detectedPatterns: '', redactionRequired: '' };
const k3: Record<keyof ReturnType<typeof rootClassify>, string> = { level: '', confidence: '', detectedPatterns: '', redactionRequired: '' };
// Reviewer B2(2): the redactForDisplay level parameter is the four-value union.
const p1: Record<Parameters<typeof redactForDisplay>[1], string> = { PUBLIC: 'a', INTERNAL: 'b', CONFIDENTIAL: 'c', RESTRICTED: 'd' };
const p2: Record<Parameters<typeof libRedact>[1], string> = { PUBLIC: 'a', INTERNAL: 'b', CONFIDENTIAL: 'c', RESTRICTED: 'd' };

// Every public result path's level.
type L1 = ReturnType<typeof runDefencePipeline>['sensitivity']['level'];
type L2 = Awaited<ReturnType<typeof runDefencePipelineWithVerify>>['sensitivity']['level'];
type L3 = DefencePipelineResultWithVerify['sensitivity']['level'];
type L4 = ScanResult['sensitivity']['level'];
type L5 = ReturnType<typeof scan>['sensitivity']['level'];
type L6 = ReturnType<typeof scanText>['sensitivity']['level'];
type L7 = SkillScanResult['sensitivity']['level'];
type L8 = ReturnType<typeof libScanSkillContent>['sensitivity']['level'];
type L9 = ReturnType<typeof rootScanSkillContent>['sensitivity']['level'];
type L10 = ReturnType<ShieldCortexGuard['scan']>['sensitivity']['level'];
type L11 = ReturnType<LcGuard['scan']>['sensitivity']['level'];
type L12 = ReturnType<LibGuard['scan']>['sensitivity']['level'];
type L13 = GuardedSaveResult['defence']['sensitivity']['level'];
type L14 = IntSave['defence']['sensitivity']['level'];
type L15 = Awaited<ReturnType<ShieldCortexGuardedMemoryBridge['save']>>['defence']['sensitivity']['level'];
type L16 = Awaited<ReturnType<IntBridge['save']>>['defence']['sensitivity']['level'];
const rec1: Record<L1, 0> = { PUBLIC: 0, INTERNAL: 0, CONFIDENTIAL: 0, RESTRICTED: 0 };
const rec2: Record<L2, 0> = { PUBLIC: 0, INTERNAL: 0, CONFIDENTIAL: 0, RESTRICTED: 0 };
const rec3: Record<L3, 0> = { PUBLIC: 0, INTERNAL: 0, CONFIDENTIAL: 0, RESTRICTED: 0 };
const rec4: Record<L4, 0> = { PUBLIC: 0, INTERNAL: 0, CONFIDENTIAL: 0, RESTRICTED: 0 };
const rec5: Record<L5, 0> = { PUBLIC: 0, INTERNAL: 0, CONFIDENTIAL: 0, RESTRICTED: 0 };
const rec6: Record<L6, 0> = { PUBLIC: 0, INTERNAL: 0, CONFIDENTIAL: 0, RESTRICTED: 0 };
const rec7: Record<L7, 0> = { PUBLIC: 0, INTERNAL: 0, CONFIDENTIAL: 0, RESTRICTED: 0 };
const rec8: Record<L8, 0> = { PUBLIC: 0, INTERNAL: 0, CONFIDENTIAL: 0, RESTRICTED: 0 };
const rec9: Record<L9, 0> = { PUBLIC: 0, INTERNAL: 0, CONFIDENTIAL: 0, RESTRICTED: 0 };
const rec10: Record<L10, 0> = { PUBLIC: 0, INTERNAL: 0, CONFIDENTIAL: 0, RESTRICTED: 0 };
const rec11: Record<L11, 0> = { PUBLIC: 0, INTERNAL: 0, CONFIDENTIAL: 0, RESTRICTED: 0 };
const rec12: Record<L12, 0> = { PUBLIC: 0, INTERNAL: 0, CONFIDENTIAL: 0, RESTRICTED: 0 };
const rec13: Record<L13, 0> = { PUBLIC: 0, INTERNAL: 0, CONFIDENTIAL: 0, RESTRICTED: 0 };
const rec14: Record<L14, 0> = { PUBLIC: 0, INTERNAL: 0, CONFIDENTIAL: 0, RESTRICTED: 0 };
const rec15: Record<L15, 0> = { PUBLIC: 0, INTERNAL: 0, CONFIDENTIAL: 0, RESTRICTED: 0 };
const rec16: Record<L16, 0> = { PUBLIC: 0, INTERNAL: 0, CONFIDENTIAL: 0, RESTRICTED: 0 };

// Excess-property check on a hand-built classification.
const c: SensitivityClassification = { level: 'PUBLIC', confidence: 1, detectedPatterns: [], redactionRequired: false };
export const shown = redactForDisplay('x', c.level);

export type Checks = [
  Assert<Equals<SensitivityLevel, Four>>,
  Assert<Equals<RootLevel, Four>>,
  Assert<Equals<LibLevel, Four>>,
  Assert<Equals<keyof SensitivityClassification, 'level' | 'confidence' | 'detectedPatterns' | 'redactionRequired'>>,
  Assert<Equals<Parameters<typeof redactForDisplay>, [content: string, level: Four]>>,
];

export const used = [r1, r2, r3, all, k1, k2, k3, p1, p2, rec1, rec2, rec3, rec4, rec5, rec6, rec7, rec8,
  rec9, rec10, rec11, rec12, rec13, rec14, rec15, rec16];
