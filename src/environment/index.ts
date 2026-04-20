export { scanUrl } from './scanner.js';
export { scoreProvenance } from './provenance.js';
export { analyseHidden } from './hidden-detector.js';
export { deriveTaint } from './taint.js';
export { formatEnvScanReport, formatEnvScanMarkdown } from './report.js';
export type {
  EnvironmentScanResult,
  ProvenanceResult,
  ProvenanceSignals,
  HiddenAnalysis,
  HiddenInstructionHit,
  InjectionHit,
  TaintLabel,
} from './types.js';
