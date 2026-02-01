/**
 * Defence layer — top-level re-exports
 */

// Pipeline
export { runDefencePipeline } from './pipeline.js';

// Config & types
export { DEFAULT_DEFENCE_CONFIG } from './types.js';
export type {
  DefenceConfig,
  DefencePipelineResult,
  DefenceSource,
  FirewallAnalysis,
  FirewallResult,
  FragmentationAnalysis,
  SensitivityClassification,
  SensitivityLevel,
  ThreatIndicator,
  TrustScore,
  QuarantineEntry,
  AuditEntry,
} from './types.js';

// Trust
export { scoreSource, filterByTrust } from './trust/index.js';

// Firewall
export { analyzeFirewall } from './firewall/index.js';

// Sensitivity
export { classifySensitivity, redactContent, redactForDisplay } from './sensitivity/index.js';

// Fragmentation
export { analyzeFragmentation, storeFragmentationData } from './fragmentation/index.js';

// Audit
export { logAudit, queryAuditLogs, getAuditStats } from './audit/index.js';
