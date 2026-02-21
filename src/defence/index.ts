/**
 * Defence layer — top-level re-exports
 */

// Pipeline
export { runDefencePipeline, runDefencePipelineWithVerify } from './pipeline.js';

// Config & types
export { DEFAULT_DEFENCE_CONFIG } from './types.js';
export type {
  DefenceConfig,
  DefencePipelineResult,
  DefencePipelineResultWithVerify,
  DefenceSource,
  FirewallAnalysis,
  FirewallResult,
  FragmentationAnalysis,
  SensitivityClassification,
  SensitivityLevel,
  ThreatIndicator,
  TrustScore,
  VerifyResult,
  VerifyThreat,
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

// Credential Leak Detection (Layer 6)
export { scanForCredentials, redactCredentials, DEFAULT_CREDENTIAL_CONFIG } from './credential-leak/index.js';
export type { CredentialScanResult, CredentialFinding, CredentialDetectionConfig, CredentialType, CredentialSeverity } from './credential-leak/index.js';

// Audit
export { logAudit, queryAuditLogs, getAuditStats } from './audit/index.js';

// Skill Scanner
export { scanSkill, scanSkillContent, discoverSkillFiles, detectFormat, detectFormatFromContent, parseSkillFile, readSkillFile } from './skill-scanner/index.js';
export type { SkillScanResult, SkillScanOptions, SkillThreatFinding, ParsedSkill, SkillFormat } from './skill-scanner/index.js';

// Cloud
export { getCloudConfig, setCloudConfig, clearCloudConfigCache, getTrustedSkills, addTrustedSkill, removeTrustedSkill, getDeviceId, getDeviceName, getDefenceMode, setDefenceMode, isConfigTampered, getVerifyConfig, setVerifyConfig } from '../cloud/config.js';
export type { CloudConfig, DefenceMode, VerifyConfig } from '../cloud/config.js';
export { syncToCloud } from '../cloud/sync.js';
export { syncQuarantineToCloud } from '../cloud/quarantine-sync.js';
export { submitVerification, pollVerification } from '../cloud/verify.js';
