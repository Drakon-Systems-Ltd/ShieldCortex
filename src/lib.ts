/**
 * ShieldCortex — Library Entry Point
 *
 * Safe to import without side effects. No MCP server started,
 * no workers spawned, no stdin consumed.
 *
 * Usage:
 *   import { runDefencePipeline, scanSkill, addMemory } from 'shieldcortex';
 *   import { runDefencePipeline } from 'shieldcortex/defence';
 */

// ── Defence ────────────────────────────────────────────────
export {
  runDefencePipeline,
  runDefencePipelineWithVerify,
  DEFAULT_DEFENCE_CONFIG,
  scoreSource,
  filterByTrust,
  analyzeFirewall,
  classifySensitivity,
  redactContent,
  redactForDisplay,
  analyzeFragmentation,
  storeFragmentationData,
  scanForCredentials,
  redactCredentials,
  DEFAULT_CREDENTIAL_CONFIG,
  logAudit,
  queryAuditLogs,
  getAuditStats,
  getDefenceMode,
  setDefenceMode,
  isConfigTampered,
  getCloudConfig,
  setCloudConfig,
  clearCloudConfigCache,
  getOpenClawAutoMemory,
  setOpenClawAutoMemory,
  getOpenClawMemoryConfig,
  setOpenClawMemoryConfig,
  getVerifyConfig,
  setVerifyConfig,
  syncToCloud,
  syncQuarantineToCloud,
  submitVerification,
  pollVerification,
  getDeviceId,
  getDeviceName,
} from './defence/index.js';

export type {
  DefenceConfig,
  DefencePipelineResultWithVerify,
  DefenceSource,
  SensitivityLevel,
  FirewallResult,
  VerifyResult,
  VerifyThreat,
} from './defence/types.js';
export type { VerifyConfig } from './cloud/config.js';

// ── Tool Response Scanner ─────────────────────────────────
export { scanToolResponse, shouldScanToolResponse } from './defence/tool-response-scanner.js';
export type { ToolResponseScanResult } from './defence/types.js';

// ── Iron Dome ─────────────────────────────────────────────
export {
  activateIronDome,
  deactivateIronDome,
  getIronDomeStatus,
  isChannelTrusted,
  isActionAllowed,
  scanForInjection,
  checkPII,
  handleKillPhrase,
  IRON_DOME_PROFILES,
  DEFAULT_IRON_DOME_CONFIG,
} from './defence/iron-dome/index.js';

export type {
  IronDomeConfig,
  IronDomeProfile,
  InjectionScanResult,
  InjectionDetection,
  GatewayResult,
  ActionGateResult,
  PiiCheckResult,
  KillSwitchResult,
} from './defence/iron-dome/index.js';

// ── Skill Scanner ──────────────────────────────────────────
export {
  scanSkill,
  scanSkillContent,
  discoverSkillFiles,
  readSkillFile,
  parseSkillFile,
  detectFormat,
  detectFormatFromContent,
} from './defence/skill-scanner/index.js';

// ── Memory ─────────────────────────────────────────────────
export {
  addMemory,
  getMemoryById,
  updateMemory,
  deleteMemory,
  accessMemory,
  reinforceFromSearch,
  MemoryPausedError,
  MemoryBlockedError,
} from './memory/store.js';

export type { Memory, MemoryType, MemoryCategory } from './memory/types.js';

// ── Memory Intelligence ────────────────────────────────────
export { calculateDecayedScore, processDecay, calculatePriority } from './memory/decay.js';
export { calculateSalience } from './memory/salience.js';
export { jaccardSimilarity, hasSignificantOverlap, wordOverlap } from './memory/similarity.js';
export { consolidate, mergeSimilarMemories, exportMemories, importMemories } from './memory/consolidate.js';
export { detectContradictions } from './memory/contradiction.js';
export { activateMemory, getActivationBoost, getActivationLevel, getActiveMemories } from './memory/activation.js';

// ── Integrations ────────────────────────────────────────────
export {
  ShieldCortexMemory,
  ShieldCortexGuard,
  ShieldCortexGuardedMemoryBridge,
  MarkdownMemoryBackend,
  OpenClawMarkdownBackend,
} from './integrations/index.js';

export type {
  ShieldCortexMemoryConfig,
  ShieldCortexGuardConfig,
  ExternalMemoryBackend,
  ExternalMemoryRecord,
  GuardedMemoryBridgeConfig,
  GuardedSaveResult,
  GuardedSearchResult,
} from './integrations/index.js';

// ── Knowledge Graph ────────────────────────────────────────
export { extractFromMemory } from './graph/extract.js';
export { processExtractionResult, mergeEntities } from './graph/resolve.js';
export { backfillGraph } from './graph/backfill.js';

// ── Database ───────────────────────────────────────────────
export { initDatabase } from './database/init.js';

// ── Audit ──────────────────────────────────────────────────
export { scanMemories, scanMcpConfigs, scanEnvFiles, scanRulesFiles } from './audit/index.js';
export { formatTerminalReport, formatMarkdownReport, formatJsonReport } from './audit/index.js';
export type { AuditFinding, AuditSeverity } from './audit/types.js';

// ── License ────────────────────────────────────────────────
export {
  getLicense,
  getLicenseTier,
  isFeatureEnabled,
  requireFeature,
  listFeatures,
  FeatureGatedError,
  verifyLicenseKey,
  TIER_RANK,
} from './license/index.js';

export type {
  LicenseTier,
  LicenseInfo,
  GatedFeature,
} from './license/index.js';

// ── Version ────────────────────────────────────────────────
import { createRequire } from 'module';
const require = createRequire(import.meta.url);
const pkg = require('../package.json');
export const version: string = pkg.version;
