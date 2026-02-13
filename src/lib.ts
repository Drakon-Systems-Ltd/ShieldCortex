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
  syncToCloud,
  syncQuarantineToCloud,
  getDeviceId,
  getDeviceName,
} from './defence/index.js';

export type {
  DefenceConfig,
  DefenceSource,
  SensitivityLevel,
  FirewallResult,
} from './defence/types.js';

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

// ── Version ────────────────────────────────────────────────
import { createRequire } from 'module';
const require = createRequire(import.meta.url);
const pkg = require('../package.json');
export const version: string = pkg.version;
