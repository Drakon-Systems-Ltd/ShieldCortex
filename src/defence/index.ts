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

// Input Sanitisation (Layer 1)
export { sanitiseInput } from './input-sanitisation/index.js';
export type { SanitisationResult, SanitisationCategory } from './input-sanitisation/index.js';

// Trust
export { scoreSource, filterByTrust } from './trust/index.js';

// Firewall
export { analyzeFirewall } from './firewall/index.js';

// Sensitivity
export { classifySensitivity, redactContent, redactForDisplay } from './sensitivity/index.js';

// Fragmentation
export { analyzeFragmentation, storeFragmentationData } from './fragmentation/index.js';

// Semantic Analysis (Layer 3 — async/deep-scan path only; degrades gracefully)
export { analyzeSemanticSimilarity, SEMANTIC_SIMILARITY_THRESHOLD } from './semantic/index.js';
export type { SemanticAnalysisResult, Embedder } from './semantic/index.js';
export { ATTACK_CORPUS } from './semantic/attack-corpus.js';

// Credential Leak Detection (Layer 6)
export { scanForCredentials, redactCredentials, DEFAULT_CREDENTIAL_CONFIG } from './credential-leak/index.js';
export type { CredentialScanResult, CredentialFinding, CredentialDetectionConfig, CredentialType, CredentialSeverity } from './credential-leak/index.js';

// Audit
export { logAudit, queryAuditLogs, getAuditStats } from './audit/index.js';

// Skill Scanner
export { scanSkill, scanSkillContent, discoverSkillFiles, detectFormat, detectFormatFromContent, parseSkillFile, readSkillFile } from './skill-scanner/index.js';
export type { SkillScanResult, SkillScanOptions, SkillThreatFinding, ParsedSkill, SkillFormat } from './skill-scanner/index.js';

// Tool Response Scanner (read-path scan; pure, no DB handle required —
// the audit write is guarded by isDatabaseInitialized()). Exposed here so the
// OpenClaw realtime plugin can scan in-process instead of shelling out to the
// MCP server per message.
export { scanToolResponse, shouldScanToolResponse } from './tool-response-scanner.js';
export type { ToolResponseScanResult } from './types.js';

// Iron Dome — Behaviour Protection Layer
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
} from './iron-dome/index.js';
// Tool Action Guard — gates what the agent DOES at runtime (shell/file/network/git).
export { evaluateToolCall, classifyFamily, isCriticalPath, normaliseToolName, detectScriptInvocation } from './iron-dome/tool-action-guard.js';
export type { ToolGuardVerdict, ToolGuardDecision, ToolGuardSeverity, ToolFamily, ToolGuardOptions } from './iron-dome/tool-action-guard.js';
export {
  sessionKeyFor,
  sessionKeySalt,
  appendSessionGuardIndex,
  recordActionGuardDegraded,
  GUARD_DEGRADED_OUTCOMES,
  isGuardIndexOrigin,
  isSummaryOrigin,
} from './iron-dome/session-guard.js';
export {
  REQUIRED_BINDING_FIELDS,
  hasRequiredBinding,
  attachEnforcementBinding,
  actionKeyForToolCall,
  nextAuditSeq,
  resolveInstanceId,
  bindRuntimeInspectPayload,
} from './iron-dome/enforcement-binding.js';
export type { EnforcementPlane, EnforcementBinding, BindingContext } from './iron-dome/enforcement-binding.js';
// Session action lease (#227) — the freeze that binds every self, not just the
// careful one. Pure core + fs layer exported through the same runtime seam as
// `evaluateToolCall` so both enforcement planes reach ONE implementation.
export { checkSessionLease, leasePermits, scopeForToolCall, findFreeze, SCOPE_KEYWORDS, DEFAULT_LEASE_TTL_MS } from './iron-dome/session-lease.js';
export type { LeaseScope, LeaseRecord, LeaseDecision, LeaseVerdict, LeaseCheckInput } from './iron-dome/session-lease.js';
export { evaluateToolCallLease, releaseToolCallLease, acquireOrRefreshLease, releaseLease, listLeases, readDecisionsLedger, decisionsLedgerPath, resolveStateDir } from './iron-dome/session-lease-store.js';
export type { LeaseGateResult, LeaseGateOptions } from './iron-dome/session-lease-store.js';
// AI-assisted approval broker (#143) — the decision core, the judge layer and
// their config. Exported so a host transport (the OpenClaw plugin, the Claude
// Code hook) can reach them at runtime without importing the package at compile
// time, the same seam `evaluateToolCall` already uses.
export { brokerDecision, timeoutOutcome, isPreClearable, PRE_CLEARABLE_SIGNALS, DEFAULT_BROKER_POLICY } from './iron-dome/approval-broker.js';
export type { BrokerInput, BrokerDecision, BrokerOutcome, BrokerAudit, BrokerPolicy, BrokerVerdictLike, JudgeResult, JudgeUnavailableReason } from './iron-dome/approval-broker.js';
export { runJudge, runJudgeDetailed, buildJudgePrompt, parseJudgeResponse, JUDGE_SYSTEM_PROMPT } from './iron-dome/approval-judge.js';
export type { JudgeRequest, JudgeRunResult, JudgeFailureReason, ModelInvoker, RunJudgeOptions } from './iron-dome/approval-judge.js';
export { normaliseBrokerConfig, normaliseBrokerModel, toBrokerPolicy, approvalTimeoutMs, DEFAULT_BROKER_CONFIG } from './iron-dome/broker-config.js';
export type { BrokerConfig, BrokerGatedSeverity } from './iron-dome/broker-config.js';
export { createCliInvoker } from './iron-dome/cli-invoker.js';
export type { CliInvokerOptions, SpawnLike } from './iron-dome/cli-invoker.js';
export type {
  IronDomeConfig,
  IronDomeProfile,
  InjectionScanResult,
  InjectionDetection,
  InjectionSeverity,
  InjectionCategory,
  GatewayResult,
  ActionGateResult,
  ActionDecision,
  PiiCheckResult,
  PiiViolation,
  KillSwitchResult,
} from './iron-dome/index.js';

// Cloud
export { getCloudConfig, setCloudConfig, clearCloudConfigCache, getTrustedSkills, addTrustedSkill, removeTrustedSkill, getDeviceId, getDeviceName, getDefenceMode, setDefenceMode, isConfigTampered, getVerifyConfig, setVerifyConfig, getOpenClawAutoMemory, setOpenClawAutoMemory, getOpenClawMemoryConfig, setOpenClawMemoryConfig } from '../cloud/config.js';
export type { CloudConfig, DefenceMode, VerifyConfig, OpenClawMemoryConfig } from '../cloud/config.js';
export { syncToCloud } from '../cloud/sync.js';
export { syncQuarantineToCloud } from '../cloud/quarantine-sync.js';
export { submitVerification, pollVerification } from '../cloud/verify.js';

// Operator notification (#143 transport, reused by the #225 conversation sink).
// Exported from the barrel so the OpenClaw plugin — which builds across a
// package boundary and can only reach us through `shieldcortex/defence` — can
// route a conversation-threat detection to a human instead of a log file.
// It gets the BUILDER and the DELIVERY CORE, not just the pieces: a caller that
// has to assemble its own notification object is a caller that can assemble a
// malformed one, which is precisely how the first cut of #225 ended up casting
// an ad-hoc `{kind, ...}` literal through `NotifyChannel.send`.
export { normaliseNotifyConfig, normaliseWebhookUrl } from './iron-dome/notify-config.js';
export type { NotifyConfig } from './iron-dome/notify-config.js';
export { createWebhookNotifyChannel } from './iron-dome/webhook-notify-channel.js';
export {
  formatOperatorNotification,
  formatConversationThreatNotification,
  buildConversationThreatNotification,
  deliverOperatorNotification,
  isConversationThreatNotification,
} from './iron-dome/operator-notify.js';
export type {
  OperatorNotification,
  ConversationThreatNotification,
  ConversationThreatOutcome,
  AnyOperatorNotification,
  NotifyChannel,
  ChannelSendResult,
} from './iron-dome/operator-notify.js';
