/**
 * Defence layer type definitions
 *
 * Backend-agnostic security types that define the interface for protecting
 * any memory backend, not just the built-in Cortex store.
 */

// ── Classification Enums ──

export type SensitivityLevel = 'PUBLIC' | 'INTERNAL' | 'CONFIDENTIAL' | 'RESTRICTED';

export type FirewallResult = 'ALLOW' | 'BLOCK' | 'QUARANTINE';

export type ThreatIndicator =
  | 'instruction_injection'
  | 'privilege_escalation'
  | 'credential_exfil'
  | 'encoding_obfuscation'
  | 'credential_leak'
  | 'external_url'
  | 'fragmented_payload'
  | 'restricted_content'
  | 'pipeline_error'
  | 'semantic_similarity'
  | 'custom_rule'
  | 'custom_pattern'
  | 'builtin_rule';

// ── Core Interfaces ──

export interface DefenceSource {
  type: 'user' | 'cli' | 'hook' | 'email' | 'web' | 'agent' | 'file' | 'api' | 'tool_response';
  identifier: string;
}

export interface ToolResponseScanResult {
  clean: boolean;
  mode: 'advisory' | 'enforce';
  toolName: string;
  injection: import('./iron-dome/injection-scanner.js').InjectionScanResult;
  credentials: import('./credential-leak/index.js').CredentialScanResult;
  threatIndicators: ThreatIndicator[];
  summary: string;
  durationMs: number;
  auditId: number;
  /**
   * Enforce-mode replacement content the agent should actually receive.
   * `null` in advisory mode and whenever the response is clean (nothing to do).
   */
  sanitisedContent: string | null;
  /** True when enforce mode withheld the whole payload (vs. surgically redacting). */
  blocked: boolean;
  /** Human-readable actions taken in enforce mode (empty otherwise). */
  enforceActions: string[];
}

export interface FirewallAnalysis {
  result: FirewallResult;
  reason: string;
  threatIndicators: ThreatIndicator[];
  anomalyScore: number;
  blockedPatterns: string[];
}

export interface FragmentationAnalysis {
  score: number; // 0-1, risk of fragmented payload assembly
  relatedMemoryIds: number[];
  suspiciousEntities: string[];
  assemblyRisk: string;
}

export interface SensitivityClassification {
  level: SensitivityLevel;
  confidence: number;
  detectedPatterns: string[];
  redactionRequired: boolean;
}

export interface TrustScore {
  score: number;
  source: DefenceSource;
  hierarchy: string[];
}

export interface DefencePipelineResult {
  allowed: boolean;
  firewall: FirewallAnalysis;
  fragmentation: FragmentationAnalysis | null;
  sensitivity: SensitivityClassification;
  trust: TrustScore;
  credentialScan?: import('./credential-leak/index.js').CredentialScanResult;
  auditId: number;
}

// ── Configuration ──

export interface DefenceConfig {
  mode: 'strict' | 'balanced' | 'permissive';
  enableFragmentationDetection: boolean;
  fragmentationWindowHours: number;
  trustThresholdForActions: number;
  autoQuarantineThreshold: number;
  flagThreshold: number;
  /** When true, unknown/undetected sources get trust 0.3 instead of 0.5, and all writes are auto-quarantined */
  strictSourceMode: boolean;
}

export const DEFAULT_DEFENCE_CONFIG: DefenceConfig = {
  mode: 'balanced',
  enableFragmentationDetection: true,
  fragmentationWindowHours: 24,
  trustThresholdForActions: 0.7,
  autoQuarantineThreshold: 0.3,
  flagThreshold: 0.5,
  strictSourceMode: false,
};

// ── LLM Verification Types ──

export interface VerifyThreat {
  type: string;
  description: string;
  severity: string;
}

export interface VerifyResult {
  id: number;
  verdict?: string;
  confidence?: number;
  threats_detected?: VerifyThreat[];
  action?: string;
  cached?: boolean;
  duration_ms?: number;
  status: string;
}

export interface DefencePipelineResultWithVerify extends DefencePipelineResult {
  verification?: {
    id: number;
    status: 'pending' | 'completed' | 'failed' | 'skipped';
    verdict?: string;
    confidence?: number;
    threats_detected?: VerifyThreat[];
    action?: string;
    mode: 'advisory' | 'enforce';
    originalFirewallResult?: FirewallResult;
  };
  /**
   * Result of the async-path semantic-similarity layer (embedding vs curated
   * attack corpus). Present only when the embedding model was available; absent
   * when it degraded. For observability — the verdict escalation it may trigger
   * is reflected in `firewall`.
   */
  semanticSimilarity?: {
    maxSimilarity: number;
    matchedPhrase?: string;
  };
}

// ── Database Row Interfaces ──

export interface QuarantineEntry {
  id: number;
  original_content: string;
  original_title: string | null;
  source_type: string;
  source_identifier: string;
  reason: string;
  threat_indicators: string; // JSON array
  anomaly_score: number;
  firewall_result: 'BLOCK' | 'QUARANTINE';
  status: 'pending' | 'approved' | 'rejected' | 'expired';
  reviewed_at: string | null;
  reviewed_by: string | null;
  created_at: string;
  expires_at: string | null;
  audit_id: number | null;
}

/** Operation that produced an audit row (provenance ledger discriminator). */
export type AuditOperation = 'write' | 'read' | 'delete' | 'update' | 'revoke';

export interface AuditEntry {
  id: number;
  memory_id: number | null;
  project: string | null;
  timestamp: string;
  source_type: string;
  source_identifier: string;
  trust_score: number;
  sensitivity_level: string;
  firewall_result: FirewallResult;
  /**
   * The operation that produced this row. Required on every new emission so the
   * ledger is queryable by read/write/delete; `null` only on legacy rows written
   * before the provenance-ledger column existed.
   */
  operation: AuditOperation | null;
  /** SHA-256 of the content at write time (tamper-evidence); null for read/delete rows. */
  content_hash?: string | null;
  anomaly_score: number;
  threat_indicators: string; // JSON array
  blocked_patterns: string; // JSON array
  reason: string | null;
  fragmentation_score: number | null;
  /**
   * Threat-graph Phase B: 1 = the source identity was system-derived
   * (env-inferred, clamped, or env-confirmed) or the deployment runs
   * strictSourceMode; 0 = accepted self-declaration; NULL/omitted = legacy
   * row or a caller that has not plumbed attestation.
   */
  source_attested?: number | null;
  /** Threat-graph Phase B: advisory trust modifier computed for this scan. */
  risk_modifier?: number | null;
  pipeline_duration_ms: number | null;
}
