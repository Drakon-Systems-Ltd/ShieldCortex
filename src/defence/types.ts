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
  | 'encoding_obfuscation'
  | 'credential_leak'
  | 'external_url'
  | 'fragmented_payload'
  | 'pipeline_error';

// ── Core Interfaces ──

export interface DefenceSource {
  type: 'user' | 'cli' | 'hook' | 'email' | 'web' | 'agent' | 'file' | 'api';
  identifier: string;
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
  anomaly_score: number;
  threat_indicators: string; // JSON array
  blocked_patterns: string; // JSON array
  reason: string | null;
  fragmentation_score: number | null;
  pipeline_duration_ms: number | null;
}
