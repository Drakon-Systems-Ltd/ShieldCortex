export type ReviewCopilotSuggestion =
  | 'approve'
  | 'reject'
  | 'keep_quarantined'
  | 'create_rule';

export type ReviewCopilotCategory =
  | 'credential_leak'
  | 'prompt_injection'
  | 'exfiltration_attempt'
  | 'scope_escalation'
  | 'persistence_attempt'
  | 'documentation_or_example'
  | 'benign_log'
  | 'uncertain';

export interface ReviewEvidence {
  snippet: string;
  reason: string;
}

export interface ReviewAnnotation {
  itemId: string;
  category: ReviewCopilotCategory;
  summary: string;
  evidence: ReviewEvidence[];
  suggestedAction: ReviewCopilotSuggestion;
  confidence: number;
  similarGroupKey: string | null;
  reasoning: string;
  copilotVersion: string;
  generatedAt: string;
  synthetic?: boolean;
}

export interface ReviewQuarantineItem {
  id: number | string;
  content: string;
  title?: string | null;
  project?: string | null;
  sourceType?: string | null;
  sourceIdentifier?: string | null;
  reason?: string | null;
  threatIndicators?: string[] | string | null;
  anomalyScore?: number | null;
  firewallResult?: string | null;
  createdAt?: string | null;
}

export interface ReviewBatch {
  key: string;
  category: ReviewCopilotCategory;
  suggestedAction: ReviewCopilotSuggestion;
  count: number;
  itemIds: string[];
  confidenceAvg: number;
  annotations: ReviewAnnotation[];
}

export interface AnnotationRunResult {
  attempted: number;
  annotated: number;
  skipped: number;
  failed: number;
}

export interface ReviewCopilotWorkerRequest {
  id: number;
  type: 'review' | 'load' | 'ping';
  modelId: string;
  cacheDir: string;
  allowRemoteModels: boolean;
  prompt?: string;
  timeoutMs: number;
}

export type ReviewCopilotWorkerResponse =
  | { id: number; ok: true; rawText?: string }
  | { id: number; ok: false; reason: string }
  | { type: 'ready' | 'heartbeat' };
