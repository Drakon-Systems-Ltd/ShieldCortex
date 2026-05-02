export type LocalAiExplainSubjectKind =
  | 'memory'
  | 'memory_file'
  | 'xray_finding'
  | 'quarantine_item'
  | 'audit_event'
  | 'generic';

export interface LocalAiExplainSubject {
  kind: LocalAiExplainSubjectKind;
  title: string;
  content: string;
  project?: string | null;
  source?: string | null;
  signals?: string[];
  metadata?: Record<string, unknown>;
}

export interface LocalAiEvidence {
  snippet: string;
  reason: string;
}

export interface LocalAiExplanation {
  kind: LocalAiExplainSubjectKind;
  summary: string;
  whyItMatters: string;
  evidence: LocalAiEvidence[];
  nextSteps: string[];
  riskSignals: string[];
  confidence: number;
  modelId: string;
  generatedAt: string;
  synthetic: boolean;
}
