'use client';

import { useMutation, useQuery } from '@tanstack/react-query';
import { authFetch, gatedFetch, readApiError } from '@/lib/auth';

const API_BASE = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:3001';

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

export interface LocalAiStatus {
  enabled: boolean;
  featureEnabled: boolean;
  modelId: string;
  modelCacheDir: string;
  modelCached: boolean;
  telemetryPath: string;
  inferenceTimeoutMs: number;
  workerHeapMB: number;
  recentTelemetry: Array<Record<string, unknown>>;
}

export interface LocalAiExplainResponse {
  success: boolean;
  explanation: LocalAiExplanation;
}

async function fetchLocalAiStatus(): Promise<LocalAiStatus> {
  const response = await authFetch(`${API_BASE}/api/v1/local-ai/status`);
  if (!response.ok) throw new Error(await readApiError(response, 'Failed to fetch Local AI status'));
  return response.json();
}

async function explainSubject(subject: LocalAiExplainSubject): Promise<LocalAiExplainResponse> {
  const response = await gatedFetch(`${API_BASE}/api/v1/local-ai/explain`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(subject),
  });
  if (!response.ok) throw new Error(await readApiError(response, 'Failed to generate local explanation'));
  return response.json();
}

export function useLocalAiExplainerStatus() {
  return useQuery({
    queryKey: ['local-ai-explainer-status'],
    queryFn: fetchLocalAiStatus,
    refetchInterval: 30000,
    retry: 2,
  });
}

export function useLocalAiExplain() {
  return useMutation({
    mutationFn: explainSubject,
  });
}
