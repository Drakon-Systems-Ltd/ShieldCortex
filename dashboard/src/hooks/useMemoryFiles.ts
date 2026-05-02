'use client';

import { useMutation, useQueryClient } from '@tanstack/react-query';
import { gatedFetch, readApiError } from '@/lib/auth';

const API_BASE = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:3001';

export type MemoryFileRisk = 'SAFE' | 'LOW' | 'MEDIUM' | 'HIGH' | 'CRITICAL';
export type MemoryFileFirewallResult = 'ALLOW' | 'QUARANTINE' | 'BLOCK';

export interface MemoryFileEvidence {
  snippet: string;
  reason: string;
}

export interface MemoryFileAuditFinding {
  scanner: string;
  severity: 'info' | 'low' | 'medium' | 'high' | 'critical';
  title: string;
  description: string;
  filePath?: string;
  matchedText?: string;
  learnMoreUrl?: string;
}

export interface MemoryFileScanRecord {
  id: string;
  path: string;
  source: string;
  sizeBytes: number;
  modifiedAt: string | null;
  contentExcerpt: string;
  auditId: number | null;
  anomalyScore: number;
  firewallResult: MemoryFileFirewallResult;
  risk: MemoryFileRisk;
  reason: string;
  threatIndicators: string[];
  evidence: MemoryFileEvidence[];
  findings: MemoryFileAuditFinding[];
}

export interface MemoryFileScanSummary {
  total: number;
  safe: number;
  flagged: number;
  critical: number;
  high: number;
  medium: number;
}

export interface MemoryFileQuarantineQueueItem {
  fileId: string;
  path: string;
  quarantineId: number | null;
  status: 'created' | 'updated' | 'skipped_safe' | 'skipped_reviewed';
}

export interface MemoryFileQuarantineQueueResult {
  created: number;
  updated: number;
  skippedSafe: number;
  skippedReviewed: number;
  items: MemoryFileQuarantineQueueItem[];
}

export interface MemoryFileScanResponse {
  success: boolean;
  scannedAt: string;
  summary: MemoryFileScanSummary;
  quarantine: MemoryFileQuarantineQueueResult;
  files: MemoryFileScanRecord[];
}

async function scanMemoryFiles(): Promise<MemoryFileScanResponse> {
  const response = await gatedFetch(`${API_BASE}/api/v1/memory-files/scan`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
  });
  if (!response.ok) throw new Error(await readApiError(response, 'Failed to scan memory files'));
  return response.json();
}

export function useMemoryFileScan() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: scanMemoryFiles,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['quarantine'] });
      queryClient.invalidateQueries({ queryKey: ['audit-stats'] });
      queryClient.invalidateQueries({ queryKey: ['audit-logs'] });
    },
  });
}
