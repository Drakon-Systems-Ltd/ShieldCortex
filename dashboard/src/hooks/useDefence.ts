'use client';

import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { authFetch, readApiError } from '@/lib/auth';

const API_BASE = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:3001';

// ── Types ──

export interface AuditEntry {
  id: number;
  memory_id: number | null;
  project: string | null;
  timestamp: string;
  source_type: string;
  source_identifier: string;
  trust_score: number;
  sensitivity_level: string;
  firewall_result: 'ALLOW' | 'BLOCK' | 'QUARANTINE';
  anomaly_score: number;
  threat_indicators: string; // JSON array
  blocked_patterns: string; // JSON array
  reason: string | null;
  fragmentation_score: number | null;
  pipeline_duration_ms: number | null;
}

export interface AuditStats {
  totalOperations: number;
  allowedCount: number;
  blockedCount: number;
  quarantinedCount: number;
  topSources: { source: string; count: number }[];
  threatBreakdown: Record<string, number>;
}

export interface QuarantineItem {
  id: number;
  title: string;
  content: string;
  source_type: string;
  source_identifier: string;
  reason: string;
  threat_indicators: string; // JSON array
  anomaly_score: number;
  status: 'pending' | 'approved' | 'rejected';
  created_at: string;
  reviewed_at: string | null;
  reviewed_by: string | null;
}

// ── Fetch Functions ──

async function fetchAuditLogs(options?: {
  startTime?: string;
  endTime?: string;
  source?: string;
  firewallResult?: string;
  project?: string;
  limit?: number;
}): Promise<{ logs: AuditEntry[]; total: number }> {
  const params = new URLSearchParams();
  if (options?.startTime) params.set('startTime', options.startTime);
  if (options?.endTime) params.set('endTime', options.endTime);
  if (options?.source) params.set('source', options.source);
  if (options?.firewallResult) params.set('firewallResult', options.firewallResult);
  if (options?.project) params.set('project', options.project);
  if (options?.limit) params.set('limit', options.limit.toString());

  const response = await authFetch(`${API_BASE}/api/v1/audit?${params}`);
  if (!response.ok) throw new Error(await readApiError(response, 'Failed to fetch audit logs'));
  return response.json();
}

async function fetchAuditStats(timeRange: '24h' | '7d' | '30d', project?: string): Promise<AuditStats> {
  const params = new URLSearchParams({ timeRange });
  if (project) params.set('project', project);
  const response = await authFetch(`${API_BASE}/api/v1/audit/stats?${params}`);
  if (!response.ok) throw new Error(await readApiError(response, 'Failed to fetch audit stats'));
  return response.json();
}

async function fetchQuarantine(status: string = 'pending', limit: number = 50, project?: string): Promise<{ items: QuarantineItem[]; total: number }> {
  const params = new URLSearchParams({ status, limit: limit.toString() });
  if (project) params.set('project', project);
  const response = await authFetch(`${API_BASE}/api/v1/quarantine?${params}`);
  if (!response.ok) throw new Error(await readApiError(response, 'Failed to fetch quarantine'));
  return response.json();
}

async function approveQuarantine(id: number): Promise<{ success: boolean; id: number; status: string }> {
  const response = await authFetch(`${API_BASE}/api/v1/quarantine/${id}/approve`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ reviewedBy: 'dashboard' }),
  });
  if (!response.ok) throw new Error(await readApiError(response, 'Failed to approve quarantined item'));
  return response.json();
}

async function rejectQuarantine(id: number, notes?: string): Promise<{ success: boolean; id: number; status: string }> {
  const response = await authFetch(`${API_BASE}/api/v1/quarantine/${id}/reject`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ reviewedBy: 'dashboard', notes }),
  });
  if (!response.ok) throw new Error(await readApiError(response, 'Failed to reject quarantined item'));
  return response.json();
}

async function bulkApproveQuarantine(ids: number[]): Promise<{ success: boolean; updated: number; total: number }> {
  const response = await authFetch(`${API_BASE}/api/v1/quarantine/bulk-approve`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ ids, reviewedBy: 'dashboard' }),
  });
  if (!response.ok) throw new Error(await readApiError(response, 'Failed to bulk approve quarantined items'));
  return response.json();
}

async function bulkRejectQuarantine(ids: number[]): Promise<{ success: boolean; updated: number; total: number }> {
  const response = await authFetch(`${API_BASE}/api/v1/quarantine/bulk-reject`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ ids, reviewedBy: 'dashboard' }),
  });
  if (!response.ok) throw new Error(await readApiError(response, 'Failed to bulk reject quarantined items'));
  return response.json();
}

// ── Hooks ──

export function useAuditLogs(options?: {
  startTime?: string;
  endTime?: string;
  source?: string;
  firewallResult?: string;
  project?: string;
  limit?: number;
}) {
  return useQuery({
    queryKey: ['audit-logs', options],
    queryFn: () => fetchAuditLogs(options),
    refetchInterval: 30000,
    retry: 2,
  });
}

export function useAuditStats(timeRange: '24h' | '7d' | '30d' = '24h', project?: string) {
  return useQuery({
    queryKey: ['audit-stats', timeRange, project],
    queryFn: () => fetchAuditStats(timeRange, project),
    refetchInterval: 30000,
    retry: 2,
  });
}

export function useQuarantine(status: string = 'pending', limit: number = 50, project?: string) {
  return useQuery({
    queryKey: ['quarantine', status, limit, project],
    queryFn: () => fetchQuarantine(status, limit, project),
    refetchInterval: 30000,
    retry: 2,
  });
}

export function useApproveQuarantine() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: approveQuarantine,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['quarantine'] });
      queryClient.invalidateQueries({ queryKey: ['audit-stats'] });
      queryClient.invalidateQueries({ queryKey: ['memories'] });
      queryClient.invalidateQueries({ queryKey: ['stats'] });
      queryClient.invalidateQueries({ queryKey: ['review-queue'] });
      queryClient.invalidateQueries({ queryKey: ['openclaw-sessions'] });
      queryClient.invalidateQueries({ queryKey: ['quality'] });
    },
  });
}

export function useRejectQuarantine() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: ({ id, notes }: { id: number; notes?: string }) => rejectQuarantine(id, notes),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['quarantine'] });
      queryClient.invalidateQueries({ queryKey: ['audit-stats'] });
      queryClient.invalidateQueries({ queryKey: ['review-queue'] });
    },
  });
}

export function useBulkApproveQuarantine() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: bulkApproveQuarantine,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['quarantine'] });
      queryClient.invalidateQueries({ queryKey: ['audit-stats'] });
      queryClient.invalidateQueries({ queryKey: ['memories'] });
      queryClient.invalidateQueries({ queryKey: ['stats'] });
      queryClient.invalidateQueries({ queryKey: ['review-queue'] });
      queryClient.invalidateQueries({ queryKey: ['openclaw-sessions'] });
      queryClient.invalidateQueries({ queryKey: ['quality'] });
    },
  });
}

export function useBulkRejectQuarantine() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: bulkRejectQuarantine,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['quarantine'] });
      queryClient.invalidateQueries({ queryKey: ['audit-stats'] });
      queryClient.invalidateQueries({ queryKey: ['review-queue'] });
    },
  });
}

// ── Defence Config ──

export type DefenceMode = 'strict' | 'balanced' | 'permissive';

export function useDefenceConfig() {
  return useQuery<{ mode: DefenceMode; tampered: boolean }>({
    queryKey: ['defence-config'],
    queryFn: async () => {
      const response = await authFetch(`${API_BASE}/api/defence/config`);
      if (!response.ok) throw new Error(await readApiError(response, 'Failed to fetch defence config'));
      return response.json();
    },
  });
}

export function useSetDefenceMode() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: async (mode: DefenceMode) => {
      const response = await authFetch(`${API_BASE}/api/defence/config`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ mode }),
      });
      if (!response.ok) throw new Error(await readApiError(response, 'Failed to update defence mode'));
      return response.json();
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['defence-config'] });
    },
  });
}
