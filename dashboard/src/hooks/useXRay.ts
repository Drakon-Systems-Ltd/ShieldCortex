'use client';

import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { gatedFetch, FeatureLockedError, readApiError } from '@/lib/auth';

const API_BASE = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:3001';

export interface XRayFinding {
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  category: string;
  title: string;
  description: string;
  file?: string;
  line?: number;
  evidence?: string;
}

export interface XRayResult {
  target: string;
  trustScore: number;
  riskLevel: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'SAFE';
  findings: XRayFinding[];
  filesScanned: number;
  scannedAt: string;
  deepScan: boolean;
}

export interface ActionableXRayFinding {
  id: string;
  status: string;
}

export interface XRayHistoryEntry {
  id: string;
  target: string;
  targetType: 'npm' | 'file' | 'dir';
  deepScan: boolean;
  trustScore: number;
  riskLevel: XRayResult['riskLevel'];
  filesScanned: number;
  findingCount: number;
  scannedAt: string;
  result: XRayResult;
}

export interface XRayActivityEntry {
  id: string;
  kind: 'scan' | 'watch' | 'preinstall';
  status: 'pass' | 'warn' | 'blocked' | 'detected';
  target: string;
  targetType: 'npm' | 'file' | 'dir';
  deepScan: boolean;
  trustScore: number;
  riskLevel: XRayResult['riskLevel'];
  filesScanned: number;
  findingCount: number;
  scannedAt: string;
  summary: string;
}

export interface XRayStatusResponse {
  capabilities: {
    localScan: boolean;
    watchMode: boolean;
    preinstallHook: boolean;
    npmInspection: boolean;
    deepScan: boolean;
    requiredTier: string;
  };
  summary: {
    scans: number;
    blockedEvents: number;
    highRiskScans: number;
    lastScannedAt: string | null;
    activeWatchRoots: number;
    staleWatchRoots: number;
    watchSessions: number;
  };
}

export interface XRayHistoryFilters {
  risk?: XRayResult['riskLevel'] | 'ALL';
  targetType?: XRayHistoryEntry['targetType'] | 'all';
  deep?: 'all' | 'true' | 'false';
  search?: string;
}

export interface XRayActivityFilters {
  kind?: XRayActivityEntry['kind'] | 'all';
  status?: XRayActivityEntry['status'] | 'all';
  risk?: XRayResult['riskLevel'] | 'ALL';
  targetType?: XRayActivityEntry['targetType'] | 'all';
  search?: string;
}

export interface XRayWatchSessionEntry {
  id: string;
  root: string;
  deepScan: boolean;
  startedAt: string;
  lastHeartbeatAt: string;
  endedAt: string | null;
  active: boolean;
  state: 'active' | 'stale' | 'ended';
  changesDetected: number;
  findingsDetected: number;
  highestRiskLevel: XRayResult['riskLevel'];
  lastEventAt: string | null;
  lastEventSummary: string | null;
}

export interface XRayWatchSessionFilters {
  state?: 'all' | 'active' | 'stale' | 'ended';
  deep?: 'all' | 'true' | 'false';
  search?: string;
}

async function fetchJson<T>(path: string, fallback: string): Promise<T> {
  const response = await gatedFetch(`${API_BASE}${path}`);
  if (!response.ok) throw new Error(await readApiError(response, fallback));
  return response.json();
}

async function runXRayScan(input: { target: string; deep?: boolean }): Promise<{ result: XRayResult; persistedFindings?: ActionableXRayFinding[] }> {
  const response = await gatedFetch(`${API_BASE}/api/xray/scan`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(input),
  });
  if (!response.ok) throw new Error(await readApiError(response, 'Failed to run X-Ray scan'));
  return response.json();
}

async function pickXRayTarget(kind: 'file' | 'folder'): Promise<{ path: string | null; kind: 'file' | 'folder' }> {
  const response = await gatedFetch(`${API_BASE}/api/xray/pick-target`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ kind }),
  });
  if (!response.ok) throw new Error(await readApiError(response, `Failed to open ${kind} picker`));
  return response.json();
}

function retryWithoutLockedFeatures(failureCount: number, error: unknown): boolean {
  if (error instanceof FeatureLockedError) return false;
  return failureCount < 2;
}

function buildQueryString(filters: Record<string, string | undefined>): string {
  const params = new URLSearchParams();
  for (const [key, value] of Object.entries(filters)) {
    if (!value || value === 'all' || value === 'ALL') continue;
    params.set(key, value);
  }
  const query = params.toString();
  return query ? `?${query}` : '';
}

export function useXRayStatus() {
  return useQuery({
    queryKey: ['xray-status'],
    queryFn: () => fetchJson<XRayStatusResponse>('/api/xray/status', 'Failed to fetch X-Ray status'),
    refetchInterval: 30000,
    retry: retryWithoutLockedFeatures,
  });
}

export function useXRayHistory(filters: XRayHistoryFilters = {}) {
  return useQuery({
    queryKey: ['xray-history', filters],
    queryFn: () => fetchJson<{ entries: XRayHistoryEntry[] }>(
      `/api/xray/history${buildQueryString({
        risk: filters.risk,
        targetType: filters.targetType,
        deep: filters.deep,
        search: filters.search?.trim() || undefined,
      })}`,
      'Failed to fetch X-Ray history',
    ),
    refetchInterval: 30000,
    retry: retryWithoutLockedFeatures,
  });
}

export function useXRayHistoryEntry(id: string | null) {
  return useQuery({
    queryKey: ['xray-history-entry', id],
    queryFn: () => fetchJson<{ entry: XRayHistoryEntry }>(`/api/xray/history/${id}`, 'Failed to fetch X-Ray scan detail'),
    enabled: Boolean(id),
    retry: retryWithoutLockedFeatures,
  });
}

export function useXRayActivity(limit = 25, filters: XRayActivityFilters = {}) {
  return useQuery({
    queryKey: ['xray-activity', limit, filters],
    queryFn: () => fetchJson<{ entries: XRayActivityEntry[] }>(
      `/api/xray/activity${buildQueryString({
        limit: String(limit),
        kind: filters.kind,
        status: filters.status,
        risk: filters.risk,
        targetType: filters.targetType,
        search: filters.search?.trim() || undefined,
      })}`,
      'Failed to fetch X-Ray activity',
    ),
    refetchInterval: 15000,
    retry: retryWithoutLockedFeatures,
  });
}

export function useXRayWatchSessions(limit = 20, filters: XRayWatchSessionFilters = {}) {
  return useQuery({
    queryKey: ['xray-watch-sessions', limit, filters],
    queryFn: () => fetchJson<{ entries: XRayWatchSessionEntry[] }>(
      `/api/xray/watch-sessions${buildQueryString({
        limit: String(limit),
        state: filters.state,
        deep: filters.deep,
        search: filters.search?.trim() || undefined,
      })}`,
      'Failed to fetch X-Ray watch sessions',
    ),
    refetchInterval: 15000,
    retry: retryWithoutLockedFeatures,
  });
}

export function useXRayScan() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: runXRayScan,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['xray-history'] });
      queryClient.invalidateQueries({ queryKey: ['xray-activity'] });
      queryClient.invalidateQueries({ queryKey: ['xray-watch-sessions'] });
      queryClient.invalidateQueries({ queryKey: ['xray-status'] });
    },
  });
}

export function usePickXRayTarget() {
  return useMutation({
    mutationFn: (kind: 'file' | 'folder') => pickXRayTarget(kind),
  });
}

// ── Watch mode management ────────────────────────────────

async function startWatch(input: { target: string; deep?: boolean }): Promise<{ started: boolean; root: string; deep: boolean; pid: number }> {
  const response = await gatedFetch(`${API_BASE}/api/xray/watch/start`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(input),
  });
  if (!response.ok) throw new Error(await readApiError(response, 'Failed to start watch'));
  return response.json();
}

async function stopWatch(target: string): Promise<{ stopped: boolean; root: string }> {
  const response = await gatedFetch(`${API_BASE}/api/xray/watch/stop`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ target }),
  });
  if (!response.ok) throw new Error(await readApiError(response, 'Failed to stop watch'));
  return response.json();
}

export function useActiveWatchers() {
  return useQuery({
    queryKey: ['xray-active-watchers'],
    queryFn: () => fetchJson<{ watchers: { root: string; pid: number; active: boolean }[] }>(
      '/api/xray/watch/active',
      'Failed to fetch active watchers',
    ),
    refetchInterval: 10000,
  });
}

export function useStartWatch() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: startWatch,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['xray-watch-sessions'] });
      queryClient.invalidateQueries({ queryKey: ['xray-active-watchers'] });
      queryClient.invalidateQueries({ queryKey: ['xray-status'] });
    },
  });
}

export function useStopWatch() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: stopWatch,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['xray-watch-sessions'] });
      queryClient.invalidateQueries({ queryKey: ['xray-active-watchers'] });
      queryClient.invalidateQueries({ queryKey: ['xray-status'] });
    },
  });
}
