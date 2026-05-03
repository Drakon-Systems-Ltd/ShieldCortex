'use client';

import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { gatedFetch, readApiError } from '@/lib/auth';

const API_BASE = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:3001';

export interface WorkerStatus {
  isRunning: boolean;
  lastLightTick: string | null;
  lastMediumTick: string | null;
  lastConsolidation: string | null;
  stats: {
    lightTicks: number;
    mediumTicks: number;
    consolidations: number;
  };
}

export interface MemoryStats {
  total: number;
  shortTerm: number;
  longTerm: number;
  episodic: number;
  averageSalience: number;
  decayDistribution: {
    healthy: number;
    fading: number;
    critical: number;
  };
}

export function useWorkerStatus() {
  return useQuery<WorkerStatus>({
    queryKey: ['worker-status'],
    queryFn: async () => {
      const res = await gatedFetch(`${API_BASE}/api/worker/status`);
      if (!res.ok) throw new Error(await readApiError(res, 'Failed to load worker status'));
      return res.json();
    },
    refetchInterval: 10000,
  });
}

export function useMemoryStats() {
  return useQuery<MemoryStats>({
    queryKey: ['memory-stats'],
    queryFn: async () => {
      const res = await gatedFetch(`${API_BASE}/api/stats`);
      if (!res.ok) throw new Error(await readApiError(res, 'Failed to load memory stats'));
      return res.json();
    },
    refetchInterval: 30000,
  });
}

export function useRunLightTick() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async () => {
      const res = await gatedFetch(`${API_BASE}/api/worker/trigger-light`, { method: 'POST' });
      if (!res.ok) throw new Error(await readApiError(res, 'Failed to run light tick'));
      return res.json();
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['worker-status'] });
      qc.invalidateQueries({ queryKey: ['memory-stats'] });
    },
  });
}

export function useRunMediumTick() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async () => {
      const res = await gatedFetch(`${API_BASE}/api/worker/trigger-medium`, { method: 'POST' });
      if (!res.ok) throw new Error(await readApiError(res, 'Failed to run medium tick'));
      return res.json();
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['worker-status'] });
      qc.invalidateQueries({ queryKey: ['memory-stats'] });
    },
  });
}

export function useRunConsolidation() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async () => {
      const res = await gatedFetch(`${API_BASE}/api/consolidate`, { method: 'POST' });
      if (!res.ok) throw new Error(await readApiError(res, 'Failed to run consolidation'));
      return res.json();
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['worker-status'] });
      qc.invalidateQueries({ queryKey: ['memory-stats'] });
    },
  });
}

// ── Prune (threshold-based) ─────────────────────────────────────────────────

export interface PruneRequest {
  salienceLte?: number;
  ageDaysGte?: number;
  project?: string;
  excludePinned?: boolean;
  dryRun?: boolean;
}

export interface PruneSampleEntry {
  id: number;
  title: string;
  project: string | null;
  salience: number;
  ageDays: number;
}

export interface PruneResponse {
  success: boolean;
  options: {
    salienceLte: number;
    ageDaysGte: number;
    project: string | null;
    excludePinned: boolean;
    dryRun: boolean;
  };
  matched: number;
  sample: PruneSampleEntry[];
  deleted?: number;
  backupPath?: string;
}

export function useRunPrune() {
  const qc = useQueryClient();
  return useMutation<PruneResponse, Error, PruneRequest>({
    mutationFn: async (req) => {
      const res = await gatedFetch(`${API_BASE}/api/memories/prune`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(req),
      });
      if (!res.ok) throw new Error(await readApiError(res, 'Failed to prune'));
      return res.json();
    },
    onSuccess: (data) => {
      // Only invalidate memory-stats when an actual delete ran.
      if (typeof data.deleted === 'number') {
        qc.invalidateQueries({ queryKey: ['memory-stats'] });
        qc.invalidateQueries({ queryKey: ['integrations-config'] });
      }
    },
  });
}

// ── Dedupe (project-scoped) ─────────────────────────────────────────────────

export interface DedupeRequest {
  project?: string;
  dryRun?: boolean;
  limit?: number;
}

export interface DedupeGroup {
  keepId: number;
  keepTitle: string;
  removeIds: number[];
  similarity: string;
}

export interface DedupeResponse {
  success: boolean;
  options: {
    project: string | null;
    dryRun: boolean;
    limit: number;
  };
  pairsFound: number;
  groups: DedupeGroup[];
  merged?: number;
  backupPath?: string;
}

export function useRunDedupe() {
  const qc = useQueryClient();
  return useMutation<DedupeResponse, Error, DedupeRequest>({
    mutationFn: async (req) => {
      const res = await gatedFetch(`${API_BASE}/api/memories/dedupe`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(req),
      });
      if (!res.ok) throw new Error(await readApiError(res, 'Failed to dedupe'));
      return res.json();
    },
    onSuccess: (data) => {
      if (typeof data.merged === 'number') {
        qc.invalidateQueries({ queryKey: ['memory-stats'] });
      }
    },
  });
}
