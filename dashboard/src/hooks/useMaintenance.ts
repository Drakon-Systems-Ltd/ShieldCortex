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
