'use client';

import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { gatedFetch, readApiError } from '@/lib/auth';

const API_BASE = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:3001';

interface FindingStats {
  total: number;
  new: number;
  reviewed: number;
  ignored: number;
  resolved: number;
  quarantined: number;
}

export function useXRayFindingsList(filters?: { status?: string; severity?: string; target?: string; limit?: number }) {
  return useQuery({
    queryKey: ['xray-findings', filters],
    queryFn: async () => {
      const params = new URLSearchParams();
      if (filters?.status) params.set('status', filters.status);
      if (filters?.severity) params.set('severity', filters.severity);
      if (filters?.target) params.set('target', filters.target);
      if (filters?.limit) params.set('limit', String(filters.limit));
      const qs = params.toString() ? `?${params}` : '';
      const res = await gatedFetch(`${API_BASE}/api/xray/findings${qs}`);
      if (!res.ok) throw new Error(await readApiError(res, 'Failed to fetch findings'));
      return res.json();
    },
    refetchInterval: 15000,
  });
}

export function useXRayFindingsStats() {
  return useQuery({
    queryKey: ['xray-findings-stats'],
    queryFn: async () => {
      const res = await gatedFetch(`${API_BASE}/api/xray/findings/stats`);
      if (!res.ok) throw new Error(await readApiError(res, 'Failed to fetch finding stats'));
      return res.json() as Promise<FindingStats>;
    },
    refetchInterval: 15000,
  });
}

export function useUpdateFindingStatus() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async ({ id, status, note }: { id: string; status: string; note?: string }) => {
      const res = await gatedFetch(`${API_BASE}/api/xray/findings/${id}`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ status, note }),
      });
      if (!res.ok) throw new Error(await readApiError(res, 'Failed to update finding'));
      return res.json();
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['xray-findings'] });
      qc.invalidateQueries({ queryKey: ['xray-findings-stats'] });
    },
  });
}

export function useQuarantineFinding() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async ({ id, note }: { id: string; note?: string }) => {
      const res = await gatedFetch(`${API_BASE}/api/xray/findings/${id}/quarantine`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ note }),
      });
      if (!res.ok) throw new Error(await readApiError(res, 'Failed to quarantine file'));
      return res.json();
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['xray-findings'] });
      qc.invalidateQueries({ queryKey: ['xray-findings-stats'] });
    },
  });
}

export function useDeleteFinding() {
  const qc = useQueryClient();
  return useMutation({
    mutationFn: async (id: string) => {
      const res = await gatedFetch(`${API_BASE}/api/xray/findings/${id}`, { method: 'DELETE' });
      if (!res.ok) throw new Error(await readApiError(res, 'Failed to delete finding'));
      return res.json();
    },
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['xray-findings'] });
      qc.invalidateQueries({ queryKey: ['xray-findings-stats'] });
    },
  });
}
