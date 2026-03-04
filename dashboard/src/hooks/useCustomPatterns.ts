'use client';

import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { gatedFetch, FeatureLockedError } from '@/lib/auth';

const API_BASE = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:3001';

export interface CustomPattern {
  id: number;
  name: string;
  category: string;
  severity: 'critical' | 'high' | 'medium' | 'low';
  regex: string;
  description: string;
  enabled: number;
  created_at: string;
}

export function useCustomPatterns() {
  const query = useQuery<{ patterns: CustomPattern[]; total: number }>({
    queryKey: ['custom-patterns'],
    queryFn: () => gatedFetch(`${API_BASE}/api/patterns`).then(r => {
      if (!r.ok) throw new Error('Failed to fetch custom patterns');
      return r.json();
    }),
    retry: (failureCount, error) => {
      if (error instanceof FeatureLockedError) return false;
      return failureCount < 2;
    },
    refetchInterval: 30000,
  });

  return {
    ...query,
    isLocked: query.error instanceof FeatureLockedError,
  };
}

export function useCreatePattern() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (pattern: { name: string; category: string; severity: string; regex: string; description?: string }) =>
      gatedFetch(`${API_BASE}/api/patterns`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(pattern),
      }).then(r => {
        if (!r.ok) return r.json().then(d => { throw new Error(d.error); });
        return r.json();
      }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['custom-patterns'] });
    },
  });
}

export function useDeletePattern() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (id: number) =>
      gatedFetch(`${API_BASE}/api/patterns/${id}`, { method: 'DELETE' }).then(r => {
        if (!r.ok) return r.json().then(d => { throw new Error(d.error); });
        return r.json();
      }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['custom-patterns'] });
    },
  });
}

export function useTestPattern() {
  return useMutation({
    mutationFn: ({ id, text }: { id: number; text: string }) =>
      gatedFetch(`${API_BASE}/api/patterns/${id}/test`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ text }),
      }).then(r => {
        if (!r.ok) return r.json().then(d => { throw new Error(d.error); });
        return r.json();
      }),
  });
}
