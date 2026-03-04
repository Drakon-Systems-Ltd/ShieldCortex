'use client';

import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { gatedFetch, FeatureLockedError } from '@/lib/auth';

const API_BASE = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:3001';

export interface IronDomePolicy {
  id: number;
  name: string;
  description: string;
  config: string;
  is_active: number;
  created_at: string;
}

export function useCustomPolicies() {
  const query = useQuery<{ policies: IronDomePolicy[]; total: number }>({
    queryKey: ['custom-policies'],
    queryFn: () => gatedFetch(`${API_BASE}/api/iron-dome/policies`).then(r => {
      if (!r.ok) throw new Error('Failed to fetch custom policies');
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

export function useCreatePolicy() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (policy: { name: string; description?: string; config?: Record<string, unknown> }) =>
      gatedFetch(`${API_BASE}/api/iron-dome/policies`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(policy),
      }).then(r => {
        if (!r.ok) return r.json().then(d => { throw new Error(d.error); });
        return r.json();
      }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['custom-policies'] });
    },
  });
}

export function useDeletePolicy() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (id: number) =>
      gatedFetch(`${API_BASE}/api/iron-dome/policies/${id}`, { method: 'DELETE' }).then(r => {
        if (!r.ok) return r.json().then(d => { throw new Error(d.error); });
        return r.json();
      }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['custom-policies'] });
    },
  });
}

export function useActivatePolicy() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (id: number) =>
      gatedFetch(`${API_BASE}/api/iron-dome/policies/${id}/activate`, { method: 'PUT' }).then(r => {
        if (!r.ok) return r.json().then(d => { throw new Error(d.error); });
        return r.json();
      }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['custom-policies'] });
    },
  });
}
