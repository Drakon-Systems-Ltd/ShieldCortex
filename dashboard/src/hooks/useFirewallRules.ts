'use client';

import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { gatedFetch, FeatureLockedError } from '@/lib/auth';

const API_BASE = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:3001';

export interface FirewallRule {
  id: number;
  name: string;
  priority: number;
  condition_type: string;
  condition_value: string;
  action: 'block' | 'allow' | 'quarantine';
  enabled: number;
  created_at: string;
}

export function useFirewallRules() {
  const query = useQuery<{ rules: FirewallRule[]; total: number }>({
    queryKey: ['firewall-rules'],
    queryFn: () => gatedFetch(`${API_BASE}/api/firewall-rules`).then(r => {
      if (!r.ok) throw new Error('Failed to fetch firewall rules');
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

export function useCreateFirewallRule() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (rule: { name: string; priority: number; condition_type: string; condition_value: string; action: string }) =>
      gatedFetch(`${API_BASE}/api/firewall-rules`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(rule),
      }).then(r => {
        if (!r.ok) return r.json().then(d => { throw new Error(d.error); });
        return r.json();
      }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['firewall-rules'] });
    },
  });
}

export function useUpdateFirewallRule() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: ({ id, ...updates }: { id: number } & Partial<FirewallRule>) =>
      gatedFetch(`${API_BASE}/api/firewall-rules/${id}`, {
        method: 'PATCH',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(updates),
      }).then(r => {
        if (!r.ok) return r.json().then(d => { throw new Error(d.error); });
        return r.json();
      }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['firewall-rules'] });
    },
  });
}

export function useDeleteFirewallRule() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: (id: number) =>
      gatedFetch(`${API_BASE}/api/firewall-rules/${id}`, { method: 'DELETE' }).then(r => {
        if (!r.ok) return r.json().then(d => { throw new Error(d.error); });
        return r.json();
      }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['firewall-rules'] });
    },
  });
}
