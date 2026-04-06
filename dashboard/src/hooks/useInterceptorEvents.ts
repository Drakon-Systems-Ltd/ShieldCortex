'use client';

import { useQuery } from '@tanstack/react-query';
import { authFetch, readApiError } from '@/lib/auth';

const API_BASE = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:3001';

export interface InterceptorEvent {
  type: 'intercept';
  tool: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  firewallResult: string;
  threats: string[];
  anomalyScore: number;
  action: string;
  outcome: string;
  preview: string;
  ts: string;
}

export interface InterceptorSummary {
  total: number;
  approved: number;
  denied: number;
  failures: number;
  bySeverity: Record<string, number>;
  topTools: Array<{ tool: string; count: number }>;
}

async function fetchInterceptorEvents(options?: {
  limit?: number;
  severity?: string;
  outcome?: string;
  tool?: string;
}): Promise<{ entries: InterceptorEvent[]; total: number; summary: InterceptorSummary }> {
  const params = new URLSearchParams();
  if (options?.limit) params.set('limit', String(options.limit));
  if (options?.severity) params.set('severity', options.severity);
  if (options?.outcome) params.set('outcome', options.outcome);
  if (options?.tool) params.set('tool', options.tool);

  const res = await authFetch(`${API_BASE}/api/v1/intercepts?${params}`);
  if (!res.ok) throw new Error(await readApiError(res, 'Failed to fetch interceptor events'));
  return res.json();
}

export function useInterceptorEvents(options?: {
  limit?: number;
  severity?: string;
  outcome?: string;
  tool?: string;
}) {
  return useQuery({
    queryKey: ['interceptor-events', options],
    queryFn: () => fetchInterceptorEvents(options),
    refetchInterval: 30000,
    retry: 2,
  });
}
