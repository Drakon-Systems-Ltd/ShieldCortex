'use client';

import { useQuery } from '@tanstack/react-query';
import { authFetch } from '@/lib/auth';
import { wsGatedInterval } from '@/lib/ws-helpers';
import { useWebSocketStatus } from '@/components/MemoryWebSocketProvider';
import type { AgentInfo, AgentTimelinePoint } from '../types/agents';
import type { AuditEntry } from './useDefence';

const API_BASE = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:3001';

// ── Fetch Functions ──

async function fetchAgentRegistry(
  timeRange: '24h' | '7d' | '30d',
  project?: string,
): Promise<{ agents: AgentInfo[] }> {
  const params = new URLSearchParams({ timeRange });
  if (project) params.set('project', project);
  const response = await authFetch(`${API_BASE}/api/v1/agents?${params}`);
  if (!response.ok) throw new Error('Failed to fetch agent registry');
  return response.json();
}

async function fetchAgentTimeline(
  identifier: string,
  timeRange: '24h' | '7d' | '30d',
  project?: string,
): Promise<{ points: AgentTimelinePoint[] }> {
  const encoded = encodeURIComponent(identifier);
  const params = new URLSearchParams({ timeRange });
  if (project) params.set('project', project);
  const response = await authFetch(`${API_BASE}/api/v1/agents/${encoded}/timeline?${params}`);
  if (!response.ok) throw new Error('Failed to fetch agent timeline');
  return response.json();
}

async function fetchAgentOperations(
  identifier: string,
  options?: { limit?: number; offset?: number; firewallResult?: string; project?: string },
): Promise<{ entries: AuditEntry[]; limit: number; offset: number }> {
  const encoded = encodeURIComponent(identifier);
  const params = new URLSearchParams();
  if (options?.limit) params.set('limit', options.limit.toString());
  if (options?.offset) params.set('offset', options.offset.toString());
  if (options?.firewallResult) params.set('firewallResult', options.firewallResult);
  if (options?.project) params.set('project', options.project);
  const response = await authFetch(`${API_BASE}/api/v1/agents/${encoded}/operations?${params}`);
  if (!response.ok) throw new Error('Failed to fetch agent operations');
  return response.json();
}

// ── Hooks ──

export function useAgentRegistry(timeRange: '24h' | '7d' | '30d' = '24h', project?: string) {
  const { isConnected } = useWebSocketStatus();
  return useQuery({
    queryKey: ['agents', timeRange, project],
    queryFn: () => fetchAgentRegistry(timeRange, project),
    // defence_event invalidates ['agents']; poll only when the socket is down.
    refetchInterval: wsGatedInterval(isConnected, 30000),
    retry: 2,
  });
}

export function useAgentTimeline(
  identifier: string | null,
  timeRange: '24h' | '7d' | '30d' = '24h',
  project?: string,
) {
  const { isConnected } = useWebSocketStatus();
  return useQuery({
    queryKey: ['agent-timeline', identifier, timeRange, project],
    queryFn: () => fetchAgentTimeline(identifier!, timeRange, project),
    enabled: !!identifier,
    // defence_event invalidates ['agent-timeline']; poll only when the socket is down.
    refetchInterval: wsGatedInterval(isConnected, 30000),
    retry: 2,
  });
}

export function useAgentOperations(
  identifier: string | null,
  options?: { limit?: number; offset?: number; firewallResult?: string; project?: string },
) {
  const { isConnected } = useWebSocketStatus();
  return useQuery({
    queryKey: ['agent-operations', identifier, options],
    queryFn: () => fetchAgentOperations(identifier!, options),
    enabled: !!identifier,
    // defence_event (Phase 4) invalidates ['agent-operations']; poll only when the socket is down.
    refetchInterval: wsGatedInterval(isConnected, 30000),
    retry: 2,
  });
}
