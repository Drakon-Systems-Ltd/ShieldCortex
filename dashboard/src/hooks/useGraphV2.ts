'use client';

import { useQuery } from '@tanstack/react-query';
import { authFetch, readApiError } from '@/lib/auth';
import { useDashboardStore } from '@/lib/store';
import type { NeighbourhoodPayload, OverviewPayload } from '@/lib/graph/transforms';

const API_BASE = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:3001';

/**
 * v2 graph data hooks. Every query key carries the global project scope
 * (GPT review #1) so switching project can never serve another project's
 * cached graph.
 */

export function useGraphOverview(minMentions: number, limit = 400) {
  const project = useDashboardStore((s) => s.projectFilter);
  return useQuery<OverviewPayload>({
    queryKey: ['graph-v2', 'overview', project ?? null, minMentions, limit],
    queryFn: async () => {
      const params = new URLSearchParams({ minMentions: String(minMentions), limit: String(limit) });
      if (project) params.set('project', project);
      const res = await authFetch(`${API_BASE}/api/graph/overview?${params}`);
      if (!res.ok) throw new Error(await readApiError(res, 'Failed to load the graph overview'));
      return res.json();
    },
    staleTime: 30_000,
  });
}

export function useNeighbourhoodV2(
  entityId: number | null,
  opts: { depth: 1 | 2; includeMemories: boolean; memLimit?: number },
) {
  const project = useDashboardStore((s) => s.projectFilter);
  return useQuery<NeighbourhoodPayload>({
    queryKey: ['graph-v2', 'neighbourhood', project ?? null, entityId, opts.depth, opts.includeMemories, opts.memLimit ?? 40],
    queryFn: async () => {
      const params = new URLSearchParams({ depth: String(opts.depth) });
      if (opts.includeMemories) {
        params.set('includeMemories', '1');
        params.set('memLimit', String(opts.memLimit ?? 40));
      }
      if (project) params.set('project', project);
      const res = await authFetch(`${API_BASE}/api/graph/entities/${entityId}/neighbourhood?${params}`);
      if (!res.ok) throw new Error(await readApiError(res, 'Failed to load the neighbourhood'));
      return res.json();
    },
    enabled: entityId !== null,
    staleTime: 15_000,
  });
}

export interface GraphSearchHit {
  id: number;
  name: string;
  type: string;
  memoryCount: number;
}

export function useGraphSearchV2(query: string) {
  const project = useDashboardStore((s) => s.projectFilter);
  return useQuery<GraphSearchHit[]>({
    queryKey: ['graph-v2', 'search', project ?? null, query],
    queryFn: async () => {
      const params = new URLSearchParams({ q: query, limit: '8' });
      if (project) params.set('project', project);
      const res = await authFetch(`${API_BASE}/api/graph/search?${params}`);
      if (!res.ok) throw new Error(await readApiError(res, 'Search failed'));
      const data = await res.json();
      return ((data.entities ?? []) as Array<{ id: number; name: string; type: string; memoryCount: number }>);
    },
    enabled: query.trim().length > 0,
    staleTime: 10_000,
  });
}

export interface PathHop {
  entity: string;
  entityId: number;
  predicate: string;
  direction: 'forward' | 'reverse' | '';
}

export interface PathPayload {
  path: PathHop[];
  sourceMemories: Array<{ id: number; title: string }>;
  /** true when the server hit its BFS budget — "no path" then means "not found within budget" */
  truncated?: boolean;
  message?: string;
}

export function useGraphPath(fromId: number | null, toId: number | null) {
  const project = useDashboardStore((s) => s.projectFilter);
  return useQuery<PathPayload>({
    queryKey: ['graph-v2', 'path', project ?? null, fromId, toId],
    queryFn: async () => {
      const params = new URLSearchParams({ fromId: String(fromId), toId: String(toId) });
      if (project) params.set('project', project);
      const res = await authFetch(`${API_BASE}/api/graph/paths?${params}`);
      if (!res.ok) throw new Error(await readApiError(res, 'Path search failed'));
      return res.json();
    },
    enabled: fromId !== null && toId !== null && fromId !== toId,
    staleTime: 30_000,
  });
}
