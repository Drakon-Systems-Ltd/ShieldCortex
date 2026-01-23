'use client';

/**
 * Memory Data Hooks
 * TanStack Query hooks for fetching memory data
 *
 * Uses WebSocket for real-time updates with polling as fallback.
 */

import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { Memory, MemoryStats, MemoryLink } from '@/types/memory';
import { useMemoryWebSocket } from '@/lib/websocket';

const API_BASE = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:3001';

// Pagination metadata from API
export interface PaginationInfo {
  offset: number;
  limit: number;
  total: number;
  hasMore: boolean;
}

// Paginated response from API
interface PaginatedMemoriesResponse {
  memories: Memory[];
  pagination: PaginationInfo;
}

// Fetch memories with pagination support
async function fetchMemories(options?: {
  project?: string;
  type?: string;
  category?: string;
  limit?: number;
  offset?: number;
  mode?: 'recent' | 'important' | 'search';
  query?: string;
}): Promise<PaginatedMemoriesResponse> {
  const params = new URLSearchParams();
  if (options?.project) params.set('project', options.project);
  if (options?.type) params.set('type', options.type);
  if (options?.category) params.set('category', options.category);
  if (options?.limit) params.set('limit', options.limit.toString());
  if (options?.offset) params.set('offset', options.offset.toString());
  if (options?.mode) params.set('mode', options.mode);
  if (options?.query) params.set('query', options.query);

  const response = await fetch(`${API_BASE}/api/memories?${params}`);
  if (!response.ok) throw new Error('Failed to fetch memories');
  return response.json();
}

// Fetch memory stats
async function fetchStats(project?: string): Promise<MemoryStats> {
  const params = project ? `?project=${project}` : '';
  const response = await fetch(`${API_BASE}/api/stats${params}`);
  if (!response.ok) throw new Error('Failed to fetch stats');
  return response.json();
}

// Fetch memory links
async function fetchLinks(project?: string): Promise<MemoryLink[]> {
  const params = project ? `?project=${project}` : '';
  const response = await fetch(`${API_BASE}/api/links${params}`);
  if (!response.ok) throw new Error('Failed to fetch links');
  return response.json();
}

// Project info from API
export interface ProjectInfo {
  project: string | null;
  memory_count: number;
  label: string;
}

// Fetch list of projects
async function fetchProjects(): Promise<{ projects: ProjectInfo[] }> {
  const response = await fetch(`${API_BASE}/api/projects`);
  if (!response.ok) throw new Error('Failed to fetch projects');
  return response.json();
}

// Access a memory (reinforce)
async function accessMemory(id: number): Promise<Memory> {
  const response = await fetch(`${API_BASE}/api/memories/${id}/access`, {
    method: 'POST',
  });
  if (!response.ok) throw new Error('Failed to access memory');
  return response.json();
}

// Trigger consolidation
async function triggerConsolidation(): Promise<{
  success: boolean;
  consolidated: number;
  decayed: number;
  deleted: number;
}> {
  const response = await fetch(`${API_BASE}/api/consolidate`, {
    method: 'POST',
  });
  if (!response.ok) throw new Error('Failed to consolidate');
  return response.json();
}

// Hook: Get all memories with pagination
// Polling is reduced because WebSocket handles real-time updates
export function useMemories(options?: {
  project?: string;
  type?: string;
  category?: string;
  limit?: number;
  offset?: number;
  mode?: 'recent' | 'important' | 'search';
  query?: string;
}) {
  const query = useQuery({
    queryKey: ['memories', options],
    queryFn: () => fetchMemories(options),
    refetchInterval: 30000, // Fallback poll every 30 seconds (WebSocket handles real-time)
  });

  // Extract memories array and pagination from response
  return {
    ...query,
    data: query.data?.memories,
    pagination: query.data?.pagination,
  };
}

// Hook: Get memory stats
export function useStats(project?: string) {
  return useQuery({
    queryKey: ['stats', project],
    queryFn: () => fetchStats(project),
    refetchInterval: 30000, // Fallback poll every 30 seconds
  });
}

// Hook: Get memory links
export function useMemoryLinks(project?: string) {
  return useQuery({
    queryKey: ['links', project],
    queryFn: () => fetchLinks(project),
    refetchInterval: 60000, // Fallback poll every 60 seconds
  });
}

// Hook: Get list of projects
export function useProjects() {
  return useQuery({
    queryKey: ['projects'],
    queryFn: fetchProjects,
    refetchInterval: 60000, // Refresh project list every minute
  });
}

// Hook: Combined memories with WebSocket real-time updates
export function useMemoriesWithRealtime(options?: {
  project?: string;
  type?: string;
  category?: string;
  limit?: number;
  offset?: number;
  mode?: 'recent' | 'important' | 'search';
  query?: string;
}) {
  // Connect to WebSocket for real-time updates
  const ws = useMemoryWebSocket();

  // Fetch memories with reduced polling (WebSocket handles most updates)
  const memories = useMemories(options);

  return {
    ...memories,
    isConnected: ws.isConnected,
    lastEvent: ws.lastEvent,
  };
}

// Hook: Access/reinforce a memory
export function useAccessMemory() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: accessMemory,
    onSuccess: () => {
      // Invalidate memories to trigger refetch
      queryClient.invalidateQueries({ queryKey: ['memories'] });
      queryClient.invalidateQueries({ queryKey: ['stats'] });
    },
  });
}

// Hook: Trigger consolidation
export function useConsolidate() {
  const queryClient = useQueryClient();

  return useMutation({
    mutationFn: triggerConsolidation,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['memories'] });
      queryClient.invalidateQueries({ queryKey: ['stats'] });
    },
  });
}
