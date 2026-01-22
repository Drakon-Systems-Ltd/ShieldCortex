'use client';

/**
 * Memory Data Hooks
 * TanStack Query hooks for fetching memory data
 */

import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query';
import { Memory, MemoryStats, MemoryLink } from '@/types/memory';

const API_BASE = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:3001';

// Fetch all memories
async function fetchMemories(options?: {
  project?: string;
  type?: string;
  category?: string;
  limit?: number;
  mode?: 'recent' | 'important' | 'search';
  query?: string;
}): Promise<Memory[]> {
  const params = new URLSearchParams();
  if (options?.project) params.set('project', options.project);
  if (options?.type) params.set('type', options.type);
  if (options?.category) params.set('category', options.category);
  if (options?.limit) params.set('limit', options.limit.toString());
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
async function fetchLinks(): Promise<MemoryLink[]> {
  const response = await fetch(`${API_BASE}/api/links`);
  if (!response.ok) throw new Error('Failed to fetch links');
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

// Hook: Get all memories
export function useMemories(options?: {
  project?: string;
  type?: string;
  category?: string;
  limit?: number;
  mode?: 'recent' | 'important' | 'search';
  query?: string;
}) {
  return useQuery({
    queryKey: ['memories', options],
    queryFn: () => fetchMemories(options),
    refetchInterval: 5000, // Poll every 5 seconds
  });
}

// Hook: Get memory stats
export function useStats(project?: string) {
  return useQuery({
    queryKey: ['stats', project],
    queryFn: () => fetchStats(project),
    refetchInterval: 10000, // Poll every 10 seconds
  });
}

// Hook: Get memory links
export function useMemoryLinks() {
  return useQuery({
    queryKey: ['links'],
    queryFn: fetchLinks,
    refetchInterval: 30000, // Less frequent
  });
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
