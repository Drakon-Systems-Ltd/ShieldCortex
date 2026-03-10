'use client';

import { useMutation, useQuery } from '@tanstack/react-query';
import { authFetch } from '@/lib/auth';
import type { Memory } from '@/types/memory';

const API_BASE = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:3001';

export interface RecallExplanationResult {
  memory: Memory;
  relevanceScore: number;
  contradictions?: Array<{ memoryId: number; title: string; score: number }>;
  explanation?: {
    query: string;
    reasons: string[];
    breakdown: Record<string, number | string[] | string | null>;
    eligibility?: {
      eligible: boolean;
      reasons: string[];
    };
  };
  recallEligibility?: {
    eligible: boolean;
    reasons: string[];
  };
}

export interface RecallExplainResponse {
  query: string;
  total: number;
  project: string | null;
  results: RecallExplanationResult[];
  expectedMemory?: {
    id: number;
    title: string;
    status: string;
    pinned: boolean;
    cloudExcluded: boolean;
    trustScore: number;
    captureMethod: string;
    sourceKind: string;
    rank: number | null;
    eligible: boolean;
    reasons: string[];
  } | null;
  misses?: Array<{
    id: number;
    title: string;
    status: string;
    salience: number;
    captureMethod: string;
    sourceKind: string;
    whyNotRecalled: string[];
  }>;
}

export interface RecallExplainOptions {
  query: string;
  project?: string | null;
  expectedId?: number | null;
}

async function fetchRecallExplain(options: RecallExplainOptions): Promise<RecallExplainResponse> {
  const params = new URLSearchParams();
  params.set('query', options.query);
  if (options.project) params.set('project', options.project);
  if (options.expectedId) params.set('expectedId', String(options.expectedId));

  const response = await authFetch(`${API_BASE}/api/recall/explain?${params.toString()}`);
  if (!response.ok) throw new Error('Failed to explain recall');
  return response.json();
}

async function fetchMemoryCandidates(query: string, project?: string | null): Promise<Memory[]> {
  const params = new URLSearchParams({
    mode: 'search',
    query,
    limit: '8',
  });
  if (project) params.set('project', project);

  const response = await authFetch(`${API_BASE}/api/memories?${params.toString()}`);
  if (!response.ok) throw new Error('Failed to fetch memory candidates');
  const json = await response.json() as { memories: Memory[] };
  return json.memories;
}

export function useRecallExplain(options: RecallExplainOptions | null) {
  return useQuery({
    queryKey: ['recall-explain', options],
    queryFn: () => fetchRecallExplain(options!),
    enabled: Boolean(options?.query?.trim()),
    staleTime: 30_000,
  });
}

export function useMemoryCandidates(query: string, project?: string | null) {
  return useQuery({
    queryKey: ['memory-candidates', query, project],
    queryFn: () => fetchMemoryCandidates(query, project),
    enabled: query.trim().length >= 2,
    staleTime: 30_000,
  });
}

export function useRecallHistory() {
  return useMutation({
    mutationFn: async (query: string) => {
      if (typeof window === 'undefined') return [];
      const key = 'shieldcortex:recall-history';
      const current = JSON.parse(window.localStorage.getItem(key) ?? '[]') as string[];
      const next = [query, ...current.filter((item) => item !== query)].slice(0, 8);
      window.localStorage.setItem(key, JSON.stringify(next));
      return next;
    },
  });
}
