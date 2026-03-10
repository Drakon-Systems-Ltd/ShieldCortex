'use client';

import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query';
import { authFetch } from '@/lib/auth';
import type { Memory } from '@/types/memory';

const API_BASE = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:3001';

export interface ReviewQueueResponse {
  summary: Record<string, number>;
  openClaw: {
    total: number;
    autoExtracted: number;
    keywordTriggered: number;
    suppressed: number;
    pinned: number;
  };
  sections: {
    stale: Memory[];
    neverUsed: Memory[];
    lowTrust: Memory[];
    noisyAutoExtracted: Memory[];
    projectless: Memory[];
    contradictions: Array<{
      memoryA: Memory;
      memoryB: Memory;
      score: number;
      reason: string;
      sharedTopics: string[];
    }>;
  };
}

async function fetchReviewQueue(project?: string | null): Promise<ReviewQueueResponse> {
  const params = project ? `?project=${encodeURIComponent(project)}` : '';
  const response = await authFetch(`${API_BASE}/api/review/queue${params}`);
  if (!response.ok) throw new Error('Failed to fetch review queue');
  return response.json();
}

async function patchReviewAction(input: {
  id: number;
  action: string;
  reviewedBy?: string;
  project?: string | null;
  scope?: 'project' | 'global';
}) {
  const response = await authFetch(`${API_BASE}/api/memories/${input.id}/review`, {
    method: 'PATCH',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(input),
  });
  if (!response.ok) throw new Error('Failed to update review state');
  return response.json();
}

export function useReviewQueue(project?: string | null) {
  return useQuery({
    queryKey: ['review-queue', project],
    queryFn: () => fetchReviewQueue(project),
    staleTime: 30_000,
  });
}

export function useReviewAction() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: patchReviewAction,
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['review-queue'] });
      queryClient.invalidateQueries({ queryKey: ['memories'] });
      queryClient.invalidateQueries({ queryKey: ['quality'] });
      queryClient.invalidateQueries({ queryKey: ['contradictions'] });
      queryClient.invalidateQueries({ queryKey: ['stats'] });
    },
  });
}
