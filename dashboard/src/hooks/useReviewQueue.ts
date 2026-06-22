'use client';

import { useMutation, useQuery, useQueryClient, type QueryClient } from '@tanstack/react-query';
import { authFetch, readApiError } from '@/lib/auth';
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
    duplicates: Array<{
      memoryA: Memory;
      memoryB: Memory;
      recommendedKeepId: number;
      similarity: string;
      titleSimilarity: number;
      contentOverlap: number;
      sharedWords: number;
    }>;
    contradictions: Array<{
      memoryA: Memory;
      memoryB: Memory;
      score: number;
      reason: string;
      sharedTopics: string[];
    }>;
  };
}

function isReviewable(memory: Memory) {
  if ((memory.status ?? 'active') === 'archived' || (memory.status ?? 'active') === 'suppressed') return false;
  // Once reviewed via the review queue, remove from the queue
  if (memory.reviewedAt) return false;
  return true;
}

function isOlderThanDay(value?: string) {
  if (!value) return false;
  return Date.now() - new Date(value).getTime() >= 24 * 60 * 60 * 1000;
}

function reconcileReviewQueueMemory(queue: ReviewQueueResponse | undefined, updated: Memory): ReviewQueueResponse | undefined {
  if (!queue) return queue;

  const mapSection = (items: Memory[], predicate: (memory: Memory) => boolean) =>
    items
      .map((memory) => (memory.id === updated.id ? updated : memory))
      .filter(predicate);

  const contradictions = queue.sections.contradictions
    .map((item) => ({
      ...item,
      memoryA: item.memoryA.id === updated.id ? updated : item.memoryA,
      memoryB: item.memoryB.id === updated.id ? updated : item.memoryB,
    }))
    .filter((item) => isReviewable(item.memoryA) && isReviewable(item.memoryB));

  const duplicates = queue.sections.duplicates
    .map((item) => ({
      ...item,
      memoryA: item.memoryA.id === updated.id ? updated : item.memoryA,
      memoryB: item.memoryB.id === updated.id ? updated : item.memoryB,
    }))
    .filter((item) => isReviewable(item.memoryA) && isReviewable(item.memoryB));

  const sections = {
    stale: mapSection(queue.sections.stale, (memory) => isReviewable(memory) && (memory.decayedScore ?? 1) < 0.3),
    neverUsed: mapSection(queue.sections.neverUsed, (memory) => isReviewable(memory) && memory.accessCount === 0 && isOlderThanDay(memory.createdAt)),
    lowTrust: mapSection(queue.sections.lowTrust, (memory) => isReviewable(memory) && (memory.trustScore ?? 1) < 0.7),
    noisyAutoExtracted: mapSection(
      queue.sections.noisyAutoExtracted,
      (memory) => isReviewable(memory) && (memory.captureMethod === 'auto' || memory.tags?.includes('auto-extracted')),
    ),
    projectless: mapSection(
      queue.sections.projectless,
      (memory) => isReviewable(memory) && !(memory.project && memory.project.trim()) && memory.scope !== 'global',
    ),
    duplicates,
    contradictions,
  };

  return {
    ...queue,
    summary: {
      stale: sections.stale.length,
      neverUsed: sections.neverUsed.length,
      lowTrust: sections.lowTrust.length,
      noisyAutoExtracted: sections.noisyAutoExtracted.length,
      projectless: sections.projectless.length,
      duplicates: sections.duplicates.length,
      contradictions: sections.contradictions.length,
    },
    openClaw: queue.openClaw,
    sections,
  };
}

function removeMergedMemoryFromReviewQueue(
  queue: ReviewQueueResponse | undefined,
  keptId: number,
  removedId: number,
  merged: Memory,
): ReviewQueueResponse | undefined {
  if (!queue) return queue;
  return reconcileReviewQueueMemory(
    {
      ...queue,
      sections: {
        ...queue.sections,
        stale: queue.sections.stale.filter((memory) => memory.id !== removedId),
        neverUsed: queue.sections.neverUsed.filter((memory) => memory.id !== removedId),
        lowTrust: queue.sections.lowTrust.filter((memory) => memory.id !== removedId),
        noisyAutoExtracted: queue.sections.noisyAutoExtracted.filter((memory) => memory.id !== removedId),
        projectless: queue.sections.projectless.filter((memory) => memory.id !== removedId),
        duplicates: queue.sections.duplicates.filter((item) => item.memoryA.id !== removedId && item.memoryB.id !== removedId),
        contradictions: queue.sections.contradictions.filter((item) => item.memoryA.id !== removedId && item.memoryB.id !== removedId),
      },
    },
    { ...merged, id: keptId },
  );
}

function updateReviewCaches(queryClient: QueryClient, updated: Memory) {
  queryClient.setQueriesData<ReviewQueueResponse>({ queryKey: ['review-queue'] }, (existing) =>
    reconcileReviewQueueMemory(existing, updated),
  );
  queryClient.setQueriesData<{ memories: Memory[]; pagination?: unknown }>({ queryKey: ['memories'] }, (existing) =>
    existing
      ? {
          ...existing,
          memories: existing.memories.map((memory) => (memory.id === updated.id ? updated : memory)),
        }
      : existing,
  );
}

async function fetchReviewQueue(project?: string | null): Promise<ReviewQueueResponse> {
  const params = project ? `?project=${encodeURIComponent(project)}` : '';
  const response = await authFetch(`${API_BASE}/api/review/queue${params}`);
  if (!response.ok) {
    throw new Error(await readApiError(response, 'Failed to fetch review queue'));
  }
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
  if (!response.ok) {
    throw new Error(await readApiError(response, 'Failed to update review state'));
  }
  return response.json();
}

async function mergeMemories(input: {
  keptId: number;
  removedId: number;
  reviewedBy?: string;
}) {
  const response = await authFetch(`${API_BASE}/api/memories/merge`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(input),
  });
  if (!response.ok) {
    throw new Error(await readApiError(response, 'Failed to merge memories'));
  }
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
    onSuccess: (updated) => {
      updateReviewCaches(queryClient, updated);
      queryClient.invalidateQueries({ queryKey: ['review-queue'] });
      queryClient.invalidateQueries({ queryKey: ['memories'] });
      queryClient.invalidateQueries({ queryKey: ['quality'] });
      queryClient.invalidateQueries({ queryKey: ['contradictions'] });
      queryClient.invalidateQueries({ queryKey: ['stats'] });
    },
  });
}

interface BulkReviewResult {
  success: boolean;
  updated: number;
  total: number;
  failed: number[];
}

async function postBulkReview(input: { ids: number[]; action: string; reviewedBy?: string }): Promise<BulkReviewResult> {
  const response = await authFetch(`${API_BASE}/api/memories/review/bulk`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(input),
  });
  if (!response.ok) {
    throw new Error(await readApiError(response, 'Bulk review failed'));
  }
  return response.json() as Promise<BulkReviewResult>;
}

export function useBulkReview() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: postBulkReview,
    onSuccess: () => {
      // Refetch authoritative queues rather than reconciling many rows by hand.
      queryClient.invalidateQueries({ queryKey: ['review-queue'] });
      queryClient.invalidateQueries({ queryKey: ['memories'] });
      queryClient.invalidateQueries({ queryKey: ['quality'] });
      queryClient.invalidateQueries({ queryKey: ['contradictions'] });
      queryClient.invalidateQueries({ queryKey: ['stats'] });
    },
  });
}

export function useMergeMemories() {
  const queryClient = useQueryClient();
  return useMutation({
    mutationFn: mergeMemories,
    onSuccess: (merged, variables) => {
      queryClient.setQueriesData<ReviewQueueResponse>({ queryKey: ['review-queue'] }, (existing) =>
        removeMergedMemoryFromReviewQueue(existing, variables.keptId, variables.removedId, merged),
      );
      queryClient.setQueriesData<{ memories: Memory[]; pagination?: unknown }>({ queryKey: ['memories'] }, (existing) =>
        existing
          ? {
              ...existing,
              memories: existing.memories
                .filter((memory) => memory.id !== variables.removedId)
                .map((memory) => (memory.id === variables.keptId ? merged : memory)),
            }
          : existing,
      );
      queryClient.invalidateQueries({ queryKey: ['review-queue'] });
      queryClient.invalidateQueries({ queryKey: ['memories'] });
      queryClient.invalidateQueries({ queryKey: ['quality'] });
      queryClient.invalidateQueries({ queryKey: ['contradictions'] });
      queryClient.invalidateQueries({ queryKey: ['stats'] });
      queryClient.invalidateQueries({ queryKey: ['graph'] });
    },
  });
}
