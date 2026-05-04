'use client';

import { useQuery } from '@tanstack/react-query';
import { gatedFetch, readApiError } from '@/lib/auth';

const API_BASE = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:3001';

export type DigestWindow = '24h' | '7d' | '30d';

export interface DigestCounts {
  scanned: number;
  allowed: number;
  blocked: number;
  quarantined: number;
  memoriesCaptured: number;
  memoriesRecalled: number;
  highSalienceCaptures: number;
}

export interface DigestMoment {
  kind: 'block' | 'quarantine' | 'capture' | 'recall' | 'pattern';
  title: string;
  detail: string;
  timestamp: string;
  memoryId?: number;
  auditId?: number;
}

export interface DigestResponse {
  window: DigestWindow;
  windowLabel: string;
  since: string;
  current: DigestCounts;
  previous: DigestCounts;
  delta: Partial<Record<keyof DigestCounts, number>>;
  topMoments: DigestMoment[];
  topThreatPatterns: Array<{ pattern: string; count: number }>;
  generatedAt: string;
}

export function useDigest(window: DigestWindow = '24h', project?: string | null) {
  return useQuery<DigestResponse>({
    queryKey: ['digest', window, project ?? null],
    queryFn: async () => {
      const params = new URLSearchParams({ window });
      if (project) params.set('project', project);
      const res = await gatedFetch(`${API_BASE}/api/digest?${params.toString()}`);
      if (!res.ok) throw new Error(await readApiError(res, 'Failed to load digest'));
      return res.json();
    },
    refetchInterval: 60_000,
    staleTime: 30_000,
  });
}

export interface TimelineDay {
  date: string;
  scanned: number;
  blocked: number;
  quarantined: number;
  captured: number;
  recalled: number;
}

export interface TimelineResponse {
  days: number;
  project: string | null;
  timeline: TimelineDay[];
}

export function useDigestTimeline(days: number = 7, project?: string | null) {
  return useQuery<TimelineResponse>({
    queryKey: ['digest-timeline', days, project ?? null],
    queryFn: async () => {
      const params = new URLSearchParams({ days: String(days) });
      if (project) params.set('project', project);
      const res = await gatedFetch(`${API_BASE}/api/digest/timeline?${params.toString()}`);
      if (!res.ok) throw new Error(await readApiError(res, 'Failed to load digest timeline'));
      return res.json();
    },
    refetchInterval: 5 * 60_000,
    staleTime: 60_000,
  });
}
