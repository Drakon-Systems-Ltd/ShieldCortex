'use client';

import { useQuery } from '@tanstack/react-query';
import { authFetch, readApiError } from '@/lib/auth';

const API_BASE = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:3001';

export interface HealthScoreComponent {
  score: number;
  label: string;
  detail: string;
}

export interface HealthScorePayload {
  overall: number;
  components: Record<string, HealthScoreComponent>;
}

/** Doctor-style memory health score (`/api/health-score`). */
export function useHealthScore() {
  return useQuery<HealthScorePayload>({
    queryKey: ['health-score'],
    queryFn: async () => {
      const res = await authFetch(`${API_BASE}/api/health-score`);
      if (!res.ok) throw new Error(await readApiError(res, 'Failed to load the health score'));
      return res.json();
    },
    staleTime: 60_000,
  });
}
