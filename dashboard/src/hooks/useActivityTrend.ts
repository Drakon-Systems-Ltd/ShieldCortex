'use client';

import { useQuery } from '@tanstack/react-query';
import { authFetch } from '@/lib/auth';

const API_BASE = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:3001';

interface ActivityDay {
  date: string;
  count: number;
}

interface AuditEntry {
  timestamp: string;
  firewall_result: string;
}

/**
 * Fetch 7-day memory activity and threat trends for sparklines.
 *
 * - memoryTrend: memories created per day (last 7 days)
 * - threatTrend: threats blocked per day (last 7 days)
 */
export function useActivityTrend(): {
  memoryTrend: number[];
  threatTrend: number[];
} {
  // Memory activity — reuse the existing /api/memories/activity endpoint
  const { data: activityData } = useQuery({
    queryKey: ['activity-trend'],
    queryFn: async (): Promise<{ activity: ActivityDay[] }> => {
      const res = await authFetch(`${API_BASE}/api/memories/activity`);
      if (!res.ok) throw new Error('Failed to fetch activity');
      return res.json();
    },
    staleTime: 5 * 60 * 1000,
    refetchInterval: 5 * 60 * 1000,
  });

  // Threat data — fetch blocked audit logs from the last 7 days
  const sevenDaysAgo = new Date();
  sevenDaysAgo.setDate(sevenDaysAgo.getDate() - 7);
  const startTime = sevenDaysAgo.toISOString();

  const { data: auditData } = useQuery({
    queryKey: ['threat-trend'],
    queryFn: async (): Promise<{ logs: AuditEntry[] }> => {
      const params = new URLSearchParams({
        firewallResult: 'BLOCK',
        startTime,
        limit: '500',
      });
      const res = await authFetch(`${API_BASE}/api/v1/audit?${params}`);
      if (!res.ok) throw new Error('Failed to fetch audit logs');
      return res.json();
    },
    staleTime: 5 * 60 * 1000,
    refetchInterval: 5 * 60 * 1000,
  });

  // Build last-7-days date keys (YYYY-MM-DD)
  const last7Days: string[] = [];
  for (let i = 6; i >= 0; i--) {
    const d = new Date();
    d.setDate(d.getDate() - i);
    last7Days.push(d.toISOString().slice(0, 10));
  }

  // Map memory activity to 7-day array
  const activityMap = new Map<string, number>();
  if (activityData?.activity) {
    for (const day of activityData.activity) {
      activityMap.set(day.date, day.count);
    }
  }
  const memoryTrend = last7Days.map(date => activityMap.get(date) ?? 0);

  // Aggregate blocked audit logs by day
  const threatMap = new Map<string, number>();
  if (auditData?.logs) {
    for (const log of auditData.logs) {
      const day = log.timestamp.slice(0, 10);
      threatMap.set(day, (threatMap.get(day) ?? 0) + 1);
    }
  }
  const threatTrend = last7Days.map(date => threatMap.get(date) ?? 0);

  return { memoryTrend, threatTrend };
}
