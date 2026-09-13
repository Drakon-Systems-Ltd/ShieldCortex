'use client';

import { useAuditLogs } from '@/hooks/useDefence';
import { useDashboardStore } from '@/lib/store';
import { useMemo, useState, useEffect } from 'react';

interface Props {
  timeRange: '24h' | '7d' | '30d';
}

export function ThreatTimeline({ timeRange }: Props) {
  const { projectFilter } = useDashboardStore();
  const hoursMap = { '24h': 24, '7d': 168, '30d': 720 } as const;
  const [baseTime, setBaseTime] = useState(() => Date.now());
  useEffect(() => { setBaseTime(Date.now()); }, [timeRange]);
  // Round to nearest minute so the query key stays stable across re-renders
  const since = useMemo(() => {
    const ms = baseTime - hoursMap[timeRange] * 3600_000;
    const rounded = Math.floor(ms / 60_000) * 60_000;
    return new Date(rounded).toISOString();
    // eslint-disable-next-line react-hooks/exhaustive-deps -- hoursMap is stable
  }, [baseTime, timeRange]);

  const { data, isLoading, isError } = useAuditLogs({ startTime: since, project: projectFilter || undefined, limit: 500 });

  // Group logs by time bucket
  const buckets = useMemo(() => {
    if (!data?.logs.length) return [];

    const bucketSize = timeRange === '24h' ? 3600_000 : timeRange === '7d' ? 6 * 3600_000 : 24 * 3600_000;
    const bucketCount = timeRange === '24h' ? 24 : timeRange === '7d' ? 28 : 30;
    const now = baseTime;

    const result = Array.from({ length: bucketCount }, (_, i) => ({
      time: now - (bucketCount - 1 - i) * bucketSize,
      allowed: 0,
      blocked: 0,
      quarantined: 0,
    }));

    for (const log of data.logs) {
      const t = new Date(log.timestamp).getTime();
      const rawIdx = Math.floor((t - (now - bucketCount * bucketSize)) / bucketSize);
      const idx = Math.min(Math.max(rawIdx, 0), bucketCount - 1);
      if (rawIdx >= 0 && rawIdx <= bucketCount) {
        if (log.firewall_result === 'ALLOW') result[idx].allowed++;
        else if (log.firewall_result === 'BLOCK') result[idx].blocked++;
        else if (log.firewall_result === 'QUARANTINE') result[idx].quarantined++;
      }
    }

    return result;
  }, [data, timeRange, baseTime]);

  const maxValue = Math.max(1, ...buckets.map((b) => b.allowed + b.blocked + b.quarantined));

  return (
    <div className="bg-[var(--sc-bg-surface)] border border-[var(--sc-border)] rounded-xl p-4">
      <h3 className="text-sm font-medium text-[var(--sc-text-primary)] mb-4">Threat Timeline</h3>

      {isLoading ? (
        <div className="h-32 flex items-center justify-center">
          <div className="text-xs text-[var(--sc-text-muted)] animate-pulse">Loading timeline...</div>
        </div>
      ) : isError ? (
        <div className="h-32 flex items-center justify-center">
          <div className="text-xs text-[var(--sc-coral)]">Failed to load timeline</div>
        </div>
      ) : buckets.length === 0 ? (
        <div className="h-32 flex items-center justify-center">
          <div className="text-xs text-[var(--sc-text-muted)]">No audit data</div>
        </div>
      ) : (
        <>
          {/* Bar chart */}
          <div className="flex gap-px h-32">
            {buckets.map((bucket, i) => {
              const total = bucket.allowed + bucket.blocked + bucket.quarantined;
              const height = (total / maxValue) * 100;
              const blockedPct = total > 0 ? (bucket.blocked / total) * 100 : 0;
              const quarantinedPct = total > 0 ? (bucket.quarantined / total) * 100 : 0;

              return (
                <div
                  key={i}
                  className="flex-1 flex flex-col justify-end"
                  title={`${new Date(bucket.time).toLocaleString()}: ${bucket.allowed} allowed, ${bucket.blocked} blocked, ${bucket.quarantined} quarantined`}
                >
                  <div
                    className="w-full rounded-t-sm overflow-hidden"
                    style={{ height: `${Math.max(height, total > 0 ? 2 : 0)}%` }}
                  >
                    {/* Stacked: blocked (red) bottom, quarantined (yellow) middle, allowed (green) top */}
                    <div className="w-full h-full flex flex-col-reverse">
                      {bucket.blocked > 0 && (
                        <div className="bg-[var(--sc-coral)]" style={{ height: `${blockedPct}%` }} />
                      )}
                      {bucket.quarantined > 0 && (
                        <div className="bg-[var(--sc-amber)]" style={{ height: `${quarantinedPct}%` }} />
                      )}
                      <div className="bg-[var(--sc-cyan)]/60 flex-1" />
                    </div>
                  </div>
                </div>
              );
            })}
          </div>

          {/* Legend */}
          <div className="flex gap-4 mt-3 justify-center">
            <div className="flex items-center gap-1">
              <div className="w-2 h-2 rounded-full bg-[var(--sc-cyan)]/60" />
              <span className="text-[10px] text-[var(--sc-text-muted)]">Allowed</span>
            </div>
            <div className="flex items-center gap-1">
              <div className="w-2 h-2 rounded-full bg-[var(--sc-coral)]" />
              <span className="text-[10px] text-[var(--sc-text-muted)]">Blocked</span>
            </div>
            <div className="flex items-center gap-1">
              <div className="w-2 h-2 rounded-full bg-[var(--sc-amber)]" />
              <span className="text-[10px] text-[var(--sc-text-muted)]">Quarantined</span>
            </div>
          </div>

          {/* Navigate to full audit view */}
          <button
            onClick={() => useDashboardStore.getState().setViewMode('audit')}
            className="mt-3 w-full text-center text-xs text-[var(--sc-cyan)] hover:text-[var(--sc-cyan)] transition-colors py-1"
          >
            View detailed audit log &rarr;
          </button>
        </>
      )}
    </div>
  );
}
