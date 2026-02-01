'use client';

import { useAuditLogs } from '@/hooks/useDefence';
import { useMemo } from 'react';

interface Props {
  timeRange: '24h' | '7d' | '30d';
}

export function ThreatTimeline({ timeRange }: Props) {
  const hoursMap = { '24h': 24, '7d': 168, '30d': 720 };
  const since = new Date(Date.now() - hoursMap[timeRange] * 3600_000).toISOString();

  const { data, isLoading } = useAuditLogs({ startTime: since, limit: 500 });

  // Group logs by time bucket
  const buckets = useMemo(() => {
    if (!data?.logs.length) return [];

    const bucketSize = timeRange === '24h' ? 3600_000 : timeRange === '7d' ? 6 * 3600_000 : 24 * 3600_000;
    const bucketCount = timeRange === '24h' ? 24 : timeRange === '7d' ? 28 : 30;
    const now = Date.now();

    const result = Array.from({ length: bucketCount }, (_, i) => ({
      time: now - (bucketCount - 1 - i) * bucketSize,
      allowed: 0,
      blocked: 0,
      quarantined: 0,
    }));

    for (const log of data.logs) {
      const t = new Date(log.timestamp).getTime();
      const idx = Math.floor((t - (now - bucketCount * bucketSize)) / bucketSize);
      if (idx >= 0 && idx < bucketCount) {
        if (log.firewall_result === 'ALLOW') result[idx].allowed++;
        else if (log.firewall_result === 'BLOCK') result[idx].blocked++;
        else if (log.firewall_result === 'QUARANTINE') result[idx].quarantined++;
      }
    }

    return result;
  }, [data, timeRange]);

  const maxValue = Math.max(1, ...buckets.map((b) => b.allowed + b.blocked + b.quarantined));

  return (
    <div className="bg-slate-900 border border-slate-800 rounded-xl p-4">
      <h3 className="text-sm font-medium text-slate-300 mb-4">Threat Timeline</h3>

      {isLoading ? (
        <div className="h-32 flex items-center justify-center">
          <div className="text-xs text-slate-500 animate-pulse">Loading timeline...</div>
        </div>
      ) : buckets.length === 0 ? (
        <div className="h-32 flex items-center justify-center">
          <div className="text-xs text-slate-500">No audit data</div>
        </div>
      ) : (
        <>
          {/* Bar chart */}
          <div className="flex items-end gap-px h-32">
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
                        <div className="bg-red-500" style={{ height: `${blockedPct}%` }} />
                      )}
                      {bucket.quarantined > 0 && (
                        <div className="bg-yellow-500" style={{ height: `${quarantinedPct}%` }} />
                      )}
                      <div className="bg-emerald-500/60 flex-1" />
                    </div>
                  </div>
                </div>
              );
            })}
          </div>

          {/* Legend */}
          <div className="flex gap-4 mt-3 justify-center">
            <div className="flex items-center gap-1">
              <div className="w-2 h-2 rounded-full bg-emerald-500/60" />
              <span className="text-[10px] text-slate-500">Allowed</span>
            </div>
            <div className="flex items-center gap-1">
              <div className="w-2 h-2 rounded-full bg-red-500" />
              <span className="text-[10px] text-slate-500">Blocked</span>
            </div>
            <div className="flex items-center gap-1">
              <div className="w-2 h-2 rounded-full bg-yellow-500" />
              <span className="text-[10px] text-slate-500">Quarantined</span>
            </div>
          </div>
        </>
      )}
    </div>
  );
}
