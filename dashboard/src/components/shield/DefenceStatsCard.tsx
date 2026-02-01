'use client';

import { useAuditStats } from '@/hooks/useDefence';

interface Props {
  timeRange: '24h' | '7d' | '30d';
}

export function DefenceStatsCard({ timeRange }: Props) {
  const { data: stats, isLoading } = useAuditStats(timeRange);

  if (isLoading) {
    return (
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-4">
        <h3 className="text-sm font-medium text-slate-300 mb-4">Stats Summary</h3>
        <div className="text-xs text-slate-500 animate-pulse">Loading...</div>
      </div>
    );
  }

  if (!stats) {
    return (
      <div className="bg-slate-900 border border-slate-800 rounded-xl p-4">
        <h3 className="text-sm font-medium text-slate-300 mb-4">Stats Summary</h3>
        <div className="text-xs text-slate-500">No data</div>
      </div>
    );
  }

  const total = stats.totalOperations || 1;
  const blockRate = ((stats.blockedCount / total) * 100).toFixed(1);

  // Top threat types from threatBreakdown
  const threats = Object.entries(stats.threatBreakdown || {})
    .sort((a, b) => b[1] - a[1])
    .slice(0, 5);

  return (
    <div className="bg-slate-900 border border-slate-800 rounded-xl p-4">
      <h3 className="text-sm font-medium text-slate-300 mb-4">Stats Summary</h3>

      {/* Key metrics */}
      <div className="grid grid-cols-2 gap-3 mb-4">
        <div className="bg-slate-800/50 rounded-lg p-3 text-center">
          <div className="text-2xl font-bold text-white">{stats.totalOperations}</div>
          <div className="text-[10px] text-slate-500 uppercase">Total Scans</div>
        </div>
        <div className="bg-slate-800/50 rounded-lg p-3 text-center">
          <div className={`text-2xl font-bold ${parseFloat(blockRate) > 10 ? 'text-red-400' : 'text-green-400'}`}>
            {blockRate}%
          </div>
          <div className="text-[10px] text-slate-500 uppercase">Block Rate</div>
        </div>
      </div>

      {/* Top sources */}
      {stats.topSources.length > 0 && (
        <div className="mb-4">
          <div className="text-[10px] text-slate-500 uppercase mb-2">Top Sources</div>
          <div className="space-y-1">
            {stats.topSources.slice(0, 3).map((s) => (
              <div key={s.source} className="flex items-center justify-between">
                <span className="text-xs text-slate-400">{s.source}</span>
                <span className="text-xs text-slate-500">{s.count}</span>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Top threat types */}
      {threats.length > 0 && (
        <div>
          <div className="text-[10px] text-slate-500 uppercase mb-2">Threat Types</div>
          <div className="space-y-1">
            {threats.map(([type, count]) => (
              <div key={type} className="flex items-center justify-between">
                <span className="text-xs text-slate-400">{type}</span>
                <span className="text-xs font-medium text-red-400">{count}</span>
              </div>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
