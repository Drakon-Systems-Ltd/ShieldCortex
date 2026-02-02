'use client';

import { useState, useMemo } from 'react';
import { useAuditLogs } from '@/hooks/useDefence';
import { useDashboardStore } from '@/lib/store';

const RESULT_COLORS: Record<string, string> = {
  ALLOW: 'bg-green-500/10 text-green-400',
  BLOCK: 'bg-red-500/10 text-red-400',
  QUARANTINE: 'bg-yellow-500/10 text-yellow-400',
};

export function AuditLogView() {
  const { projectFilter } = useDashboardStore();
  const [timeRange, setTimeRange] = useState<'24h' | '7d' | '30d'>('24h');
  const [sourceFilter, setSourceFilter] = useState<string | undefined>(undefined);
  const [resultFilter, setResultFilter] = useState<string | undefined>(undefined);

  const hoursMap = { '24h': 24, '7d': 168, '30d': 720 };
  const since = useMemo(() => {
    const ms = Date.now() - hoursMap[timeRange] * 3600_000;
    return new Date(Math.floor(ms / 60_000) * 60_000).toISOString();
  }, [timeRange]);

  const { data, isLoading } = useAuditLogs({
    startTime: since,
    source: sourceFilter,
    firewallResult: resultFilter,
    project: projectFilter || undefined,
    limit: 200,
  });

  const logs = data?.logs ?? [];

  return (
    <div className="h-full flex flex-col overflow-hidden">
      {/* Header & Filters */}
      <div className="p-4 border-b border-slate-800 shrink-0">
        <div className="flex items-center justify-between mb-3">
          <h2 className="text-lg font-semibold text-white">Audit Log</h2>
          <div className="flex gap-1 bg-slate-800 rounded-lg p-0.5">
            {(['24h', '7d', '30d'] as const).map((range) => (
              <button
                key={range}
                onClick={() => setTimeRange(range)}
                className={`px-3 py-1 text-xs rounded-md transition-colors ${
                  timeRange === range ? 'bg-cyan-600 text-white' : 'text-slate-400 hover:text-white'
                }`}
              >
                {range}
              </button>
            ))}
          </div>
        </div>

        <div className="flex gap-2">
          {/* Result filter */}
          <select
            value={resultFilter || ''}
            onChange={(e) => setResultFilter(e.target.value || undefined)}
            className="bg-slate-800 border border-slate-700 text-white text-xs rounded-lg px-2 py-1"
          >
            <option value="">All Results</option>
            <option value="ALLOW">Allowed</option>
            <option value="BLOCK">Blocked</option>
            <option value="QUARANTINE">Quarantined</option>
          </select>

          {/* Source filter */}
          <select
            value={sourceFilter || ''}
            onChange={(e) => setSourceFilter(e.target.value || undefined)}
            className="bg-slate-800 border border-slate-700 text-white text-xs rounded-lg px-2 py-1"
          >
            <option value="">All Sources</option>
            <option value="hook">Hook</option>
            <option value="api">API</option>
            <option value="agent">Agent</option>
            <option value="user">User</option>
            <option value="cli">CLI</option>
          </select>

          <span className="text-xs text-slate-500 self-center ml-auto">
            {logs.length} entries
          </span>
        </div>
      </div>

      {/* Table */}
      <div className="flex-1 overflow-y-auto">
        {isLoading ? (
          <div className="flex items-center justify-center h-32">
            <div className="text-xs text-slate-500 animate-pulse">Loading audit logs...</div>
          </div>
        ) : logs.length === 0 ? (
          <div className="flex items-center justify-center h-32">
            <div className="text-xs text-slate-500">No audit entries for this period</div>
          </div>
        ) : (
          <table className="w-full text-xs">
            <thead className="sticky top-0 bg-slate-900">
              <tr className="border-b border-slate-800">
                <th className="text-left text-slate-500 font-medium px-4 py-2">Time</th>
                <th className="text-left text-slate-500 font-medium px-4 py-2">Source</th>
                <th className="text-left text-slate-500 font-medium px-4 py-2">Result</th>
                <th className="text-left text-slate-500 font-medium px-4 py-2">Trust</th>
                <th className="text-left text-slate-500 font-medium px-4 py-2">Anomaly</th>
                <th className="text-left text-slate-500 font-medium px-4 py-2">Reason</th>
              </tr>
            </thead>
            <tbody>
              {logs.map((log) => (
                <tr key={log.id} className="border-b border-slate-800/50 hover:bg-slate-800/30">
                  <td className="px-4 py-2 text-slate-400 whitespace-nowrap">
                    {new Date(log.timestamp).toLocaleString()}
                  </td>
                  <td className="px-4 py-2 text-slate-300">
                    {log.source_type}
                  </td>
                  <td className="px-4 py-2">
                    <span className={`px-1.5 py-0.5 rounded text-[10px] font-medium ${RESULT_COLORS[log.firewall_result] || 'text-slate-400'}`}>
                      {log.firewall_result}
                    </span>
                  </td>
                  <td className="px-4 py-2 text-slate-400">
                    {log.trust_score.toFixed(1)}
                  </td>
                  <td className="px-4 py-2">
                    <span className={log.anomaly_score > 0.5 ? 'text-red-400' : log.anomaly_score > 0.2 ? 'text-yellow-400' : 'text-slate-400'}>
                      {log.anomaly_score.toFixed(2)}
                    </span>
                  </td>
                  <td className="px-4 py-2 text-slate-400 max-w-xs truncate">
                    {log.reason || '—'}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}
