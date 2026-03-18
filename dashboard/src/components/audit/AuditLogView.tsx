'use client';

import { useState, useMemo, useEffect, useCallback } from 'react';
import { useAuditLogs, AuditEntry } from '@/hooks/useDefence';
import { useDashboardStore } from '@/lib/store';
import { AuditExportPanel } from './AuditExportPanel';
import { AuditDetailPanel } from './AuditDetailPanel';

const RESULT_COLORS: Record<string, string> = {
  ALLOW: 'bg-green-500/10 text-green-400',
  BLOCK: 'bg-red-500/10 text-red-400',
  QUARANTINE: 'bg-yellow-500/10 text-yellow-400',
};

export function AuditLogView() {
  const { projectFilter, selectedAuditEntry, setSelectedAuditEntry } = useDashboardStore();
  const [timeRange, setTimeRange] = useState<'24h' | '7d' | '30d'>('24h');
  const [sourceFilter, setSourceFilter] = useState<string | undefined>(undefined);
  const [resultFilter, setResultFilter] = useState<string | undefined>(undefined);

  const hoursMap = { '24h': 24, '7d': 168, '30d': 720 } as const;
  const [baseTime, setBaseTime] = useState(() => Date.now());
  useEffect(() => { setBaseTime(Date.now()); }, [timeRange]);
  const since = useMemo(() => {
    const ms = baseTime - hoursMap[timeRange] * 3600_000;
    return new Date(Math.floor(ms / 60_000) * 60_000).toISOString();
    // eslint-disable-next-line react-hooks/exhaustive-deps -- hoursMap is stable
  }, [baseTime, timeRange]);

  const { data, isLoading } = useAuditLogs({
    startTime: since,
    source: sourceFilter,
    firewallResult: resultFilter,
    project: projectFilter || undefined,
    limit: 200,
  });

  const logs = useMemo(() => data?.logs ?? [], [data?.logs]);
  const blockedCount = logs.filter((log) => log.firewall_result === 'BLOCK').length;
  const quarantinedCount = logs.filter((log) => log.firewall_result === 'QUARANTINE').length;
  const allowedCount = logs.filter((log) => log.firewall_result === 'ALLOW').length;

  // Keyboard navigation: Escape closes, Up/Down navigates
  const handleKeyDown = useCallback((e: KeyboardEvent) => {
    if (!selectedAuditEntry || logs.length === 0) return;
    const idx = logs.findIndex((l) => l.id === selectedAuditEntry.id);
    if (e.key === 'Escape') {
      setSelectedAuditEntry(null);
    } else if (e.key === 'ArrowDown' && idx < logs.length - 1) {
      e.preventDefault();
      setSelectedAuditEntry(logs[idx + 1]);
    } else if (e.key === 'ArrowUp' && idx > 0) {
      e.preventDefault();
      setSelectedAuditEntry(logs[idx - 1]);
    }
  }, [selectedAuditEntry, logs, setSelectedAuditEntry]);

  useEffect(() => {
    window.addEventListener('keydown', handleKeyDown);
    return () => window.removeEventListener('keydown', handleKeyDown);
  }, [handleKeyDown]);

  const handleRowClick = (entry: AuditEntry) => {
    setSelectedAuditEntry(
      selectedAuditEntry?.id === entry.id ? null : entry
    );
  };

  return (
    <div className="h-full overflow-y-auto bg-slate-950">
      <div className="mx-auto max-w-7xl space-y-6 p-6">
        <section className="rounded-2xl border border-slate-800 bg-slate-900/70 p-5">
          <div className="flex flex-col gap-4 xl:flex-row xl:items-start xl:justify-between mb-3">
            <div>
              <h2 className="text-lg font-semibold text-white">Audit Log</h2>
              <p className="mt-1 text-sm text-slate-400">
                Start with the result counts and pick a row only when you need the deeper payload. Export stays available, but it should not dominate the first screen.
              </p>
            </div>
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

          <div className="mb-4 grid gap-3 md:grid-cols-4">
            <div className="rounded-xl border border-slate-800 bg-slate-950/60 p-3">
              <div className="text-[10px] uppercase tracking-[0.18em] text-slate-500">Entries</div>
              <div className="mt-1 text-xl font-semibold text-white">{logs.length}</div>
            </div>
            <div className="rounded-xl border border-slate-800 bg-slate-950/60 p-3">
              <div className="text-[10px] uppercase tracking-[0.18em] text-slate-500">Allowed</div>
              <div className="mt-1 text-xl font-semibold text-emerald-300">{allowedCount}</div>
            </div>
            <div className="rounded-xl border border-slate-800 bg-slate-950/60 p-3">
              <div className="text-[10px] uppercase tracking-[0.18em] text-slate-500">Blocked</div>
              <div className="mt-1 text-xl font-semibold text-red-300">{blockedCount}</div>
            </div>
            <div className="rounded-xl border border-slate-800 bg-slate-950/60 p-3">
              <div className="text-[10px] uppercase tracking-[0.18em] text-slate-500">Quarantined</div>
              <div className="mt-1 text-xl font-semibold text-amber-300">{quarantinedCount}</div>
            </div>
          </div>

          <div className="flex gap-2 flex-wrap">
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

            <button
              onClick={() => setSelectedAuditEntry(null)}
              className="ml-auto rounded-full border border-slate-700 bg-slate-900/70 px-3 py-1 text-xs text-slate-300 transition-colors hover:border-slate-500 hover:text-white"
            >
              Clear selection
            </button>
          </div>
        </section>

        <div className={`grid gap-6 ${selectedAuditEntry ? 'xl:grid-cols-[minmax(0,1.35fr)_360px]' : ''}`}>
          <section className="rounded-2xl border border-slate-800 bg-slate-900/70 overflow-hidden">
            {isLoading ? (
              <div className="flex items-center justify-center h-32">
                <div className="text-xs text-slate-500 animate-pulse">Loading audit logs...</div>
              </div>
            ) : logs.length === 0 ? (
              <div className="flex items-center justify-center h-32">
                <div className="text-xs text-slate-500">No audit entries for this period</div>
              </div>
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full text-xs">
                  <thead className="bg-slate-950/80">
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
                      <tr
                        key={log.id}
                        onClick={() => handleRowClick(log)}
                        className={`border-b border-slate-800/50 cursor-pointer transition-colors ${
                          selectedAuditEntry?.id === log.id
                            ? 'bg-cyan-500/10 hover:bg-cyan-500/15'
                            : 'hover:bg-slate-800/30'
                        }`}
                      >
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
              </div>
            )}
          </section>

          {selectedAuditEntry && (
            <div className="xl:sticky xl:top-6 self-start">
              <AuditDetailPanel
                entry={selectedAuditEntry}
                onClose={() => setSelectedAuditEntry(null)}
              />
            </div>
          )}
        </div>

        <details className="rounded-2xl border border-slate-800 bg-slate-900/50 p-4">
          <summary className="cursor-pointer list-none text-sm font-medium text-slate-200">
            Export audit trail
          </summary>
          <div className="mt-4">
            <AuditExportPanel />
          </div>
        </details>
      </div>
    </div>
  );
}
