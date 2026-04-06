'use client';

import { useState, useMemo, useEffect, useCallback } from 'react';
import { useAuditLogs, AuditEntry } from '@/hooks/useDefence';
import { useDashboardStore } from '@/lib/store';
import { AuditExportPanel } from './AuditExportPanel';
import { AuditDetailPanel } from './AuditDetailPanel';

const RESULT_COLORS: Record<string, string> = {
  ALLOW: 'bg-[var(--sc-cyan)]/10 text-[var(--sc-cyan)]',
  BLOCK: 'bg-[var(--sc-coral)]/10 text-[var(--sc-coral)]',
  QUARANTINE: 'bg-[var(--sc-amber)]/10 text-[var(--sc-amber)]',
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
    <div className="space-y-6">
      <div className="glass-card-strong p-5">
        <div className="flex flex-col gap-4 xl:flex-row xl:items-start xl:justify-between mb-3">
          <div className="flex gap-1 bg-[var(--sc-bg-elevated)] rounded-lg p-0.5 ml-auto">
            {(['24h', '7d', '30d'] as const).map((range) => (
              <button
                key={range}
                onClick={() => setTimeRange(range)}
                className={`px-3 py-1 text-xs rounded-md transition-colors ${
                  timeRange === range ? 'bg-[var(--sc-cyan)] text-[var(--sc-text-primary)]' : 'text-[var(--sc-text-secondary)] hover:text-[var(--sc-text-primary)]'
                }`}
              >
                {range}
              </button>
            ))}
          </div>
        </div>

        <div className="mb-4 grid gap-3 md:grid-cols-4">
          <div className="rounded-xl border border-[var(--sc-border)] bg-[var(--sc-bg-deep)] p-3">
            <div className="text-[10px] uppercase tracking-[0.18em] text-[var(--sc-text-muted)]">Entries</div>
            <div className="mt-1 text-xl font-semibold text-[var(--sc-text-primary)]">{logs.length}</div>
          </div>
          <div className="rounded-xl border border-[var(--sc-border)] bg-[var(--sc-bg-deep)] p-3">
            <div className="text-[10px] uppercase tracking-[0.18em] text-[var(--sc-text-muted)]">Allowed</div>
            <div className="mt-1 text-xl font-semibold text-[var(--sc-cyan)]">{allowedCount}</div>
          </div>
          <div className="rounded-xl border border-[var(--sc-border)] bg-[var(--sc-bg-deep)] p-3">
            <div className="text-[10px] uppercase tracking-[0.18em] text-[var(--sc-text-muted)]">Blocked</div>
            <div className="mt-1 text-xl font-semibold text-[var(--sc-coral)]">{blockedCount}</div>
          </div>
          <div className="rounded-xl border border-[var(--sc-border)] bg-[var(--sc-bg-deep)] p-3">
            <div className="text-[10px] uppercase tracking-[0.18em] text-[var(--sc-text-muted)]">Quarantined</div>
            <div className="mt-1 text-xl font-semibold text-[var(--sc-amber)]">{quarantinedCount}</div>
          </div>
        </div>

        <div className="flex gap-2 flex-wrap">
          <select
            value={resultFilter || ''}
            onChange={(e) => setResultFilter(e.target.value || undefined)}
            className="bg-[var(--sc-bg-elevated)] border border-[var(--sc-border)] text-[var(--sc-text-primary)] text-xs rounded-lg px-2 py-1"
          >
            <option value="">All Results</option>
            <option value="ALLOW">Allowed</option>
            <option value="BLOCK">Blocked</option>
            <option value="QUARANTINE">Quarantined</option>
          </select>

          <select
            value={sourceFilter || ''}
            onChange={(e) => setSourceFilter(e.target.value || undefined)}
            className="bg-[var(--sc-bg-elevated)] border border-[var(--sc-border)] text-[var(--sc-text-primary)] text-xs rounded-lg px-2 py-1"
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
            className="ml-auto rounded-full border border-[var(--sc-border)] bg-[var(--sc-bg-surface)] px-3 py-1 text-xs text-[var(--sc-text-primary)] transition-colors hover:border-[var(--sc-border)] hover:text-[var(--sc-text-primary)]"
          >
            Clear selection
          </button>
        </div>
      </div>

      <div className={`grid gap-6 ${selectedAuditEntry ? 'xl:grid-cols-[minmax(0,1.35fr)_360px]' : ''}`}>
        <div className="glass-card overflow-hidden">
          {isLoading ? (
            <div className="flex items-center justify-center h-32">
              <div className="text-xs text-[var(--sc-text-muted)] animate-pulse">Loading audit logs...</div>
            </div>
          ) : logs.length === 0 ? (
            <div className="flex items-center justify-center h-32">
              <div className="text-xs text-[var(--sc-text-muted)]">No audit entries for this period</div>
            </div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-xs">
                <thead className="bg-[var(--sc-bg-deep)]">
                  <tr className="border-b border-[var(--sc-border)]">
                    <th className="text-left text-[var(--sc-text-muted)] font-medium px-4 py-2">Time</th>
                    <th className="text-left text-[var(--sc-text-muted)] font-medium px-4 py-2">Source</th>
                    <th className="text-left text-[var(--sc-text-muted)] font-medium px-4 py-2">Result</th>
                    <th className="text-left text-[var(--sc-text-muted)] font-medium px-4 py-2">Trust</th>
                    <th className="text-left text-[var(--sc-text-muted)] font-medium px-4 py-2">Anomaly</th>
                    <th className="text-left text-[var(--sc-text-muted)] font-medium px-4 py-2">Reason</th>
                  </tr>
                </thead>
                <tbody>
                  {logs.map((log) => (
                    <tr
                      key={log.id}
                      onClick={() => handleRowClick(log)}
                      className={`border-b border-[var(--sc-border)] cursor-pointer transition-colors ${
                        selectedAuditEntry?.id === log.id
                          ? 'bg-[var(--sc-cyan)]/10 hover:bg-[var(--sc-cyan)]/15'
                          : 'hover:bg-[var(--sc-surface-interactive)]'
                      }`}
                    >
                      <td className="px-4 py-2 text-[var(--sc-text-secondary)] whitespace-nowrap">
                        {new Date(log.timestamp).toLocaleString()}
                      </td>
                      <td className="px-4 py-2 text-[var(--sc-text-primary)]">
                        {log.source_type}
                      </td>
                      <td className="px-4 py-2">
                        <span className={`px-1.5 py-0.5 rounded text-[10px] font-medium ${RESULT_COLORS[log.firewall_result] || 'text-[var(--sc-text-secondary)]'}`}>
                          {log.firewall_result}
                        </span>
                      </td>
                      <td className="px-4 py-2 text-[var(--sc-text-secondary)]">
                        {log.trust_score.toFixed(1)}
                      </td>
                      <td className="px-4 py-2">
                        <span className={log.anomaly_score > 0.5 ? 'text-[var(--sc-coral)]' : log.anomaly_score > 0.2 ? 'text-[var(--sc-amber)]' : 'text-[var(--sc-text-secondary)]'}>
                          {log.anomaly_score.toFixed(2)}
                        </span>
                      </td>
                      <td className="px-4 py-2 text-[var(--sc-text-secondary)] max-w-xs truncate">
                        {log.reason || '\u2014'}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>

        {selectedAuditEntry && (
          <div className="xl:sticky xl:top-6 self-start">
            <AuditDetailPanel
              entry={selectedAuditEntry}
              onClose={() => setSelectedAuditEntry(null)}
            />
          </div>
        )}
      </div>

      <details className="glass-card p-6">
        <summary className="cursor-pointer list-none text-sm font-medium text-[var(--sc-text-primary)]">
          Export audit trail
        </summary>
        <div className="mt-4">
          <AuditExportPanel />
        </div>
      </details>
    </div>
  );
}
