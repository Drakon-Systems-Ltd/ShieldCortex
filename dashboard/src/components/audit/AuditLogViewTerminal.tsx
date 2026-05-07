'use client';

import { useState, useMemo, useEffect, useCallback } from 'react';
import { useAuditLogs, AuditEntry } from '@/hooks/useDefence';
import { useDashboardStore } from '@/lib/store';
import { GlassCard } from '@/components/ds/GlassCard';
import { Badge, riskVariant } from '@/components/ds/Badge';
import { AuditExportPanel } from './AuditExportPanel';
import { AuditDetailPanel } from './AuditDetailPanel';

const RESULT_VARIANT: Record<string, 'safe' | 'critical' | 'medium' | 'info'> = {
  ALLOW: 'safe',
  BLOCK: 'critical',
  QUARANTINE: 'medium',
};

function formatTs(ts: string): string {
  // ISO-style timestamp without locale formatting — terminal-friendly.
  return new Date(ts).toISOString().replace('T', ' ').replace(/\.\d+Z$/, 'Z');
}

export function AuditLogViewTerminal() {
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
    setSelectedAuditEntry(selectedAuditEntry?.id === entry.id ? null : entry);
  };

  return (
    <div className="space-y-6">
      <GlassCard
        title="audit.filter"
        statusLine={`window=${timeRange} · entries=${logs.length} · allow=${allowedCount} · block=${blockedCount} · quarantine=${quarantinedCount}`}
      >
        <div className="flex flex-wrap items-center gap-3 font-mono text-xs">
          <span className="text-[var(--term-text-muted)]">range</span>
          <span className="text-[var(--term-text-muted)]" aria-hidden>=</span>
          <div className="flex gap-1">
            {(['24h', '7d', '30d'] as const).map((range) => (
              <button
                key={range}
                type="button"
                onClick={() => setTimeRange(range)}
                className={`px-2 py-0.5 transition-colors ${
                  timeRange === range
                    ? 'text-[var(--term-electric-fg)]'
                    : 'text-[var(--term-text-muted)] hover:text-[var(--term-text)]'
                }`}
              >
                [{range}]
              </button>
            ))}
          </div>

          <span className="text-[var(--term-text-muted)] ml-3">result</span>
          <span className="text-[var(--term-text-muted)]" aria-hidden>=</span>
          <select
            aria-label="Filter by firewall result"
            value={resultFilter || ''}
            onChange={(e) => setResultFilter(e.target.value || undefined)}
            className="bg-[var(--term-surface-2)] border border-[var(--term-border)] text-[var(--term-text)] text-xs rounded-sm px-2 py-0.5 font-mono focus:outline-none focus:border-[var(--term-electric)]"
          >
            <option value="">*</option>
            <option value="ALLOW">ALLOW</option>
            <option value="BLOCK">BLOCK</option>
            <option value="QUARANTINE">QUARANTINE</option>
          </select>

          <span className="text-[var(--term-text-muted)] ml-3">source</span>
          <span className="text-[var(--term-text-muted)]" aria-hidden>=</span>
          <select
            aria-label="Filter by source"
            value={sourceFilter || ''}
            onChange={(e) => setSourceFilter(e.target.value || undefined)}
            className="bg-[var(--term-surface-2)] border border-[var(--term-border)] text-[var(--term-text)] text-xs rounded-sm px-2 py-0.5 font-mono focus:outline-none focus:border-[var(--term-electric)]"
          >
            <option value="">*</option>
            <option value="hook">hook</option>
            <option value="api">api</option>
            <option value="agent">agent</option>
            <option value="user">user</option>
            <option value="cli">cli</option>
          </select>

          <button
            type="button"
            onClick={() => setSelectedAuditEntry(null)}
            className="ml-auto text-[var(--term-text-muted)] hover:text-[var(--term-text)]"
          >
            [clear]
          </button>
        </div>
      </GlassCard>

      <div className={`grid gap-6 ${selectedAuditEntry ? 'xl:grid-cols-[minmax(0,1.35fr)_360px]' : ''}`}>
        <GlassCard
          title="audit.log"
          bodyPadding={false}
          statusLine={isLoading ? 'loading…' : `${logs.length} entr${logs.length === 1 ? 'y' : 'ies'}`}
        >
          {isLoading ? (
            <div className="flex items-center justify-center h-32 font-mono">
              <div className="text-xs text-[var(--term-text-muted)] animate-pulse">$ tail -f audit.log…</div>
            </div>
          ) : logs.length === 0 ? (
            <div className="flex items-center justify-center h-32 font-mono">
              <div className="text-xs text-[var(--term-text-muted)]"># no audit entries for this period</div>
            </div>
          ) : (
            <div className="overflow-x-auto font-mono">
              <table className="w-full text-xs">
                <thead className="bg-[var(--term-surface-2)] sticky top-0">
                  <tr className="border-b border-[var(--term-border)]">
                    <th className="text-left text-[var(--term-text-muted)] font-normal px-3 py-2 uppercase tracking-wider text-[10px]">timestamp</th>
                    <th className="text-left text-[var(--term-text-muted)] font-normal px-3 py-2 uppercase tracking-wider text-[10px]">result</th>
                    <th className="text-left text-[var(--term-text-muted)] font-normal px-3 py-2 uppercase tracking-wider text-[10px]">source</th>
                    <th className="text-right text-[var(--term-text-muted)] font-normal px-3 py-2 uppercase tracking-wider text-[10px]">trust</th>
                    <th className="text-right text-[var(--term-text-muted)] font-normal px-3 py-2 uppercase tracking-wider text-[10px]">anomaly</th>
                    <th className="text-left text-[var(--term-text-muted)] font-normal px-3 py-2 uppercase tracking-wider text-[10px]">reason</th>
                  </tr>
                </thead>
                <tbody>
                  {logs.map((log) => {
                    const variant = RESULT_VARIANT[log.firewall_result] ?? riskVariant('INFO');
                    const isSelected = selectedAuditEntry?.id === log.id;
                    return (
                      <tr
                        key={log.id}
                        onClick={() => handleRowClick(log)}
                        className={`border-b border-[var(--term-border)] cursor-pointer transition-colors ${
                          isSelected
                            ? 'bg-[var(--term-surface-2)]'
                            : 'hover:bg-[var(--term-surface-2)]'
                        }`}
                      >
                        <td className="px-3 py-1.5 text-[var(--term-text-muted)] whitespace-nowrap tabular-nums">
                          {formatTs(log.timestamp)}
                        </td>
                        <td className="px-3 py-1.5 whitespace-nowrap">
                          <Badge variant={variant}>{log.firewall_result}</Badge>
                        </td>
                        <td className="px-3 py-1.5 text-[var(--term-text)]">
                          {log.source_type}
                        </td>
                        <td className="px-3 py-1.5 text-right text-[var(--term-text-dim)] tabular-nums">
                          {log.trust_score.toFixed(1)}
                        </td>
                        <td className="px-3 py-1.5 text-right tabular-nums">
                          <span className={
                            log.anomaly_score > 0.5 ? 'text-[var(--term-danger)]'
                            : log.anomaly_score > 0.2 ? 'text-[var(--term-warn)]'
                            : 'text-[var(--term-text-muted)]'
                          }>
                            {log.anomaly_score.toFixed(2)}
                          </span>
                        </td>
                        <td className="px-3 py-1.5 text-[var(--term-text-dim)] max-w-xs truncate">
                          {log.reason || '—'}
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          )}
        </GlassCard>

        {selectedAuditEntry && (
          <div className="xl:sticky xl:top-6 self-start">
            <AuditDetailPanel
              entry={selectedAuditEntry}
              onClose={() => setSelectedAuditEntry(null)}
            />
          </div>
        )}
      </div>

      <details className="glass-card p-5">
        <summary className="cursor-pointer list-none font-mono text-sm text-[var(--term-text)]">
          <span className="text-[var(--term-electric-fg)]">$</span> shieldcortex audit export
        </summary>
        <div className="mt-4">
          <AuditExportPanel />
        </div>
      </details>
    </div>
  );
}
