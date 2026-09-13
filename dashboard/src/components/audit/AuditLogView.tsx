'use client';

import { useState, useMemo, useEffect, useCallback } from 'react';
import { CheckCircle2, ListChecks, ShieldAlert, ShieldQuestion } from 'lucide-react';
import { useAuditLogs, type AuditEntry } from '@/hooks/useDefence';
import { useDashboardStore } from '@/lib/store';
import { CardError } from '@/components/ds/CardError';
import { Drawer } from '@/components/ds/Drawer';
import { Select } from '@/components/ds/Field';
import { StatCard } from '@/components/ds/StatCard';
import { Table, type Column } from '@/components/ds/Table';
import { AuditExportPanel } from './AuditExportPanel';
import { AuditDetailPanel } from './AuditDetailPanel';

const RESULT_BADGE: Record<string, string> = {
  ALLOW: 'bg-[var(--sc-ok-soft)] text-[var(--sc-ok)]',
  BLOCK: 'bg-[var(--sc-danger-soft)] text-[var(--sc-danger)]',
  QUARANTINE: 'bg-[var(--sc-warn-soft)] text-[var(--sc-warn)]',
};

/** Protection → Audit (brief §8): one Table, filter chips, detail drawer,
 *  export. Replaces the Glass-shell twin this used to unconditionally
 *  re-export (retired to legacy-v1 per §13.5). */
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

  const { data, isLoading, isError, error, refetch } = useAuditLogs({
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

  const columns: Column<AuditEntry>[] = [
    {
      key: 'timestamp',
      header: 'Time',
      cell: (log) => new Date(log.timestamp).toLocaleString(),
      sortValue: (log) => new Date(log.timestamp).getTime(),
      className: 'whitespace-nowrap text-[var(--sc-text-dim)]',
    },
    { key: 'source', header: 'Source', cell: (log) => log.source_type, sortValue: (log) => log.source_type },
    {
      key: 'result',
      header: 'Result',
      cell: (log) => (
        <span className={`rounded px-1.5 py-0.5 text-[10px] font-medium ${RESULT_BADGE[log.firewall_result] ?? 'text-[var(--sc-text-dim)]'}`}>
          {log.firewall_result}
        </span>
      ),
      sortValue: (log) => log.firewall_result,
    },
    { key: 'trust', header: 'Trust', cell: (log) => log.trust_score.toFixed(1), sortValue: (log) => log.trust_score },
    {
      key: 'anomaly',
      header: 'Anomaly',
      cell: (log) => (
        <span className={log.anomaly_score > 0.5 ? 'text-[var(--sc-danger)]' : log.anomaly_score > 0.2 ? 'text-[var(--sc-warn)]' : 'text-[var(--sc-text-dim)]'}>
          {log.anomaly_score.toFixed(2)}
        </span>
      ),
      sortValue: (log) => log.anomaly_score,
    },
    {
      key: 'reason',
      header: 'Reason',
      cell: (log) => log.reason || '—',
      className: 'max-w-xs truncate text-[var(--sc-text-dim)]',
    },
  ];

  return (
    <div className="space-y-4">
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div className="flex items-center gap-1 rounded-lg bg-[var(--sc-surface-2)] p-0.5">
          {(['24h', '7d', '30d'] as const).map((range) => (
            <button
              key={range}
              type="button"
              onClick={() => setTimeRange(range)}
              className={`rounded-md px-3 py-1 text-xs transition-colors ${
                timeRange === range ? 'bg-[var(--sc-ok)] text-[var(--sc-primary-fg)]' : 'text-[var(--sc-text-dim)] hover:text-[var(--sc-text)]'
              }`}
            >
              {range}
            </button>
          ))}
        </div>
        <div className="flex flex-wrap items-center gap-2">
          <Select value={resultFilter || ''} onChange={(e) => setResultFilter(e.target.value || undefined)} aria-label="Filter by verdict" className="w-auto">
            <option value="">All results</option>
            <option value="ALLOW">Allowed</option>
            <option value="BLOCK">Blocked</option>
            <option value="QUARANTINE">Quarantined</option>
          </Select>
          <Select value={sourceFilter || ''} onChange={(e) => setSourceFilter(e.target.value || undefined)} aria-label="Filter by source" className="w-auto">
            <option value="">All sources</option>
            <option value="hook">Hook</option>
            <option value="api">API</option>
            <option value="agent">Agent</option>
            <option value="user">User</option>
            <option value="cli">CLI</option>
          </Select>
        </div>
      </div>

      <div className="grid gap-3 md:grid-cols-4">
        <StatCard label="Entries" value={logs.length} icon={ListChecks} accent="muted" />
        <StatCard label="Allowed" value={allowedCount} icon={CheckCircle2} accent="cyan" />
        <StatCard label="Blocked" value={blockedCount} icon={ShieldAlert} accent={blockedCount ? 'coral' : 'muted'} />
        <StatCard label="Quarantined" value={quarantinedCount} icon={ShieldQuestion} accent={quarantinedCount ? 'amber' : 'muted'} />
      </div>

      {isError ? (
        <CardError message={`Failed to load audit logs: ${error instanceof Error ? error.message : 'fetch failed'}`} onRetry={() => refetch()} />
      ) : (
        <Table
          columns={columns}
          rows={logs}
          rowKey={(log) => log.id}
          onRowClick={(log) => setSelectedAuditEntry(selectedAuditEntry?.id === log.id ? null : log)}
          selectedKey={selectedAuditEntry?.id ?? null}
          loading={isLoading}
          emptyMessage="No audit entries for this period."
          initialSort={{ key: 'timestamp', dir: 'desc' }}
        />
      )}

      <Drawer open={selectedAuditEntry !== null} onClose={() => setSelectedAuditEntry(null)} title="Audit entry" modal={false}>
        {selectedAuditEntry && <AuditDetailPanel entry={selectedAuditEntry} onClose={() => setSelectedAuditEntry(null)} />}
      </Drawer>

      <details className="glass-card p-6">
        <summary className="cursor-pointer list-none text-sm font-medium text-[var(--sc-text)]">Export audit trail</summary>
        <div className="mt-4">
          <AuditExportPanel />
        </div>
      </details>
    </div>
  );
}
