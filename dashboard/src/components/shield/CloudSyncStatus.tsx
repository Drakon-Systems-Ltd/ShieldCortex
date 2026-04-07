'use client';

import { AlertTriangle, CheckCircle2, Clock3, RefreshCw, Server } from 'lucide-react';
import { useCloudSyncStatus } from '../../hooks/useCloudSyncStatus';
import { useDashboardStore } from '@/lib/store';

function formatTimeAgo(isoString: string): string {
  const diff = Date.now() - new Date(isoString).getTime();
  const seconds = Math.max(0, Math.floor(diff / 1000));

  if (seconds < 60) return `${seconds}s ago`;

  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) return `${minutes}m ago`;

  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `${hours}h ago`;

  const days = Math.floor(hours / 24);
  return `${days}d ago`;
}

function formatTimeUntil(isoString: string): string {
  const diff = new Date(isoString).getTime() - Date.now();
  const seconds = Math.max(0, Math.floor(diff / 1000));

  if (seconds < 60) return `in ${seconds}s`;

  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) return `in ${minutes}m`;

  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `in ${hours}h`;

  const days = Math.floor(hours / 24);
  return `in ${days}d`;
}

function isCloudSyncStale(lastSyncAt: string | null): boolean {
  return lastSyncAt ? Date.now() - new Date(lastSyncAt).getTime() > 24 * 60 * 60 * 1000 : false;
}

function statusTone(status: 'healthy' | 'queued' | 'warning' | 'disabled') {
  switch (status) {
    case 'healthy':
      return {
        border: 'border-[var(--sc-cyan)]/20',
        bg: 'bg-[var(--sc-cyan)]/10',
        text: 'text-[var(--sc-cyan)]',
        icon: CheckCircle2,
      };
    case 'queued':
      return {
        border: 'border-[var(--sc-amber)]/20',
        bg: 'bg-[var(--sc-amber)]/10',
        text: 'text-[var(--sc-amber)]',
        icon: RefreshCw,
      };
    case 'warning':
      return {
        border: 'border-[var(--sc-coral)]/20',
        bg: 'bg-[var(--sc-coral)]/10',
        text: 'text-[var(--sc-coral)]',
        icon: AlertTriangle,
      };
    default:
      return {
        border: 'border-[var(--sc-border)]',
        bg: 'bg-[var(--sc-bg-elevated)]',
        text: 'text-[var(--sc-text-primary)]',
        icon: Server,
      };
  }
}

export function CloudSyncStatus() {
  const { data, isLoading } = useCloudSyncStatus();
  const setViewMode = useDashboardStore((state) => state.setViewMode);

  if (isLoading || !data) return null;

  const { enabled, apiKeySet, lastSyncAt, queue, device } = data;
  const memoryQueue = queue.byKind.memory;
  const graphQueue = queue.byKind.graph;
  const replicationPending = memoryQueue.pending + graphQueue.pending;
  const replicationFailed = memoryQueue.failed + graphQueue.failed;
  const auxiliaryFailed =
    queue.byKind.audit.failed +
    queue.byKind.quarantine.failed +
    queue.byKind.unknown.failed;

  let status: 'healthy' | 'queued' | 'warning' | 'disabled' = 'disabled';
  let label = 'Cloud sync disabled';
  let detail = 'Enable cloud sync with a Team+ key to replicate memories.';

  if (enabled && apiKeySet) {
    const stale = isCloudSyncStale(lastSyncAt);

    if (replicationPending > 0 && replicationFailed > 0) {
      status = 'warning';
      label = 'Cloud sync needs attention';
      detail = queue.lastError ?? 'One or more sync jobs failed and need retry.';
    } else if (replicationFailed > 0) {
      status = 'warning';
      label = `${replicationFailed} failed sync job${replicationFailed === 1 ? '' : 's'} need clearing`;
      detail = queue.lastError
        ? `${queue.lastError}${queue.latestFailureAt ? ` • last failure ${formatTimeAgo(queue.latestFailureAt)}` : ''}`
        : `These items exhausted retries. Clear them or investigate.`;
    } else if (replicationPending > 0) {
      status = 'queued';
      label = 'Cloud sync queued';
      detail = queue.nextRetryAt
        ? `Next retry ${formatTimeUntil(queue.nextRetryAt)}`
        : 'Waiting to flush queued sync jobs.';
    } else if (stale) {
      status = 'warning';
      label = 'Cloud sync stale';
      detail = lastSyncAt ? `Last successful sync ${formatTimeAgo(lastSyncAt)}` : 'No successful sync recorded yet.';
    } else {
      status = 'healthy';
      label = 'Cloud sync healthy';
      detail = lastSyncAt ? `Last successful sync ${formatTimeAgo(lastSyncAt)}` : 'Connected and ready to sync.';
      if (auxiliaryFailed > 0) {
        detail += ` Auxiliary audit/quarantine history: ${auxiliaryFailed} failed job${auxiliaryFailed === 1 ? '' : 's'}.`;
      }
    }
  }

  const tone = statusTone(status);
  const StatusIcon = tone.icon;

  return (
    <div className={`mb-4 rounded-xl border ${tone.border} ${tone.bg} p-4`}>
      <div className="flex flex-col gap-4 lg:flex-row lg:items-start lg:justify-between">
        <div className="min-w-0">
          <div className="flex items-center gap-2">
            <StatusIcon size={16} className={tone.text} />
            <span className={`text-sm font-medium ${tone.text}`}>{label}</span>
          </div>
          <p className="mt-1 text-xs text-[var(--sc-text-secondary)]">{detail}</p>
          <div className="mt-3 flex flex-wrap items-center gap-2 text-[11px] text-[var(--sc-text-muted)]">
            <span className="inline-flex items-center gap-1 rounded-full bg-[var(--sc-bg-surface)] px-2 py-1">
              <Server size={11} />
              {device.name}
            </span>
            {lastSyncAt && (
              <span className="inline-flex items-center gap-1 rounded-full bg-[var(--sc-bg-surface)] px-2 py-1">
                <Clock3 size={11} />
                Synced {formatTimeAgo(lastSyncAt)}
              </span>
            )}
            {queue.oldestPendingAt && (
              <span className="inline-flex items-center gap-1 rounded-full bg-[var(--sc-bg-surface)] px-2 py-1">
                Oldest queued {formatTimeAgo(queue.oldestPendingAt)}
              </span>
            )}
          </div>
        </div>

        <div className="grid grid-cols-2 gap-2 text-xs sm:min-w-[260px]">
          <div className="rounded-lg border border-[var(--sc-border)] bg-[var(--sc-bg-deep)]/70 p-3">
            <div className="text-[var(--sc-text-muted)]">Memory queue</div>
            <div className="mt-1 text-lg font-semibold text-[var(--sc-text-primary)]">{memoryQueue.pending}</div>
            <div className="text-[11px] text-[var(--sc-text-muted)]">pending writes</div>
          </div>
          <div className="rounded-lg border border-[var(--sc-border)] bg-[var(--sc-bg-deep)]/70 p-3">
            <div className="text-[var(--sc-text-muted)]">Replication failures</div>
            <div className={`mt-1 text-lg font-semibold ${replicationFailed > 0 ? 'text-[var(--sc-coral)]' : 'text-[var(--sc-text-primary)]'}`}>
              {replicationFailed}
            </div>
            <div className="text-[11px] text-[var(--sc-text-muted)]">memory + graph only</div>
          </div>
          <div className="rounded-lg border border-[var(--sc-border)] bg-[var(--sc-bg-deep)]/70 p-3">
            <div className="text-[var(--sc-text-muted)]">Replicated</div>
            <div className="mt-1 text-lg font-semibold text-[var(--sc-text-primary)]">{memoryQueue.synced}</div>
            <div className="text-[11px] text-[var(--sc-text-muted)]">memory sync jobs</div>
          </div>
          <div className="rounded-lg border border-[var(--sc-border)] bg-[var(--sc-bg-deep)]/70 p-3">
            <div className="text-[var(--sc-text-muted)]">Retrying next</div>
            <div className="mt-1 text-sm font-semibold text-[var(--sc-text-primary)]">
              {queue.nextRetryAt ? formatTimeUntil(queue.nextRetryAt) : 'Idle'}
            </div>
            <div className="text-[11px] text-[var(--sc-text-muted)]">
              {queue.lastErrorKind ? `${queue.lastErrorKind} queue` : 'no pending retry'}
            </div>
          </div>
        </div>
      </div>
      <div className="mt-4 flex justify-end">
        <button
          onClick={() => setViewMode('cloud')}
          className="rounded-lg border border-[var(--sc-border)] bg-[var(--sc-bg-deep)]/70 px-3 py-2 text-xs font-medium text-[var(--sc-text-primary)] transition-colors hover:border-[var(--sc-cyan)]/40 hover:text-[var(--sc-text-primary)]"
        >
          Open cloud diagnostics
        </button>
      </div>
    </div>
  );
}
