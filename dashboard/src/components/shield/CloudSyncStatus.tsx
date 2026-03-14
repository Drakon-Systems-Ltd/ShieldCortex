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
        border: 'border-emerald-500/20',
        bg: 'bg-emerald-500/10',
        text: 'text-emerald-300',
        icon: CheckCircle2,
      };
    case 'queued':
      return {
        border: 'border-amber-500/20',
        bg: 'bg-amber-500/10',
        text: 'text-amber-300',
        icon: RefreshCw,
      };
    case 'warning':
      return {
        border: 'border-red-500/20',
        bg: 'bg-red-500/10',
        text: 'text-red-300',
        icon: AlertTriangle,
      };
    default:
      return {
        border: 'border-slate-700',
        bg: 'bg-slate-800/80',
        text: 'text-slate-300',
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

  let status: 'healthy' | 'queued' | 'warning' | 'disabled' = 'disabled';
  let label = 'Cloud sync disabled';
  let detail = 'Enable cloud sync with a Team+ key to replicate memories.';

  if (enabled && apiKeySet) {
    const stale = isCloudSyncStale(lastSyncAt);

    if (queue.pending > 0 && (memoryQueue.failed > 0 || queue.failed > 0)) {
      status = 'warning';
      label = 'Cloud sync needs attention';
      detail = queue.lastError ?? 'One or more sync jobs failed and need retry.';
    } else if (queue.failed > 0) {
      status = stale ? 'warning' : 'queued';
      label = stale ? 'Cloud sync has unresolved failures' : 'Cloud sync healthy, with failed history';
      detail = queue.lastError
        ? `${queue.lastError}${queue.latestFailureAt ? ` • last failure ${formatTimeAgo(queue.latestFailureAt)}` : ''}`
        : `${queue.failed} failed job${queue.failed === 1 ? '' : 's'} remain in history.`;
    } else if (memoryQueue.pending > 0 || queue.pending > 0) {
      status = 'queued';
      label = memoryQueue.pending > 0 ? 'Memory sync queued' : 'Cloud sync queued';
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
          <p className="mt-1 text-xs text-slate-400">{detail}</p>
          <div className="mt-3 flex flex-wrap items-center gap-2 text-[11px] text-slate-500">
            <span className="inline-flex items-center gap-1 rounded-full bg-slate-900/70 px-2 py-1">
              <Server size={11} />
              {device.name}
            </span>
            {lastSyncAt && (
              <span className="inline-flex items-center gap-1 rounded-full bg-slate-900/70 px-2 py-1">
                <Clock3 size={11} />
                Synced {formatTimeAgo(lastSyncAt)}
              </span>
            )}
            {queue.oldestPendingAt && (
              <span className="inline-flex items-center gap-1 rounded-full bg-slate-900/70 px-2 py-1">
                Oldest queued {formatTimeAgo(queue.oldestPendingAt)}
              </span>
            )}
          </div>
        </div>

        <div className="grid grid-cols-2 gap-2 text-xs sm:min-w-[260px]">
          <div className="rounded-lg border border-slate-800 bg-slate-950/70 p-3">
            <div className="text-slate-500">Memory queue</div>
            <div className="mt-1 text-lg font-semibold text-white">{memoryQueue.pending}</div>
            <div className="text-[11px] text-slate-500">pending writes</div>
          </div>
          <div className="rounded-lg border border-slate-800 bg-slate-950/70 p-3">
            <div className="text-slate-500">Failed jobs</div>
            <div className={`mt-1 text-lg font-semibold ${queue.failed > 0 ? 'text-red-300' : 'text-white'}`}>
              {queue.failed}
            </div>
            <div className="text-[11px] text-slate-500">all payload kinds</div>
          </div>
          <div className="rounded-lg border border-slate-800 bg-slate-950/70 p-3">
            <div className="text-slate-500">Replicated</div>
            <div className="mt-1 text-lg font-semibold text-white">{memoryQueue.synced}</div>
            <div className="text-[11px] text-slate-500">memory sync jobs</div>
          </div>
          <div className="rounded-lg border border-slate-800 bg-slate-950/70 p-3">
            <div className="text-slate-500">Retrying next</div>
            <div className="mt-1 text-sm font-semibold text-white">
              {queue.nextRetryAt ? formatTimeUntil(queue.nextRetryAt) : 'Idle'}
            </div>
            <div className="text-[11px] text-slate-500">
              {queue.lastErrorKind ? `${queue.lastErrorKind} queue` : 'no pending retry'}
            </div>
          </div>
        </div>
      </div>
      <div className="mt-4 flex justify-end">
        <button
          onClick={() => setViewMode('cloud')}
          className="rounded-lg border border-slate-700 bg-slate-950/70 px-3 py-2 text-xs font-medium text-slate-300 transition-colors hover:border-cyan-500/40 hover:text-white"
        >
          Open cloud diagnostics
        </button>
      </div>
    </div>
  );
}
