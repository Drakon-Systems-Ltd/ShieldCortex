'use client';

import { useCloudSyncStatus } from '../../hooks/useCloudSyncStatus';

function formatTimeAgo(isoString: string): string {
  const diff = Date.now() - new Date(isoString).getTime();
  const seconds = Math.floor(diff / 1000);
  if (seconds < 60) return `${seconds}s ago`;
  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) return `${minutes}m ago`;
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `${hours}h ago`;
  const days = Math.floor(hours / 24);
  return `${days}d ago`;
}

export function CloudSyncStatus() {
  const { data, isLoading } = useCloudSyncStatus();

  if (isLoading || !data) return null;

  const { enabled, apiKeySet, lastSyncAt, queue } = data;

  // Determine status
  let dotColour: string;
  let label: string;

  if (!enabled || !apiKeySet) {
    dotColour = 'bg-slate-500';
    label = 'Cloud sync: disabled';
  } else if (queue.failed > 0) {
    dotColour = 'bg-red-500';
    label = `${queue.failed} event${queue.failed === 1 ? '' : 's'} failed`;
  } else if (queue.pending > 0) {
    dotColour = 'bg-amber-500';
    label = `${queue.pending} event${queue.pending === 1 ? '' : 's'} pending`;
  } else if (lastSyncAt) {
    dotColour = 'bg-emerald-500';
    label = 'Cloud sync: OK';
  } else {
    dotColour = 'bg-emerald-500';
    label = 'Cloud sync: connected';
  }

  const timeAgo = lastSyncAt ? formatTimeAgo(lastSyncAt) : null;

  return (
    <div className="flex items-center gap-2 px-3 py-1.5 mb-4 bg-slate-800 rounded-lg text-xs w-fit">
      <span className={`inline-block w-2 h-2 rounded-full ${dotColour}`} />
      <span className="text-slate-300">{label}</span>
      {timeAgo && (
        <span className="text-slate-500">last sync {timeAgo}</span>
      )}
    </div>
  );
}
