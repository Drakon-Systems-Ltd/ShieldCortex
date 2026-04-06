'use client';

import { useQuarantine } from '@/hooks/useDefence';
import { useDashboardStore } from '@/lib/store';
import { AlertTriangle } from 'lucide-react';

export function QuarantinePreview() {
  const { setViewMode, projectFilter } = useDashboardStore();
  const { data, isLoading, isError } = useQuarantine('pending', 3, projectFilter || undefined);

  const pendingCount = data?.total ?? 0;
  const items = data?.items ?? [];

  return (
    <div className="bg-[var(--sc-bg-surface)] border border-[var(--sc-border)] rounded-xl p-4">
      <div className="flex items-center justify-between mb-4">
        <h3 className="text-sm font-medium text-[var(--sc-text-primary)]">Quarantine Queue</h3>
        {pendingCount > 0 && (
          <span className="text-xs font-medium text-[var(--sc-amber)] bg-[var(--sc-amber)]/10 px-2 py-0.5 rounded-full">
            {pendingCount} pending
          </span>
        )}
      </div>

      {isLoading ? (
        <div className="text-xs text-[var(--sc-text-muted)] animate-pulse">Loading...</div>
      ) : isError ? (
        <div className="text-xs text-[var(--sc-coral)]">Failed to load quarantine</div>
      ) : items.length === 0 ? (
        <div className="flex flex-col items-center py-6 text-[var(--sc-text-muted)]">
          <AlertTriangle size={24} className="mb-2 text-[var(--sc-text-muted)]" />
          <span className="text-xs">No items in quarantine</span>
        </div>
      ) : (
        <div className="space-y-2">
          {items.map((item) => {
            const indicators = (() => {
              try { return JSON.parse(item.threat_indicators); } catch { return []; }
            })();
            return (
              <div
                key={item.id}
                className="bg-[var(--sc-bg-elevated)] border border-[var(--sc-border)] rounded-lg p-3"
              >
                <div className="flex items-start justify-between">
                  <div className="flex-1 min-w-0">
                    <div className="text-xs font-medium text-[var(--sc-text-primary)] truncate">
                      {item.title || 'Untitled'}
                    </div>
                    <div className="text-[10px] text-[var(--sc-text-muted)] mt-0.5">
                      {item.source_type} &middot; {new Date(item.created_at).toLocaleTimeString()}
                    </div>
                  </div>
                  <span className="text-[10px] text-[var(--sc-coral)] bg-[var(--sc-coral)]/10 px-1.5 py-0.5 rounded shrink-0 ml-2">
                    {item.reason?.slice(0, 30) || 'Threat detected'}
                  </span>
                </div>
                {indicators.length > 0 && (
                  <div className="flex gap-1 mt-1.5 flex-wrap">
                    {indicators.slice(0, 3).map((ind: string, i: number) => (
                      <span key={i} className="text-[9px] text-[var(--sc-amber)] bg-[var(--sc-amber)]/10 px-1 py-0.5 rounded">
                        {ind}
                      </span>
                    ))}
                  </div>
                )}
              </div>
            );
          })}
        </div>
      )}

      {pendingCount > 0 && (
        <button
          onClick={() => setViewMode('quarantine')}
          className="w-full mt-3 text-xs text-[var(--sc-cyan)] hover:text-[var(--sc-cyan)] transition-colors"
        >
          Review all {pendingCount} items →
        </button>
      )}
    </div>
  );
}
