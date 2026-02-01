'use client';

import { useQuarantine } from '@/hooks/useDefence';
import { useDashboardStore } from '@/lib/store';
import { AlertTriangle } from 'lucide-react';

export function QuarantinePreview() {
  const { data, isLoading } = useQuarantine('pending', 3);
  const { setViewMode } = useDashboardStore();

  const pendingCount = data?.total ?? 0;
  const items = data?.items ?? [];

  return (
    <div className="bg-slate-900 border border-slate-800 rounded-xl p-4">
      <div className="flex items-center justify-between mb-4">
        <h3 className="text-sm font-medium text-slate-300">Quarantine Queue</h3>
        {pendingCount > 0 && (
          <span className="text-xs font-medium text-yellow-400 bg-yellow-400/10 px-2 py-0.5 rounded-full">
            {pendingCount} pending
          </span>
        )}
      </div>

      {isLoading ? (
        <div className="text-xs text-slate-500 animate-pulse">Loading...</div>
      ) : items.length === 0 ? (
        <div className="flex flex-col items-center py-6 text-slate-500">
          <AlertTriangle size={24} className="mb-2 text-slate-600" />
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
                className="bg-slate-800/50 border border-slate-700 rounded-lg p-3"
              >
                <div className="flex items-start justify-between">
                  <div className="flex-1 min-w-0">
                    <div className="text-xs font-medium text-white truncate">
                      {item.title || 'Untitled'}
                    </div>
                    <div className="text-[10px] text-slate-500 mt-0.5">
                      {item.source_type} &middot; {new Date(item.created_at).toLocaleTimeString()}
                    </div>
                  </div>
                  <span className="text-[10px] text-red-400 bg-red-400/10 px-1.5 py-0.5 rounded shrink-0 ml-2">
                    {item.reason?.slice(0, 30) || 'Threat detected'}
                  </span>
                </div>
                {indicators.length > 0 && (
                  <div className="flex gap-1 mt-1.5 flex-wrap">
                    {indicators.slice(0, 3).map((ind: string, i: number) => (
                      <span key={i} className="text-[9px] text-yellow-400 bg-yellow-400/10 px-1 py-0.5 rounded">
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
          className="w-full mt-3 text-xs text-cyan-400 hover:text-cyan-300 transition-colors"
        >
          Review all {pendingCount} items →
        </button>
      )}
    </div>
  );
}
