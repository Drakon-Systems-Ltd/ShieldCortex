'use client';

import { Shield } from 'lucide-react';
import { useIronDomeStatus, useIronDomeAudit } from '@/hooks/useIronDome';
import { useDashboardStore } from '@/lib/store';

export function IronDomeCard() {
  const { data: status, isLoading } = useIronDomeStatus();
  const { data: auditData } = useIronDomeAudit(100);

  const isActive = status?.enabled ?? false;
  const profileName = status?.profile ?? 'custom';

  // Derive 24h stats from audit logs
  const oneDayAgo = Date.now() - 24 * 60 * 60 * 1000;
  const recentLogs = (auditData?.logs ?? []).filter(
    (log: any) => new Date(log.timestamp).getTime() > oneDayAgo
  );
  const detections = recentLogs.filter(
    (log: any) => log.reason?.includes('[iron-dome:') && log.firewall_result === 'BLOCK'
  ).length;
  const totalEvents = recentLogs.length;

  return (
    <div className="bg-slate-900 border border-slate-800 rounded-xl p-4">
      <div className="flex items-center justify-between mb-3">
        <h3 className="text-sm font-medium text-slate-300">Iron Dome</h3>
        <span
          className={`text-[10px] font-medium px-2 py-0.5 rounded-full ${
            isActive
              ? 'bg-red-500/20 text-red-400 border border-red-500/30'
              : 'bg-slate-700/50 text-slate-500'
          }`}
        >
          {isActive ? 'ACTIVE' : 'INACTIVE'}
        </span>
      </div>

      {isLoading ? (
        <div className="text-xs text-slate-500 animate-pulse">Loading...</div>
      ) : isActive ? (
        <>
          <div className="text-xs text-slate-500 mb-3">
            Profile: <span className="text-red-400 font-medium">{profileName}</span>
          </div>
          <div className="grid grid-cols-2 gap-3 mb-3">
            <div className="bg-slate-800/50 rounded-lg p-2 text-center">
              <div className="text-lg font-bold text-red-400">{detections}</div>
              <div className="text-[10px] text-slate-500 uppercase">Blocks</div>
            </div>
            <div className="bg-slate-800/50 rounded-lg p-2 text-center">
              <div className="text-lg font-bold text-slate-300">{totalEvents}</div>
              <div className="text-[10px] text-slate-500 uppercase">Events</div>
            </div>
          </div>
        </>
      ) : (
        <div className="text-center py-3">
          <Shield size={20} className="text-slate-600 mx-auto mb-1.5" />
          <p className="text-[10px] text-slate-500">
            Behaviour protection layer — not active
          </p>
        </div>
      )}

      <button
        onClick={() => useDashboardStore.getState().setViewMode('dome')}
        className="w-full text-center text-xs text-red-400 hover:text-red-300 transition-colors py-1"
      >
        View Iron Dome &rarr;
      </button>
    </div>
  );
}
