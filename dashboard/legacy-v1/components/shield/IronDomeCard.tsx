'use client';

import { Shield } from 'lucide-react';
import { useIronDomeStatus, useIronDomeAudit, type IronDomeAuditLog } from '@/hooks/useIronDome';
import { useDashboardStore } from '@/lib/store';
import { CardError } from '@/components/ds/CardError';

export function IronDomeCard() {
  const { data: status, isLoading, isError, refetch } = useIronDomeStatus();
  const { data: auditData } = useIronDomeAudit(100);

  const isActive = status?.enabled ?? false;
  const profileName = status?.profile ?? 'custom';

  // Derive stats from recent audit logs (query already limits to 100)
  const logs = auditData?.logs ?? [];
  const detections = logs.filter(
    (log: IronDomeAuditLog) => log.reason?.includes('[iron-dome:') && log.firewall_result === 'BLOCK'
  ).length;
  const totalEvents = logs.length;

  return (
    <div className="bg-[var(--sc-bg-surface)] border border-[var(--sc-border)] rounded-xl p-4">
      <div className="flex items-center justify-between mb-3">
        <h3 className="text-sm font-medium text-[var(--sc-text-primary)]">Iron Dome</h3>
        <span
          className={`text-[10px] font-medium px-2 py-0.5 rounded-full ${
            isActive
              ? 'bg-[var(--sc-coral)]/20 text-[var(--sc-coral)] border border-[var(--sc-coral)]/30'
              : 'bg-[var(--sc-bg-elevated)]/50 text-[var(--sc-text-muted)]'
          }`}
        >
          {isActive ? 'ACTIVE' : 'INACTIVE'}
        </span>
      </div>

      {isError ? (
        <CardError inline message="Iron Dome status unavailable" onRetry={() => refetch()} />
      ) : isLoading ? (
        <div className="text-xs text-[var(--sc-text-muted)] animate-pulse">Loading...</div>
      ) : isActive ? (
        <>
          <div className="text-xs text-[var(--sc-text-muted)] mb-3">
            Profile: <span className="text-[var(--sc-coral)] font-medium">{profileName}</span>
          </div>
          <div className="grid grid-cols-2 gap-3 mb-3">
            <div className="bg-[var(--sc-bg-elevated)] rounded-lg p-2 text-center">
              <div className="text-lg font-bold text-[var(--sc-coral)]">{detections}</div>
              <div className="text-[10px] text-[var(--sc-text-muted)] uppercase">Blocks</div>
            </div>
            <div className="bg-[var(--sc-bg-elevated)] rounded-lg p-2 text-center">
              <div className="text-lg font-bold text-[var(--sc-text-primary)]">{totalEvents}</div>
              <div className="text-[10px] text-[var(--sc-text-muted)] uppercase">Events</div>
            </div>
          </div>
        </>
      ) : (
        <div className="text-center py-3">
          <Shield size={20} className="text-[var(--sc-text-muted)] mx-auto mb-1.5" />
          <p className="text-[10px] text-[var(--sc-text-muted)]">
            Behaviour protection layer — not active
          </p>
        </div>
      )}

      <button
        onClick={() => useDashboardStore.getState().setViewMode('dome')}
        className="w-full text-center text-xs text-[var(--sc-coral)] hover:text-[var(--sc-coral)] transition-colors py-1"
      >
        View Iron Dome &rarr;
      </button>
    </div>
  );
}
