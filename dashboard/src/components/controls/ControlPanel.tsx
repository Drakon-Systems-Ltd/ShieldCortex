'use client';

/**
 * Control Panel Component
 *
 * Provides controls for pausing/resuming memory creation
 * and displays server status including uptime.
 * Shows kill switch state when active.
 */

import { useControlStatus, usePauseMemory, useResumeMemory, useConsolidate, type ControlStatus } from '@/hooks/useMemories';
import { Button } from '@/components/ui/button';
import { VersionPanel } from './VersionPanel';

export function ControlPanel() {
  const { data: status, isLoading } = useControlStatus();
  const pauseMutation = usePauseMemory();
  const resumeMutation = useResumeMemory();
  const consolidateMutation = useConsolidate();

  const isPaused = status?.paused ?? false;
  const isKillSwitchActive = (status as ControlStatus | undefined)?.killSwitchActive ?? false;
  const isToggling = pauseMutation.isPending || resumeMutation.isPending;

  const handleTogglePause = () => {
    if (isPaused) {
      resumeMutation.mutate();
    } else {
      pauseMutation.mutate();
    }
  };

  const handleConsolidate = () => {
    consolidateMutation.mutate();
  };

  if (isLoading) {
    return (
      <div className="p-3 rounded-lg bg-[var(--sc-bg-elevated)] border border-[var(--sc-border)] animate-pulse">
        <div className="h-4 bg-[var(--sc-bg-elevated)] rounded w-24 mb-2"></div>
        <div className="h-8 bg-[var(--sc-bg-elevated)] rounded w-full"></div>
      </div>
    );
  }

  return (
    <div className="space-y-3">
      {/* Kill Switch Banner */}
      {isKillSwitchActive && (
        <div className="px-3 py-2 rounded-lg bg-[var(--sc-coral)]/20 border border-[var(--sc-coral)]/50 text-[var(--sc-coral)] text-sm flex items-center gap-2">
          <span className="text-lg">🛑</span>
          <span className="font-bold">KILL SWITCH ACTIVE</span>
        </div>
      )}

      {/* Pause Banner (only when paused but NOT kill switch) */}
      {isPaused && !isKillSwitchActive && (
        <div className="px-3 py-2 rounded-lg bg-[var(--sc-coral)]/20 border border-[var(--sc-coral)]/50 text-[var(--sc-coral)] text-sm flex items-center gap-2">
          <span className="text-lg">⏸</span>
          <span>Memory creation paused</span>
        </div>
      )}

      {/* Server Status */}
      <div className={`p-3 rounded-lg bg-[var(--sc-bg-elevated)] border ${isKillSwitchActive ? 'border-[var(--sc-coral)]/50' : 'border-[var(--sc-border)]'}`}>
        <div className="flex items-center justify-between mb-3">
          <span className="text-sm text-[var(--sc-text-secondary)]">Server Status</span>
          <div className="flex items-center gap-2">
            <span
              className={`w-2 h-2 rounded-full ${
                isKillSwitchActive ? 'bg-[var(--sc-coral)] animate-pulse' :
                isPaused ? 'bg-[var(--sc-coral)]' : 'bg-[var(--sc-cyan)]'
              }`}
            />
            <span className="text-xs text-[var(--sc-text-primary)]">
              {isKillSwitchActive ? 'Locked Down' : isPaused ? 'Paused' : 'Active'}
            </span>
          </div>
        </div>

        <div className="text-xs text-[var(--sc-text-muted)] mb-3">
          Uptime: {status?.uptimeFormatted || '—'}
        </div>

        {/* Control Buttons — disabled during kill switch */}
        <div className="grid grid-cols-2 gap-2">
          <Button
            variant="outline"
            size="sm"
            onClick={handleTogglePause}
            disabled={isToggling || isKillSwitchActive}
            className={`text-xs ${
              isKillSwitchActive
                ? 'border-[var(--sc-coral)] text-[var(--sc-coral)] opacity-50 cursor-not-allowed'
                : isPaused
                  ? 'border-[var(--sc-cyan)] text-[var(--sc-cyan)] hover:bg-[var(--sc-cyan)]/20 hover:text-[var(--sc-cyan)]'
                  : 'border-[var(--sc-coral)] text-[var(--sc-coral)] hover:bg-[var(--sc-coral)]/20 hover:text-[var(--sc-coral)]'
            }`}
            title={isKillSwitchActive ? 'Kill switch active — use Iron Dome to resume' : isPaused ? 'Resume memory creation' : 'Pause memory creation'}
          >
            {isToggling ? '...' : isPaused ? '▶ Resume' : '⏸ Pause'}
          </Button>

          <Button
            variant="outline"
            size="sm"
            onClick={handleConsolidate}
            disabled={consolidateMutation.isPending || isKillSwitchActive}
            className={`text-xs ${isKillSwitchActive ? 'border-[var(--sc-coral)] text-[var(--sc-coral)] opacity-50 cursor-not-allowed' : 'border-[var(--sc-border)] text-[var(--sc-text-primary)] hover:bg-[var(--sc-bg-elevated)]/20'}`}
            title={isKillSwitchActive ? 'Kill switch active — operations blocked' : 'Consolidate memories (promote STM to LTM)'}
          >
            {consolidateMutation.isPending ? '...' : '🔄 Sync'}
          </Button>
        </div>
      </div>

      {/* Version Panel */}
      <VersionPanel />
    </div>
  );
}
