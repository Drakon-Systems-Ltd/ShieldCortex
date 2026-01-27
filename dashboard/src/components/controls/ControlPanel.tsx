'use client';

/**
 * Control Panel Component
 *
 * Provides controls for pausing/resuming memory creation
 * and displays server status including uptime.
 */

import { useControlStatus, usePauseMemory, useResumeMemory, useConsolidate } from '@/hooks/useMemories';
import { Button } from '@/components/ui/button';

export function ControlPanel() {
  const { data: status, isLoading } = useControlStatus();
  const pauseMutation = usePauseMemory();
  const resumeMutation = useResumeMemory();
  const consolidateMutation = useConsolidate();

  const isPaused = status?.paused ?? false;
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
      <div className="p-3 rounded-lg bg-slate-800/50 border border-slate-700 animate-pulse">
        <div className="h-4 bg-slate-700 rounded w-24 mb-2"></div>
        <div className="h-8 bg-slate-700 rounded w-full"></div>
      </div>
    );
  }

  return (
    <div className="space-y-3">
      {/* Status Banner (only when paused) */}
      {isPaused && (
        <div className="px-3 py-2 rounded-lg bg-orange-500/20 border border-orange-500/50 text-orange-300 text-sm flex items-center gap-2">
          <span className="text-lg">⏸</span>
          <span>Memory creation paused</span>
        </div>
      )}

      {/* Server Status */}
      <div className="p-3 rounded-lg bg-slate-800/50 border border-slate-700">
        <div className="flex items-center justify-between mb-3">
          <span className="text-sm text-slate-400">Server Status</span>
          <div className="flex items-center gap-2">
            <span
              className={`w-2 h-2 rounded-full ${isPaused ? 'bg-orange-500' : 'bg-green-500'}`}
            />
            <span className="text-xs text-slate-300">
              {isPaused ? 'Paused' : 'Active'}
            </span>
          </div>
        </div>

        <div className="text-xs text-slate-500 mb-3">
          Uptime: {status?.uptimeFormatted || '—'}
        </div>

        {/* Control Buttons */}
        <div className="flex gap-2">
          <Button
            variant="outline"
            size="sm"
            onClick={handleTogglePause}
            disabled={isToggling}
            className={`flex-1 ${
              isPaused
                ? 'border-green-600 text-green-400 hover:bg-green-600/20 hover:text-green-300'
                : 'border-orange-600 text-orange-400 hover:bg-orange-600/20 hover:text-orange-300'
            }`}
          >
            {isToggling ? '...' : isPaused ? '▶ Resume' : '⏸ Pause'}
          </Button>

          <Button
            variant="outline"
            size="sm"
            onClick={handleConsolidate}
            disabled={consolidateMutation.isPending}
            className="flex-1 border-slate-600 text-slate-300 hover:bg-slate-600/20"
          >
            {consolidateMutation.isPending ? '...' : '🔄 Consolidate'}
          </Button>
        </div>
      </div>
    </div>
  );
}
