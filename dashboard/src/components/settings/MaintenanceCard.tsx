'use client';

import { Activity, Brain, RefreshCw, Sparkles } from 'lucide-react';
import { toast } from 'sonner';
import { Badge } from '@/components/ds/Badge';
import { Button } from '@/components/ds/Button';
import { GlassCard } from '@/components/ds/GlassCard';
import {
  useMemoryStats,
  useRunConsolidation,
  useRunLightTick,
  useRunMediumTick,
  useWorkerStatus,
} from '@/hooks/useMaintenance';

function formatRelative(iso: string | null): string {
  if (!iso) return 'never';
  const ms = Date.now() - new Date(iso).getTime();
  if (ms < 0) return 'just now';
  const sec = Math.floor(ms / 1000);
  if (sec < 60) return `${sec}s ago`;
  const min = Math.floor(sec / 60);
  if (min < 60) return `${min}m ago`;
  const hr = Math.floor(min / 60);
  if (hr < 24) return `${hr}h ago`;
  const day = Math.floor(hr / 24);
  return `${day}d ago`;
}

export function MaintenanceCard() {
  const { data: status, isLoading: statusLoading } = useWorkerStatus();
  const { data: stats } = useMemoryStats();
  const lightTick = useRunLightTick();
  const mediumTick = useRunMediumTick();
  const consolidate = useRunConsolidation();

  const isPending = lightTick.isPending || mediumTick.isPending || consolidate.isPending;

  const runLight = () => {
    lightTick.mutate(undefined, {
      onSuccess: () => toast.success('Light cleanup triggered'),
      onError: (e) => toast.error(e instanceof Error ? e.message : 'Failed to trigger light cleanup'),
    });
  };
  const runMedium = () => {
    mediumTick.mutate(undefined, {
      onSuccess: () => toast.success('Heavy cleanup triggered'),
      onError: (e) => toast.error(e instanceof Error ? e.message : 'Failed to trigger heavy cleanup'),
    });
  };
  const runConsolidate = () => {
    consolidate.mutate(undefined, {
      onSuccess: () => toast.success('Consolidation triggered'),
      onError: (e) => toast.error(e instanceof Error ? e.message : 'Failed to trigger consolidation'),
    });
  };

  return (
    <GlassCard className="p-6">
      <div className="flex items-center gap-2">
        <Brain size={16} className="text-[var(--sc-cyan)]" />
        <h3 className="text-lg font-semibold text-[var(--sc-text-primary)]">Memory Maintenance</h3>
        {status?.isRunning ? (
          <Badge variant="cyan" dot>Running</Badge>
        ) : statusLoading ? (
          <Badge variant="muted">Loading</Badge>
        ) : (
          <Badge variant="amber">Stopped</Badge>
        )}
      </div>
      <p className="mt-2 text-sm text-[var(--sc-text-secondary)]">
        Background brain worker prunes activation cache, consolidates short-term to long-term, removes
        low-salience duplicates, and prunes orphan graph entities. Runs automatically on intervals;
        you can trigger a tick manually below.
      </p>

      {/* Decay distribution */}
      {stats && (
        <div className="mt-4 grid grid-cols-3 gap-3 text-sm">
          <div className="rounded-lg border border-[var(--sc-border)] bg-[var(--sc-bg-deep)]/50 p-3">
            <div className="text-[10px] uppercase tracking-[0.14em] text-[var(--sc-text-muted)]">Healthy</div>
            <div className="mt-1 text-xl font-semibold text-[var(--sc-cyan)]">{stats.decayDistribution.healthy}</div>
          </div>
          <div className="rounded-lg border border-[var(--sc-border)] bg-[var(--sc-bg-deep)]/50 p-3">
            <div className="text-[10px] uppercase tracking-[0.14em] text-[var(--sc-text-muted)]">Fading</div>
            <div className="mt-1 text-xl font-semibold text-[var(--sc-amber)]">{stats.decayDistribution.fading}</div>
          </div>
          <div className="rounded-lg border border-[var(--sc-border)] bg-[var(--sc-bg-deep)]/50 p-3">
            <div className="text-[10px] uppercase tracking-[0.14em] text-[var(--sc-text-muted)]">Critical</div>
            <div className="mt-1 text-xl font-semibold text-[var(--sc-coral)]">{stats.decayDistribution.critical}</div>
          </div>
        </div>
      )}

      {/* Last-run summary */}
      <div className="mt-4 space-y-2 rounded-lg border border-[var(--sc-border)] bg-[var(--sc-bg-deep)]/50 p-3 text-xs">
        <div className="flex items-center justify-between">
          <span className="text-[var(--sc-text-muted)]">Light tick (every ~5 min)</span>
          <span className="text-[var(--sc-text-primary)]">
            {formatRelative(status?.lastLightTick ?? null)} · {status?.stats.lightTicks ?? 0} runs
          </span>
        </div>
        <div className="flex items-center justify-between">
          <span className="text-[var(--sc-text-muted)]">Heavy tick (every ~1 hr)</span>
          <span className="text-[var(--sc-text-primary)]">
            {formatRelative(status?.lastMediumTick ?? null)} · {status?.stats.mediumTicks ?? 0} runs
          </span>
        </div>
        <div className="flex items-center justify-between">
          <span className="text-[var(--sc-text-muted)]">Last consolidation</span>
          <span className="text-[var(--sc-text-primary)]">
            {formatRelative(status?.lastConsolidation ?? null)} · {status?.stats.consolidations ?? 0} runs
          </span>
        </div>
      </div>

      {/* Manual triggers */}
      <div className="mt-4 flex flex-wrap gap-2">
        <Button
          variant="outline"
          size="sm"
          onClick={runLight}
          disabled={isPending}
          pulse={lightTick.isPending}
        >
          <Activity size={13} />
          {lightTick.isPending ? 'Running' : 'Run light cleanup'}
        </Button>
        <Button
          variant="outline"
          size="sm"
          onClick={runMedium}
          disabled={isPending}
          pulse={mediumTick.isPending}
        >
          <RefreshCw size={13} />
          {mediumTick.isPending ? 'Running' : 'Run heavy cleanup'}
        </Button>
        <Button
          variant="cyan"
          size="sm"
          onClick={runConsolidate}
          disabled={isPending}
          pulse={consolidate.isPending}
        >
          <Sparkles size={13} />
          {consolidate.isPending ? 'Running' : 'Consolidate now'}
        </Button>
      </div>

      <p className="mt-3 text-[11px] text-[var(--sc-text-muted)]">
        CLI equivalent: <code className="font-mono">shieldcortex consolidate</code>. Auto-cleanup
        runs continuously while the dashboard service is up; check{' '}
        <code className="font-mono">shieldcortex service status</code> if ticks haven&apos;t advanced.
      </p>
    </GlassCard>
  );
}
