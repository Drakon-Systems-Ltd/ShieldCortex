'use client';

/**
 * Top Stats Bar — Brain Tab Control Centre
 *
 * Thin dark glass bar showing key brain metrics at a glance:
 * Brain Health %, total memories, links, contradictions, quarantine, last consolidation.
 */

import { MemoryStats } from '@/types/memory';

interface TopStatsBarProps {
  stats: MemoryStats;
  contradictionCount: number;
  quarantineCount: number;
  lastConsolidation: string | null;
  workerStatus?: { running?: boolean; lastRun?: string } | null;
  onClickContradictions?: () => void;
  onClickQuarantine?: () => void;
  onClickConsolidation?: () => void;
}

function formatConsolidationTime(timestamp: string | null): string {
  if (!timestamp) return 'Never';
  const date = new Date(timestamp);
  const now = Date.now();
  const diffMs = now - date.getTime();
  const diffMins = Math.floor(diffMs / 60000);

  if (diffMins < 1) return 'Just now';
  if (diffMins < 60) return `${diffMins}m ago`;
  const diffHours = Math.floor(diffMins / 60);
  if (diffHours < 24) return `${diffHours}h ago`;
  const diffDays = Math.floor(diffHours / 24);
  return `${diffDays}d ago`;
}

export function TopStatsBar({
  stats,
  contradictionCount,
  quarantineCount,
  lastConsolidation,
  workerStatus,
  onClickContradictions,
  onClickQuarantine,
  onClickConsolidation,
}: TopStatsBarProps) {
  // Calculate brain health percentage from decay distribution
  const total =
    (stats?.decayDistribution?.healthy ?? 0) +
    (stats?.decayDistribution?.fading ?? 0) +
    (stats?.decayDistribution?.critical ?? 0);
  const healthPct =
    total > 0
      ? Math.round(((stats?.decayDistribution?.healthy ?? 0) / total) * 100)
      : 100;

  // Health colour: green > 70, amber > 40, red otherwise
  const healthColor =
    healthPct > 70
      ? 'text-[var(--sc-cyan)]'
      : healthPct > 40
        ? 'text-[var(--sc-amber)]'
        : 'text-[var(--sc-coral)]';

  const totalMemories = stats?.total ?? 0;
  const totalLinks =
    (stats as MemoryStats & { totalLinks?: number; links?: number })?.totalLinks ??
    (stats as MemoryStats & { totalLinks?: number; links?: number })?.links ??
    0;

  return (
    <div className="flex items-center h-10 px-4 bg-[var(--sc-bg-surface)] backdrop-blur-sm border-b border-[var(--sc-border)] text-sm">
      {/* Brain Health */}
      <div className="flex items-center gap-1.5">
        <span className="text-[var(--sc-text-secondary)]">Brain Health</span>
        <span className={`font-medium ${healthColor}`}>{healthPct}%</span>
      </div>

      <div className="w-px h-4 bg-[var(--sc-bg-elevated)] mx-3" />

      {/* Total Memories */}
      <div className="flex items-center gap-1.5">
        <span className="text-[var(--sc-text-secondary)]">Memories</span>
        <span className="text-[var(--sc-text-primary)] font-medium">{totalMemories}</span>
      </div>

      <div className="w-px h-4 bg-[var(--sc-bg-elevated)] mx-3" />

      {/* Total Links */}
      <div className="flex items-center gap-1.5">
        <span className="text-[var(--sc-text-secondary)]">Links</span>
        <span className="text-[var(--sc-text-primary)] font-medium">{totalLinks}</span>
      </div>

      <div className="w-px h-4 bg-[var(--sc-bg-elevated)] mx-3" />

      {/* Contradictions */}
      <button
        onClick={onClickContradictions}
        className="flex items-center gap-1.5 hover:bg-[var(--sc-bg-elevated)] rounded px-1.5 py-0.5 transition-colors"
      >
        <span className="text-[var(--sc-text-secondary)]">Contradictions</span>
        <span
          className={`font-medium ${
            contradictionCount > 0
              ? 'text-[var(--sc-amber)] animate-pulse'
              : 'text-[var(--sc-text-primary)]'
          }`}
        >
          {contradictionCount}
        </span>
      </button>

      <div className="w-px h-4 bg-[var(--sc-bg-elevated)] mx-3" />

      {/* Quarantine */}
      <button
        onClick={onClickQuarantine}
        className="flex items-center gap-1.5 hover:bg-[var(--sc-bg-elevated)] rounded px-1.5 py-0.5 transition-colors"
      >
        <span className="text-[var(--sc-text-secondary)]">Quarantine</span>
        <span
          className={`font-medium ${
            quarantineCount > 0
              ? 'text-[var(--sc-coral)] animate-pulse'
              : 'text-[var(--sc-text-primary)]'
          }`}
        >
          {quarantineCount}
        </span>
      </button>

      <div className="w-px h-4 bg-[var(--sc-bg-elevated)] mx-3" />

      {/* Last Consolidation */}
      <button
        onClick={onClickConsolidation}
        className="flex items-center gap-1.5 hover:bg-[var(--sc-bg-elevated)] rounded px-1.5 py-0.5 transition-colors"
      >
        <span className="text-[var(--sc-text-secondary)]">Consolidated</span>
        <span className="text-[var(--sc-text-primary)] font-medium">
          {formatConsolidationTime(lastConsolidation)}
        </span>
      </button>
    </div>
  );
}
