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
      ? 'text-emerald-400'
      : healthPct > 40
        ? 'text-amber-400'
        : 'text-red-400';

  const totalMemories = stats?.total ?? 0;
  const totalLinks =
    (stats as MemoryStats & { totalLinks?: number; links?: number })?.totalLinks ??
    (stats as MemoryStats & { totalLinks?: number; links?: number })?.links ??
    0;

  return (
    <div className="flex items-center h-10 px-4 bg-slate-900/80 backdrop-blur-sm border-b border-slate-800 text-sm">
      {/* Brain Health */}
      <div className="flex items-center gap-1.5">
        <span className="text-slate-400">Brain Health</span>
        <span className={`font-medium ${healthColor}`}>{healthPct}%</span>
      </div>

      <div className="w-px h-4 bg-slate-700 mx-3" />

      {/* Total Memories */}
      <div className="flex items-center gap-1.5">
        <span className="text-slate-400">Memories</span>
        <span className="text-slate-200 font-medium">{totalMemories}</span>
      </div>

      <div className="w-px h-4 bg-slate-700 mx-3" />

      {/* Total Links */}
      <div className="flex items-center gap-1.5">
        <span className="text-slate-400">Links</span>
        <span className="text-slate-200 font-medium">{totalLinks}</span>
      </div>

      <div className="w-px h-4 bg-slate-700 mx-3" />

      {/* Contradictions */}
      <button
        onClick={onClickContradictions}
        className="flex items-center gap-1.5 hover:bg-slate-800/60 rounded px-1.5 py-0.5 transition-colors"
      >
        <span className="text-slate-400">Contradictions</span>
        <span
          className={`font-medium ${
            contradictionCount > 0
              ? 'text-amber-400 animate-pulse'
              : 'text-slate-200'
          }`}
        >
          {contradictionCount}
        </span>
      </button>

      <div className="w-px h-4 bg-slate-700 mx-3" />

      {/* Quarantine */}
      <button
        onClick={onClickQuarantine}
        className="flex items-center gap-1.5 hover:bg-slate-800/60 rounded px-1.5 py-0.5 transition-colors"
      >
        <span className="text-slate-400">Quarantine</span>
        <span
          className={`font-medium ${
            quarantineCount > 0
              ? 'text-red-400 animate-pulse'
              : 'text-slate-200'
          }`}
        >
          {quarantineCount}
        </span>
      </button>

      <div className="w-px h-4 bg-slate-700 mx-3" />

      {/* Last Consolidation */}
      <button
        onClick={onClickConsolidation}
        className="flex items-center gap-1.5 hover:bg-slate-800/60 rounded px-1.5 py-0.5 transition-colors"
      >
        <span className="text-slate-400">Consolidated</span>
        <span className="text-slate-200 font-medium">
          {formatConsolidationTime(lastConsolidation)}
        </span>
      </button>
    </div>
  );
}
