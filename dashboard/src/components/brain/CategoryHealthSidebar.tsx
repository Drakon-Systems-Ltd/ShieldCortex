'use client';

/**
 * CategoryHealthSidebar — Left sidebar panel for the Brain control centre.
 *
 * Three sections:
 * 1. Top: HealthRing showing overall brain health
 * 2. Middle: Scrollable list of CategoryHealthRow components
 * 3. Bottom: Quick actions (consolidate, scan contradictions, worker status)
 *
 * Semi-transparent dark glass style consistent with the existing dashboard.
 */

import { useMemo } from 'react';
import { Memory, MemoryStats, MemoryCategory } from '@/types/memory';
import { CATEGORY_COLORS } from '@/lib/category-colors';
import { HealthRing } from './HealthRing';
import { CategoryHealthRow } from './CategoryHealthRow';

interface CategoryHealthSidebarProps {
  stats: MemoryStats;
  memories: Memory[];
  onCategoryClick: (category: string | null) => void;
  activeCategory: string | null;
  onConsolidate: () => void;
  isConsolidating: boolean;
  onScanContradictions?: () => void;
  workerStatus?: any;
}

export function CategoryHealthSidebar({
  stats,
  memories,
  onCategoryClick,
  activeCategory,
  onConsolidate,
  isConsolidating,
  onScanContradictions,
  workerStatus,
}: CategoryHealthSidebarProps) {
  // Overall brain health from decay distribution
  const overallHealth = useMemo(() => {
    const total =
      (stats?.decayDistribution?.healthy ?? 0) +
      (stats?.decayDistribution?.fading ?? 0) +
      (stats?.decayDistribution?.critical ?? 0);
    return total > 0
      ? Math.round(((stats?.decayDistribution?.healthy ?? 0) / total) * 100)
      : 100;
  }, [stats?.decayDistribution]);

  // Per-category health: average decayedScore of memories in that category
  const categoryHealthData = useMemo(() => {
    const categories = stats?.byCategory ?? {};
    const categoryKeys = Object.keys(categories) as MemoryCategory[];

    return categoryKeys.map((category) => {
      const categoryMemories = memories.filter((m) => m.category === category);
      const count = categories[category] ?? 0;

      // Average decayed score (0-1) mapped to percentage
      let healthPct = 100;
      if (categoryMemories.length > 0) {
        const totalDecayed = categoryMemories.reduce(
          (sum, m) => sum + (m.decayedScore ?? m.salience ?? 0.5),
          0
        );
        healthPct = Math.round((totalDecayed / categoryMemories.length) * 100);
      }

      const color =
        CATEGORY_COLORS[category as MemoryCategory] ?? CATEGORY_COLORS.custom;

      return { category, healthPct, count, color };
    });
  }, [stats?.byCategory, memories]);

  // Worker status display
  const workerLabel = workerStatus?.running
    ? 'Active'
    : workerStatus?.lastRun
      ? 'Idle'
      : 'Stopped';
  const workerDotClass = workerStatus?.running
    ? 'bg-emerald-400'
    : workerStatus?.lastRun
      ? 'bg-amber-400'
      : 'bg-slate-500';

  return (
    <div className="w-56 shrink-0 h-full flex flex-col bg-slate-900/80 backdrop-blur-sm border-r border-slate-800">
      {/* -- Top: Overall Health Ring -- */}
      <div className="flex flex-col items-center py-4 px-3 border-b border-slate-800">
        <HealthRing percentage={overallHealth} size={80} strokeWidth={6} />
        <span className="text-[11px] text-slate-400 mt-2">Brain Health</span>
      </div>

      {/* -- Middle: Category Health List -- */}
      <div className="flex-1 overflow-y-auto px-2 py-2 space-y-0.5">
        <div className="text-[10px] text-slate-500 uppercase tracking-wider px-2 mb-1">
          Categories
        </div>
        {categoryHealthData.length === 0 && (
          <div className="text-[11px] text-slate-500 px-2 py-2">
            No categories yet
          </div>
        )}
        {categoryHealthData.map(({ category, healthPct, count, color }) => (
          <CategoryHealthRow
            key={category}
            category={category}
            healthPct={healthPct}
            count={count}
            color={color}
            isActive={activeCategory === category}
            onClick={() =>
              onCategoryClick(activeCategory === category ? null : category)
            }
          />
        ))}
      </div>

      {/* -- Bottom: Quick Actions -- */}
      <div className="px-3 py-3 border-t border-slate-800 space-y-2">
        <button
          onClick={onConsolidate}
          disabled={isConsolidating}
          className={`w-full px-2 py-1.5 text-[11px] rounded transition-colors ${
            isConsolidating
              ? 'bg-slate-700 text-slate-500 cursor-not-allowed'
              : 'bg-blue-600/80 text-blue-100 hover:bg-blue-600'
          }`}
        >
          {isConsolidating ? 'Consolidating...' : 'Consolidate Now'}
        </button>

        {onScanContradictions && (
          <button
            onClick={onScanContradictions}
            className="w-full px-2 py-1.5 text-[11px] rounded bg-slate-700/60 text-slate-300 hover:bg-slate-700 transition-colors"
          >
            Scan Contradictions
          </button>
        )}

        {/* Worker status indicator */}
        <div className="flex items-center gap-2 px-1 pt-1">
          <span className={`w-1.5 h-1.5 rounded-full ${workerDotClass}`} />
          <span className="text-[10px] text-slate-500">
            Worker: {workerLabel}
          </span>
        </div>
      </div>
    </div>
  );
}
