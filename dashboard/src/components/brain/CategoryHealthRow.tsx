'use client';

/**
 * CategoryHealthRow — A single row in the category health list.
 *
 * Shows category name, horizontal progress bar coloured by health
 * (green >70, amber >40, red), count badge, and a warning dot when health <50%.
 * Highlighted border/bg when this category is the active filter.
 */

interface CategoryHealthRowProps {
  category: string;
  healthPct: number;
  count: number;
  color: string;
  isActive: boolean;
  onClick: () => void;
}

export function CategoryHealthRow({
  category,
  healthPct,
  count,
  color,
  isActive,
  onClick,
}: CategoryHealthRowProps) {
  const clamped = Math.max(0, Math.min(100, healthPct));

  // Health-based bar colour (distinct from category colour)
  const barColor =
    clamped > 70 ? '#10B981' : clamped > 40 ? '#F59E0B' : '#EF4444';

  return (
    <button
      onClick={onClick}
      className={`w-full flex items-center gap-2 px-2 py-1.5 rounded text-left transition-colors ${
        isActive
          ? 'bg-slate-700/60 border border-slate-600'
          : 'bg-transparent border border-transparent hover:bg-slate-800/60'
      }`}
    >
      {/* Category colour dot */}
      <span
        className="w-2 h-2 rounded-full flex-shrink-0"
        style={{ backgroundColor: color }}
      />

      {/* Name and bar */}
      <div className="flex-1 min-w-0">
        <div className="flex items-center justify-between mb-0.5">
          <span className="text-[11px] text-slate-300 capitalize truncate">
            {category}
          </span>

          <div className="flex items-center gap-1 flex-shrink-0 ml-1">
            {/* Warning indicator when health <50% */}
            {clamped < 50 && (
              <span
                className="w-1.5 h-1.5 rounded-full bg-amber-400 flex-shrink-0"
                title="Health below 50%"
              />
            )}
            <span className="text-[10px] text-slate-500">{count}</span>
          </div>
        </div>

        {/* Horizontal progress bar */}
        <div className="w-full h-1 rounded-full bg-slate-700 overflow-hidden">
          <div
            className="h-full rounded-full"
            style={{
              width: `${clamped}%`,
              backgroundColor: barColor,
              transition: 'width 0.4s ease, background-color 0.4s ease',
            }}
          />
        </div>
      </div>
    </button>
  );
}
