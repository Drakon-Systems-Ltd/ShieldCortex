'use client';

import { useDashboardStore } from '@/lib/store';
import { useStats } from '@/hooks/useMemories';
import { Network, LayoutGrid, BarChart3, Brain, Share2 } from 'lucide-react';

const NAV_ITEMS = [
  { id: 'graph' as const, label: 'Graph', icon: Network },
  { id: 'memories' as const, label: 'Memories', icon: LayoutGrid },
  { id: 'insights' as const, label: 'Insights', icon: BarChart3 },
  { id: 'brain' as const, label: 'Brain', icon: Brain },
  { id: 'ontology' as const, label: 'Ontology', icon: Share2 },
];

export function NavRail() {
  const { viewMode, setViewMode } = useDashboardStore();
  const { data: stats } = useStats();

  const healthPercent = stats?.decayDistribution
    ? Math.round(
        (stats.decayDistribution.healthy /
          Math.max(1, stats.total)) *
          100
      )
    : null;

  return (
    <nav className="w-14 border-r border-slate-800 bg-slate-900/50 flex flex-col items-center py-3 shrink-0">
      <div className="flex-1 flex flex-col items-center gap-1">
        {NAV_ITEMS.map(({ id, label, icon: Icon }) => (
          <button
            key={id}
            onClick={() => setViewMode(id)}
            className={`w-10 h-10 rounded-lg flex flex-col items-center justify-center gap-0.5 transition-colors ${
              viewMode === id
                ? 'bg-cyan-600/20 text-cyan-400'
                : 'text-slate-500 hover:text-slate-300 hover:bg-slate-800'
            }`}
            title={label}
          >
            <Icon size={18} />
            <span className="text-[9px] leading-none">{label}</span>
          </button>
        ))}
      </div>

      {/* Bottom stats */}
      <div className="flex flex-col items-center gap-1 text-[10px] text-slate-500">
        {stats && <span>{stats.total}</span>}
        {healthPercent !== null && <span>{healthPercent}%</span>}
      </div>
    </nav>
  );
}
