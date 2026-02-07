'use client';

import { useDashboardStore } from '@/lib/store';
import { useStats } from '@/hooks/useMemories';
import { useAuditStats } from '@/hooks/useDefence';
import { Shield, FileText, AlertTriangle, Database, Brain, GitBranch, Users, FileSearch } from 'lucide-react';

const NAV_ITEMS = [
  { id: 'shield' as const, label: 'Shield', icon: Shield },
  { id: 'audit' as const, label: 'Audit', icon: FileText },
  { id: 'quarantine' as const, label: 'Queue', icon: AlertTriangle },
  { id: 'agents' as const, label: 'Agents', icon: Users },
  { id: 'skills' as const, label: 'Skills', icon: FileSearch },
  { id: 'memories' as const, label: 'Memories', icon: Database },
  { id: 'brain' as const, label: 'Brain', icon: Brain },
  { id: 'graph' as const, label: 'Graph', icon: GitBranch },
];

export function NavRail() {
  const { viewMode, setViewMode } = useDashboardStore();
  const { data: stats } = useStats();
  const { data: auditStats } = useAuditStats('24h');

  const healthPercent = stats?.decayDistribution
    ? Math.round(
        (stats.decayDistribution.healthy /
          Math.max(1, stats.total)) *
          100
      )
    : null;

  const blockedCount = auditStats?.blockedCount ?? 0;

  return (
    <nav className="w-14 border-r border-slate-800 bg-slate-900/50 flex flex-col items-center py-3 shrink-0">
      <div className="flex-1 flex flex-col items-center gap-1">
        {NAV_ITEMS.map(({ id, label, icon: Icon }) => (
          <button
            key={id}
            onClick={() => setViewMode(id)}
            className={`relative w-10 h-10 rounded-lg flex flex-col items-center justify-center gap-0.5 transition-colors ${
              viewMode === id
                ? 'bg-cyan-600/20 text-cyan-400'
                : 'text-slate-500 hover:text-slate-300 hover:bg-slate-800'
            }`}
            title={label}
          >
            <Icon size={18} />
            <span className="text-[9px] leading-none">{label}</span>
            {id === 'shield' && blockedCount > 0 && (
              <span className="absolute -top-0.5 -right-0.5 min-w-[14px] h-[14px] rounded-full bg-red-500 text-white text-[8px] flex items-center justify-center px-0.5">
                {blockedCount > 99 ? '99+' : blockedCount}
              </span>
            )}
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
