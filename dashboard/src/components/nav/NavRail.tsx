'use client';

import { useDashboardStore } from '@/lib/store';
import { useStats, useVersion } from '@/hooks/useMemories';
import { useAuditStats } from '@/hooks/useDefence';
import { useLicenseStatus } from '@/hooks/useLicense';
import { useActivityTrend } from '@/hooks/useActivityTrend';
import { Sparkline } from '@/components/nav/Sparkline';
import { LayoutDashboard, Shield, FileText, AlertTriangle, Database, Brain, GitBranch, Users, FileSearch, Zap, Clock, Search, Inbox } from 'lucide-react';
import { Cloud } from 'lucide-react';

const NAV_ITEMS = [
  { id: 'overview' as const, label: 'Home', icon: LayoutDashboard },
  { id: 'recall' as const, label: 'Recall', icon: Search },
  { id: 'review' as const, label: 'Review', icon: Inbox },
  { id: 'shield' as const, label: 'Shield', icon: Shield },
  { id: 'graph' as const, label: 'Graph', icon: GitBranch },
  { id: 'cloud' as const, label: 'Cloud', icon: Cloud },
  { id: 'audit' as const, label: 'Audit', icon: FileText },
  { id: 'memories' as const, label: 'Capture', icon: Database },
  { id: 'quarantine' as const, label: 'Queue', icon: AlertTriangle },
  { id: 'agents' as const, label: 'Agents', icon: Users },
  { id: 'skills' as const, label: 'Skills', icon: FileSearch },
  { id: 'dome' as const, label: 'Dome', icon: Zap },
  { id: 'timeline' as const, label: 'Timeline', icon: Clock },
  { id: 'brain' as const, label: 'Brain', icon: Brain },
];

// Tabs that contain Pro-gated panels
const PRO_TABS = new Set(['shield', 'audit', 'skills', 'dome']);

export function NavRail() {
  const { viewMode, setViewMode } = useDashboardStore();
  const { data: stats } = useStats();
  const { data: auditStats } = useAuditStats('24h');
  const { data: versionData } = useVersion();
  const { data: license } = useLicenseStatus();
  const { memoryTrend, threatTrend } = useActivityTrend();

  const isFreeTier = !license || license.tier === 'free';

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
        {NAV_ITEMS.map(({ id, label, icon: Icon }) => {
          const sparkData =
            id === 'memories' ? memoryTrend :
            id === 'shield' ? threatTrend :
            null;
          const sparkColor =
            id === 'shield' ? '#f87171' : '#22d3ee';
          const hasSparkData = sparkData && sparkData.some(v => v > 0);

          return (
          <button
            key={id}
            onClick={() => setViewMode(id)}
            className={`relative w-10 rounded-lg flex flex-col items-center justify-center gap-0.5 transition-colors ${
              hasSparkData ? 'h-12' : 'h-10'
            } ${
              viewMode === id
                ? id === 'dome'
                  ? 'bg-red-600/20 text-red-400'
                  : 'bg-cyan-600/20 text-cyan-400'
                : 'text-slate-500 hover:text-slate-300 hover:bg-slate-800'
            }`}
            title={label}
          >
            <Icon size={18} />
            {hasSparkData && (
              <Sparkline data={sparkData} color={sparkColor} width={24} height={10} />
            )}
            <span className="text-[9px] leading-none">{label}</span>
            {id === 'shield' && blockedCount > 0 && (
              <span className="absolute -top-0.5 -right-0.5 min-w-[14px] h-[14px] rounded-full bg-red-500 text-white text-[8px] flex items-center justify-center px-0.5">
                {blockedCount > 99 ? '99+' : blockedCount}
              </span>
            )}
            {isFreeTier && PRO_TABS.has(id) && (
              <span className="absolute -bottom-0.5 -left-0.5 px-1 h-[12px] rounded-full bg-cyan-600/80 text-white text-[7px] font-bold flex items-center justify-center leading-none">
                PRO
              </span>
            )}
          </button>
          );
        })}
      </div>

      {/* Bottom stats */}
      <div className="flex flex-col items-center gap-1 text-[10px] text-slate-500">
        {stats && <span>{stats.total}</span>}
        {healthPercent !== null && <span>{healthPercent}%</span>}
        {versionData?.version && <span>v{versionData.version}</span>}
      </div>
    </nav>
  );
}
