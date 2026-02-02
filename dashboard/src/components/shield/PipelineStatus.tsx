'use client';

import { useAuditStats } from '@/hooks/useDefence';
import { useDashboardStore } from '@/lib/store';
import { Shield, Flame, Eye, Puzzle, FileText } from 'lucide-react';

const PIPELINE_LAYERS = [
  { key: 'trust', label: 'Trust', icon: Shield, color: 'text-blue-400', bg: 'bg-blue-400/10' },
  { key: 'firewall', label: 'Firewall', icon: Flame, color: 'text-orange-400', bg: 'bg-orange-400/10' },
  { key: 'sensitivity', label: 'Sensitivity', icon: Eye, color: 'text-purple-400', bg: 'bg-purple-400/10' },
  { key: 'fragmentation', label: 'Fragment', icon: Puzzle, color: 'text-cyan-400', bg: 'bg-cyan-400/10' },
  { key: 'audit', label: 'Audit', icon: FileText, color: 'text-green-400', bg: 'bg-green-400/10' },
];

interface Props {
  timeRange: '24h' | '7d' | '30d';
}

export function PipelineStatus({ timeRange }: Props) {
  const { projectFilter } = useDashboardStore();
  const { data: stats, isLoading, isError } = useAuditStats(timeRange, projectFilter || undefined);

  return (
    <div className="bg-slate-900 border border-slate-800 rounded-xl p-4">
      <h3 className="text-sm font-medium text-slate-300 mb-4">Defence Pipeline</h3>

      {/* Pipeline steps */}
      <div className="flex items-center gap-1 mb-4">
        {PIPELINE_LAYERS.map(({ key, label, icon: Icon, color, bg }, i) => (
          <div key={key} className="flex items-center">
            <div className={`flex items-center gap-1.5 px-3 py-2 rounded-lg ${bg}`}>
              <Icon size={14} className={color} />
              <span className={`text-xs font-medium ${color}`}>{label}</span>
            </div>
            {i < PIPELINE_LAYERS.length - 1 && (
              <div className="w-4 h-px bg-slate-700 mx-0.5" />
            )}
          </div>
        ))}
      </div>

      {/* Stats row */}
      {isLoading ? (
        <div className="text-xs text-slate-500 animate-pulse">Loading stats...</div>
      ) : isError ? (
        <div className="text-xs text-red-400">Failed to load stats</div>
      ) : stats ? (
        <div className="grid grid-cols-3 gap-3">
          <div className="text-center">
            <div className="text-2xl font-bold text-green-400">{stats.allowedCount}</div>
            <div className="text-[10px] text-slate-500 uppercase">Allowed</div>
          </div>
          <div className="text-center">
            <div className="text-2xl font-bold text-red-400">{stats.blockedCount}</div>
            <div className="text-[10px] text-slate-500 uppercase">Blocked</div>
          </div>
          <div className="text-center">
            <div className="text-2xl font-bold text-yellow-400">{stats.quarantinedCount}</div>
            <div className="text-[10px] text-slate-500 uppercase">Quarantined</div>
          </div>
        </div>
      ) : (
        <div className="text-xs text-slate-500">No data</div>
      )}

      {/* Firewall mode indicator */}
      <div className="mt-4 pt-3 border-t border-slate-800 flex items-center justify-between">
        <span className="text-xs text-slate-500">Firewall Mode</span>
        <span className="text-xs font-medium text-cyan-400 bg-cyan-400/10 px-2 py-0.5 rounded">
          balanced
        </span>
      </div>
    </div>
  );
}
