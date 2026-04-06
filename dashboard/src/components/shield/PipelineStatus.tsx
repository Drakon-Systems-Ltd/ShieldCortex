'use client';

import { useState, useRef, useEffect } from 'react';
import { useAuditStats, useDefenceConfig, useSetDefenceMode, type DefenceMode } from '@/hooks/useDefence';
import { useDashboardStore } from '@/lib/store';
import { Shield, Flame, Eye, Puzzle, FileText, ChevronDown, AlertTriangle } from 'lucide-react';

const PIPELINE_LAYERS = [
  { key: 'trust', label: 'Trust', icon: Shield, color: 'text-blue-400', bg: 'bg-blue-400/10' },
  { key: 'firewall', label: 'Firewall', icon: Flame, color: 'text-[var(--sc-coral)]', bg: 'bg-[var(--sc-coral)]/10' },
  { key: 'sensitivity', label: 'Sensitivity', icon: Eye, color: 'text-purple-400', bg: 'bg-purple-400/10' },
  { key: 'fragmentation', label: 'Fragment', icon: Puzzle, color: 'text-[var(--sc-cyan)]', bg: 'bg-[var(--sc-cyan)]/10' },
  { key: 'audit', label: 'Audit', icon: FileText, color: 'text-[var(--sc-cyan)]', bg: 'bg-[var(--sc-cyan)]/10' },
];

const MODE_STYLES: Record<DefenceMode, { color: string; bg: string }> = {
  strict: { color: 'text-[var(--sc-coral)]', bg: 'bg-[var(--sc-coral)]/10' },
  balanced: { color: 'text-[var(--sc-cyan)]', bg: 'bg-[var(--sc-cyan)]/10' },
  permissive: { color: 'text-[var(--sc-cyan)]', bg: 'bg-[var(--sc-cyan)]/10' },
};

interface Props {
  timeRange: '24h' | '7d' | '30d';
}

export function PipelineStatus({ timeRange }: Props) {
  const { projectFilter } = useDashboardStore();
  const { data: stats, isLoading, isError } = useAuditStats(timeRange, projectFilter || undefined);
  const { data: defenceConfig } = useDefenceConfig();
  const setMode = useSetDefenceMode();
  const [dropdownOpen, setDropdownOpen] = useState(false);
  const dropdownRef = useRef<HTMLDivElement>(null);

  const currentMode: DefenceMode = defenceConfig?.mode ?? 'balanced';
  const style = MODE_STYLES[currentMode];

  // Close dropdown on outside click
  useEffect(() => {
    function handleClick(e: MouseEvent) {
      if (dropdownRef.current && !dropdownRef.current.contains(e.target as Node)) {
        setDropdownOpen(false);
      }
    }
    if (dropdownOpen) document.addEventListener('mousedown', handleClick);
    return () => document.removeEventListener('mousedown', handleClick);
  }, [dropdownOpen]);

  return (
    <div className="bg-[var(--sc-bg-surface)] border border-[var(--sc-border)] rounded-xl p-4">
      {defenceConfig?.tampered && (
        <div className="flex items-center gap-2 bg-[var(--sc-coral)]/10 border border-[var(--sc-coral)]/30 rounded-lg px-3 py-2 mb-3">
          <AlertTriangle size={14} className="text-[var(--sc-coral)] shrink-0" />
          <span className="text-xs text-[var(--sc-coral)]">Config integrity check failed — running in strict mode</span>
        </div>
      )}
      <h3 className="text-sm font-medium text-[var(--sc-text-primary)] mb-4">Defence Pipeline</h3>

      {/* Pipeline steps */}
      <div className="flex items-center gap-1 mb-4">
        {PIPELINE_LAYERS.map(({ key, label, icon: Icon, color, bg }, i) => (
          <div key={key} className="flex items-center">
            <div className={`flex items-center gap-1.5 px-3 py-2 rounded-lg ${bg}`}>
              <Icon size={14} className={color} />
              <span className={`text-xs font-medium ${color}`}>{label}</span>
            </div>
            {i < PIPELINE_LAYERS.length - 1 && (
              <div className="w-4 h-px bg-[var(--sc-bg-elevated)] mx-0.5" />
            )}
          </div>
        ))}
      </div>

      {/* Stats row */}
      {isLoading ? (
        <div className="text-xs text-[var(--sc-text-muted)] animate-pulse">Loading stats...</div>
      ) : isError ? (
        <div className="text-xs text-[var(--sc-coral)]">Failed to load stats</div>
      ) : stats ? (
        <div className="grid grid-cols-3 gap-3">
          <div className="text-center">
            <div className="text-2xl font-bold text-[var(--sc-cyan)]">{stats.allowedCount}</div>
            <div className="text-[10px] text-[var(--sc-text-muted)] uppercase">Allowed</div>
          </div>
          <div className="text-center">
            <div className="text-2xl font-bold text-[var(--sc-coral)]">{stats.blockedCount}</div>
            <div className="text-[10px] text-[var(--sc-text-muted)] uppercase">Blocked</div>
          </div>
          <div className="text-center">
            <div className="text-2xl font-bold text-[var(--sc-amber)]">{stats.quarantinedCount}</div>
            <div className="text-[10px] text-[var(--sc-text-muted)] uppercase">Quarantined</div>
          </div>
        </div>
      ) : (
        <div className="text-xs text-[var(--sc-text-muted)]">No data</div>
      )}

      {/* View full audit log */}
      <button
        onClick={() => useDashboardStore.getState().setViewMode('audit')}
        className="mt-3 w-full text-center text-xs text-[var(--sc-cyan)] hover:text-[var(--sc-cyan)] transition-colors py-1"
      >
        View full audit log &rarr;
      </button>

      {/* Firewall mode selector */}
      <div className="mt-2 pt-3 border-t border-[var(--sc-border)] flex items-center justify-between">
        <span className="text-xs text-[var(--sc-text-muted)]">Firewall Mode</span>
        <div className="relative" ref={dropdownRef}>
          <button
            onClick={() => setDropdownOpen(!dropdownOpen)}
            className={`text-xs font-medium ${style.color} ${style.bg} px-2 py-0.5 rounded flex items-center gap-1 hover:opacity-80 transition-opacity`}
          >
            {currentMode}
            <ChevronDown size={10} />
          </button>
          {dropdownOpen && (
            <div className="absolute right-0 top-full mt-1 bg-[var(--sc-bg-elevated)] border border-[var(--sc-border)] rounded-lg shadow-xl z-50 min-w-[120px] py-1">
              {(['strict', 'balanced', 'permissive'] as DefenceMode[]).map((mode) => {
                const ms = MODE_STYLES[mode];
                return (
                  <button
                    key={mode}
                    onClick={() => {
                      setMode.mutate(mode);
                      setDropdownOpen(false);
                    }}
                    className={`w-full text-left px-3 py-1.5 text-xs hover:bg-[var(--sc-bg-elevated)]/50 transition-colors flex items-center justify-between ${
                      mode === currentMode ? ms.color + ' font-medium' : 'text-[var(--sc-text-secondary)]'
                    }`}
                  >
                    {mode}
                    {mode === currentMode && <span className="text-[10px]">&#10003;</span>}
                  </button>
                );
              })}
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
