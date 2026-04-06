'use client';

import { useState, useMemo } from 'react';
import { motion, AnimatePresence } from 'framer-motion';
import { Users, Filter, ArrowUpDown, AlertTriangle, ChevronRight } from 'lucide-react';
import { useAgentRegistry } from '@/hooks/useAgents';
import { useDashboardStore } from '@/lib/store';
import type { AgentInfo } from '@/types/agents';
import { getTrustTier, trustTierColors, trustTierBg, trustTierLabels } from '@/types/agents';
import { TrustTimeline } from './TrustTimeline';
import { FlaggedOperations } from './FlaggedOperations';
import { AlertFeed } from './AlertFeed';

type SortField = 'operation_count' | 'avg_trust_score' | 'last_seen' | 'flagged_count';
type TimeRange = '24h' | '7d' | '30d';

function parseHierarchy(identifier: string): string[] {
  return identifier.split('>').map((s) => s.trim());
}

// Helper for relative time - accepts current timestamp to avoid Date.now() during render
function formatTimeAgo(ts: string, now: number): string {
  const diff = now - new Date(ts).getTime();
  if (diff < 60_000) return 'just now';
  if (diff < 3600_000) return `${Math.floor(diff / 60_000)}m ago`;
  if (diff < 86400_000) return `${Math.floor(diff / 3600_000)}h ago`;
  return `${Math.floor(diff / 86400_000)}d ago`;
}

function AgentIdentifier({ identifier, compact }: { identifier: string; compact?: boolean }) {
  const parts = parseHierarchy(identifier);
  if (parts.length === 1) {
    return <span className="font-mono text-sm text-[var(--sc-text-primary)]">{identifier}</span>;
  }
  if (compact) {
    return (
      <span className="font-mono text-sm">
        <span className="text-[var(--sc-text-muted)]">{parts.slice(0, -1).join(' › ')} › </span>
        <span className="text-[var(--sc-text-primary)]">{parts[parts.length - 1]}</span>
      </span>
    );
  }
  return (
    <div className="font-mono text-sm">
      {parts.map((part, i) => (
        <span key={i}>
          {i > 0 && <ChevronRight size={12} className="inline text-[var(--sc-text-muted)] mx-0.5" />}
          <span className={i === parts.length - 1 ? 'text-[var(--sc-text-primary)]' : 'text-[var(--sc-text-muted)]'}>{part}</span>
        </span>
      ))}
    </div>
  );
}

function TrustBadge({ score }: { score: number }) {
  const tier = getTrustTier(score);
  return (
    <span className={`inline-flex items-center gap-1 px-1.5 py-0.5 rounded text-[10px] font-medium ${trustTierColors[tier]} ${trustTierBg[tier]}`}>
      {score.toFixed(2)} · {trustTierLabels[tier]}
    </span>
  );
}

function SourceTypeBadge({ type }: { type: string }) {
  const colors: Record<string, string> = {
    agent: 'text-purple-400 bg-purple-500/10',
    cli: 'text-[var(--sc-cyan)] bg-[var(--sc-cyan)]/10',
    user: 'text-[var(--sc-cyan)] bg-[var(--sc-cyan)]/10',
    hook: 'text-blue-400 bg-blue-500/10',
    api: 'text-[var(--sc-coral)] bg-[var(--sc-coral)]/10',
    web: 'text-[var(--sc-coral)] bg-[var(--sc-coral)]/10',
    file: 'text-[var(--sc-text-secondary)] bg-[var(--sc-bg-elevated)]/10',
    email: 'text-[var(--sc-amber)] bg-[var(--sc-amber)]/10',
  };
  const color = colors[type] ?? 'text-[var(--sc-text-secondary)] bg-[var(--sc-bg-elevated)]/10';
  return (
    <span className={`px-1.5 py-0.5 rounded text-[10px] font-medium ${color}`}>{type}</span>
  );
}

export function AgentsView() {
  const { projectFilter } = useDashboardStore();
  const [timeRange, setTimeRange] = useState<TimeRange>('24h');
  const [selectedAgent, setSelectedAgent] = useState<AgentInfo | null>(null);
  const [sortField, setSortField] = useState<SortField>('operation_count');
  const [sortAsc, setSortAsc] = useState(false);
  const [typeFilter, setTypeFilter] = useState<string | null>(null);
  const [tierFilter, setTierFilter] = useState<string | null>(null);
  const [flaggedOnly, setFlaggedOnly] = useState(false);
  const [now] = useState(() => Date.now()); // stable timestamp for relative times

  const { data, isLoading } = useAgentRegistry(timeRange, projectFilter ?? undefined);
  const agents = useMemo(() => data?.agents ?? [], [data?.agents]);

  // Filter
  const filtered = useMemo(() => {
    let result = agents;
    if (typeFilter) result = result.filter((a) => a.source_type === typeFilter);
    if (tierFilter) result = result.filter((a) => getTrustTier(a.avg_trust_score) === tierFilter);
    if (flaggedOnly) result = result.filter((a) => a.flagged_count > 0);
    return result;
  }, [agents, typeFilter, tierFilter, flaggedOnly]);

  // Sort
  const sorted = useMemo(() => {
    const arr = [...filtered];
    arr.sort((a, b) => {
      const av = a[sortField];
      const bv = b[sortField];
      if (typeof av === 'string' && typeof bv === 'string') return sortAsc ? av.localeCompare(bv) : bv.localeCompare(av);
      return sortAsc ? (av as number) - (bv as number) : (bv as number) - (av as number);
    });
    return arr;
  }, [filtered, sortField, sortAsc]);

  // Unique source types for filter chips
  const sourceTypes = useMemo(() => [...new Set(agents.map((a) => a.source_type))], [agents]);

  const handleSort = (field: SortField) => {
    if (sortField === field) {
      setSortAsc(!sortAsc);
    } else {
      setSortField(field);
      setSortAsc(false);
    }
  };

  // timeAgo helper is now formatTimeAgo() defined outside component

  return (
    <div className="flex h-full">
      {/* Left panel — Agent Registry */}
      <div className={`${selectedAgent ? 'w-1/2' : 'w-full'} border-r border-[var(--sc-border)] flex flex-col`}>
        {/* Header */}
        <div className="p-3 border-b border-[var(--sc-border)] flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Users size={16} className="text-[var(--sc-cyan)]" />
            <h2 className="text-sm font-medium text-[var(--sc-text-primary)]">Agent Registry</h2>
            <span className="text-xs text-[var(--sc-text-muted)]">{sorted.length} agents</span>
          </div>

          {/* Time range toggle */}
          <div className="flex gap-1">
            {(['24h', '7d', '30d'] as const).map((t) => (
              <button
                key={t}
                onClick={() => setTimeRange(t)}
                className={`px-2 py-0.5 text-[10px] rounded transition-colors ${
                  timeRange === t ? 'bg-[var(--sc-cyan)] text-[var(--sc-text-primary)]' : 'text-[var(--sc-text-secondary)] hover:text-[var(--sc-text-primary)]'
                }`}
              >
                {t}
              </button>
            ))}
          </div>
        </div>

        {/* Filters */}
        <div className="px-3 py-2 border-b border-[var(--sc-border)] flex items-center gap-2 flex-wrap">
          <Filter size={12} className="text-[var(--sc-text-muted)]" />
          {sourceTypes.map((st) => (
            <button
              key={st}
              onClick={() => setTypeFilter(typeFilter === st ? null : st)}
              className={`px-1.5 py-0.5 text-[10px] rounded transition-colors ${
                typeFilter === st ? 'bg-[var(--sc-cyan)]/20 text-[var(--sc-cyan)]' : 'text-[var(--sc-text-muted)] hover:text-[var(--sc-text-primary)]'
              }`}
            >
              {st}
            </button>
          ))}
          <span className="text-[var(--sc-text-muted)]">|</span>
          {(['full', 'limited', 'restricted'] as const).map((tier) => (
            <button
              key={tier}
              onClick={() => setTierFilter(tierFilter === tier ? null : tier)}
              className={`px-1.5 py-0.5 text-[10px] rounded transition-colors ${
                tierFilter === tier ? 'bg-[var(--sc-cyan)]/20 text-[var(--sc-cyan)]' : 'text-[var(--sc-text-muted)] hover:text-[var(--sc-text-primary)]'
              }`}
            >
              {tier}
            </button>
          ))}
          <span className="text-[var(--sc-text-muted)]">|</span>
          <button
            onClick={() => setFlaggedOnly(!flaggedOnly)}
            className={`px-1.5 py-0.5 text-[10px] rounded transition-colors flex items-center gap-0.5 ${
              flaggedOnly ? 'bg-[var(--sc-coral)]/20 text-[var(--sc-coral)]' : 'text-[var(--sc-text-muted)] hover:text-[var(--sc-text-primary)]'
            }`}
          >
            <AlertTriangle size={10} /> flagged
          </button>
        </div>

        {/* Table header */}
        <div className="px-3 py-1.5 border-b border-[var(--sc-border)] grid grid-cols-[1fr_80px_60px_60px_70px] gap-2 text-[10px] text-[var(--sc-text-muted)]">
          <span>Agent</span>
          <button onClick={() => handleSort('avg_trust_score')} className="flex items-center gap-0.5 hover:text-[var(--sc-text-primary)]">
            Trust <ArrowUpDown size={8} />
          </button>
          <button onClick={() => handleSort('operation_count')} className="flex items-center gap-0.5 hover:text-[var(--sc-text-primary)]">
            Ops <ArrowUpDown size={8} />
          </button>
          <button onClick={() => handleSort('flagged_count')} className="flex items-center gap-0.5 hover:text-[var(--sc-text-primary)]">
            Flagged <ArrowUpDown size={8} />
          </button>
          <button onClick={() => handleSort('last_seen')} className="flex items-center gap-0.5 hover:text-[var(--sc-text-primary)]">
            Last seen <ArrowUpDown size={8} />
          </button>
        </div>

        {/* Agent list */}
        <div className="flex-1 overflow-y-auto">
          {isLoading && (
            <div className="p-4 text-center text-[var(--sc-text-muted)] text-xs">Loading agents...</div>
          )}
          {!isLoading && sorted.length === 0 && (
            <div className="p-4 text-center text-[var(--sc-text-muted)] text-xs">No agents found in this time range.</div>
          )}
          {sorted.map((agent) => {
            const isSelected =
              selectedAgent?.source_identifier === agent.source_identifier &&
              selectedAgent?.source_type === agent.source_type;
            return (
              <button
                key={`${agent.source_type}:${agent.source_identifier}`}
                onClick={() => setSelectedAgent(isSelected ? null : agent)}
                className={`w-full px-3 py-2 grid grid-cols-[1fr_80px_60px_60px_70px] gap-2 items-center text-left transition-colors border-b border-[var(--sc-border)]/50 ${
                  isSelected ? 'bg-[var(--sc-cyan)]/10' : 'hover:bg-[var(--sc-bg-elevated)]'
                }`}
              >
                <div className="min-w-0">
                  <AgentIdentifier identifier={agent.source_identifier} compact />
                  <div className="mt-0.5">
                    <SourceTypeBadge type={agent.source_type} />
                  </div>
                </div>
                <TrustBadge score={agent.avg_trust_score} />
                <span className="text-xs text-[var(--sc-text-primary)] tabular-nums">{agent.operation_count}</span>
                <span className={`text-xs tabular-nums ${agent.flagged_count > 0 ? 'text-[var(--sc-coral)]' : 'text-[var(--sc-text-muted)]'}`}>
                  {agent.flagged_count}
                </span>
                <span className="text-[10px] text-[var(--sc-text-muted)]">{formatTimeAgo(agent.last_seen, now)}</span>
              </button>
            );
          })}
        </div>
      </div>

      {/* Right panel — Agent Detail */}
      <AnimatePresence>
        {selectedAgent && (
          <motion.div
            initial={{ opacity: 0, x: 20 }}
            animate={{ opacity: 1, x: 0 }}
            exit={{ opacity: 0, x: 20 }}
            className="w-1/2 flex flex-col overflow-y-auto"
          >
            {/* Agent header */}
            <div className="p-3 border-b border-[var(--sc-border)]">
              <div className="flex items-center justify-between">
                <AgentIdentifier identifier={selectedAgent.source_identifier} />
                <button
                  onClick={() => setSelectedAgent(null)}
                  className="text-[var(--sc-text-muted)] hover:text-[var(--sc-text-primary)] text-xs"
                >
                  Close
                </button>
              </div>
              <div className="flex items-center gap-2 mt-1.5">
                <SourceTypeBadge type={selectedAgent.source_type} />
                <TrustBadge score={selectedAgent.avg_trust_score} />
                <span className="text-[10px] text-[var(--sc-text-muted)]">
                  {selectedAgent.operation_count} ops · {selectedAgent.flagged_count} flagged
                </span>
              </div>
            </div>

            {/* Trust Timeline */}
            <div className="p-3 border-b border-[var(--sc-border)]">
              <h3 className="text-xs font-medium text-[var(--sc-text-secondary)] mb-2">Trust Score Timeline</h3>
              <TrustTimeline identifier={selectedAgent.source_identifier} timeRange={timeRange} />
            </div>

            {/* Flagged Operations */}
            <div className="p-3 border-b border-[var(--sc-border)]">
              <h3 className="text-xs font-medium text-[var(--sc-text-secondary)] mb-2">
                Flagged Operations
                {selectedAgent.flagged_count > 0 && (
                  <span className="ml-1 text-[var(--sc-coral)]">({selectedAgent.flagged_count})</span>
                )}
              </h3>
              <FlaggedOperations identifier={selectedAgent.source_identifier} />
            </div>

            {/* Alert Feed */}
            <div className="p-3">
              <h3 className="text-xs font-medium text-[var(--sc-text-secondary)] mb-2">Live Alerts</h3>
              <AlertFeed agentFilter={selectedAgent.source_identifier} />
            </div>
          </motion.div>
        )}
      </AnimatePresence>
    </div>
  );
}
