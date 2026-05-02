'use client';

import { useState, useMemo, useCallback } from 'react';
import { useOpenClawSessions, useMemoriesWithRealtime, useAccessMemory } from '@/hooks/useMemories';
import { useDashboardStore } from '@/lib/store';
import { GlassCard } from '@/components/ds/GlassCard';
import { Badge } from '@/components/ds/Badge';
import { SessionCard } from './SessionCard';
import { MemoryCard } from './MemoryCard';
import { MemoryActionModal } from './MemoryActionModal';
import type { Memory } from '@/types/memory';

type ViewTab = 'sessions' | 'all';
type SortKey = 'salience' | 'recent' | 'oldest';

export function MemoriesView() {
  const [viewTab, setViewTab] = useState<ViewTab>('all');
  const [sortKey, setSortKey] = useState<SortKey>('recent');
  const [search, setSearch] = useState('');
  const [expandedSession, setExpandedSession] = useState<string | null>(null);

  const { selectedMemory, setSelectedMemory, projectFilter, typeFilter, categoryFilter } =
    useDashboardStore();

  const { data: openClawData } = useOpenClawSessions();
  const { data: memories = [] } = useMemoriesWithRealtime({
    limit: 1000,
    project: projectFilter || undefined,
    type: typeFilter || undefined,
    category: categoryFilter || undefined,
    mode: search ? 'search' : 'recent',
    query: search || undefined,
  });
  const accessMutation = useAccessMemory();

  const sessions = useMemo(() => openClawData?.sessions ?? [], [openClawData?.sessions]);

  const sorted = useMemo(() => {
    const arr = [...memories];
    switch (sortKey) {
      case 'salience':
        arr.sort((a, b) => b.salience - a.salience);
        break;
      case 'recent':
        arr.sort((a, b) => new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime());
        break;
      case 'oldest':
        arr.sort((a, b) => new Date(a.createdAt).getTime() - new Date(b.createdAt).getTime());
        break;
    }
    return arr;
  }, [memories, sortKey]);

  const handleToggleSession = useCallback((sessionId: string) => {
    setExpandedSession((prev) => (prev === sessionId ? null : sessionId));
  }, []);

  const handleSelectMemory = useCallback(
    (memory: Memory | null) => setSelectedMemory(memory),
    [setSelectedMemory],
  );

  return (
    <div className="space-y-4">
      {/* Controls */}
      <div className="flex flex-wrap items-center gap-3">
        <div className="flex items-center overflow-hidden rounded-lg border border-[var(--sc-border)]">
          <button
            onClick={() => setViewTab('sessions')}
            className={`px-3 py-1.5 text-xs font-medium transition-colors ${
              viewTab === 'sessions'
                ? 'bg-[var(--sc-border)] text-[var(--sc-text-primary)]'
                : 'text-[var(--sc-text-secondary)] hover:text-[var(--sc-text-primary)]'
            }`}
          >
            Sessions{' '}
            <span className="ml-1 text-[var(--sc-text-muted)]">{sessions.length}</span>
          </button>
          <button
            onClick={() => setViewTab('all')}
            className={`px-3 py-1.5 text-xs font-medium transition-colors ${
              viewTab === 'all'
                ? 'bg-[var(--sc-border)] text-[var(--sc-text-primary)]'
                : 'text-[var(--sc-text-secondary)] hover:text-[var(--sc-text-primary)]'
            }`}
          >
            All{' '}
            <span className="ml-1 text-[var(--sc-text-muted)]">{memories.length}</span>
          </button>
        </div>

        <select
          value={sortKey}
          onChange={(e) => setSortKey(e.target.value as SortKey)}
          className="rounded-lg border border-[var(--sc-border)] bg-[var(--sc-bg-elevated)] px-2 py-1.5 text-xs text-[var(--sc-text-primary)]"
        >
          <option value="salience">Salience</option>
          <option value="recent">Recent</option>
          <option value="oldest">Oldest</option>
        </select>

        <input
          type="text"
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          placeholder="Search memories..."
          className="ml-auto w-56 rounded-lg border border-[var(--sc-border)] bg-[var(--sc-bg-elevated)] px-3 py-1.5 text-xs text-[var(--sc-text-primary)] placeholder:text-[var(--sc-text-muted)] focus:border-[var(--sc-cyan)] focus:outline-none"
        />
      </div>

      {/* Sessions view */}
      {viewTab === 'sessions' && (
        <div className="space-y-3">
          {sessions.length === 0 && (
            <GlassCard className="p-6">
              <p className="text-sm text-[var(--sc-text-secondary)]">
                No OpenClaw sessions found. Sessions appear after OpenClaw hooks capture memories.
              </p>
            </GlassCard>
          )}
          {sessions.map((session) => (
            <SessionCard
              key={session.sessionId}
              session={session}
              expanded={expandedSession === session.sessionId}
              onToggle={() => handleToggleSession(session.sessionId)}
            />
          ))}
        </div>
      )}

      {/* All memories view */}
      {viewTab === 'all' && (
        <div className="grid grid-cols-1 gap-3 md:grid-cols-2 2xl:grid-cols-3">
          {sorted.length === 0 && (
            <GlassCard className="col-span-full p-6">
              <p className="text-sm text-[var(--sc-text-secondary)]">
                {search ? 'No memories match your search.' : 'No memories found.'}
              </p>
            </GlassCard>
          )}
          {sorted.map((memory) => (
            <MemoryCard
              key={memory.id}
              memory={memory}
              isSelected={selectedMemory?.id === memory.id}
              onSelect={handleSelectMemory}
            />
          ))}
        </div>
      )}

      {selectedMemory && (
        <MemoryActionModal
          memory={selectedMemory}
          onClose={() => handleSelectMemory(null)}
        />
      )}
    </div>
  );
}
