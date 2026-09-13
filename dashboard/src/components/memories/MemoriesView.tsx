'use client';

import { useState, useMemo, useCallback } from 'react';
import { Database } from 'lucide-react';
import { useOpenClawSessions, useMemoriesWithRealtime } from '@/hooks/useMemories';
import { useDashboardStore } from '@/lib/store';
import { CardError } from '@/components/ds/CardError';
import { EmptyState } from '@/components/ds/EmptyState';
import { Skeleton } from '@/components/ds/Skeleton';
import { SearchInput, Select } from '@/components/ds/Field';
import { SessionCard } from './SessionCard';
import { MemoryCard } from './MemoryCard';
import { MemoryActionModal } from './MemoryActionModal';
import type { Memory } from '@/types/memory';

type ViewTab = 'sessions' | 'all';
type SortKey = 'salience' | 'recent' | 'oldest';

/** Library tab (brief §4, §5): the default Memory view, on the DS token set
 *  and components (SearchInput/Select/EmptyState/Skeleton/CardError) — the
 *  Glass-shell twin this replaced is retired to legacy-v1 per §13.5. */
export function MemoriesView() {
  const [viewTab, setViewTab] = useState<ViewTab>('all');
  const [sortKey, setSortKey] = useState<SortKey>('recent');
  const [search, setSearch] = useState('');
  const [expandedSession, setExpandedSession] = useState<string | null>(null);

  const { selectedMemory, setSelectedMemory, projectFilter, typeFilter, categoryFilter } =
    useDashboardStore();

  const { data: openClawData } = useOpenClawSessions();
  const {
    data: memories = [],
    isLoading,
    isError,
    error,
    refetch,
  } = useMemoriesWithRealtime({
    limit: 1000,
    project: projectFilter || undefined,
    type: typeFilter || undefined,
    category: categoryFilter || undefined,
    mode: search ? 'search' : 'recent',
    query: search || undefined,
  });

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
            type="button"
            onClick={() => setViewTab('sessions')}
            className={`px-3 py-1.5 text-xs font-medium transition-colors ${
              viewTab === 'sessions'
                ? 'bg-[var(--sc-border)] text-[var(--sc-text)]'
                : 'text-[var(--sc-text-dim)] hover:text-[var(--sc-text)]'
            }`}
          >
            Sessions <span className="ml-1 text-[var(--sc-text-muted)]">{sessions.length}</span>
          </button>
          <button
            type="button"
            onClick={() => setViewTab('all')}
            className={`px-3 py-1.5 text-xs font-medium transition-colors ${
              viewTab === 'all'
                ? 'bg-[var(--sc-border)] text-[var(--sc-text)]'
                : 'text-[var(--sc-text-dim)] hover:text-[var(--sc-text)]'
            }`}
          >
            All <span className="ml-1 text-[var(--sc-text-muted)]">{memories.length}</span>
          </button>
        </div>

        <Select
          value={sortKey}
          onChange={(e) => setSortKey(e.target.value as SortKey)}
          aria-label="Sort memories"
          className="w-auto"
        >
          <option value="salience">Salience</option>
          <option value="recent">Recent</option>
          <option value="oldest">Oldest</option>
        </Select>

        <SearchInput
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          placeholder="Search memories…"
          aria-label="Search memories"
          containerClassName="ml-auto w-56"
        />
      </div>

      {isError && (
        <CardError
          message={`Failed to load memories: ${error instanceof Error ? error.message : 'fetch failed'}`}
          onRetry={() => refetch()}
        />
      )}

      {isLoading && !isError && (
        <div className="grid grid-cols-1 gap-3 md:grid-cols-2 2xl:grid-cols-3">
          <Skeleton className="h-32" />
          <Skeleton className="h-32" />
          <Skeleton className="h-32" />
        </div>
      )}

      {!isLoading && !isError && (
        <>
          {/* Sessions view */}
          {viewTab === 'sessions' && (
            <div className="space-y-3">
              {sessions.length === 0 && (
                <EmptyState
                  icon={Database}
                  message="No OpenClaw sessions found. Sessions appear here after OpenClaw hooks capture memories."
                />
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
                <EmptyState
                  className="col-span-full"
                  icon={Database}
                  message={search ? 'No memories match your search.' : 'No memories found yet — they appear here as they are captured.'}
                />
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
        </>
      )}

      {selectedMemory && (
        <MemoryActionModal memory={selectedMemory} onClose={() => handleSelectMemory(null)} />
      )}
    </div>
  );
}
