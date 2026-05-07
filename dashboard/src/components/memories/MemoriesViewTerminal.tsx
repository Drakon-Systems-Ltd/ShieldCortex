'use client';

import { useState, useMemo, useCallback } from 'react';
import { useOpenClawSessions, useMemoriesWithRealtime } from '@/hooks/useMemories';
import { useDashboardStore } from '@/lib/store';
import { GlassCard } from '@/components/ds/GlassCard';
import { Badge } from '@/components/ds/Badge';
import { SessionCard } from './SessionCard';
import { MemoryActionModal } from './MemoryActionModal';
import type { Memory, MemoryType, MemoryCategory } from '@/types/memory';
import { cn } from '@/lib/utils';

type ViewTab = 'sessions' | 'all';
type SortKey = 'salience' | 'recent' | 'oldest';

const TYPE_LABEL: Record<MemoryType, string> = {
  short_term: 'STM',
  long_term: 'LTM',
  episodic: 'EPI',
};

const TYPE_VARIANT: Record<MemoryType, 'cyan' | 'safe' | 'low'> = {
  short_term: 'low',
  long_term: 'safe',
  episodic: 'cyan',
};

const CATEGORY_SHORT: Record<MemoryCategory, string> = {
  architecture: 'arch',
  pattern: 'patt',
  preference: 'pref',
  error: 'err ',
  context: 'ctx ',
  learning: 'lrn ',
  todo: 'todo',
  note: 'note',
  relationship: 'rel ',
  custom: 'cust',
};

function salienceBar(s: number): string {
  // 10-cell bar using density-graded blocks.
  const filled = Math.round(s * 10);
  const blocks = '█'.repeat(Math.max(0, filled));
  const dots = '░'.repeat(Math.max(0, 10 - filled));
  return blocks + dots;
}

function fmtDate(iso: string): string {
  return iso.replace('T', ' ').replace(/:\d{2}\.\d+Z$/, 'Z').slice(0, 16);
}

export function MemoriesViewTerminal() {
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
      <div className="flex flex-wrap items-center gap-3 font-mono text-xs">
        <div className="flex items-center gap-1">
          <button
            type="button"
            onClick={() => setViewTab('sessions')}
            className={cn(
              'px-2 py-1 transition-colors',
              viewTab === 'sessions'
                ? 'text-[var(--term-electric-fg)]'
                : 'text-[var(--term-text-muted)] hover:text-[var(--term-text)]',
            )}
          >
            [sessions ({sessions.length})]
          </button>
          <button
            type="button"
            onClick={() => setViewTab('all')}
            className={cn(
              'px-2 py-1 transition-colors',
              viewTab === 'all'
                ? 'text-[var(--term-electric-fg)]'
                : 'text-[var(--term-text-muted)] hover:text-[var(--term-text)]',
            )}
          >
            [all ({memories.length})]
          </button>
        </div>

        <span className="text-[var(--term-text-muted)] ml-2">sort</span>
        <span className="text-[var(--term-text-muted)]" aria-hidden>=</span>
        <select
          aria-label="Sort memories"
          value={sortKey}
          onChange={(e) => setSortKey(e.target.value as SortKey)}
          className="rounded-sm border border-[var(--term-border)] bg-[var(--term-surface-2)] px-2 py-0.5 text-[var(--term-text)] font-mono focus:outline-none focus:border-[var(--term-electric)]"
        >
          <option value="salience">salience</option>
          <option value="recent">recent</option>
          <option value="oldest">oldest</option>
        </select>

        <div className="ml-auto flex items-center gap-2">
          <span className="text-[var(--term-electric-fg)]" aria-hidden>›</span>
          <input
            type="text"
            value={search}
            onChange={(e) => setSearch(e.target.value)}
            placeholder="grep memories…"
            aria-label="Search memories"
            className="w-64 rounded-sm border border-[var(--term-border)] bg-[var(--term-surface-2)] px-2 py-0.5 text-[var(--term-text)] placeholder:text-[var(--term-text-muted)] font-mono focus:border-[var(--term-electric)] focus:outline-none"
          />
        </div>
      </div>

      {viewTab === 'sessions' && (
        <div className="space-y-3">
          {sessions.length === 0 && (
            <GlassCard title="memory.sessions">
              <p className="text-sm font-mono text-[var(--term-text-muted)]">
                # no OpenClaw sessions found. sessions appear after OpenClaw hooks capture memories.
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

      {viewTab === 'all' && (
        <GlassCard
          title="memory.list"
          bodyPadding={false}
          statusLine={`${sorted.length} memor${sorted.length === 1 ? 'y' : 'ies'} · sort=${sortKey}${search ? ` · q="${search}"` : ''}`}
        >
          {sorted.length === 0 ? (
            <div className="p-6 font-mono text-sm text-[var(--term-text-muted)]">
              # {search ? 'no memories match your search' : 'no memories found'}
            </div>
          ) : (
            <ul className="font-mono text-xs">
              {sorted.map((memory) => {
                const isSelected = selectedMemory?.id === memory.id;
                return (
                  <li key={memory.id}>
                    <button
                      type="button"
                      onClick={() => handleSelectMemory(memory)}
                      className={cn(
                        'flex w-full items-center gap-3 px-3 py-1.5 text-left border-b border-[var(--term-border)] last:border-0 transition-colors',
                        isSelected
                          ? 'bg-[var(--term-surface-2)]'
                          : 'hover:bg-[var(--term-surface-2)]',
                      )}
                    >
                      <span className="shrink-0 text-[var(--term-text-muted)] tabular-nums w-32 truncate">
                        {fmtDate(memory.createdAt)}
                      </span>
                      <span className="shrink-0 w-14">
                        <Badge variant={TYPE_VARIANT[memory.type]}>{TYPE_LABEL[memory.type]}</Badge>
                      </span>
                      <span className="shrink-0 w-12 text-[var(--term-text-muted)]">
                        {CATEGORY_SHORT[memory.category]}
                      </span>
                      <span className="shrink-0 w-32 truncate text-[var(--term-text-muted)]">
                        {memory.project ?? '—'}
                      </span>
                      <span className="flex-1 truncate text-[var(--term-text)]">
                        {memory.title}
                      </span>
                      <span className="shrink-0 text-[var(--term-electric-fg)] tracking-tighter select-none">
                        {salienceBar(memory.salience)}
                      </span>
                      <span className="shrink-0 w-10 text-right text-[var(--term-text-dim)] tabular-nums">
                        {memory.salience.toFixed(2)}
                      </span>
                    </button>
                  </li>
                );
              })}
            </ul>
          )}
        </GlassCard>
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
