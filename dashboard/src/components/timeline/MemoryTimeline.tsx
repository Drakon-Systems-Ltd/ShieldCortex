'use client';

/**
 * MemoryTimeline — chronological view of memories grouped by day, with
 * category/type badges and client-side filtering (brief §4 Memory > Timeline).
 */

import { useMemo, useState } from 'react';
import { Clock, Pin } from 'lucide-react';
import { useMemoriesWithRealtime } from '@/hooks/useMemories';
import { useDashboardStore } from '@/lib/store';
import { useResolvedTheme } from '@/hooks/useTheme';
import { memoryCategoryHex } from '@/lib/semantic-colours';
import { CardError } from '@/components/ds/CardError';
import { EmptyState } from '@/components/ds/EmptyState';
import { Skeleton } from '@/components/ds/Skeleton';
import { SearchInput } from '@/components/ds/Field';
import { Badge } from '@/components/ds/Badge';
import { cn } from '@/lib/utils';
import { Memory, MemoryType, MemoryCategory } from '@/types/memory';

const MEMORY_TYPE_LABELS: Record<MemoryType, string> = {
  short_term: 'STM',
  long_term: 'LTM',
  episodic: 'Episodic',
};

const ALL_CATEGORIES: MemoryCategory[] = [
  'architecture',
  'pattern',
  'preference',
  'error',
  'context',
  'learning',
  'todo',
  'note',
  'relationship',
  'custom',
];

const TYPE_FILTER_OPTIONS: Array<{ label: string; value: MemoryType | 'all' }> = [
  { label: 'All', value: 'all' },
  { label: 'STM', value: 'short_term' },
  { label: 'LTM', value: 'long_term' },
  { label: 'Episodic', value: 'episodic' },
];

function formatTime(iso: string): string {
  return new Date(iso).toLocaleTimeString(undefined, { hour: 'numeric', minute: '2-digit' });
}

function dayKey(iso: string): string {
  const d = new Date(iso);
  return `${d.getFullYear()}-${String(d.getMonth() + 1).padStart(2, '0')}-${String(d.getDate()).padStart(2, '0')}`;
}

function dayLabel(dateKey: string): string {
  const today = new Date();
  const todayKey = dayKey(today.toISOString());
  const yesterday = new Date(today);
  yesterday.setDate(yesterday.getDate() - 1);
  const yesterdayKey = dayKey(yesterday.toISOString());

  if (dateKey === todayKey) return 'Today';
  if (dateKey === yesterdayKey) return 'Yesterday';

  const [y, m, d] = dateKey.split('-').map(Number);
  const date = new Date(y, m - 1, d);
  return date.toLocaleDateString(undefined, {
    month: 'long',
    day: 'numeric',
    year: date.getFullYear() !== today.getFullYear() ? 'numeric' : undefined,
  });
}

interface DayGroup {
  key: string;
  label: string;
  memories: Memory[];
}

function groupByDay(memories: Memory[]): DayGroup[] {
  const map = new Map<string, Memory[]>();
  for (const m of memories) {
    const k = dayKey(m.createdAt);
    if (!map.has(k)) map.set(k, []);
    map.get(k)!.push(m);
  }
  return Array.from(map.entries())
    .sort(([a], [b]) => b.localeCompare(a))
    .map(([key, mems]) => ({ key, label: dayLabel(key), memories: mems }));
}

/** Timeline tab (brief §4): DS tokens/components only, real data, honest states. */
export function MemoryTimeline() {
  const theme = useResolvedTheme();
  const { projectFilter } = useDashboardStore();
  const [selectedCategories, setSelectedCategories] = useState<Set<MemoryCategory>>(new Set());
  const [typeFilter, setTypeFilter] = useState<MemoryType | 'all'>('all');
  const [searchQuery, setSearchQuery] = useState('');

  const {
    data: memories = [],
    isLoading,
    isError,
    error,
    refetch,
  } = useMemoriesWithRealtime({
    limit: 200,
    project: projectFilter || undefined,
    mode: 'recent',
  });

  const filtered = useMemo(() => {
    let result = memories;
    if (selectedCategories.size > 0) {
      result = result.filter((m) => selectedCategories.has(m.category));
    }
    if (typeFilter !== 'all') {
      result = result.filter((m) => m.type === typeFilter);
    }
    if (searchQuery.trim()) {
      const q = searchQuery.toLowerCase();
      result = result.filter(
        (m) => m.title.toLowerCase().includes(q) || m.content.toLowerCase().includes(q),
      );
    }
    return result;
  }, [memories, selectedCategories, typeFilter, searchQuery]);

  const groups = useMemo(() => groupByDay(filtered), [filtered]);

  function toggleCategory(cat: MemoryCategory) {
    setSelectedCategories((prev) => {
      const next = new Set(prev);
      if (next.has(cat)) next.delete(cat);
      else next.add(cat);
      return next;
    });
  }

  if (isError) {
    return <CardError message={`Failed to load the timeline: ${error instanceof Error ? error.message : 'fetch failed'}`} onRetry={() => refetch()} />;
  }

  return (
    <div className="space-y-4">
      {/* Filter bar */}
      <div className="flex flex-wrap items-center gap-3">
        <SearchInput
          value={searchQuery}
          onChange={(e) => setSearchQuery(e.target.value)}
          placeholder="Search memories…"
          aria-label="Search the timeline"
          containerClassName="w-56"
        />
        <div className="flex items-center gap-1.5">
          <span className="text-[11px] uppercase tracking-wide text-[var(--sc-text-muted)]">Type</span>
          {TYPE_FILTER_OPTIONS.map((opt) => (
            <button
              key={opt.value}
              type="button"
              aria-pressed={typeFilter === opt.value}
              onClick={() => setTypeFilter(opt.value)}
              className={cn(
                'rounded-md border px-2 py-1 text-xs font-medium transition-colors',
                typeFilter === opt.value
                  ? 'border-[var(--sc-primary)] bg-[var(--sc-primary-soft)] text-[var(--sc-primary)]'
                  : 'border-[var(--sc-border)] text-[var(--sc-text-dim)] hover:border-[var(--sc-border-strong)]',
              )}
            >
              {opt.label}
            </button>
          ))}
        </div>
        <div className="flex flex-wrap items-center gap-1">
          <span className="text-[11px] uppercase tracking-wide text-[var(--sc-text-muted)]">Category</span>
          {ALL_CATEGORIES.map((cat) => {
            const active = selectedCategories.has(cat);
            const colour = memoryCategoryHex(theme, cat);
            return (
              <button
                key={cat}
                type="button"
                aria-pressed={active}
                onClick={() => toggleCategory(cat)}
                className="rounded-md border px-2 py-1 text-xs font-medium transition-colors"
                style={{
                  borderColor: active ? colour : 'var(--sc-border)',
                  color: active ? colour : 'var(--sc-text-dim)',
                  background: active ? `${colour}1a` : 'transparent',
                }}
              >
                {cat}
              </button>
            );
          })}
          {selectedCategories.size > 0 && (
            <button
              type="button"
              onClick={() => setSelectedCategories(new Set())}
              className="px-1.5 text-xs text-[var(--sc-text-muted)] hover:text-[var(--sc-text)]"
            >
              Clear
            </button>
          )}
        </div>
      </div>

      {isLoading && (
        <div className="space-y-3">
          <Skeleton className="h-20" />
          <Skeleton className="h-20" />
          <Skeleton className="h-20" />
        </div>
      )}

      {!isLoading && groups.length === 0 && (
        <EmptyState
          icon={Clock}
          message={
            memories.length === 0
              ? 'No memories yet. They appear here on the timeline as they are captured.'
              : 'No memories match the current filters.'
          }
        />
      )}

      {!isLoading && groups.length > 0 && (
        <ol className="space-y-6">
          {groups.map((group) => (
            <li key={group.key}>
              <div className="sticky top-0 z-[1] -mx-1 mb-2 bg-[var(--sc-bg)] px-1 py-1 text-xs font-semibold uppercase tracking-wide text-[var(--sc-text-muted)]">
                {group.label}
              </div>
              <ul className="space-y-2 border-l border-[var(--sc-border)] pl-4">
                {group.memories.map((memory) => {
                  const colour = memoryCategoryHex(theme, memory.category);
                  return (
                    <li
                      key={memory.id}
                      className="relative rounded-lg border border-[var(--sc-border)] bg-[var(--sc-surface)] p-3 shadow-[var(--sc-shadow-card)]"
                    >
                      <span
                        aria-hidden
                        className="absolute -left-[21px] top-4 h-2 w-2 rounded-full"
                        style={{ background: colour }}
                      />
                      <div className="mb-1 flex items-start justify-between gap-2">
                        <h3 className="line-clamp-1 flex-1 text-sm font-medium text-[var(--sc-text)]">
                          {memory.pinned && <Pin size={11} aria-label="Pinned" className="mr-1 inline text-[var(--sc-primary)]" />}
                          {memory.title}
                        </h3>
                        <span className="shrink-0 text-[11px] tabular-nums text-[var(--sc-text-muted)]">
                          {formatTime(memory.createdAt)}
                        </span>
                      </div>
                      <p className="mb-2 line-clamp-2 text-xs text-[var(--sc-text-dim)]">{memory.content}</p>
                      <div className="flex flex-wrap items-center gap-1.5">
                        <span
                          className="inline-flex items-center gap-1 rounded-full px-2 py-0.5 text-[11px] font-medium"
                          style={{ color: colour, background: `${colour}1a` }}
                        >
                          {memory.category}
                        </span>
                        <Badge variant="muted">{MEMORY_TYPE_LABELS[memory.type] ?? memory.type}</Badge>
                        {memory.status && memory.status !== 'active' && <Badge variant="amber">{memory.status}</Badge>}
                        <span className="text-[10px] tabular-nums text-[var(--sc-text-muted)]">
                          salience {Math.round(memory.salience * 100)}%
                        </span>
                      </div>
                    </li>
                  );
                })}
              </ul>
            </li>
          ))}
        </ol>
      )}
    </div>
  );
}

export default MemoryTimeline;
