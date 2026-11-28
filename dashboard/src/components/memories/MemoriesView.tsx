'use client';

import { useState, useMemo, useCallback } from 'react';
import { Database } from 'lucide-react';
import { useOpenClawSessions, useMemoriesWithRealtime, type PaginationInfo } from '@/hooks/useMemories';
import { useDashboardStore } from '@/lib/store';
import { Button } from '@/components/ds/Button';
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

/**
 * Browse asks for PAGE_SIZE rows and steps by PAGE_SIZE in both directions.
 * The step is this constant, never a size read back from a response, so
 * Previous always lands on a page boundary; a response reporting any other
 * page size is refused by checkPage instead of being stepped by.
 *
 * What paging by offset cannot give, and this view does not claim:
 *  - a stable walk. /api/memories has no cursor or snapshot; `recent` is
 *    ordered by last access with no unique tie-break. A memory written,
 *    deleted or accessed between two requests moves the rows after it, so one
 *    can repeat or be missed across a page boundary. The view says so beside
 *    the pager; it cannot detect or prevent it from here.
 *  - cheap deep pages. Past the first page the route asks SQLite for
 *    LIMIT PAGE_SIZE OFFSET n instead of reading the earlier rows back and
 *    slicing; what SQLite spends skipping those rows is unmeasured.
 */
const PAGE_SIZE = 50;
/** Search is one ranked window, not a paged or exhaustive result. */
const SEARCH_WINDOW = 1000;
const NO_ROWS: Memory[] = [];

/** Unavailable steps use aria-disabled, not `disabled`: a disabled button
 *  drops out of the tab order and can lose focus mid-step. */
const STEP_CLASS =
  'aria-disabled:cursor-not-allowed aria-disabled:opacity-50 aria-disabled:hover:border-[var(--sc-border)]';

type CheckedPage = { rows: Memory[]; page: PaginationInfo } | { invalid: string };

/**
 * A response is only shown when it is the page that was asked for: its
 * position labels, the total and both steps are all derived from these fields,
 * so a missing, mistyped or contradictory one is reported, not rendered.
 */
function checkPage(rows: unknown, meta: unknown, offset: number, limit: number): CheckedPage {
  if (!Array.isArray(rows)) return { invalid: 'no memory list' };
  if (typeof meta !== 'object' || meta === null) return { invalid: 'no pagination' };
  const page = meta as Record<keyof PaginationInfo, unknown>;
  const isCount = (value: unknown): value is number => Number.isSafeInteger(value) && (value as number) >= 0;
  for (const field of ['offset', 'limit', 'total'] as const) {
    if (!isCount(page[field])) return { invalid: `${field} is not a whole number` };
  }
  if (typeof page.hasMore !== 'boolean') return { invalid: 'hasMore is not true or false' };
  if (page.offset !== offset) return { invalid: `offset ${page.offset} returned for offset ${offset}` };
  if (page.limit !== limit) return { invalid: `page size ${page.limit} returned for ${limit}` };
  if (rows.length > limit) return { invalid: `${rows.length} rows returned for a page of ${limit}` };
  if (rows.length > 0 && offset + rows.length > (page.total as number)) {
    return { invalid: `${rows.length} rows from offset ${offset} with a total of ${page.total}` };
  }
  return { rows: rows as Memory[], page: page as PaginationInfo };
}

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

  // Reset before the query observes a new scope, including a return to an old scope.
  const scope = JSON.stringify([projectFilter, typeFilter, categoryFilter, search]);
  const [page, setPage] = useState({ scope, offset: 0 });
  const offset = page.scope === scope ? page.offset : 0;
  if (page.scope !== scope) setPage({ scope, offset: 0 });

  const limit = search ? SEARCH_WINDOW : PAGE_SIZE;
  const { data: openClawData } = useOpenClawSessions();
  const {
    data,
    isLoading,
    isPending,
    isError,
    error,
    pagination,
    refetch,
  } = useMemoriesWithRealtime({
    offset,
    limit,
    project: projectFilter || undefined,
    type: typeFilter || undefined,
    category: categoryFilter || undefined,
    mode: search ? 'search' : 'recent',
    query: search || undefined,
  });

  const sessions = useMemo(() => openClawData?.sessions ?? [], [openClawData?.sessions]);

  // A failed refresh keeps `data`, so a page loaded earlier stays usable; only
  // a load with nothing to show (`data` undefined) leaves the page empty.
  const loadFailed = isError && data === undefined;
  const checked = isPending || loadFailed ? undefined : checkPage(data, pagination, offset, limit);
  const current = checked && 'page' in checked ? checked : undefined;
  const invalid = checked && 'invalid' in checked ? checked.invalid : undefined;
  const memories = current?.rows ?? NO_ROWS;
  const currentPage = current?.page;
  const pageSort = viewTab === 'all' && !search;

  // Steps come from the requested offset, so Previous still works when the
  // requested page failed or was unusable. Both wait while a page is pending.
  const lastPageOffset = currentPage ? Math.max(0, Math.ceil(currentPage.total / PAGE_SIZE) - 1) * PAGE_SIZE : offset;
  const previousOffset = Math.max(0, Math.min(offset - PAGE_SIZE, lastPageOffset));
  const canPrevious = !isPending && offset > 0;
  const canNext = !!currentPage?.hasMore;
  const range = `${offset + 1}–${offset + PAGE_SIZE}`;
  const status = (() => {
    if (search) {
      if (isPending) return 'Searching…';
      return currentPage ? `${memories.length} results returned (up to ${SEARCH_WINDOW})` : 'Search results unavailable';
    }
    if (isPending) return `Loading rows ${range}…`;
    if (loadFailed) return `Rows ${range} did not load`;
    if (!currentPage) return `Rows ${range} unavailable`;
    if (memories.length) return `Showing ${offset + 1}–${offset + memories.length} of ${currentPage.total}`;
    return currentPage.total ? `No rows on this page (${currentPage.total} matches)` : '0 matches';
  })();
  const failure = error instanceof Error ? error.message : 'fetch failed';

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
            All <span className="ml-1 text-[var(--sc-text-muted)]">{currentPage && (search ? memories.length : currentPage.total)}</span>
          </button>
        </div>

        <div className="flex items-center gap-2">
          {pageSort && <label htmlFor="memory-sort" className="text-xs">Sort this page</label>}
          <Select
            id="memory-sort"
            value={sortKey}
            onChange={(e) => setSortKey(e.target.value as SortKey)}
            aria-label={pageSort ? undefined : 'Sort memories'}
            className="w-auto"
          >
            <option value="salience">Salience</option>
            <option value="recent">Recent</option>
            <option value="oldest">Oldest</option>
          </Select>
        </div>

        <SearchInput
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          placeholder="Search memories…"
          aria-label="Search memories"
          containerClassName="ml-auto w-56"
        />
      </div>

      {/* Always mounted on this tab: the status is a live region, and a step
          control that unmounted while its page loaded would drop keyboard focus. */}
      {viewTab === 'all' && (
        <div className="space-y-1 text-xs">
          <div className="flex flex-wrap items-center gap-3">
            <span role="status">{status}</span>
            {!search && (
              <div className="flex items-center gap-3">
                <Button type="button" size="sm" variant="secondary" className={STEP_CLASS} aria-disabled={!canPrevious}
                  onClick={() => { if (canPrevious) setPage({ scope, offset: previousOffset }); }}>
                  Previous
                </Button>
                <Button type="button" size="sm" variant="secondary" className={STEP_CLASS} aria-disabled={!canNext}
                  onClick={() => { if (canNext) setPage({ scope, offset: offset + PAGE_SIZE }); }}>
                  Next
                </Button>
              </div>
            )}
          </div>
          {!search && (
            <p className="text-[var(--sc-text-muted)]">
              Live order by last access: if memories change while you browse, a row can repeat or be missed between pages.
            </p>
          )}
        </div>
      )}

      {invalid && viewTab === 'all' ? (
        <CardError
          message={`The server returned unusable page information (${invalid}), so this page is not shown.`}
          onRetry={() => refetch()}
        />
      ) : isError && (
        <CardError
          message={current
            ? `Could not refresh memories: ${failure}. Showing the page loaded earlier.`
            : `Failed to load memories: ${failure}`}
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

      {!isLoading && (
        <>
          {/* Sessions view */}
          {viewTab === 'sessions' && !isError && (
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

          {/* All memories view: under a failed refresh too, from the page loaded earlier */}
          {viewTab === 'all' && currentPage && (
            <div className="grid grid-cols-1 gap-3 md:grid-cols-2 2xl:grid-cols-3">
              {sorted.length === 0 && (search || currentPage.total === 0) && (
                <EmptyState
                  className="col-span-full"
                  icon={Database}
                  message={search ? 'No memories match your search.' : 'No memories match the current filters.'}
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
