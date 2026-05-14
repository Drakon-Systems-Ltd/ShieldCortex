'use client';

import { Suspense, useEffect, useMemo, useState } from 'react';
import { useRouter, useSearchParams } from 'next/navigation';
import { PageHeader } from '@/components/ds/PageHeader';
import { PageSkeleton } from '@/components/ds/Skeleton';
import { Button } from '@/components/ds/Button';
import { SessionList } from '@/components/replay/SessionList';
import { Timeline } from '@/components/replay/Timeline';
import { EventDetail } from '@/components/replay/EventDetail';
import { PlayControls } from '@/components/replay/PlayControls';
import {
  useReplayEvents,
  useReplayPlayback,
  useReplaySessions,
} from '@/hooks/useReplaySession';
import { authFetch, readApiError } from '@/lib/auth';

const API_URL = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:3001';

/**
 * /memory/replay — v4.18 session capture viewer.
 *
 * Layout: 3-column on lg+ (session list | timeline + controls | event detail).
 * Collapses to a stacked view on smaller screens. Selected session lives in
 * `?session=…` so refresh + share-by-URL Just Works.
 */
function ReplayContent() {
  const router = useRouter();
  const searchParams = useSearchParams();
  const urlSession = searchParams.get('session');

  const [importStatus, setImportStatus] = useState<string | null>(null);
  const [importing, setImporting] = useState(false);

  const sessionsQuery = useReplaySessions();
  const eventsQuery = useReplayEvents(urlSession);
  const events = useMemo(() => eventsQuery.data?.events ?? [], [eventsQuery.data]);
  const playback = useReplayPlayback(events);

  // Auto-select the most recent session once on first load so the user
  // lands on something instead of an empty pane.
  useEffect(() => {
    if (urlSession) return;
    const list = sessionsQuery.data?.sessions;
    if (list && list.length > 0) {
      const params = new URLSearchParams(searchParams.toString());
      params.set('session', list[0].session_id);
      router.replace(`/memory/replay?${params.toString()}`);
    }
  }, [sessionsQuery.data, urlSession, router, searchParams]);

  const onSelectSession = (id: string) => {
    const params = new URLSearchParams(searchParams.toString());
    params.set('session', id);
    router.replace(`/memory/replay?${params.toString()}`);
  };

  const triggerImport = async () => {
    setImporting(true);
    setImportStatus(null);
    try {
      // Empty body → server runs the default ~/.claude/projects/**/*.jsonl glob.
      const res = await authFetch(`${API_URL}/api/sessions/import-jsonl`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: '{}',
      });
      if (!res.ok) throw new Error(await readApiError(res, 'Import failed'));
      const data = (await res.json()) as {
        filesImported?: number;
        filesMatched?: number;
        filesFailed?: number;
        eventCount?: number;
      };
      const parts: string[] = [];
      if (typeof data.filesImported === 'number' && typeof data.filesMatched === 'number') {
        parts.push(`${data.filesImported}/${data.filesMatched} file${data.filesMatched === 1 ? '' : 's'}`);
      }
      if (typeof data.eventCount === 'number') {
        parts.push(`${data.eventCount} event${data.eventCount === 1 ? '' : 's'}`);
      }
      if (data.filesFailed) parts.push(`${data.filesFailed} failed`);
      setImportStatus(parts.length > 0 ? `Imported: ${parts.join(', ')}` : 'Import complete');
      await sessionsQuery.refetch();
    } catch (err) {
      setImportStatus(`Import failed: ${(err as Error).message}`);
    } finally {
      setImporting(false);
    }
  };

  const sessions = sessionsQuery.data?.sessions ?? [];

  return (
    <div className="space-y-4">
      <PageHeader
        eyebrow="Memory"
        title="Replay"
        subtitle="Scrubbable timeline of prompts, tool calls, and responses captured across sessions."
        actions={
          <div className="flex items-center gap-2">
            <Button variant="outline" size="sm" onClick={() => sessionsQuery.refetch()}>
              Refresh
            </Button>
            <Button variant="cyan" size="sm" onClick={triggerImport} disabled={importing}>
              {importing ? 'Importing…' : 'Import JSONL'}
            </Button>
          </div>
        }
      />

      {importStatus && (
        <div className="rounded border border-[var(--term-border)] theme-glass:border-[var(--sc-border)] px-3 py-2 text-xs font-mono text-[var(--term-text-muted)]">
          {importStatus}
        </div>
      )}

      <div className="grid grid-cols-1 gap-4 lg:grid-cols-[260px_minmax(0,1fr)_minmax(0,360px)]">
        {/* Left rail: session list */}
        <div className="rounded border border-[var(--term-border)] theme-glass:border-[var(--sc-border)] theme-glass:bg-[var(--sc-surface-glass)] h-[640px] overflow-hidden">
          <SessionList
            sessions={sessions}
            selectedSessionId={urlSession}
            onSelect={onSelectSession}
            loading={sessionsQuery.isLoading}
            error={sessionsQuery.error as Error | null}
            onRetry={() => sessionsQuery.refetch()}
          />
        </div>

        {/* Centre: timeline + controls */}
        <div className="space-y-3">
          <Timeline
            events={events}
            currentIndex={playback.currentIndex}
            onSeek={playback.setIndex}
            playing={playback.playing}
          />
          <PlayControls playback={playback} />
          {eventsQuery.isError && (
            <div className="rounded border border-[var(--term-danger)]/40 bg-[var(--term-danger)]/10 px-3 py-2 text-xs font-mono text-[var(--term-danger)]">
              {(eventsQuery.error as Error).message}
            </div>
          )}
          {!urlSession && (
            <div className="rounded border border-[var(--term-border)] theme-glass:border-[var(--sc-border)] p-6 text-center text-xs font-mono text-[var(--term-text-muted)]">
              Pick a session from the list on the left to start replaying.
            </div>
          )}
        </div>

        {/* Right rail: focused event */}
        <div className="rounded border border-[var(--term-border)] theme-glass:border-[var(--sc-border)] theme-glass:bg-[var(--sc-surface-glass)] h-[640px] overflow-hidden">
          <EventDetail
            event={playback.current}
            indexLabel={
              playback.events.length > 0
                ? `${playback.currentIndex + 1} / ${playback.events.length}`
                : undefined
            }
            // While the events query is fetching for a session the user just
            // selected, render a skeleton instead of the previous session's
            // last-focused event (which would otherwise hang around for the
            // refetch duration).
            loading={!!urlSession && eventsQuery.isFetching && events.length === 0}
          />
        </div>
      </div>

      {/* Keyboard hint */}
      <div className="text-[10px] font-mono text-[var(--term-text-dim)]">
        Shortcuts:
        <kbd className="mx-1 rounded border border-[var(--term-border)] px-1">space</kbd>play/pause ·
        <kbd className="mx-1 rounded border border-[var(--term-border)] px-1">←</kbd>
        <kbd className="rounded border border-[var(--term-border)] px-1">→</kbd>step ·
        <kbd className="mx-1 rounded border border-[var(--term-border)] px-1">shift</kbd>+arrows jump ·
        <kbd className="mx-1 rounded border border-[var(--term-border)] px-1">[</kbd>
        <kbd className="rounded border border-[var(--term-border)] px-1">]</kbd>speed
      </div>
    </div>
  );
}

export default function ReplayPage() {
  return (
    <Suspense fallback={<PageSkeleton />}>
      <ReplayContent />
    </Suspense>
  );
}
