'use client';

import { cn } from '@/lib/utils';
import { useMemo, useState } from 'react';
import type { ReplaySessionSummary } from '@/hooks/useReplaySession';

type SortKey = 'recency' | 'events';

interface SessionListProps {
  sessions: readonly ReplaySessionSummary[];
  selectedSessionId: string | null;
  onSelect(sessionId: string): void;
  loading?: boolean;
}

export function SessionList({ sessions, selectedSessionId, onSelect, loading }: SessionListProps) {
  const [sort, setSort] = useState<SortKey>('recency');

  const sorted = useMemo(() => {
    const copy = [...sessions];
    if (sort === 'recency') {
      copy.sort((a, b) => Date.parse(b.last_ts) - Date.parse(a.last_ts));
    } else {
      copy.sort((a, b) => b.event_count - a.event_count);
    }
    return copy;
  }, [sessions, sort]);

  return (
    <div className="flex h-full flex-col">
      {/* Header — terminal: bracketed sort toggle, glass: pill buttons. */}
      <div className="flex items-center justify-between border-b border-[var(--term-border)] px-3 py-2 theme-glass:border-[var(--sc-border)]">
        <span className="text-xs font-mono uppercase tracking-wider text-[var(--term-text-muted)] theme-glass:text-[var(--sc-text-secondary)]">
          Sessions <span className="text-[var(--term-text-dim)]">({sessions.length})</span>
        </span>
        <div className="flex gap-1">
          {(['recency', 'events'] as const).map((key) => (
            <button
              key={key}
              type="button"
              onClick={() => setSort(key)}
              className={cn(
                'rounded px-2 py-0.5 text-[10px] font-mono uppercase tracking-wider transition-colors',
                sort === key
                  ? 'text-[var(--term-neon-fg)] bg-[var(--term-neon)]/10 theme-glass:bg-[var(--sc-cyan)]/15 theme-glass:text-[var(--sc-cyan)]'
                  : 'text-[var(--term-text-dim)] hover:text-[var(--term-text)] theme-glass:text-[var(--sc-text-secondary)]',
              )}
            >
              {key === 'recency' ? 'recent' : 'events'}
            </button>
          ))}
        </div>
      </div>

      {/* List */}
      <div className="flex-1 overflow-y-auto">
        {loading && sessions.length === 0 ? (
          <div className="p-4 text-xs font-mono text-[var(--term-text-muted)]">Loading…</div>
        ) : sorted.length === 0 ? (
          <div className="p-4 text-xs font-mono text-[var(--term-text-muted)]">
            No sessions yet.
            <div className="mt-1 text-[var(--term-text-dim)]">
              Run <code className="text-[var(--term-neon-fg)]">shieldcortex import-jsonl</code> to backfill.
            </div>
          </div>
        ) : (
          <ul className="divide-y divide-[var(--term-border)] theme-glass:divide-[var(--sc-border)]">
            {sorted.map((s) => (
              <li key={s.session_id}>
                <button
                  type="button"
                  onClick={() => onSelect(s.session_id)}
                  className={cn(
                    'block w-full text-left px-3 py-2 transition-colors',
                    'hover:bg-[var(--term-electric)]/5 theme-glass:hover:bg-[var(--sc-surface-interactive)]',
                    selectedSessionId === s.session_id &&
                      'bg-[var(--term-electric)]/10 theme-glass:bg-[var(--sc-cyan)]/10',
                  )}
                >
                  <div className="flex items-baseline justify-between gap-2">
                    <code className="text-[11px] font-mono text-[var(--term-text)] theme-glass:text-[var(--sc-text-primary)] truncate">
                      {shortSessionId(s.session_id)}
                    </code>
                    <span className="text-[10px] font-mono text-[var(--term-text-muted)] theme-glass:text-[var(--sc-text-secondary)] tabular-nums">
                      {s.event_count}
                    </span>
                  </div>
                  <div className="mt-0.5 flex items-baseline justify-between gap-2">
                    <span className="text-[10px] font-mono text-[var(--term-text-dim)] truncate">
                      {s.project ?? '(no project)'}
                    </span>
                    <span className="text-[10px] font-mono text-[var(--term-text-dim)] tabular-nums">
                      {relativeTime(s.last_ts)}
                    </span>
                  </div>
                </button>
              </li>
            ))}
          </ul>
        )}
      </div>
    </div>
  );
}

function shortSessionId(id: string): string {
  // UUIDs: keep first 8 + last 4. Other formats: trim to ~20 chars.
  if (/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(id)) {
    return `${id.slice(0, 8)}…${id.slice(-4)}`;
  }
  return id.length > 22 ? `${id.slice(0, 20)}…` : id;
}

function relativeTime(iso: string): string {
  const t = Date.parse(iso);
  if (!Number.isFinite(t)) return '';
  const diff = Date.now() - t;
  const sec = Math.floor(diff / 1000);
  if (sec < 60) return `${sec}s`;
  const min = Math.floor(sec / 60);
  if (min < 60) return `${min}m`;
  const hr = Math.floor(min / 60);
  if (hr < 24) return `${hr}h`;
  const days = Math.floor(hr / 24);
  if (days < 30) return `${days}d`;
  const months = Math.floor(days / 30);
  if (months < 12) return `${months}mo`;
  return `${Math.floor(months / 12)}y`;
}
