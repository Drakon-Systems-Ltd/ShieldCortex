'use client';

import { useMemo, useState } from 'react';
import { Search } from 'lucide-react';
import { GlassCard } from '@/components/ds/GlassCard';
import { Badge } from '@/components/ds/Badge';
import { Button } from '@/components/ds/Button';
import {
  useMemoryCandidates,
  useRecallExplain,
  useRecallHistory,
  type RecallExplanationResult,
} from '@/hooks/useRecallWorkspace';
import { useDashboardStore } from '@/lib/store';

function timeAgo(dateStr: string): string {
  const seconds = Math.floor((Date.now() - new Date(dateStr).getTime()) / 1000);
  if (seconds < 60) return 'just now';
  const minutes = Math.floor(seconds / 60);
  if (minutes < 60) return `${minutes}m ago`;
  const hours = Math.floor(minutes / 60);
  if (hours < 24) return `${hours}h ago`;
  const days = Math.floor(hours / 24);
  return `${days}d ago`;
}

function RelevanceBar({ score }: { score: number }) {
  const pct = Math.round(score * 100);
  return (
    <div className="mt-2 flex items-center gap-2">
      <div className="h-1.5 flex-1 overflow-hidden rounded-full bg-[var(--sc-bg-deep)]">
        <div
          className="h-full rounded-full transition-all"
          style={{
            width: `${pct}%`,
            background: `linear-gradient(90deg, var(--sc-cyan), var(--sc-coral))`,
          }}
        />
      </div>
      <span className="text-[10px] tabular-nums text-[var(--sc-text-muted)]">{pct}%</span>
    </div>
  );
}

function ResultCard({ result }: { result: RecallExplanationResult }) {
  const [expanded, setExpanded] = useState(false);
  const memory = result.memory;

  return (
    <GlassCard
      hover
      className="p-4"
      onClick={() => setExpanded((v) => !v)}
    >
      <div className="flex items-start justify-between gap-3">
        <div className="min-w-0 flex-1">
          <div className="text-sm font-semibold text-[var(--sc-text-primary)]">
            {memory.title}
          </div>
          <div className="mt-1.5 flex flex-wrap items-center gap-1.5">
            <Badge variant="muted">{memory.category}</Badge>
            <Badge variant="cyan">{memory.project || 'global'}</Badge>
            <span className="text-xs text-[var(--sc-text-muted)]">
              {timeAgo(memory.createdAt)}
            </span>
          </div>
          <RelevanceBar score={result.relevanceScore} />
        </div>
        <div className="shrink-0 rounded-lg bg-[var(--sc-cyan)]/10 px-2.5 py-1.5 text-center">
          <span className="text-sm font-semibold tabular-nums text-[var(--sc-cyan)]">
            {result.relevanceScore.toFixed(2)}
          </span>
        </div>
      </div>

      {expanded && (
        <div className="mt-3 border-t border-[var(--sc-border)] pt-3 text-xs text-[var(--sc-text-muted)]">
          {memory.content.slice(0, 200)}
          {memory.content.length > 200 && '...'}
        </div>
      )}
    </GlassCard>
  );
}

export function RecallWorkspace() {
  const { projectFilter } = useDashboardStore();
  const [query, setQuery] = useState('');
  const [submittedQuery, setSubmittedQuery] = useState('');
  const [expectedSearch, setExpectedSearch] = useState('');
  const [expectedId, setExpectedId] = useState<number | null>(null);
  const historyMutation = useRecallHistory();

  const explainQuery = useMemo(
    () =>
      submittedQuery.trim()
        ? { query: submittedQuery.trim(), project: projectFilter, expectedId }
        : null,
    [submittedQuery, projectFilter, expectedId],
  );
  const { data, isLoading } = useRecallExplain(explainQuery);
  const { data: candidates = [] } = useMemoryCandidates(expectedSearch, projectFilter);

  const avgRelevance =
    data?.results.length
      ? data.results.reduce((sum, r) => sum + r.relevanceScore, 0) / data.results.length
      : 0;

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault();
    if (!query.trim()) return;
    setSubmittedQuery(query.trim());
    historyMutation.mutate(query.trim());
  };

  return (
    <div className="space-y-4">
      {/* Search bar */}
      <GlassCard className="p-4">
        <form onSubmit={handleSubmit} className="flex gap-3">
          <div className="relative flex-1">
            <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-[var(--sc-text-muted)]" />
            <input
              value={query}
              onChange={(e) => setQuery(e.target.value)}
              placeholder="Why did we choose PostgreSQL over SQLite?"
              className="h-10 w-full rounded-xl border border-[var(--sc-border)] bg-[var(--sc-bg-elevated)] pl-10 pr-4 text-sm text-[var(--sc-text-primary)] placeholder:text-[var(--sc-text-muted)] focus-ring-cyan"
            />
          </div>
          <Button type="submit" variant="coral" size="md">
            Explain recall
          </Button>
        </form>
      </GlassCard>

      {/* Stats row */}
      {data && !isLoading && (
        <div className="flex items-center gap-2">
          <Badge variant="cyan">{data.total} result{data.total === 1 ? '' : 's'}</Badge>
          <Badge variant="muted">avg relevance {avgRelevance.toFixed(2)}</Badge>
        </div>
      )}

      {/* Loading state */}
      {isLoading && (
        <div className="py-8 text-center text-sm text-[var(--sc-text-muted)] animate-pulse">
          Analysing recall...
        </div>
      )}

      {/* Empty state */}
      {!isLoading && !data && !submittedQuery && (
        <div className="py-8 text-center text-sm text-[var(--sc-text-muted)]">
          Type a query to see what the agent would remember
        </div>
      )}

      {/* No results */}
      {!isLoading && data && data.results.length === 0 && (
        <div className="py-8 text-center text-sm text-[var(--sc-text-muted)]">
          No recalled memories for this query.
        </div>
      )}

      {/* Results list */}
      {!isLoading && data && data.results.length > 0 && (
        <div className="space-y-3">
          {data.results.map((result) => (
            <ResultCard key={result.memory.id} result={result} />
          ))}
        </div>
      )}

      {/* Advanced: Recall Debugger */}
      <details className="glass-card">
        <summary className="cursor-pointer select-none p-4 text-xs uppercase tracking-[0.18em] text-[var(--sc-text-muted)]">
          Advanced: Recall Debugger
        </summary>
        <div className="space-y-6 border-t border-[var(--sc-border)] p-4">
          {/* Expected memory selector */}
          <div>
            <div className="text-xs uppercase tracking-[0.18em] text-[var(--sc-text-muted)]">
              Expected memory
            </div>
            <p className="mt-1 text-xs text-[var(--sc-text-secondary)]">
              Search for a memory you expected to appear, then compare its rank.
            </p>
            <input
              value={expectedSearch}
              onChange={(e) => setExpectedSearch(e.target.value)}
              placeholder="Search a memory to compare..."
              className="mt-3 h-9 w-full rounded-xl border border-[var(--sc-border)] bg-[var(--sc-bg-elevated)] px-3 text-sm text-[var(--sc-text-primary)] placeholder:text-[var(--sc-text-muted)] focus-ring-cyan"
            />
            <div className="mt-3 space-y-2">
              {candidates.map((memory) => (
                <button
                  key={memory.id}
                  onClick={() => {
                    setExpectedId(memory.id);
                    setExpectedSearch(memory.title);
                  }}
                  className={`block w-full rounded-lg border px-3 py-2 text-left text-sm ${
                    expectedId === memory.id
                      ? 'border-[var(--sc-cyan)]/50 bg-[var(--sc-cyan)]/10 text-[var(--sc-text-primary)]'
                      : 'border-[var(--sc-border)] bg-[var(--sc-bg-surface)] text-[var(--sc-text-primary)] hover:border-[var(--sc-text-muted)]'
                  }`}
                >
                  <div className="font-medium">{memory.title}</div>
                  <div className="text-xs text-[var(--sc-text-muted)]">
                    {memory.category} · {memory.project || 'workspace'}
                  </div>
                </button>
              ))}
            </div>
          </div>

          {/* Expected memory eligibility breakdown */}
          {data?.expectedMemory && (
            <div>
              <div className="text-xs uppercase tracking-[0.18em] text-[var(--sc-text-muted)]">
                Eligibility breakdown
              </div>
              <div className="mt-3 rounded-xl border border-[var(--sc-border)] bg-[var(--sc-bg-deep)]/60 p-3 text-sm text-[var(--sc-text-primary)]">
                <div className="text-base font-medium">{data.expectedMemory.title}</div>
                <div className="mt-2 space-y-1 text-xs text-[var(--sc-text-secondary)]">
                  <div>Rank: {data.expectedMemory.rank ?? 'not returned'}</div>
                  <div>Status: {data.expectedMemory.status}</div>
                  <div>
                    Capture: {data.expectedMemory.captureMethod} · {data.expectedMemory.sourceKind}
                  </div>
                  <div>
                    Eligible:{' '}
                    <Badge variant={data.expectedMemory.eligible ? 'safe' : 'coral'}>
                      {data.expectedMemory.eligible ? 'yes' : 'no'}
                    </Badge>
                  </div>
                </div>
                <div className="mt-3 space-y-1">
                  {data.expectedMemory.reasons.map((reason) => (
                    <div
                      key={reason}
                      className="rounded-lg border border-[var(--sc-border)] bg-[var(--sc-bg-deep)]/60 px-3 py-2 text-xs text-[var(--sc-text-secondary)]"
                    >
                      {reason}
                    </div>
                  ))}
                </div>
              </div>
            </div>
          )}

          {/* Likely misses */}
          {data?.misses && data.misses.length > 0 && (
            <div>
              <div className="text-xs uppercase tracking-[0.18em] text-[var(--sc-text-muted)]">
                Likely misses ({data.misses.length})
              </div>
              <div className="mt-3 space-y-3">
                {data.misses.map((miss) => (
                  <div
                    key={miss.id}
                    className="rounded-xl border border-[var(--sc-border)] bg-[var(--sc-bg-deep)]/60 p-3"
                  >
                    <div className="text-sm font-medium text-[var(--sc-text-primary)]">
                      {miss.title}
                    </div>
                    <div className="mt-1 text-xs text-[var(--sc-text-muted)]">
                      {miss.captureMethod} · salience {miss.salience.toFixed(2)}
                    </div>
                    <ul className="mt-2 space-y-1 text-xs text-[var(--sc-text-secondary)]">
                      {miss.whyNotRecalled.map((reason) => (
                        <li key={reason}>• {reason}</li>
                      ))}
                    </ul>
                  </div>
                ))}
              </div>
            </div>
          )}

          {!data && (
            <div className="text-sm text-[var(--sc-text-secondary)]">
              Run a recall query first, then use this section to debug ranking and misses.
            </div>
          )}
        </div>
      </details>
    </div>
  );
}
