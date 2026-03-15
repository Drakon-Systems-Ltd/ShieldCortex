'use client';

import { useMemo, useState } from 'react';
import { Search, ShieldAlert, Sparkles, Waypoints } from 'lucide-react';
import { Input } from '@/components/ui/input';
import { Button } from '@/components/ui/button';
import { useMemoryCandidates, useRecallExplain, useRecallHistory } from '@/hooks/useRecallWorkspace';
import { useDashboardStore } from '@/lib/store';

export function RecallWorkspace() {
  const { projectFilter, setSelectedMemory, setViewMode } = useDashboardStore();
  const [query, setQuery] = useState('');
  const [submittedQuery, setSubmittedQuery] = useState('');
  const [expectedSearch, setExpectedSearch] = useState('');
  const [expectedId, setExpectedId] = useState<number | null>(null);
  const [history, setHistory] = useState<string[]>(() => {
    if (typeof window === 'undefined') return [];
    return JSON.parse(window.localStorage.getItem('shieldcortex:recall-history') ?? '[]');
  });
  const historyMutation = useRecallHistory();

  const explainQuery = useMemo(
    () => submittedQuery.trim()
      ? { query: submittedQuery.trim(), project: projectFilter, expectedId }
      : null,
    [submittedQuery, projectFilter, expectedId],
  );
  const { data, isLoading } = useRecallExplain(explainQuery);
  const { data: candidates = [] } = useMemoryCandidates(expectedSearch, projectFilter);

  return (
    <div className="h-full overflow-y-auto bg-slate-950">
      <div className="mx-auto max-w-6xl px-6 py-6 space-y-6">
        <section className="rounded-2xl border border-slate-800 bg-slate-900/70 p-6">
          <div className="flex items-start justify-between gap-4">
            <div>
              <div className="inline-flex items-center gap-2 rounded-full border border-cyan-500/20 bg-cyan-500/10 px-3 py-1 text-xs uppercase tracking-[0.18em] text-cyan-300">
                <Sparkles size={12} />
                Recall Workspace
              </div>
              <h2 className="mt-4 text-3xl font-semibold text-white">Debug what the agent would remember.</h2>
              <p className="mt-2 max-w-2xl text-sm text-slate-400">
                Run a recall query, inspect ranking factors, see contradiction pressure, and compare an expected memory against the returned set.
              </p>
            </div>
          </div>

          <div className="mt-6 grid gap-4 lg:grid-cols-[minmax(0,2fr)_minmax(280px,1fr)]">
            <form
              className="space-y-3"
              onSubmit={(event) => {
                event.preventDefault();
                if (!query.trim()) return;
                setSubmittedQuery(query.trim());
                historyMutation.mutate(query.trim(), {
                  onSuccess: (next) => setHistory(next),
                });
              }}
            >
              <div className="flex gap-3">
                <div className="relative flex-1">
                  <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-slate-500" />
                  <Input
                    value={query}
                    onChange={(e) => setQuery(e.target.value)}
                    placeholder="Why did we choose PostgreSQL over SQLite?"
                    className="h-11 border-slate-700 bg-slate-950 pl-10 text-white"
                  />
                </div>
                <Button type="submit" className="h-11 bg-cyan-600 hover:bg-cyan-500">Explain recall</Button>
              </div>
              {history.length > 0 && (
                <div className="flex flex-wrap gap-2">
                  {history.map((item) => (
                    <button
                      key={item}
                      type="button"
                      onClick={() => {
                        setQuery(item);
                        setSubmittedQuery(item);
                      }}
                      className="rounded-full border border-slate-700 bg-slate-900 px-3 py-1 text-xs text-slate-300 hover:border-slate-500 hover:text-white"
                    >
                      {item}
                    </button>
                  ))}
                </div>
              )}
            </form>

            <div className="rounded-xl border border-slate-800 bg-slate-950/60 p-4">
              <div className="text-xs uppercase tracking-[0.18em] text-slate-500">Expected memory</div>
              <Input
                value={expectedSearch}
                onChange={(e) => setExpectedSearch(e.target.value)}
                placeholder="Search a memory to compare..."
                className="mt-3 border-slate-700 bg-slate-950 text-white"
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
                        ? 'border-cyan-500/50 bg-cyan-500/10 text-white'
                        : 'border-slate-800 bg-slate-900 text-slate-300 hover:border-slate-600'
                    }`}
                  >
                    <div className="font-medium">{memory.title}</div>
                    <div className="text-xs text-slate-500">{memory.category} · {memory.project || 'workspace'}</div>
                  </button>
                ))}
              </div>
            </div>
          </div>
        </section>

        <div className="grid gap-6 xl:grid-cols-[minmax(0,1.5fr)_minmax(320px,0.9fr)]">
          <section className="rounded-2xl border border-slate-800 bg-slate-900/70 p-5">
            <div className="flex items-center justify-between">
              <div>
                <div className="text-xs uppercase tracking-[0.18em] text-slate-500">Ranked recall set</div>
                <div className="mt-1 text-sm text-slate-400">{data?.total ?? 0} results</div>
              </div>
              {isLoading && <div className="text-sm text-slate-400">Explaining…</div>}
            </div>

            <div className="mt-4 space-y-3">
              {data?.results.map((result, index) => (
                <button
                  key={result.memory.id}
                  onClick={() => {
                    setSelectedMemory(result.memory);
                    setViewMode('memories');
                  }}
                  className="block w-full rounded-xl border border-slate-800 bg-slate-950/70 p-4 text-left hover:border-slate-600"
                >
                  <div className="flex items-start justify-between gap-4">
                    <div>
                      <div className="text-xs uppercase tracking-[0.18em] text-slate-500">Rank #{index + 1}</div>
                      <div className="mt-1 text-lg font-medium text-white">{result.memory.title}</div>
                      <div className="mt-1 text-xs text-slate-400">
                        {result.memory.category} · {result.memory.captureMethod || 'manual'} · trust {(result.memory.trustScore ?? 1).toFixed(2)}
                      </div>
                    </div>
                    <div className="rounded-lg bg-cyan-500/10 px-3 py-2 text-right">
                      <div className="text-[10px] uppercase tracking-[0.18em] text-cyan-300">Score</div>
                      <div className="text-base font-semibold text-cyan-100">{result.relevanceScore.toFixed(2)}</div>
                    </div>
                  </div>
                  <div className="mt-3 flex flex-wrap gap-2 text-xs text-slate-300">
                    {(result.explanation?.reasons ?? []).slice(0, 4).map((reason) => (
                      <span key={reason} className="rounded-full border border-slate-700 px-2 py-1">{reason}</span>
                    ))}
                  </div>
                  {result.contradictions && result.contradictions.length > 0 && (
                    <div className="mt-3 inline-flex items-center gap-2 rounded-full bg-amber-500/10 px-3 py-1 text-xs text-amber-300">
                      <ShieldAlert size={12} />
                      {result.contradictions.length} contradiction link{result.contradictions.length === 1 ? '' : 's'}
                    </div>
                  )}
                </button>
              ))}
              {!isLoading && !data?.results.length && submittedQuery && (
                <div className="rounded-xl border border-slate-800 bg-slate-950/60 p-6 text-sm text-slate-400">
                  No recalled memories for this query.
                </div>
              )}
            </div>
          </section>

          <section className="space-y-6">
            <div className="rounded-2xl border border-slate-800 bg-slate-900/70 p-5">
              <div className="flex items-center gap-2 text-xs uppercase tracking-[0.18em] text-slate-500">
                <Waypoints size={13} />
                Expected memory debugger
              </div>
              {data?.expectedMemory ? (
                <div className="mt-4 space-y-3 text-sm text-slate-300">
                  <div className="text-lg font-medium text-white">{data.expectedMemory.title}</div>
                  <div className="rounded-xl border border-slate-800 bg-slate-950/60 p-3">
                    <div>Rank: {data.expectedMemory.rank ?? 'not returned'}</div>
                    <div>Status: {data.expectedMemory.status}</div>
                    <div>Capture: {data.expectedMemory.captureMethod} · {data.expectedMemory.sourceKind}</div>
                  </div>
                  <div className="space-y-2">
                    {data.expectedMemory.reasons.map((reason) => (
                      <div key={reason} className="rounded-lg border border-slate-800 bg-slate-950/60 px-3 py-2 text-xs text-slate-400">{reason}</div>
                    ))}
                  </div>
                </div>
              ) : (
                <div className="mt-4 text-sm text-slate-400">Pick an expected memory to compare it against the ranked result set.</div>
              )}
            </div>

            <div className="rounded-2xl border border-slate-800 bg-slate-900/70 p-5">
              <div className="text-xs uppercase tracking-[0.18em] text-slate-500">Likely misses</div>
              <div className="mt-4 space-y-3">
                {(data?.misses ?? []).map((miss) => (
                  <div key={miss.id} className="rounded-xl border border-slate-800 bg-slate-950/60 p-3">
                    <div className="text-sm font-medium text-white">{miss.title}</div>
                    <div className="mt-1 text-xs text-slate-500">{miss.captureMethod} · salience {miss.salience.toFixed(2)}</div>
                    <ul className="mt-2 space-y-1 text-xs text-slate-400">
                      {miss.whyNotRecalled.map((reason) => <li key={reason}>• {reason}</li>)}
                    </ul>
                  </div>
                ))}
                {!data?.misses?.length && (
                  <div className="text-sm text-slate-400">No notable misses for this query.</div>
                )}
              </div>
            </div>
          </section>
        </div>
      </div>
    </div>
  );
}
