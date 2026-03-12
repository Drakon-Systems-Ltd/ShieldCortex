'use client';

import { Archive, CloudOff, Pin, ShieldAlert, Sparkles, Layers } from 'lucide-react';
import { useMergeMemories, useReviewAction, useReviewQueue } from '@/hooks/useReviewQueue';
import { useDashboardStore } from '@/lib/store';
import type { Memory } from '@/types/memory';

function ReviewActionBar({
  memory,
  onOpen,
}: {
  memory: Memory;
  onOpen: (memory: Memory) => void;
}) {
  const reviewAction = useReviewAction();

  const act = (action: string) => {
    reviewAction.mutate({ id: memory.id, action, reviewedBy: 'dashboard' });
  };

  return (
    <div className="mt-3 flex flex-wrap gap-2">
      <button onClick={() => onOpen(memory)} className="rounded-lg border border-slate-700 px-3 py-1 text-xs text-slate-300 hover:border-slate-500">Inspect</button>
      <button onClick={() => act(memory.pinned ? 'unpin' : 'pin')} className="rounded-lg border border-slate-700 px-3 py-1 text-xs text-slate-300 hover:border-slate-500">
        <Pin className="mr-1 inline h-3 w-3" />{memory.pinned ? 'Unpin' : 'Pin'}
      </button>
      <button onClick={() => act('suppress')} className="rounded-lg border border-amber-500/40 px-3 py-1 text-xs text-amber-300 hover:bg-amber-500/10">Suppress</button>
      <button onClick={() => act('archive')} className="rounded-lg border border-slate-700 px-3 py-1 text-xs text-slate-300 hover:border-slate-500">
        <Archive className="mr-1 inline h-3 w-3" />Archive
      </button>
      <button onClick={() => act(memory.cloudExcluded ? 'includeCloud' : 'excludeCloud')} className="rounded-lg border border-slate-700 px-3 py-1 text-xs text-slate-300 hover:border-slate-500">
        <CloudOff className="mr-1 inline h-3 w-3" />{memory.cloudExcluded ? 'Include cloud' : 'Exclude cloud'}
      </button>
      <button onClick={() => act(memory.scope === 'global' ? 'rescopeProject' : 'rescopeGlobal')} className="rounded-lg border border-slate-700 px-3 py-1 text-xs text-slate-300 hover:border-slate-500">
        {memory.scope === 'global' ? 'Project scope' : 'Make global'}
      </button>
      <button onClick={() => act('canonicalize')} className="rounded-lg border border-emerald-500/40 px-3 py-1 text-xs text-emerald-300 hover:bg-emerald-500/10">Canonical</button>
    </div>
  );
}

function MemorySection({
  title,
  detail,
  items,
  onOpen,
}: {
  title: string;
  detail: string;
  items: Memory[];
  onOpen: (memory: Memory) => void;
}) {
  return (
    <section className="rounded-2xl border border-slate-800 bg-slate-900/70 p-5">
      <div className="flex items-center justify-between">
        <div>
          <h3 className="text-lg font-semibold text-white">{title}</h3>
          <p className="mt-1 text-sm text-slate-400">{detail}</p>
        </div>
        <div className="rounded-full bg-slate-800 px-3 py-1 text-xs text-slate-300">{items.length}</div>
      </div>
      <div className="mt-4 space-y-3">
        {items.slice(0, 8).map((memory) => (
          <div key={memory.id} className="rounded-xl border border-slate-800 bg-slate-950/60 p-4">
            <div className="flex items-start justify-between gap-4">
              <div>
                <div className="text-base font-medium text-white">{memory.title}</div>
                <div className="mt-1 text-xs text-slate-500">
                  {memory.category} · {memory.captureMethod || 'manual'} · trust {(memory.trustScore ?? 1).toFixed(2)}
                </div>
              </div>
              <div className="rounded-lg bg-slate-800 px-3 py-2 text-right">
                <div className="text-[10px] uppercase tracking-[0.18em] text-slate-500">State</div>
                <div className="text-sm text-slate-100">{memory.status || 'active'}</div>
              </div>
            </div>
            <ReviewActionBar memory={memory} onOpen={onOpen} />
          </div>
        ))}
        {!items.length && <div className="text-sm text-slate-400">Nothing to review here.</div>}
      </div>
    </section>
  );
}

export function ReviewQueueView() {
  const { projectFilter, setSelectedMemory, setViewMode } = useDashboardStore();
  const { data, isLoading } = useReviewQueue(projectFilter);
  const mergeMutation = useMergeMemories();

  const openMemory = (memory: Memory) => {
    setSelectedMemory(memory);
    setViewMode('memories');
  };

  return (
    <div className="h-full overflow-y-auto bg-slate-950">
      <div className="mx-auto max-w-6xl px-6 py-6 space-y-6">
        <section className="rounded-2xl border border-slate-800 bg-slate-900/70 p-6">
          <div className="inline-flex items-center gap-2 rounded-full border border-amber-500/20 bg-amber-500/10 px-3 py-1 text-xs uppercase tracking-[0.18em] text-amber-300">
            <Layers size={12} />
            Review Queue
          </div>
          <h2 className="mt-4 text-3xl font-semibold text-white">Fix memory quality before it turns into recall debt.</h2>
          <p className="mt-2 max-w-2xl text-sm text-slate-400">
            Review stale, contradictory, low-trust, and noisy auto-extracted memories. Pin the good ones, suppress the noisy ones, and keep cloud sync intentional.
          </p>

          <div className="mt-6 grid gap-4 md:grid-cols-3 xl:grid-cols-6">
            {Object.entries(data?.summary ?? {}).map(([key, count]) => (
              <div key={key} className="rounded-xl border border-slate-800 bg-slate-950/70 p-4">
                <div className="text-xs uppercase tracking-[0.18em] text-slate-500">{key}</div>
                <div className="mt-2 text-2xl font-semibold text-white">{count}</div>
              </div>
            ))}
          </div>

          <div className="mt-6 rounded-2xl border border-slate-800 bg-slate-950/60 p-4">
            <div className="flex items-center gap-2 text-xs uppercase tracking-[0.18em] text-slate-500">
              <Sparkles size={12} />
              OpenClaw capture
            </div>
            <div className="mt-4 grid gap-4 md:grid-cols-5">
              <div><div className="text-xs text-slate-500">Total</div><div className="text-xl font-semibold text-white">{data?.openClaw.total ?? 0}</div></div>
              <div><div className="text-xs text-slate-500">Auto-extracted</div><div className="text-xl font-semibold text-white">{data?.openClaw.autoExtracted ?? 0}</div></div>
              <div><div className="text-xs text-slate-500">Keyword-triggered</div><div className="text-xl font-semibold text-white">{data?.openClaw.keywordTriggered ?? 0}</div></div>
              <div><div className="text-xs text-slate-500">Suppressed</div><div className="text-xl font-semibold text-white">{data?.openClaw.suppressed ?? 0}</div></div>
              <div><div className="text-xs text-slate-500">Pinned</div><div className="text-xl font-semibold text-white">{data?.openClaw.pinned ?? 0}</div></div>
            </div>
          </div>
        </section>

        {isLoading && <div className="text-sm text-slate-400">Loading review queue…</div>}

        <div className="grid gap-6 xl:grid-cols-2">
          <MemorySection title="Low trust" detail="These memories came from weaker or noisier sources." items={data?.sections.lowTrust ?? []} onOpen={openMemory} />
          <MemorySection title="Noisy auto-extracted" detail="Auto capture is useful, but not every extraction deserves to stay hot." items={data?.sections.noisyAutoExtracted ?? []} onOpen={openMemory} />
          <MemorySection title="Stale" detail="Useful once, maybe. Worth archiving or refreshing now." items={data?.sections.stale ?? []} onOpen={openMemory} />
          <MemorySection title="Never used" detail="Stored but never recalled. High count usually means capture is too noisy." items={data?.sections.neverUsed ?? []} onOpen={openMemory} />
          <MemorySection title="Projectless" detail="These memories have no useful project scope and are likely to leak into the wrong context." items={data?.sections.projectless ?? []} onOpen={openMemory} />
          <section className="rounded-2xl border border-slate-800 bg-slate-900/70 p-5">
            <div className="flex items-center gap-2">
              <Layers size={16} className="text-cyan-300" />
              <h3 className="text-lg font-semibold text-white">Duplicate candidates</h3>
            </div>
            <p className="mt-1 text-sm text-slate-400">One click keeps the recommended memory, merges unique content, and removes the duplicate.</p>
            <div className="mt-4 space-y-3">
              {(data?.sections.duplicates ?? []).slice(0, 8).map((pair) => {
                const keep = pair.recommendedKeepId === pair.memoryA.id ? pair.memoryA : pair.memoryB;
                const remove = pair.recommendedKeepId === pair.memoryA.id ? pair.memoryB : pair.memoryA;
                return (
                  <div key={`${pair.memoryA.id}-${pair.memoryB.id}`} className="rounded-xl border border-slate-800 bg-slate-950/60 p-4">
                    <div className="flex items-start justify-between gap-4">
                      <div>
                        <div className="text-sm font-medium text-white">{pair.memoryA.title}</div>
                        <div className="mt-1 text-xs text-slate-500">paired with {pair.memoryB.title}</div>
                        <div className="mt-2 text-xs text-slate-400">{pair.similarity} · shared title words {pair.sharedWords}</div>
                      </div>
                      <div className="rounded-lg bg-emerald-500/10 px-3 py-2 text-xs text-emerald-300">
                        Keep {keep.id}
                      </div>
                    </div>
                    <div className="mt-3 flex flex-wrap gap-2">
                      <button onClick={() => openMemory(pair.memoryA)} className="rounded-lg border border-slate-700 px-3 py-1 text-xs text-slate-300 hover:border-slate-500">Inspect A</button>
                      <button onClick={() => openMemory(pair.memoryB)} className="rounded-lg border border-slate-700 px-3 py-1 text-xs text-slate-300 hover:border-slate-500">Inspect B</button>
                      <button
                        onClick={() => mergeMutation.mutate({ keptId: keep.id, removedId: remove.id, reviewedBy: 'dashboard-merge' })}
                        className="rounded-lg border border-emerald-500/40 px-3 py-1 text-xs text-emerald-300 hover:bg-emerald-500/10"
                      >
                        Merge into recommended
                      </button>
                      <button
                        onClick={() => mergeMutation.mutate({ keptId: remove.id, removedId: keep.id, reviewedBy: 'dashboard-merge' })}
                        className="rounded-lg border border-slate-700 px-3 py-1 text-xs text-slate-300 hover:border-slate-500"
                      >
                        Keep other instead
                      </button>
                    </div>
                  </div>
                );
              })}
              {!data?.sections.duplicates?.length && <div className="text-sm text-slate-400">No duplicate candidates detected.</div>}
            </div>
          </section>

          <section className="rounded-2xl border border-slate-800 bg-slate-900/70 p-5">
            <div className="flex items-center gap-2">
              <ShieldAlert size={16} className="text-amber-300" />
              <h3 className="text-lg font-semibold text-white">Contradiction clusters</h3>
            </div>
            <div className="mt-4 space-y-3">
              {(data?.sections.contradictions ?? []).slice(0, 8).map((item) => (
                <div key={`${item.memoryA.id}-${item.memoryB.id}`} className="rounded-xl border border-slate-800 bg-slate-950/60 p-4">
                  <div className="text-sm font-medium text-white">{item.memoryA.title}</div>
                  <div className="mt-1 text-xs text-slate-500">conflicts with</div>
                  <div className="mt-1 text-sm font-medium text-white">{item.memoryB.title}</div>
                  <div className="mt-2 text-xs text-slate-400">{item.reason}</div>
                  <div className="mt-3 flex gap-2">
                    <button onClick={() => openMemory(item.memoryA)} className="rounded-lg border border-slate-700 px-3 py-1 text-xs text-slate-300 hover:border-slate-500">Inspect A</button>
                    <button onClick={() => openMemory(item.memoryB)} className="rounded-lg border border-slate-700 px-3 py-1 text-xs text-slate-300 hover:border-slate-500">Inspect B</button>
                  </div>
                </div>
              ))}
              {!data?.sections.contradictions?.length && <div className="text-sm text-slate-400">No contradiction clusters detected.</div>}
            </div>
          </section>
        </div>
      </div>
    </div>
  );
}
