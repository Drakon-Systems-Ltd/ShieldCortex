'use client';

import { useEffect, useMemo, useState } from 'react';
import { Archive, CloudOff, Pin, ShieldAlert, Sparkles, Layers, CheckCircle2 } from 'lucide-react';
import { useMergeMemories, useReviewAction, useReviewQueue } from '@/hooks/useReviewQueue';
import { useDashboardStore } from '@/lib/store';
import type { Memory } from '@/types/memory';
import { MemoryDetail } from '@/components/memory/MemoryDetail';

function timeSince(value?: string | null) {
  if (!value) return null;
  const diffMs = Date.now() - new Date(value).getTime();
  const hours = Math.floor(diffMs / (1000 * 60 * 60));
  if (hours < 1) return 'just now';
  if (hours < 24) return `${hours}h ago`;
  const days = Math.floor(hours / 24);
  if (days < 7) return `${days}d ago`;
  return `${Math.floor(days / 7)}w ago`;
}

function ReviewSignals({ memory }: { memory: Memory }) {
  const status = memory.status ?? 'active';
  const reviewed = timeSince(memory.reviewedAt);
  const chips = [
    memory.pinned ? { label: 'Pinned', tone: 'emerald' as const } : null,
    status === 'canonical' ? { label: 'Canonical', tone: 'emerald' as const } : null,
    status === 'suppressed' ? { label: 'Suppressed', tone: 'amber' as const } : null,
    status === 'archived' ? { label: 'Archived', tone: 'slate' as const } : null,
    memory.cloudExcluded ? { label: 'Cloud excluded', tone: 'cyan' as const } : null,
    memory.scope === 'global' ? { label: 'Global', tone: 'violet' as const } : null,
    reviewed ? { label: `Reviewed ${reviewed}`, tone: 'slate' as const } : null,
  ].filter(Boolean) as Array<{ label: string; tone: 'emerald' | 'amber' | 'slate' | 'cyan' | 'violet' }>;

  const toneClass: Record<string, string> = {
    emerald: 'border-emerald-500/30 bg-emerald-500/10 text-emerald-200',
    amber: 'border-amber-500/30 bg-amber-500/10 text-amber-200',
    slate: 'border-slate-700 bg-slate-800/80 text-slate-300',
    cyan: 'border-cyan-500/30 bg-cyan-500/10 text-cyan-200',
    violet: 'border-violet-500/30 bg-violet-500/10 text-violet-200',
  };

  return (
    <div className="mt-3 flex flex-wrap gap-2">
      {chips.length > 0 ? chips.map((chip) => (
        <span key={chip.label} className={`rounded-full border px-2.5 py-1 text-[11px] ${toneClass[chip.tone]}`}>
          {chip.label}
        </span>
      )) : (
        <span className="rounded-full border border-slate-700 bg-slate-800/80 px-2.5 py-1 text-[11px] text-slate-300">
          Ready for recall
        </span>
      )}
    </div>
  );
}

function ReviewActionBar({
  memory,
  onOpen,
  onAct,
  busy,
}: {
  memory: Memory;
  onOpen: (memory: Memory) => void;
  onAct: (memory: Memory, action: string) => void | Promise<void>;
  busy: boolean;
}) {
  return (
    <div className="mt-3 flex flex-wrap gap-2">
      <button onClick={() => onOpen(memory)} className="rounded-lg border border-slate-700 px-3 py-1 text-xs text-slate-300 hover:border-slate-500">Inspect in panel</button>
      <button disabled={busy} onClick={() => onAct(memory, memory.pinned ? 'unpin' : 'pin')} className="rounded-lg border border-slate-700 px-3 py-1 text-xs text-slate-300 hover:border-slate-500 disabled:opacity-50">
        <Pin className="mr-1 inline h-3 w-3" />{memory.pinned ? 'Unpin' : 'Pin'}
      </button>
      <button disabled={busy} onClick={() => onAct(memory, 'suppress')} className="rounded-lg border border-amber-500/40 px-3 py-1 text-xs text-amber-300 hover:bg-amber-500/10 disabled:opacity-50">Suppress</button>
      <button disabled={busy} onClick={() => onAct(memory, memory.status === 'archived' || memory.status === 'suppressed' ? 'restore' : 'archive')} className="rounded-lg border border-slate-700 px-3 py-1 text-xs text-slate-300 hover:border-slate-500 disabled:opacity-50">
        <Archive className="mr-1 inline h-3 w-3" />{memory.status === 'archived' || memory.status === 'suppressed' ? 'Restore' : 'Archive'}
      </button>
      <button disabled={busy} onClick={() => onAct(memory, memory.cloudExcluded ? 'includeCloud' : 'excludeCloud')} className="rounded-lg border border-slate-700 px-3 py-1 text-xs text-slate-300 hover:border-slate-500 disabled:opacity-50">
        <CloudOff className="mr-1 inline h-3 w-3" />{memory.cloudExcluded ? 'Include cloud' : 'Exclude cloud'}
      </button>
      <button disabled={busy} onClick={() => onAct(memory, memory.scope === 'global' ? 'rescopeProject' : 'rescopeGlobal')} className="rounded-lg border border-slate-700 px-3 py-1 text-xs text-slate-300 hover:border-slate-500 disabled:opacity-50">
        {memory.scope === 'global' ? 'Project scope' : 'Make global'}
      </button>
      <button disabled={busy} onClick={() => onAct(memory, 'canonicalize')} className="rounded-lg border border-emerald-500/40 px-3 py-1 text-xs text-emerald-300 hover:bg-emerald-500/10 disabled:opacity-50">Canonical</button>
    </div>
  );
}

function MemorySection({
  title,
  detail,
  items,
  onOpen,
  onAct,
  busy,
}: {
  title: string;
  detail: string;
  items: Memory[];
  onOpen: (memory: Memory) => void;
  onAct: (memory: Memory, action: string) => void | Promise<void>;
  busy: boolean;
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
                <ReviewSignals memory={memory} />
              </div>
              <div className="rounded-lg bg-slate-800 px-3 py-2 text-right">
                <div className="text-[10px] uppercase tracking-[0.18em] text-slate-500">Next move</div>
                <div className="text-sm text-slate-100">
                  {memory.status === 'canonical'
                    ? 'Keep hot'
                    : memory.status === 'archived'
                      ? 'Restore or leave archived'
                      : memory.status === 'suppressed'
                        ? 'Restore or leave suppressed'
                        : 'Review or keep'}
                </div>
              </div>
            </div>
            <ReviewActionBar memory={memory} onOpen={onOpen} onAct={onAct} busy={busy} />
          </div>
        ))}
        {!items.length && <div className="text-sm text-slate-400">Nothing to review here.</div>}
      </div>
    </section>
  );
}

type ReviewSectionKey =
  | 'lowTrust'
  | 'noisyAutoExtracted'
  | 'stale'
  | 'neverUsed'
  | 'projectless'
  | 'duplicates'
  | 'contradictions';

const REVIEW_SECTION_IDS: Record<ReviewSectionKey, string> = {
  lowTrust: 'review-section-lowTrust',
  noisyAutoExtracted: 'review-section-noisyAutoExtracted',
  stale: 'review-section-stale',
  neverUsed: 'review-section-neverUsed',
  projectless: 'review-section-projectless',
  duplicates: 'review-section-duplicates',
  contradictions: 'review-section-contradictions',
};

export function ReviewQueueView() {
  const { projectFilter, reviewFocus, setReviewFocus, selectedMemory, setSelectedMemory } = useDashboardStore();
  const { data, isLoading } = useReviewQueue(projectFilter);
  const mergeMutation = useMergeMemories();
  const reviewAction = useReviewAction();
  const [feedback, setFeedback] = useState<{ kind: 'success' | 'error'; message: string } | null>(null);

  const openMemory = (memory: Memory) => {
    setSelectedMemory(memory);
  };

  useEffect(() => {
    if (!reviewFocus) return;
    const target = document.getElementById(REVIEW_SECTION_IDS[reviewFocus]);
    if (!target) return;
    target.scrollIntoView({ behavior: 'smooth', block: 'start' });
  }, [reviewFocus]);

  const runReviewAction = async (memory: Memory, action: string) => {
    try {
      setFeedback(null);
      const updated = await reviewAction.mutateAsync({ id: memory.id, action, reviewedBy: 'dashboard-review', project: memory.project ?? null, scope: memory.scope });
      if (selectedMemory?.id === updated.id || selectedMemory?.id === memory.id) {
        setSelectedMemory(updated);
      }
      const verbs: Record<string, string> = {
        pin: 'Pinned',
        unpin: 'Unpinned',
        suppress: 'Suppressed',
        archive: 'Archived',
        includeCloud: 'Included in cloud sync',
        excludeCloud: 'Excluded from cloud sync',
        rescopeProject: 'Moved to project scope',
        rescopeGlobal: 'Moved to global scope',
        canonicalize: 'Marked canonical',
      };
      setFeedback({ kind: 'success', message: `${verbs[action] ?? 'Updated'}: ${updated.title}` });
    } catch (error) {
      setFeedback({ kind: 'error', message: error instanceof Error ? error.message : `Failed to update ${memory.title}` });
    }
  };

  const runMerge = async (kept: Memory, removed: Memory) => {
    try {
      setFeedback(null);
      await mergeMutation.mutateAsync({ keptId: kept.id, removedId: removed.id, reviewedBy: 'dashboard-merge' });
      setSelectedMemory(kept);
      setFeedback({ kind: 'success', message: `Merged duplicate into "${kept.title}"` });
    } catch (error) {
      setFeedback({ kind: 'error', message: error instanceof Error ? error.message : 'Failed to merge duplicate memories' });
    }
  };

  const resolveContradiction = async (keep: Memory, suppress: Memory) => {
    try {
      setFeedback(null);
      await reviewAction.mutateAsync({ id: keep.id, action: 'canonicalize', reviewedBy: 'dashboard-review' });
      await reviewAction.mutateAsync({ id: suppress.id, action: 'suppress', reviewedBy: 'dashboard-review' });
      setSelectedMemory(keep);
      setFeedback({ kind: 'success', message: `Kept "${keep.title}" and suppressed "${suppress.title}"` });
    } catch (error) {
      setFeedback({ kind: 'error', message: error instanceof Error ? error.message : 'Failed to resolve contradiction' });
    }
  };

  const sectionOrder = useMemo(() => {
    const defaultOrder: ReviewSectionKey[] = [
      'lowTrust',
      'noisyAutoExtracted',
      'stale',
      'neverUsed',
      'projectless',
      'duplicates',
      'contradictions',
    ];
    if (!reviewFocus) return defaultOrder;
    return [reviewFocus, ...defaultOrder.filter((section) => section !== reviewFocus)];
  }, [reviewFocus]);

  const sectionCounts = {
    lowTrust: data?.sections.lowTrust.length ?? 0,
    noisyAutoExtracted: data?.sections.noisyAutoExtracted.length ?? 0,
    stale: data?.sections.stale.length ?? 0,
    neverUsed: data?.sections.neverUsed.length ?? 0,
    projectless: data?.sections.projectless.length ?? 0,
    duplicates: data?.sections.duplicates.length ?? 0,
    contradictions: data?.sections.contradictions.length ?? 0,
  };

  const sections = {
    lowTrust: (
      <section id={REVIEW_SECTION_IDS.lowTrust} className="scroll-mt-6">
        <MemorySection title="Low trust" detail="These memories came from weaker or noisier sources." items={data?.sections.lowTrust ?? []} onOpen={openMemory} onAct={runReviewAction} busy={reviewAction.isPending || mergeMutation.isPending} />
      </section>
    ),
    noisyAutoExtracted: (
      <section id={REVIEW_SECTION_IDS.noisyAutoExtracted} className="scroll-mt-6">
        <MemorySection title="Noisy auto-extracted" detail="Auto capture is useful, but not every extraction deserves to stay hot." items={data?.sections.noisyAutoExtracted ?? []} onOpen={openMemory} onAct={runReviewAction} busy={reviewAction.isPending || mergeMutation.isPending} />
      </section>
    ),
    stale: (
      <section id={REVIEW_SECTION_IDS.stale} className="scroll-mt-6">
        <MemorySection title="Stale" detail="Useful once, maybe. Worth archiving or refreshing now." items={data?.sections.stale ?? []} onOpen={openMemory} onAct={runReviewAction} busy={reviewAction.isPending || mergeMutation.isPending} />
      </section>
    ),
    neverUsed: (
      <section id={REVIEW_SECTION_IDS.neverUsed} className="scroll-mt-6">
        <MemorySection title="Never used" detail="Stored but never recalled. High count usually means capture is too noisy." items={data?.sections.neverUsed ?? []} onOpen={openMemory} onAct={runReviewAction} busy={reviewAction.isPending || mergeMutation.isPending} />
      </section>
    ),
    projectless: (
      <section id={REVIEW_SECTION_IDS.projectless} className="scroll-mt-6">
        <MemorySection title="Projectless" detail="These memories have no useful project scope and are likely to leak into the wrong context." items={data?.sections.projectless ?? []} onOpen={openMemory} onAct={runReviewAction} busy={reviewAction.isPending || mergeMutation.isPending} />
      </section>
    ),
    duplicates: (
      <section id={REVIEW_SECTION_IDS.duplicates} className="scroll-mt-6 rounded-2xl border border-slate-800 bg-slate-900/70 p-5">
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
                    onClick={() => runMerge(keep, remove)}
                    disabled={reviewAction.isPending || mergeMutation.isPending}
                    className="rounded-lg border border-emerald-500/40 px-3 py-1 text-xs text-emerald-300 hover:bg-emerald-500/10 disabled:opacity-50"
                  >
                    Merge into recommended
                  </button>
                  <button
                    onClick={() => runMerge(remove, keep)}
                    disabled={reviewAction.isPending || mergeMutation.isPending}
                    className="rounded-lg border border-slate-700 px-3 py-1 text-xs text-slate-300 hover:border-slate-500 disabled:opacity-50"
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
    ),
    contradictions: (
      <section id={REVIEW_SECTION_IDS.contradictions} className="scroll-mt-6 rounded-2xl border border-slate-800 bg-slate-900/70 p-5">
        <div className="flex items-center gap-2">
          <ShieldAlert size={16} className="text-amber-300" />
          <h3 className="text-lg font-semibold text-white">Contradiction clusters</h3>
        </div>
        <p className="mt-1 text-sm text-slate-400">Compare both sides, keep the stronger memory hot, and suppress the one you no longer want shaping recall.</p>
        <div className="mt-4 space-y-4">
          {(data?.sections.contradictions ?? []).slice(0, 8).map((item) => (
            <div key={`${item.memoryA.id}-${item.memoryB.id}`} className="rounded-xl border border-amber-500/20 bg-slate-950/60 p-4">
              <div className="flex items-start justify-between gap-4">
                <div>
                  <div className="text-xs uppercase tracking-[0.18em] text-slate-500">Contradiction score</div>
                  <div className="mt-1 text-lg font-semibold text-white">{Math.round(item.score * 100)}%</div>
                </div>
                <div className="text-right">
                  <div className="text-xs uppercase tracking-[0.18em] text-slate-500">Shared topics</div>
                  <div className="mt-1 text-sm text-slate-300">{item.sharedTopics.length ? item.sharedTopics.join(' · ') : 'No obvious shared topic'}</div>
                </div>
              </div>

              <div className="mt-3 rounded-xl border border-slate-800 bg-slate-900/60 p-3 text-sm text-slate-300">
                {item.reason}
              </div>

              <div className="mt-4 grid gap-4 xl:grid-cols-2">
                {[item.memoryA, item.memoryB].map((memory, index) => {
                  const other = index === 0 ? item.memoryB : item.memoryA;
                  return (
                    <div key={memory.id} className="rounded-xl border border-slate-800 bg-slate-900/70 p-4">
                      <div className="flex items-start justify-between gap-3">
                        <div>
                          <div className="text-xs uppercase tracking-[0.18em] text-slate-500">{index === 0 ? 'Option A' : 'Option B'}</div>
                          <div className="mt-1 text-base font-medium text-white">{memory.title}</div>
                          <div className="mt-1 text-xs text-slate-500">
                            {memory.category} · {memory.captureMethod || 'manual'} · trust {(memory.trustScore ?? 1).toFixed(2)}
                          </div>
                        </div>
                        <div className="rounded-lg bg-slate-800 px-3 py-2 text-right text-sm text-slate-100">
                          {(memory.trustScore ?? 1).toFixed(2)} trust
                        </div>
                      </div>
                      <ReviewSignals memory={memory} />
                      <div className="mt-3 line-clamp-4 text-sm text-slate-400">{memory.content}</div>
                      <div className="mt-4 flex flex-wrap gap-2">
                        <button onClick={() => openMemory(memory)} className="rounded-lg border border-slate-700 px-3 py-1 text-xs text-slate-300 hover:border-slate-500">Inspect</button>
                        <button disabled={reviewAction.isPending || mergeMutation.isPending} onClick={() => runReviewAction(memory, memory.pinned ? 'unpin' : 'pin')} className="rounded-lg border border-slate-700 px-3 py-1 text-xs text-slate-300 hover:border-slate-500 disabled:opacity-50">
                          {memory.pinned ? 'Unpin' : 'Pin'}
                        </button>
                        <button disabled={reviewAction.isPending || mergeMutation.isPending} onClick={() => resolveContradiction(memory, other)} className="rounded-lg border border-emerald-500/40 px-3 py-1 text-xs text-emerald-300 hover:bg-emerald-500/10 disabled:opacity-50">
                          Keep this, suppress other
                        </button>
                        <button disabled={reviewAction.isPending || mergeMutation.isPending} onClick={() => runReviewAction(memory, 'suppress')} className="rounded-lg border border-amber-500/40 px-3 py-1 text-xs text-amber-300 hover:bg-amber-500/10 disabled:opacity-50">
                          Suppress this one
                        </button>
                      </div>
                    </div>
                  );
                })}
              </div>
            </div>
          ))}
          {!data?.sections.contradictions?.length && <div className="text-sm text-slate-400">No contradiction clusters detected.</div>}
        </div>
      </section>
    ),
  };

  return (
    <div className="h-full overflow-y-auto bg-slate-950">
      <div className="mx-auto max-w-[1440px] px-6 py-6 space-y-6">
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

          <div className="mt-6 flex flex-wrap gap-2">
            {[
              ['contradictions', 'Contradictions'],
              ['duplicates', 'Duplicates'],
              ['stale', 'Stale'],
              ['neverUsed', 'Never used'],
              ['lowTrust', 'Low trust'],
              ['noisyAutoExtracted', 'Noisy auto'],
              ['projectless', 'Projectless'],
            ].map(([key, label]) => (
              <button
                key={key}
                onClick={() => setReviewFocus(key as typeof reviewFocus)}
                className={`rounded-full border px-3 py-1 text-xs transition-colors ${
                  reviewFocus === key
                    ? 'border-cyan-400/50 bg-cyan-500/10 text-cyan-200'
                    : 'border-slate-700 bg-slate-950/60 text-slate-300 hover:border-slate-500'
                }`}
              >
                {label} ({sectionCounts[key as keyof typeof sectionCounts]})
              </button>
            ))}
            {reviewFocus && (
              <button
                onClick={() => setReviewFocus(null)}
                className="rounded-full border border-slate-700 px-3 py-1 text-xs text-slate-300 hover:border-slate-500"
              >
                Clear focus
              </button>
            )}
          </div>
        </section>

        {isLoading && <div className="text-sm text-slate-400">Loading review queue…</div>}

        {feedback && (
          <div className={`rounded-2xl border px-4 py-3 text-sm ${
            feedback.kind === 'error'
              ? 'border-red-500/30 bg-red-500/10 text-red-200'
              : 'border-emerald-500/30 bg-emerald-500/10 text-emerald-200'
          }`}>
            <div className="flex items-start gap-2">
              {feedback.kind === 'success' && <CheckCircle2 className="mt-0.5 h-4 w-4 shrink-0" />}
              <span>{feedback.message}</span>
            </div>
          </div>
        )}

        <div className={selectedMemory ? 'grid gap-6 xl:grid-cols-[minmax(0,1fr)_420px] xl:items-start' : ''}>
          <div className="grid gap-6 xl:grid-cols-2">
            {sectionOrder.map((sectionKey) => (
              <div key={sectionKey} className={reviewFocus === sectionKey ? 'ring-1 ring-cyan-400/40 rounded-2xl' : ''}>
                {sections[sectionKey]}
              </div>
            ))}
          </div>

          {selectedMemory && (
            <aside className="xl:sticky xl:top-6 xl:self-start">
              <div className="rounded-2xl border border-cyan-500/20 bg-slate-900/70">
                <div className="border-b border-slate-800 px-4 py-3">
                  <div className="text-[10px] uppercase tracking-[0.18em] text-cyan-300">Selected memory</div>
                  <div className="mt-1 text-sm text-slate-400">
                    Inspect the memory here while you keep resolving duplicates and contradictions in the review queue.
                  </div>
                </div>
                <div className="xl:max-h-[calc(100vh-8rem)] xl:overflow-y-auto">
                  <MemoryDetail
                    memory={selectedMemory}
                    onClose={() => setSelectedMemory(null)}
                  />
                </div>
                <div className="border-t border-slate-800 px-4 py-3">
                  <button
                    onClick={() => setSelectedMemory(null)}
                    className="rounded-lg border border-slate-700 px-3 py-1 text-xs text-slate-300 hover:border-slate-500"
                  >
                    Close panel
                  </button>
                </div>
              </div>
            </aside>
          )}
        </div>
      </div>
    </div>
  );
}
