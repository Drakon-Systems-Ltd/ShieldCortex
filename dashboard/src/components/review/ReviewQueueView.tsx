'use client';

import { useEffect, useRef, useState } from 'react';
import { CheckCircle2, Layers, ShieldAlert } from 'lucide-react';
import { useMergeMemories, useReviewAction, useReviewQueue } from '@/hooks/useReviewQueue';
import { useDashboardStore } from '@/lib/store';
import { Button } from '@/components/ds/Button';
import { ReviewCard, type ReviewCardAction } from './ReviewCard';
import type { Memory } from '@/types/memory';

const FOCUS_TO_QUEUE: Record<string, QueueKey | null> = {
  lowTrust: 'lowTrust',
  stale: 'stale',
  noisyAutoExtracted: 'noisyAutoExtracted',
  neverUsed: 'neverUsed',
  projectless: 'projectless',
  duplicates: null,      // scroll target, not a queue
  contradictions: null,  // scroll target, not a queue
};

type QueueKey = 'lowTrust' | 'stale' | 'noisyAutoExtracted' | 'neverUsed' | 'projectless';

const QUEUE_META: Record<QueueKey, { label: string; reasonLabel: string; reasonVariant: string }> = {
  lowTrust: { label: 'Low Trust', reasonLabel: 'LOW TRUST', reasonVariant: 'coral' },
  stale: { label: 'Stale', reasonLabel: 'STALE', reasonVariant: 'amber' },
  noisyAutoExtracted: { label: 'Noisy Auto', reasonLabel: 'AUTO-EXTRACTED', reasonVariant: 'medium' },
  neverUsed: { label: 'Never Used', reasonLabel: 'NEVER USED', reasonVariant: 'muted' },
  projectless: { label: 'Projectless', reasonLabel: 'NO PROJECT', reasonVariant: 'info' },
};

const QUEUE_ORDER: QueueKey[] = ['lowTrust', 'stale', 'noisyAutoExtracted', 'neverUsed', 'projectless'];

function buildReasons(memory: Memory, queue: QueueKey): { label: string; variant: string }[] {
  const reasons: { label: string; variant: string }[] = [];
  const meta = QUEUE_META[queue];
  reasons.push({ label: meta.reasonLabel, variant: meta.reasonVariant });

  const trust = memory.trustScore ?? 1;
  if (queue !== 'lowTrust' && trust < 0.7) {
    reasons.push({ label: `TRUST ${trust.toFixed(1)}`, variant: 'coral' });
  }
  if (queue === 'lowTrust') {
    reasons.push({ label: `${trust.toFixed(2)}`, variant: 'coral' });
  }
  if (memory.captureMethod === 'auto' || memory.tags?.includes('auto-extracted')) {
    if (queue !== 'noisyAutoExtracted') {
      reasons.push({ label: 'AUTO-EXTRACTED', variant: 'medium' });
    }
  }
  return reasons;
}

function actionToApi(action: ReviewCardAction, memory: Memory): string {
  switch (action) {
    case 'keep': return 'restore';
    case 'suppress': return 'suppress';
    case 'archive': return 'archive';
    case 'pin': return memory.pinned ? 'unpin' : 'pin';
    case 'canonical': return 'canonicalize';
    case 'global': return memory.scope === 'global' ? 'rescopeProject' : 'rescopeGlobal';
    case 'cloudExclude': return memory.cloudExcluded ? 'includeCloud' : 'excludeCloud';
  }
}

export function ReviewQueueView() {
  const { projectFilter, selectedMemory, setSelectedMemory, reviewFocus, setReviewFocus } = useDashboardStore();
  const { data, isLoading } = useReviewQueue(projectFilter);
  const reviewAction = useReviewAction();
  const mergeMutation = useMergeMemories();

  const [activeQueue, setActiveQueue] = useState<QueueKey>('lowTrust');
  const [currentIndex, setCurrentIndex] = useState(0);
  const [feedback, setFeedback] = useState<{ kind: 'success' | 'error'; message: string } | null>(null);
  const [exiting, setExiting] = useState(false);
  const cardKey = useRef(0);
  const contradictionsRef = useRef<HTMLDivElement>(null);
  const duplicatesRef = useRef<HTMLDivElement>(null);
  const focusHandled = useRef<string | null>(null);

  // Handle reviewFocus from OverviewView navigation
  useEffect(() => {
    if (!reviewFocus || !data || focusHandled.current === reviewFocus) return;
    focusHandled.current = reviewFocus;

    const queueTarget = FOCUS_TO_QUEUE[reviewFocus];
    if (queueTarget) {
      setActiveQueue(queueTarget);
      setCurrentIndex(0);
    } else if (reviewFocus === 'duplicates') {
      setTimeout(() => duplicatesRef.current?.scrollIntoView({ behavior: 'smooth', block: 'start' }), 100);
    } else if (reviewFocus === 'contradictions') {
      setTimeout(() => contradictionsRef.current?.scrollIntoView({ behavior: 'smooth', block: 'start' }), 100);
    }

    // Clear focus so re-clicking from overview works
    setReviewFocus(null);
  }, [reviewFocus, data, setReviewFocus]);

  const busy = reviewAction.isPending || mergeMutation.isPending || exiting;

  const items: Memory[] = data?.sections[activeQueue] ?? [];
  const total = items.length;
  const current = items[currentIndex] ?? null;

  const contradictions = data?.sections.contradictions ?? [];
  const duplicates = data?.sections.duplicates ?? [];

  // Clamp index when queue shrinks (e.g. after Keep/Suppress removes an item)
  useEffect(() => {
    if (total > 0 && currentIndex >= total) {
      setCurrentIndex(total - 1);
    }
  }, [total, currentIndex]);

  const switchQueue = (queue: QueueKey) => {
    setActiveQueue(queue);
    setCurrentIndex(0);
    setFeedback(null);
  };

  const showFeedback = (kind: 'success' | 'error', message: string) => {
    setFeedback({ kind, message });
    if (kind === 'success') {
      setTimeout(() => setFeedback(null), 2000);
    }
  };

  const handleAction = async (action: ReviewCardAction) => {
    if (!current || exiting) return;
    const memory = current;
    const apiAction = actionToApi(action, memory);

    // Animate exit first
    setExiting(true);
    await new Promise((r) => setTimeout(r, 250));
    cardKey.current++;

    try {
      setFeedback(null);
      const updated = await reviewAction.mutateAsync({
        id: memory.id,
        action: apiAction,
        reviewedBy: 'dashboard-review',
        project: memory.project ?? null,
        scope: memory.scope,
      });
      if (selectedMemory?.id === updated.id) {
        setSelectedMemory(updated);
      }
      const verbs: Record<string, string> = {
        restore: 'Kept',
        suppress: 'Suppressed',
        archive: 'Archived',
        pin: 'Pinned',
        unpin: 'Unpinned',
        canonicalize: 'Marked canonical',
        rescopeGlobal: 'Made global',
        rescopeProject: 'Moved to project scope',
        excludeCloud: 'Excluded from cloud',
        includeCloud: 'Included in cloud',
      };
      showFeedback('success', `${verbs[apiAction] ?? 'Updated'}: ${updated.title}`);
    } catch (error) {
      showFeedback('error', error instanceof Error ? error.message : 'Failed to update');
    } finally {
      setExiting(false);
    }
  };

  const resolveContradiction = async (keep: Memory, suppress: Memory) => {
    try {
      setFeedback(null);
      await reviewAction.mutateAsync({ id: keep.id, action: 'canonicalize', reviewedBy: 'dashboard-review' });
      await reviewAction.mutateAsync({ id: suppress.id, action: 'suppress', reviewedBy: 'dashboard-review' });
      showFeedback('success', `Kept "${keep.title}", suppressed "${suppress.title}"`);
    } catch (error) {
      showFeedback('error', error instanceof Error ? error.message : 'Failed to resolve contradiction');
    }
  };

  const runMerge = async (kept: Memory, removed: Memory) => {
    try {
      setFeedback(null);
      const merged = await mergeMutation.mutateAsync({ keptId: kept.id, removedId: removed.id, reviewedBy: 'dashboard-merge' });
      if (selectedMemory?.id === removed.id) {
        setSelectedMemory(merged);
      }
      showFeedback('success', `Merged duplicate into "${kept.title}"`);
    } catch (error) {
      showFeedback('error', error instanceof Error ? error.message : 'Failed to merge');
    }
  };

  const totalReviewable = QUEUE_ORDER.reduce((sum, key) => sum + (data?.summary[key] ?? 0), 0)
    + (data?.summary.contradictions ?? 0) + (data?.summary.duplicates ?? 0);

  if (isLoading) {
    return (
      <div className="space-y-6">
        <div className="text-sm text-[var(--sc-text-secondary)]">Loading review queue…</div>
      </div>
    );
  }

  if (totalReviewable === 0 && data) {
    return (
      <div className="space-y-6">
        <div className="glass-card-strong flex flex-col items-center justify-center p-12 text-center">
          <CheckCircle2 className="h-12 w-12 text-[var(--sc-cyan)]" />
          <h3 className="mt-4 text-xl font-semibold text-[var(--sc-text-primary)]">All caught up</h3>
          <p className="mt-2 text-sm text-[var(--sc-text-secondary)]">No memories need review right now.</p>
        </div>
      </div>
    );
  }

  const progressPct = total > 0 ? Math.round(((currentIndex + 1) / total) * 100) : 0;

  return (
    <div className="space-y-6">
      {/* Filter pills */}
      <div className="flex flex-wrap gap-2">
        {QUEUE_ORDER.map((key) => {
          const meta = QUEUE_META[key];
          const count = data?.summary[key] ?? 0;
          const isActive = activeQueue === key;
          return (
            <button
              key={key}
              onClick={() => switchQueue(key)}
              className={`rounded-full border px-3 py-1.5 text-xs font-semibold transition-colors ${
                isActive
                  ? 'border-[var(--sc-coral)]/50 bg-[var(--sc-coral)] text-white'
                  : 'border-[var(--sc-border)] bg-[var(--sc-surface-interactive)] text-[var(--sc-text-secondary)] hover:border-[var(--sc-text-muted)]'
              }`}
            >
              {meta.label} {count}
            </button>
          );
        })}
      </div>

      {/* Feedback toast */}
      {feedback && (
        <div className={`rounded-2xl border px-4 py-3 text-sm ${
          feedback.kind === 'error'
            ? 'border-[var(--sc-coral)]/30 bg-[var(--sc-coral)]/10 text-[var(--sc-coral)]'
            : 'border-[var(--sc-cyan)]/30 bg-[var(--sc-cyan)]/10 text-[var(--sc-cyan)]'
        }`}>
          <div className="flex items-start gap-2">
            {feedback.kind === 'success' && <CheckCircle2 className="mt-0.5 h-4 w-4 shrink-0" />}
            <span>{feedback.message}</span>
          </div>
        </div>
      )}

      {/* Current review card */}
      {current ? (
        <>
          {/* Progress bar + nav ABOVE the card so buttons don't shift */}
          <div className="space-y-2">
            <div className="flex items-center justify-between text-xs text-[var(--sc-text-muted)]">
              <span>Card {currentIndex + 1} of {total} · {QUEUE_META[activeQueue].label} queue</span>
              <div className="flex gap-2">
                <button
                  type="button"
                  disabled={currentIndex === 0}
                  onClick={() => setCurrentIndex((i) => Math.max(0, i - 1))}
                  className="rounded px-2 py-0.5 text-[var(--sc-text-secondary)] transition-colors hover:bg-[var(--sc-surface-interactive)] disabled:opacity-30"
                >
                  ← Prev
                </button>
                <button
                  type="button"
                  disabled={currentIndex >= total - 1}
                  onClick={() => setCurrentIndex((i) => Math.min(total - 1, i + 1))}
                  className="rounded px-2 py-0.5 text-[var(--sc-text-secondary)] transition-colors hover:bg-[var(--sc-surface-interactive)] disabled:opacity-30"
                >
                  Next →
                </button>
              </div>
            </div>
            <div className="h-1.5 w-full overflow-hidden rounded-full bg-[var(--sc-bg-elevated)]">
              <div
                className="h-full rounded-full bg-[var(--sc-cyan)] transition-all"
                style={{ width: `${progressPct}%` }}
              />
            </div>
          </div>

          <div
            key={cardKey.current}
            className={exiting ? 'sc-card-exit' : 'sc-card-enter'}
            style={{ transition: 'opacity 200ms ease, transform 200ms ease' }}
          >
            <ReviewCard
              memory={current}
              reasons={buildReasons(current, activeQueue)}
              onAction={handleAction}
              busy={busy}
            />
          </div>
        </>
      ) : (
        <div className="glass-card-strong p-8 text-center">
          <p className="text-sm text-[var(--sc-text-secondary)]">
            No {QUEUE_META[activeQueue].label.toLowerCase()} memories to review.
          </p>
        </div>
      )}

      {/* Contradictions */}
      <div ref={contradictionsRef} className="glass-card-strong p-5">
        <div className="flex items-center gap-2">
          <ShieldAlert size={16} className="text-[var(--sc-amber)]" />
          <h3 className="text-base font-semibold text-[var(--sc-text-primary)]">
            Contradictions ({contradictions.length})
          </h3>
        </div>

        {contradictions.length === 0 ? (
          <p className="mt-3 text-sm text-[var(--sc-text-secondary)]">No contradictions detected.</p>
        ) : (
          <div className="mt-4 space-y-4">
            {contradictions.slice(0, 8).map((item) => (
              <div key={`${item.memoryA.id}-${item.memoryB.id}`} className="rounded-xl border border-[var(--sc-amber)]/20 bg-[var(--sc-bg-deep)]/60 p-4">
                <div className="flex items-start justify-between gap-4">
                  <div>
                    <div className="text-xs uppercase tracking-[0.18em] text-[var(--sc-text-muted)]">Score</div>
                    <div className="text-lg font-semibold text-[var(--sc-text-primary)]">{Math.round(item.score * 100)}%</div>
                  </div>
                  <div className="text-right text-xs text-[var(--sc-text-muted)]">
                    {item.sharedTopics.length ? item.sharedTopics.join(' · ') : 'No shared topic'}
                  </div>
                </div>
                <div className="mt-3 rounded-lg border border-[var(--sc-border)] bg-[var(--sc-bg-surface)]/60 p-3 text-sm text-[var(--sc-text-primary)]">
                  {item.reason}
                </div>
                <div className="mt-4 grid gap-3 md:grid-cols-2">
                  {[item.memoryA, item.memoryB].map((memory, idx) => {
                    const other = idx === 0 ? item.memoryB : item.memoryA;
                    return (
                      <div key={memory.id} className="rounded-lg border border-[var(--sc-border)] bg-[var(--sc-bg-surface)]/70 p-3">
                        <div className="text-xs uppercase tracking-[0.18em] text-[var(--sc-text-muted)]">{idx === 0 ? 'A' : 'B'}</div>
                        <div className="mt-1 text-sm font-medium text-[var(--sc-text-primary)]">{memory.title}</div>
                        <div className="mt-1 line-clamp-2 text-xs text-[var(--sc-text-secondary)]">{memory.content}</div>
                        <div className="mt-2 text-xs text-[var(--sc-text-muted)]">
                          trust {(memory.trustScore ?? 1).toFixed(2)} · {memory.captureMethod || 'manual'}
                        </div>
                        <div className="mt-2 flex flex-wrap gap-2">
                          <Button variant="cyan" size="sm" disabled={busy} onClick={() => resolveContradiction(memory, other)}>
                            Keep this
                          </Button>
                          <Button variant="ghost" size="sm" disabled={busy} onClick={() => reviewAction.mutateAsync({ id: memory.id, action: 'suppress', reviewedBy: 'dashboard-review' }).then(() => showFeedback('success', `Suppressed: ${memory.title}`)).catch((e: unknown) => showFeedback('error', e instanceof Error ? e.message : 'Failed to suppress'))}>
                            Suppress
                          </Button>
                        </div>
                      </div>
                    );
                  })}
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      {/* Duplicates */}
      <div ref={duplicatesRef} className="glass-card-strong p-5">
        <div className="flex items-center gap-2">
          <Layers size={16} className="text-[var(--sc-cyan)]" />
          <h3 className="text-base font-semibold text-[var(--sc-text-primary)]">
            Duplicates ({duplicates.length})
          </h3>
        </div>

        {duplicates.length === 0 ? (
          <p className="mt-3 text-sm text-[var(--sc-text-secondary)]">No duplicate candidates detected.</p>
        ) : (
          <div className="mt-4 space-y-3">
            {duplicates.slice(0, 8).map((pair) => {
              const keep = pair.recommendedKeepId === pair.memoryA.id ? pair.memoryA : pair.memoryB;
              const remove = pair.recommendedKeepId === pair.memoryA.id ? pair.memoryB : pair.memoryA;
              return (
                <div key={`${pair.memoryA.id}-${pair.memoryB.id}`} className="rounded-xl border border-[var(--sc-border)] bg-[var(--sc-bg-deep)]/60 p-4">
                  <div className="flex items-start justify-between gap-4">
                    <div>
                      <div className="text-sm font-medium text-[var(--sc-text-primary)]">
                        &ldquo;{pair.memoryA.title}&rdquo; vs &ldquo;{pair.memoryB.title}&rdquo;
                      </div>
                      <div className="mt-1 text-xs text-[var(--sc-text-muted)]">
                        {pair.similarity} · {pair.sharedWords} shared words
                      </div>
                    </div>
                  </div>
                  <div className="mt-3 flex flex-wrap gap-2">
                    <Button variant="cyan" size="sm" disabled={busy} onClick={() => runMerge(pair.memoryA, pair.memoryB)}>
                      Keep A
                    </Button>
                    <Button variant="outline" size="sm" disabled={busy} onClick={() => runMerge(pair.memoryB, pair.memoryA)}>
                      Keep B
                    </Button>
                    <Button variant="ghost" size="sm" disabled={busy} onClick={() => runMerge(keep, remove)}>
                      Merge (recommended)
                    </Button>
                  </div>
                </div>
              );
            })}
          </div>
        )}
      </div>
    </div>
  );
}
