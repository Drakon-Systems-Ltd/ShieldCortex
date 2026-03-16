'use client';

import { useState, useMemo, useCallback, useEffect } from 'react';
import { useQueryClient } from '@tanstack/react-query';
import { authFetch } from '@/lib/auth';
import { Memory, MemoryLink } from '@/types/memory';
import { useOpenClawSessions } from '@/hooks/useMemories';
import { useReviewAction } from '@/hooks/useReviewQueue';
import { MemoryCard } from './MemoryCard';
import { MemoryDetail } from '@/components/memory/MemoryDetail';

const API_BASE = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:3001';

type SortKey = 'salience' | 'createdAt' | 'lastAccessed' | 'decayedScore';
type ViewStyle = 'grid' | 'list';

interface MemoriesViewProps {
  memories: Memory[];
  selectedMemory: Memory | null;
  onSelectMemory: (m: Memory | null) => void;
  links?: MemoryLink[];
  onReinforce?: (id: number) => void;
  onSelectMemoryById?: (id: number) => void;
  isReinforcing?: boolean;
  reinforceSuccess?: boolean;
}

function formatDateTime(value: string): string {
  return new Date(value).toLocaleString();
}

function relativeTime(value: string): string {
  const diff = Date.now() - new Date(value).getTime();
  const mins = Math.floor(diff / 60000);
  if (mins < 1) return 'just now';
  if (mins < 60) return `${mins}m ago`;
  const hours = Math.floor(mins / 60);
  if (hours < 24) return `${hours}h ago`;
  const days = Math.floor(hours / 24);
  return `${days}d ago`;
}

export function MemoriesView({
  memories,
  selectedMemory,
  onSelectMemory,
  links = [],
  onReinforce,
  onSelectMemoryById,
  isReinforcing = false,
  reinforceSuccess = false,
}: MemoriesViewProps) {
  const [sortKey, setSortKey] = useState<SortKey>('salience');
  const [viewStyle, setViewStyle] = useState<ViewStyle>('grid');
  const [bulkMode, setBulkMode] = useState(false);
  const [checked, setChecked] = useState<Set<number>>(new Set());
  const [deleting, setDeleting] = useState(false);
  const [selectedSessionId, setSelectedSessionId] = useState<string | null>(null);
  const queryClient = useQueryClient();
  const { data: openClawData } = useOpenClawSessions();
  const reviewAction = useReviewAction();

  const openClawSessions = useMemo(
    () => openClawData?.sessions ?? [],
    [openClawData?.sessions]
  );

  useEffect(() => {
    if (!openClawSessions.length) {
      setSelectedSessionId(null);
      return;
    }
    if (!selectedSessionId || !openClawSessions.some((session) => session.sessionId === selectedSessionId)) {
      setSelectedSessionId(openClawSessions[0].sessionId);
    }
  }, [openClawSessions, selectedSessionId]);

  const selectedSession = useMemo(
    () => openClawSessions.find((session) => session.sessionId === selectedSessionId) ?? openClawSessions[0] ?? null,
    [openClawSessions, selectedSessionId]
  );

  const sorted = useMemo(() => {
    const arr = [...memories];
    arr.sort((a, b) => {
      switch (sortKey) {
        case 'salience': return b.salience - a.salience;
        case 'createdAt': return new Date(b.createdAt).getTime() - new Date(a.createdAt).getTime();
        case 'lastAccessed': return new Date(b.lastAccessed).getTime() - new Date(a.lastAccessed).getTime();
        case 'decayedScore': return (b.decayedScore ?? b.salience) - (a.decayedScore ?? a.salience);
        default: return 0;
      }
    });
    return arr;
  }, [memories, sortKey]);

  const handleCheck = useCallback((id: number, val: boolean) => {
    setChecked((prev) => {
      const next = new Set(prev);
      if (val) next.add(id); else next.delete(id);
      return next;
    });
  }, []);

  const selectAll = () => setChecked(new Set(sorted.map((m) => m.id)));
  const _deselectAll = () => setChecked(new Set());

  const deleteSelected = async () => {
    if (checked.size === 0) return;
    setDeleting(true);
    try {
      await Promise.all(
        Array.from(checked).map((id) =>
          authFetch(`${API_BASE}/api/memories/${id}`, { method: 'DELETE' })
        )
      );
      setChecked(new Set());
      queryClient.invalidateQueries({ queryKey: ['memories'] });
    } finally {
      setDeleting(false);
    }
  };

  const runReviewAction = useCallback((memory: Memory, action: string) => {
    reviewAction.mutate(
      { id: memory.id, action, reviewedBy: 'capture-session' },
      {
        onSuccess: async () => {
          await Promise.all([
            queryClient.invalidateQueries({ queryKey: ['memories'] }),
            queryClient.invalidateQueries({ queryKey: ['openclaw-sessions'] }),
            queryClient.invalidateQueries({ queryKey: ['review-queue'] }),
          ]);
        },
      }
    );
  }, [queryClient, reviewAction]);

  return (
    <div className="pb-6">
      {/* Toolbar */}
      <div className="flex items-center gap-3 border-b border-slate-800 px-4 py-2">
        <span className="text-xs text-slate-400">{memories.length} memories</span>

        <div className="w-px h-5 bg-slate-700" />

        <select
          value={sortKey}
          onChange={(e) => setSortKey(e.target.value as SortKey)}
          className="bg-slate-800 border border-slate-700 text-white text-xs rounded px-2 py-1"
        >
          <option value="salience">Salience</option>
          <option value="createdAt">Created</option>
          <option value="lastAccessed">Last Accessed</option>
          <option value="decayedScore">Decay Score</option>
        </select>

        <div className="flex items-center border border-slate-700 rounded overflow-hidden">
          <button
            onClick={() => setViewStyle('grid')}
            className={`px-2 py-1 text-xs ${viewStyle === 'grid' ? 'bg-slate-700 text-white' : 'text-slate-400 hover:text-white'}`}
          >
            Grid
          </button>
          <button
            onClick={() => setViewStyle('list')}
            className={`px-2 py-1 text-xs ${viewStyle === 'list' ? 'bg-slate-700 text-white' : 'text-slate-400 hover:text-white'}`}
          >
            List
          </button>
        </div>

        <div className="w-px h-5 bg-slate-700" />

        <button
          onClick={() => { setBulkMode(!bulkMode); setChecked(new Set()); }}
          className={`px-2 py-1 text-xs rounded ${bulkMode ? 'bg-blue-600 text-white' : 'bg-slate-800 text-slate-400 hover:text-white'}`}
        >
          Select
        </button>

        {bulkMode && (
          <>
            <button onClick={selectAll} className="px-2 py-1 text-xs text-slate-400 hover:text-white">
              Select all
            </button>
            <button
              onClick={deleteSelected}
              disabled={checked.size === 0 || deleting}
              className="px-2 py-1 text-xs rounded bg-red-600/20 text-red-400 hover:bg-red-600/40 disabled:opacity-40"
            >
              {deleting ? 'Deleting...' : `Delete (${checked.size})`}
            </button>
          </>
        )}
      </div>

      <div className="px-4 pt-4">
        <div className="rounded-2xl border border-slate-800 bg-slate-900/60 p-5">
          <div className="flex flex-col gap-4 lg:flex-row lg:items-end lg:justify-between">
            <div>
              <div className="inline-flex items-center gap-2 rounded-full border border-cyan-500/20 bg-cyan-500/10 px-3 py-1 text-xs uppercase tracking-[0.18em] text-cyan-300">
                Capture Workflow
              </div>
              <h2 className="mt-3 text-2xl font-semibold text-white">See what was captured, from where, and how risky it looks.</h2>
              <p className="mt-2 max-w-2xl text-sm text-slate-400">
                Capture is where stored memories, OpenClaw sessions, and source trust come together. Use it to inspect what got saved before it quietly shapes recall.
              </p>
            </div>
            <div className="grid grid-cols-2 gap-3 sm:grid-cols-4">
              <div className="rounded-xl border border-slate-800 bg-slate-950/70 p-4">
                <div className="text-xs uppercase tracking-[0.18em] text-slate-500">Memories</div>
                <div className="mt-2 text-2xl font-semibold text-white">{memories.length}</div>
              </div>
              <div className="rounded-xl border border-slate-800 bg-slate-950/70 p-4">
                <div className="text-xs uppercase tracking-[0.18em] text-slate-500">OpenClaw sessions</div>
                <div className="mt-2 text-2xl font-semibold text-white">{openClawData?.summary.sessions ?? 0}</div>
              </div>
              <div className="rounded-xl border border-slate-800 bg-slate-950/70 p-4">
                <div className="text-xs uppercase tracking-[0.18em] text-slate-500">Auto-saved</div>
                <div className="mt-2 text-2xl font-semibold text-white">{openClawData?.summary.saved ?? 0}</div>
              </div>
              <div className="rounded-xl border border-slate-800 bg-slate-950/70 p-4">
                <div className="text-xs uppercase tracking-[0.18em] text-slate-500">Threats</div>
                <div className="mt-2 text-2xl font-semibold text-white">{openClawData?.summary.threats ?? 0}</div>
              </div>
            </div>
          </div>

          <div className="mt-6 grid gap-4 xl:grid-cols-[minmax(340px,0.8fr)_minmax(0,1.2fr)]">
            <div className="rounded-xl border border-slate-800 bg-slate-950/60 p-4">
              <div className="flex items-center justify-between gap-3">
                <div className="text-xs uppercase tracking-[0.18em] text-slate-500">OpenClaw sessions</div>
                <div className="text-xs text-slate-500">{openClawSessions.length} recent</div>
              </div>
              <div className="mt-4 space-y-3">
                {openClawSessions.slice(0, 8).map((session) => (
                  <button
                    key={session.sessionId}
                    onClick={() => setSelectedSessionId(session.sessionId)}
                    className={`block w-full rounded-xl border p-4 text-left transition-colors ${
                      selectedSession?.sessionId === session.sessionId
                        ? 'border-cyan-400/40 bg-cyan-500/10'
                        : 'border-slate-800 bg-slate-900/70 hover:border-slate-700'
                    }`}
                  >
                    <div className="flex items-start justify-between gap-4">
                      <div>
                        <div className="text-sm font-medium text-white">{session.sessionId}</div>
                        <div className="mt-1 text-xs text-slate-500">
                          {session.models[0] || 'model unknown'} · {relativeTime(session.lastSeenAt)}
                        </div>
                      </div>
                      <div className="rounded-lg bg-slate-800 px-3 py-2 text-right">
                        <div className="text-[10px] uppercase tracking-[0.18em] text-slate-500">Saved</div>
                        <div className="text-base font-semibold text-white">{session.saved}</div>
                      </div>
                    </div>
                    <div className="mt-3 flex flex-wrap gap-2 text-xs">
                      <span className="rounded-full border border-slate-700 px-2 py-1 text-slate-300">{session.skipped} skipped</span>
                      <span className={`rounded-full border px-2 py-1 ${session.threats > 0 ? 'border-red-500/40 text-red-300' : 'border-emerald-500/40 text-emerald-300'}`}>
                        {session.threats} threat{session.threats === 1 ? '' : 's'}
                      </span>
                      {session.quarantined > 0 && (
                        <span className="rounded-full border border-amber-500/40 px-2 py-1 text-amber-300">
                          {session.quarantined} quarantined
                        </span>
                      )}
                      {session.hooks.map((hook) => (
                        <span key={hook} className="rounded-full border border-slate-700 px-2 py-1 text-slate-300">{hook}</span>
                      ))}
                    </div>
                  </button>
                ))}
                {!openClawData?.sessions?.length && (
                  <div className="text-sm text-slate-400">No recent OpenClaw session evidence found.</div>
                )}
              </div>
            </div>

            <div className="rounded-xl border border-slate-800 bg-slate-950/60 p-4">
              <div className="flex items-center justify-between gap-3">
                <div>
                  <div className="text-xs uppercase tracking-[0.18em] text-slate-500">Session View</div>
                  <div className="mt-1 text-lg font-semibold text-white">
                    {selectedSession ? `OpenClaw session ${selectedSession.sessionId}` : 'Select a session'}
                  </div>
                </div>
                {selectedSession && (
                  <div className="text-right text-xs text-slate-500">
                    <div>First seen {formatDateTime(selectedSession.firstSeenAt)}</div>
                    <div>Last seen {formatDateTime(selectedSession.lastSeenAt)}</div>
                  </div>
                )}
              </div>

              {!selectedSession ? (
                <div className="mt-6 text-sm text-slate-400">Choose a session to inspect what OpenClaw learned, skipped, or tripped over.</div>
              ) : (
                <div className="mt-4 space-y-4">
                  <div className="grid gap-3 md:grid-cols-3 xl:grid-cols-6">
                    <div className="rounded-xl border border-slate-800 bg-slate-900/70 p-4">
                      <div className="text-[10px] uppercase tracking-[0.18em] text-slate-500">Saved</div>
                      <div className="mt-2 text-xl font-semibold text-white">{selectedSession.saved}</div>
                    </div>
                    <div className="rounded-xl border border-slate-800 bg-slate-900/70 p-4">
                      <div className="text-[10px] uppercase tracking-[0.18em] text-slate-500">Skipped</div>
                      <div className="mt-2 text-xl font-semibold text-white">{selectedSession.skipped}</div>
                    </div>
                    <div className="rounded-xl border border-slate-800 bg-slate-900/70 p-4">
                      <div className="text-[10px] uppercase tracking-[0.18em] text-slate-500">Threats</div>
                      <div className="mt-2 text-xl font-semibold text-white">{selectedSession.threats}</div>
                    </div>
                    <div className="rounded-xl border border-slate-800 bg-slate-900/70 p-4">
                      <div className="text-[10px] uppercase tracking-[0.18em] text-slate-500">Auto</div>
                      <div className="mt-2 text-xl font-semibold text-white">{selectedSession.autoExtracted}</div>
                    </div>
                    <div className="rounded-xl border border-slate-800 bg-slate-900/70 p-4">
                      <div className="text-[10px] uppercase tracking-[0.18em] text-slate-500">Keyword</div>
                      <div className="mt-2 text-xl font-semibold text-white">{selectedSession.keywordTriggered}</div>
                    </div>
                    <div className="rounded-xl border border-slate-800 bg-slate-900/70 p-4">
                      <div className="text-[10px] uppercase tracking-[0.18em] text-slate-500">Suppressed</div>
                      <div className="mt-2 text-xl font-semibold text-white">{selectedSession.suppressed}</div>
                    </div>
                  </div>

                  <div className="grid gap-4 xl:grid-cols-[minmax(0,1.1fr)_minmax(320px,0.9fr)]">
                    <div className="rounded-xl border border-slate-800 bg-slate-900/70 p-4">
                      <div className="flex items-center justify-between gap-3">
                        <div>
                          <div className="text-xs uppercase tracking-[0.18em] text-slate-500">Session recap</div>
                          <div className="mt-1 text-sm text-slate-300">
                            Review the exact memories this session created and decide what should stay hot.
                          </div>
                        </div>
                        <div className="text-right text-xs text-slate-500">
                          <div>{selectedSession.models.join(', ') || 'model unknown'}</div>
                          <div>{selectedSession.agentIds.join(', ') || 'agent unknown'}</div>
                        </div>
                      </div>

                      <div className="mt-4 space-y-3">
                        {selectedSession.memories.length > 0 ? selectedSession.memories.map((memory) => (
                          <div key={memory.id} className="rounded-xl border border-slate-800 bg-slate-950/60 p-4">
                            <div className="flex items-start justify-between gap-4">
                              <div className="min-w-0">
                                <button
                                  onClick={() => onSelectMemory(memory)}
                                  className="text-left text-base font-medium text-white hover:text-cyan-300"
                                >
                                  {memory.title}
                                </button>
                                <div className="mt-1 text-xs text-slate-500">
                                  {memory.category} · {memory.captureMethod || 'manual'} · trust {(memory.trustScore ?? 1).toFixed(2)}
                                </div>
                                <div className="mt-2 line-clamp-2 text-sm text-slate-400">{memory.content}</div>
                              </div>
                              <div className="rounded-lg bg-slate-800 px-3 py-2 text-right">
                                <div className="text-[10px] uppercase tracking-[0.18em] text-slate-500">State</div>
                                <div className="text-sm text-slate-100">{memory.status || 'active'}</div>
                              </div>
                            </div>
                            <div className="mt-3 flex flex-wrap gap-2">
                              <button onClick={() => onSelectMemory(memory)} className="rounded-lg border border-slate-700 px-3 py-1 text-xs text-slate-300 hover:border-slate-500">Inspect</button>
                              <button onClick={() => runReviewAction(memory, memory.pinned ? 'unpin' : 'pin')} className="rounded-lg border border-slate-700 px-3 py-1 text-xs text-slate-300 hover:border-slate-500">
                                {memory.pinned ? 'Unpin' : 'Pin'}
                              </button>
                              <button onClick={() => runReviewAction(memory, 'suppress')} className="rounded-lg border border-amber-500/40 px-3 py-1 text-xs text-amber-300 hover:bg-amber-500/10">Discard</button>
                              <button onClick={() => runReviewAction(memory, 'archive')} className="rounded-lg border border-slate-700 px-3 py-1 text-xs text-slate-300 hover:border-slate-500">Archive</button>
                              <button onClick={() => runReviewAction(memory, 'canonicalize')} className="rounded-lg border border-emerald-500/40 px-3 py-1 text-xs text-emerald-300 hover:bg-emerald-500/10">Keep as canonical</button>
                            </div>
                          </div>
                        )) : (
                          <div className="text-sm text-slate-400">No stored memories were linked back to this session.</div>
                        )}
                      </div>
                    </div>

                    <div className="space-y-4">
                      <div className="rounded-xl border border-slate-800 bg-slate-900/70 p-4">
                        <div className="text-xs uppercase tracking-[0.18em] text-slate-500">Security cues</div>
                        <div className="mt-4 space-y-3 text-sm text-slate-400">
                          <div className="rounded-xl border border-slate-800 bg-slate-950/60 p-4">
                            Threats: {selectedSession.threats} · blocked hints: {selectedSession.blocked} · quarantine hints: {selectedSession.quarantined}
                          </div>
                          <div className="rounded-xl border border-slate-800 bg-slate-950/60 p-4">
                            Low-trust or noisy auto-extracted memories belong in Review before they influence recall too much.
                          </div>
                          <div className="rounded-xl border border-slate-800 bg-slate-950/60 p-4">
                            Shield remains the place to inspect blocked/quarantined operations and policy pressure across sources.
                          </div>
                        </div>
                      </div>

                      <div className="rounded-xl border border-slate-800 bg-slate-900/70 p-4">
                        <div className="text-xs uppercase tracking-[0.18em] text-slate-500">Event trail</div>
                        <div className="mt-4 space-y-3">
                          {selectedSession.events.slice(0, 8).map((event, index) => (
                            <div key={`${event.ts}-${event.type}-${index}`} className="rounded-xl border border-slate-800 bg-slate-950/60 p-3">
                              <div className="flex items-center justify-between gap-3">
                                <div className="text-sm font-medium text-white">
                                  {event.type === 'memory' ? 'Memory capture' : event.type === 'quarantine' ? 'Quarantine pressure' : event.type === 'blocked' ? 'Blocked signal' : 'Threat signal'}
                                </div>
                                <div className="text-xs text-slate-500">{formatDateTime(event.ts)}</div>
                              </div>
                              <div className="mt-1 text-xs text-slate-500">
                                {[event.hook, event.model].filter(Boolean).join(' · ') || 'OpenClaw event'}
                              </div>
                              {typeof event.count === 'number' && (
                                <div className="mt-2 text-xs text-slate-400">
                                  saved {event.count}{typeof event.skipped === 'number' ? ` · skipped ${event.skipped}` : ''}
                                </div>
                              )}
                              {event.preview && (
                                <div className="mt-2 line-clamp-3 text-xs text-slate-400">{event.preview}</div>
                              )}
                            </div>
                          ))}
                          {!selectedSession.events.length && (
                            <div className="text-sm text-slate-400">No event trail was found for this session.</div>
                          )}
                        </div>
                      </div>
                    </div>
                  </div>
                </div>
              )}
            </div>
          </div>
        </div>
      </div>

      {/* Card grid */}
      <div className="p-4">
        <div className="mb-3 flex items-center justify-between gap-3">
          <div>
            <div className="text-xs uppercase tracking-[0.18em] text-slate-500">Captured memories</div>
            <div className="mt-1 text-sm text-slate-400">
              Inspect the actual memory records that came out of capture, not just the session summary.
            </div>
          </div>
          <div className="text-xs text-slate-500">
            {sorted.length} record{sorted.length === 1 ? '' : 's'}
          </div>
        </div>
        <div className={`grid gap-4 ${selectedMemory ? 'xl:grid-cols-[minmax(0,1fr)_360px]' : ''} items-start`}>
          <div
            className={
              viewStyle === 'grid'
                ? 'grid grid-cols-1 md:grid-cols-2 2xl:grid-cols-3 gap-3'
                : 'flex flex-col gap-3 max-w-2xl'
            }
          >
            {sorted.map((memory) => (
              <MemoryCard
                key={memory.id}
                memory={memory}
                isSelected={selectedMemory?.id === memory.id}
                onSelect={onSelectMemory}
                isChecked={bulkMode ? checked.has(memory.id) : undefined}
                onCheck={bulkMode ? handleCheck : undefined}
              />
            ))}
          </div>

          {selectedMemory && (
            <div className="xl:sticky xl:top-4">
              <div className="mb-2 px-1 text-[10px] uppercase tracking-[0.18em] text-slate-500">
                Selected memory
              </div>
              <div className="max-h-[calc(100vh-7rem)] overflow-y-auto rounded-xl border border-slate-800 bg-slate-900/40">
                <MemoryDetail
                  memory={selectedMemory}
                  links={links}
                  memories={memories}
                  onClose={() => onSelectMemory(null)}
                  onReinforce={onReinforce}
                  onSelectMemory={onSelectMemoryById}
                  isReinforcing={isReinforcing}
                  reinforceSuccess={reinforceSuccess}
                />
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
