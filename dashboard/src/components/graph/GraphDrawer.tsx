'use client';

import { useMemo, useState } from 'react';
import { useRouter } from 'next/navigation';
import { useQuery } from '@tanstack/react-query';
import { toast } from 'sonner';
import { ArrowUpRight, Crosshair, Pin, PinOff, ShieldAlert, TrendingUp } from 'lucide-react';
import { authFetch, readApiError } from '@/lib/auth';
import { Badge } from '@/components/ds/Badge';
import { Button } from '@/components/ds/Button';
import { Drawer } from '@/components/ds/Drawer';
import { ConfirmDialog } from '@/components/ds/Dialog';
import { useBoostMemory, useEditMemory, useQuarantineMemory } from '@/hooks/useMemories';
import { useDashboardStore } from '@/lib/store';
import type { GraphMemory, NeighbourhoodPayload, V2Node } from '@/lib/graph/transforms';

const API_BASE = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:3001';

interface GraphDrawerProps {
  node: V2Node | null;
  neighbourhood: NeighbourhoodPayload | undefined;
  /** state of the depth-1 fetch made on select (review item 8) */
  neighbourhoodStatus?: 'idle' | 'pending' | 'error';
  onClose: () => void;
  onFocus: (entityId: number) => void;
  onSelectEntity: (entityId: number) => void;
  onPathFrom: (entityId: number) => void;
}

interface MemoryDetailPayload {
  id: number;
  title: string;
  content?: string;
  category: string;
  type: string;
  salience: number;
  trust_score: number;
  status: string;
  pinned: number | boolean;
  project: string | null;
  created_at: string;
}

/** Right drawer for the graph: entity or memory details + real actions. */
export function GraphDrawer({ node, neighbourhood, neighbourhoodStatus = 'idle', onClose, onFocus, onSelectEntity, onPathFrom }: GraphDrawerProps) {
  return (
    <Drawer open={node !== null} onClose={onClose} title={node?.label} modal={false}>
      {node?.kind === 'entity' && (
        <EntityDetails
          node={node}
          neighbourhood={neighbourhood}
          neighbourhoodStatus={neighbourhoodStatus}
          onFocus={onFocus}
          onSelectEntity={onSelectEntity}
          onPathFrom={onPathFrom}
        />
      )}
      {node?.kind === 'memory' && node.memory && <MemoryDetails memory={node.memory} />}
    </Drawer>
  );
}

function EntityDetails({
  node,
  neighbourhood,
  neighbourhoodStatus,
  onFocus,
  onSelectEntity,
  onPathFrom,
}: {
  node: V2Node;
  neighbourhood: NeighbourhoodPayload | undefined;
  neighbourhoodStatus: 'idle' | 'pending' | 'error';
  onFocus: (entityId: number) => void;
  onSelectEntity: (entityId: number) => void;
  onPathFrom: (entityId: number) => void;
}) {
  const isFocalLoaded = neighbourhood?.focal.id === node.numericId;
  const related = useMemo(() => {
    if (!isFocalLoaded || !neighbourhood) return new Map<string, Array<{ id: number; name: string }>>();
    const groups = new Map<string, Array<{ id: number; name: string }>>();
    for (const t of neighbourhood.triples) {
      const otherIsObject = t.subject_id === node.numericId;
      const otherId = otherIsObject ? t.object_id : t.subject_id;
      if (otherId === node.numericId) continue;
      const other = neighbourhood.neighbours.find((n) => n.id === otherId);
      if (!other) continue;
      const label = otherIsObject ? t.predicate : `${t.predicate} (incoming)`;
      const list = groups.get(label) ?? [];
      if (!list.some((e) => e.id === other.id)) list.push({ id: other.id, name: other.name });
      groups.set(label, list);
    }
    return groups;
  }, [isFocalLoaded, neighbourhood, node.numericId]);

  const memories = isFocalLoaded ? neighbourhood?.memories ?? [] : [];

  return (
    <div className="space-y-4 text-sm">
      <div className="flex flex-wrap items-center gap-2">
        <Badge variant="low">{node.subtype}</Badge>
        <span className="text-xs text-[var(--sc-text-muted)] tabular-nums">{node.size} linked memories</span>
      </div>

      <div className="flex flex-wrap gap-2">
        <Button size="sm" onClick={() => onFocus(node.numericId)}>
          <Crosshair size={13} aria-hidden /> Focus
        </Button>
        <Button size="sm" variant="secondary" onClick={() => onPathFrom(node.numericId)}>
          Path from here
        </Button>
      </div>

      {related.size > 0 && (
        <section>
          <h3 className="mb-1.5 text-xs font-medium uppercase tracking-wide text-[var(--sc-text-muted)]">Related</h3>
          <div className="space-y-2">
            {[...related.entries()].map(([predicate, entities]) => (
              <div key={predicate}>
                <div className="font-mono text-[11px] text-[var(--sc-violet)]">{predicate}</div>
                <div className="mt-0.5 flex flex-wrap gap-1.5">
                  {entities.map((e) => (
                    <button
                      key={e.id}
                      type="button"
                      onClick={() => onSelectEntity(e.id)}
                      className="rounded-full border border-[var(--sc-border)] px-2 py-0.5 text-xs text-[var(--sc-text-dim)] hover:border-[var(--sc-border-strong)] hover:text-[var(--sc-text)] focus-visible:outline-2 focus-visible:outline-[var(--sc-focus)]"
                    >
                      {e.name}
                    </button>
                  ))}
                </div>
              </div>
            ))}
          </div>
        </section>
      )}

      <section>
        <h3 className="mb-1.5 text-xs font-medium uppercase tracking-wide text-[var(--sc-text-muted)]">
          Memories {isFocalLoaded && neighbourhood ? `(${neighbourhood.counts.totalMemories})` : ''}
        </h3>
        {!isFocalLoaded && neighbourhoodStatus === 'error' && (
          <p className="text-xs text-[var(--sc-warn)]">Memories unavailable — the neighbourhood fetch failed.</p>
        )}
        {!isFocalLoaded && neighbourhoodStatus !== 'error' && (
          <p className="text-xs text-[var(--sc-text-muted)]">Loading related entities and memories…</p>
        )}
        {isFocalLoaded && memories.length === 0 && (
          <p className="text-xs text-[var(--sc-text-muted)]">No memories linked to this entity{neighbourhood?.counts.totalMemories ? ' in this view' : ''}.</p>
        )}
        <ul className="space-y-1.5">
          {memories.map((m) => (
            <MemoryRow key={m.id} memory={m} />
          ))}
        </ul>
        {isFocalLoaded && neighbourhood && neighbourhood.counts.omittedMemories > 0 && (
          <p className="mt-1.5 text-[11px] text-[var(--sc-text-muted)]">
            {neighbourhood.counts.omittedMemories} more not shown (capped view).
          </p>
        )}
      </section>
    </div>
  );
}

function MemoryRow({ memory }: { memory: GraphMemory }) {
  const [expanded, setExpanded] = useState(false);
  return (
    <li className="rounded-md border border-[var(--sc-border)] p-2">
      <button
        type="button"
        onClick={() => setExpanded((e) => !e)}
        aria-expanded={expanded}
        className="w-full text-left text-xs text-[var(--sc-text)] hover:text-[var(--sc-primary)] focus-visible:outline-2 focus-visible:outline-[var(--sc-focus)]"
      >
        {memory.pinned ? <Pin size={10} aria-label="Pinned" className="mr-1 inline text-[var(--sc-primary)]" /> : null}
        {memory.title}
      </button>
      {expanded && <MemoryDetails memory={memory} compact />}
    </li>
  );
}

/** Memory details + actions. Content preview comes from /api/memories/:id,
 *  which the server deep-redacts for RESTRICTED rows (title stays, content
 *  is withheld server-side — the browser never receives it). */
function MemoryDetails({ memory, compact = false }: { memory: GraphMemory; compact?: boolean }) {
  const router = useRouter();
  const setSearchQuery = useDashboardStore((s) => s.setSearchQuery);
  const editMemory = useEditMemory();
  const boost = useBoostMemory();
  const quarantine = useQuarantineMemory();
  const [confirmQuarantine, setConfirmQuarantine] = useState(false);

  const { data: detail, error } = useQuery<MemoryDetailPayload>({
    queryKey: ['memory-detail', memory.id],
    queryFn: async () => {
      const res = await authFetch(`${API_BASE}/api/memories/${memory.id}`);
      if (!res.ok) throw new Error(await readApiError(res, 'Failed to load memory'));
      return res.json();
    },
    staleTime: 15_000,
  });

  const pinned = Boolean(detail?.pinned ?? memory.pinned);

  const doPin = () => {
    editMemory.mutate(
      { id: memory.id, updates: { pinned: !pinned } },
      {
        onSuccess: () => toast.success(pinned ? `Unpinned “${memory.title}”` : `Pinned “${memory.title}”`),
        onError: (e) => toast.error(`Pin failed: ${e instanceof Error ? e.message : String(e)}`),
      },
    );
  };

  const doBoost = () => {
    boost.mutate(memory.id, {
      onSuccess: () => toast.success(`Boosted “${memory.title}” — salience raised`),
      onError: (e) => toast.error(`Boost failed: ${e instanceof Error ? e.message : String(e)}`),
    });
  };

  const doQuarantine = () => {
    quarantine.mutate(
      { id: memory.id, reason: 'Quarantined from the memory graph' },
      {
        onSuccess: () => {
          toast.success(`Quarantined “${memory.title}”`);
          setConfirmQuarantine(false);
        },
        onError: (e) => {
          toast.error(`Quarantine failed: ${e instanceof Error ? e.message : String(e)}`);
          setConfirmQuarantine(false);
        },
      },
    );
  };

  return (
    <div className={compact ? 'mt-2 space-y-2 border-t border-[var(--sc-border)] pt-2' : 'space-y-3 text-sm'}>
      <div className="flex flex-wrap items-center gap-1.5 text-[11px]">
        <Badge variant="muted">{memory.category}</Badge>
        <Badge variant="muted">{memory.type.replace('_', ' ')}</Badge>
        {memory.status !== 'active' && <Badge variant="amber">{memory.status}</Badge>}
        <span className="tabular-nums text-[var(--sc-text-muted)]">salience {Math.round(memory.salience * 100)}%</span>
        <span className="tabular-nums text-[var(--sc-text-muted)]">trust {Math.round(memory.trust_score * 100)}%</span>
      </div>
      <div className="text-[11px] text-[var(--sc-text-muted)]">
        {memory.project ? `Project ${memory.project}` : 'No project'} · created {memory.created_at?.slice(0, 10)}
      </div>
      {error ? (
        <p className="text-xs text-[var(--sc-warn)]">Content unavailable: {error instanceof Error ? error.message : 'fetch failed'}</p>
      ) : detail?.content !== undefined ? (
        <p className="line-clamp-4 whitespace-pre-wrap text-xs text-[var(--sc-text-dim)]">{detail.content}</p>
      ) : (
        <p className="text-xs text-[var(--sc-text-muted)]">Loading content…</p>
      )}
      <div className="flex flex-wrap gap-1.5">
        <Button
          size="sm"
          variant="ghost"
          onClick={() => {
            setSearchQuery(memory.title);
            router.push('/memory');
          }}
        >
          <ArrowUpRight size={12} aria-hidden /> Open in Library
        </Button>
        <Button size="sm" variant="ghost" onClick={doPin} disabled={editMemory.isPending}>
          {pinned ? <PinOff size={12} aria-hidden /> : <Pin size={12} aria-hidden />} {pinned ? 'Unpin' : 'Pin'}
        </Button>
        <Button size="sm" variant="ghost" onClick={doBoost} disabled={boost.isPending}>
          <TrendingUp size={12} aria-hidden /> Boost
        </Button>
        <Button size="sm" variant="danger" onClick={() => setConfirmQuarantine(true)} disabled={quarantine.isPending}>
          <ShieldAlert size={12} aria-hidden /> Quarantine
        </Button>
      </div>
      <ConfirmDialog
        open={confirmQuarantine}
        title="Quarantine this memory?"
        description={
          <>
            “{memory.title}” (#{memory.id}) will be moved to quarantine and stop influencing recall until it is
            reviewed. You can approve or reject it from Protection → Quarantine.
          </>
        }
        confirmLabel="Quarantine"
        danger
        pending={quarantine.isPending}
        onConfirm={doQuarantine}
        onCancel={() => setConfirmQuarantine(false)}
      />
    </div>
  );
}
