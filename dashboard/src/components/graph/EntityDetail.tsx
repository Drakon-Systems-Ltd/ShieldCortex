'use client';

import { GlassCard } from '@/components/ds/GlassCard';
import { Badge } from '@/components/ds/Badge';
import type { LinkedMemory } from '@/hooks/useGraphData';

// ── Helpers ────────────────────────────────────────────────

const TYPE_BADGE: Record<string, 'cyan' | 'coral' | 'amber' | 'muted'> = {
  tool: 'cyan',
  concept: 'coral',
  project: 'amber',
  service: 'cyan',
  person: 'cyan',
};

const CATEGORY_BADGE: Record<string, 'cyan' | 'coral' | 'amber' | 'muted'> = {
  architecture: 'cyan',
  error: 'coral',
  decision: 'amber',
  learning: 'cyan',
  preference: 'muted',
};

function formatDate(iso: string): string {
  const d = new Date(iso);
  return d.toLocaleDateString('en-GB', { day: '2-digit', month: '2-digit', year: 'numeric' });
}

// ── Props ──────────────────────────────────────────────────

export interface EntityDetailProps {
  entity: { id: string; label: string; type: string; memoryCount: number };
  relatedEntities: { id: string; label: string; type: string; memoryCount: number }[];
  recentMemories: LinkedMemory[];
  onNavigate: (entityId: string) => void;
}

// ── Component ──────────────────────────────────────────────

export function EntityDetail({ entity, relatedEntities, recentMemories, onNavigate }: EntityDetailProps) {
  return (
    <div className="flex flex-col gap-4 overflow-y-auto">
      {/* Entity header */}
      <GlassCard className="p-4">
        <div className="flex items-start gap-3">
          <span
            className="mt-1 h-3 w-3 shrink-0 rounded-full"
            style={{ backgroundColor: TYPE_BADGE[entity.type] === 'coral' ? '#ff4d4d' : TYPE_BADGE[entity.type] === 'amber' ? '#f5a623' : '#00e5cc' }}
          />
          <div className="min-w-0">
            <h2 className="truncate text-lg font-semibold text-[var(--sc-text-primary)]">
              {entity.label}
            </h2>
            <div className="mt-1 flex items-center gap-2">
              <Badge variant={TYPE_BADGE[entity.type] || 'muted'}>{entity.type}</Badge>
              <span className="text-xs text-[var(--sc-text-muted)]">
                {entity.memoryCount} {entity.memoryCount === 1 ? 'memory' : 'memories'}
              </span>
            </div>
          </div>
        </div>
      </GlassCard>

      {/* Related entities */}
      {relatedEntities.length > 0 && (
        <div>
          <h3 className="mb-2 text-[11px] font-semibold uppercase tracking-wider text-[var(--sc-text-muted)]">
            Related Entities
          </h3>
          <GlassCard className="divide-y divide-[var(--sc-border)] p-0">
            {relatedEntities.map((re) => (
              <button
                key={re.id}
                onClick={() => onNavigate(re.id)}
                className="flex w-full items-center justify-between px-4 py-2.5 text-left transition-colors hover:bg-[var(--sc-surface-interactive)]"
              >
                <div className="flex items-center gap-2 min-w-0">
                  <span
                    className="h-2 w-2 shrink-0 rounded-full"
                    style={{ backgroundColor: TYPE_BADGE[re.type] === 'coral' ? '#ff4d4d' : TYPE_BADGE[re.type] === 'amber' ? '#f5a623' : '#00e5cc' }}
                  />
                  <span className="truncate text-sm text-[var(--sc-text-primary)]">{re.label}</span>
                </div>
                <span className="shrink-0 text-xs tabular-nums text-[var(--sc-text-muted)]">
                  {re.memoryCount}
                </span>
              </button>
            ))}
          </GlassCard>
        </div>
      )}

      {/* Recent memories */}
      {recentMemories.length > 0 && (
        <div>
          <h3 className="mb-2 text-[11px] font-semibold uppercase tracking-wider text-[var(--sc-text-muted)]">
            Recent Memories
          </h3>
          <div className="flex flex-col gap-2">
            {recentMemories.slice(0, 8).map((m) => (
              <GlassCard key={m.id} className="p-3">
                <p className="truncate text-sm text-[var(--sc-text-primary)]">{m.title}</p>
                <div className="mt-1.5 flex items-center gap-2">
                  <Badge variant={CATEGORY_BADGE[m.category] || 'muted'} className="text-[10px]">
                    {m.category}
                  </Badge>
                  <span className="text-[10px] text-[var(--sc-text-muted)]">
                    {formatDate(m.created_at)}
                  </span>
                </div>
              </GlassCard>
            ))}
          </div>
        </div>
      )}
    </div>
  );
}
