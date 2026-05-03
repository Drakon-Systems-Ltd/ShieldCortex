'use client';

import { useState } from 'react';
import { GitMerge, Search } from 'lucide-react';
import { toast } from 'sonner';
import { Button } from '@/components/ds/Button';
import { GlassCard } from '@/components/ds/GlassCard';
import { useDashboardStore } from '@/lib/store';
import { useRunDedupe, type DedupeResponse } from '@/hooks/useMaintenance';

export function DedupePanel() {
  const { projectFilter } = useDashboardStore();
  const [scope, setScope] = useState<'all' | 'current'>(projectFilter ? 'current' : 'all');
  const [preview, setPreview] = useState<DedupeResponse | null>(null);

  const dedupe = useRunDedupe();
  const projectArg = scope === 'current' && projectFilter ? projectFilter : undefined;

  const onScan = () => {
    setPreview(null);
    dedupe.mutate(
      { project: projectArg, dryRun: true },
      {
        onSuccess: (data) => {
          setPreview(data);
          toast.success(
            data.groups.length === 0
              ? 'No duplicate clusters found'
              : `Found ${data.groups.length} cluster(s), ${data.groups.reduce((sum, g) => sum + g.removeIds.length, 0)} removable`,
          );
        },
        onError: (e) => toast.error(e.message),
      },
    );
  };

  const totalToRemove = preview?.groups.reduce((sum, g) => sum + g.removeIds.length, 0) ?? 0;

  const onMergeAll = () => {
    if (!preview || totalToRemove === 0) return;
    if (!window.confirm(`Merge ${preview.groups.length} cluster(s) and delete ${totalToRemove} duplicate(s)? Backup auto-saved first.`)) return;
    dedupe.mutate(
      { project: projectArg, dryRun: false },
      {
        onSuccess: (data) => {
          setPreview(null);
          toast.success(`Merged ${data.merged ?? 0}. Backup: ${data.backupPath ?? 'see ~/.shieldcortex/backups/'}`, {
            duration: 8000,
          });
        },
        onError: (e) => toast.error(e.message),
      },
    );
  };

  return (
    <GlassCard className="p-6">
      <div className="flex items-center gap-2">
        <GitMerge size={16} className="text-[var(--sc-cyan)]" />
        <h3 className="text-lg font-semibold text-[var(--sc-text-primary)]">Project Dedupe</h3>
      </div>
      <p className="mt-2 text-sm text-[var(--sc-text-secondary)]">
        Find clusters of near-duplicate long-term memories (text similarity: title overlap + content
        Jaccard). Merging keeps the highest-salience representative and deletes the rest. Backup
        auto-saved before any merge.
      </p>

      {/* Scope */}
      <div className="mt-4 flex flex-wrap items-center gap-3 text-xs">
        <span className="text-[var(--sc-text-muted)]">Scope:</span>
        <button
          type="button"
          onClick={() => setScope('all')}
          className={`rounded-md border px-2 py-1 ${
            scope === 'all'
              ? 'border-[var(--sc-cyan)] text-[var(--sc-cyan)]'
              : 'border-[var(--sc-border)] text-[var(--sc-text-muted)]'
          }`}
        >
          All projects
        </button>
        <button
          type="button"
          disabled={!projectFilter}
          onClick={() => setScope('current')}
          className={`rounded-md border px-2 py-1 disabled:opacity-40 ${
            scope === 'current'
              ? 'border-[var(--sc-cyan)] text-[var(--sc-cyan)]'
              : 'border-[var(--sc-border)] text-[var(--sc-text-muted)]'
          }`}
        >
          Current ({projectFilter ?? 'none selected'})
        </button>
      </div>

      {/* Preview output */}
      {preview && (
        <div className="mt-4 rounded-lg border border-[var(--sc-border)] bg-[var(--sc-bg-deep)]/50 p-3">
          <div className="flex items-center justify-between">
            <span className="text-sm font-semibold text-[var(--sc-text-primary)]">
              {preview.groups.length} cluster(s) · {totalToRemove} removable
            </span>
            <span className="text-[10px] text-[var(--sc-text-muted)]">{preview.pairsFound} pairs scanned</span>
          </div>
          {preview.groups.length === 0 ? (
            <div className="mt-2 text-xs text-[var(--sc-text-muted)]">No duplicates at the current heuristic threshold.</div>
          ) : (
            <ul className="mt-2 max-h-64 space-y-2 overflow-y-auto text-xs">
              {preview.groups.map((g) => (
                <li key={g.keepId} className="rounded border border-[var(--sc-border)] bg-[var(--sc-bg-surface)] p-2">
                  <div className="text-[10px] uppercase tracking-[0.14em] text-[var(--sc-text-muted)]">
                    Keep #{g.keepId} · remove {g.removeIds.length} · {g.similarity}
                  </div>
                  <div className="mt-1 font-semibold text-[var(--sc-text-primary)] truncate">{g.keepTitle}</div>
                  <div className="mt-0.5 text-[var(--sc-text-secondary)]">
                    Will delete: {g.removeIds.map((id) => `#${id}`).join(', ')}
                  </div>
                </li>
              ))}
            </ul>
          )}
        </div>
      )}

      {/* Actions */}
      <div className="mt-4 flex flex-wrap gap-2">
        <Button variant="outline" size="sm" onClick={onScan} disabled={dedupe.isPending} pulse={dedupe.isPending && dedupe.variables?.dryRun}>
          <Search size={13} />
          {dedupe.isPending && dedupe.variables?.dryRun ? 'Scanning' : 'Find duplicates'}
        </Button>
        <Button
          variant="cyan"
          size="sm"
          onClick={onMergeAll}
          disabled={!preview || totalToRemove === 0 || dedupe.isPending}
          pulse={dedupe.isPending && dedupe.variables?.dryRun === false}
        >
          <GitMerge size={13} />
          {dedupe.isPending && dedupe.variables?.dryRun === false
            ? 'Merging'
            : preview && totalToRemove > 0 ? `Merge all (${totalToRemove})` : 'Merge'}
        </Button>
      </div>
    </GlassCard>
  );
}
