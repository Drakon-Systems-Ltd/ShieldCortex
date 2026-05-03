'use client';

import { useState } from 'react';
import { Eye, Trash2 } from 'lucide-react';
import { toast } from 'sonner';
import { Button } from '@/components/ds/Button';
import { GlassCard } from '@/components/ds/GlassCard';
import { useDashboardStore } from '@/lib/store';
import { useRunPrune, type PruneResponse } from '@/hooks/useMaintenance';

const SALIENCE_PRESETS = [0.1, 0.2, 0.3, 0.4, 0.5];
const AGE_PRESETS = [7, 30, 90, 180, 365];

export function PrunePanel() {
  const { projectFilter } = useDashboardStore();
  const [salienceLte, setSalienceLte] = useState(0.2);
  const [ageDaysGte, setAgeDaysGte] = useState(30);
  const [excludePinned, setExcludePinned] = useState(true);
  const [scope, setScope] = useState<'all' | 'current'>(projectFilter ? 'current' : 'all');
  const [preview, setPreview] = useState<PruneResponse | null>(null);

  const prune = useRunPrune();

  const projectArg = scope === 'current' && projectFilter ? projectFilter : undefined;

  const onPreview = () => {
    setPreview(null);
    prune.mutate(
      { salienceLte, ageDaysGte, excludePinned, project: projectArg, dryRun: true },
      {
        onSuccess: (data) => {
          setPreview(data);
          toast.success(`${data.matched} memories match — review before delete`);
        },
        onError: (e) => toast.error(e.message),
      },
    );
  };

  const onExecute = () => {
    if (!preview || preview.matched === 0) return;
    if (!window.confirm(`Permanently delete ${preview.matched} memories? A backup is auto-saved first.`)) return;
    prune.mutate(
      { salienceLte, ageDaysGte, excludePinned, project: projectArg, dryRun: false },
      {
        onSuccess: (data) => {
          setPreview(null);
          toast.success(`Deleted ${data.deleted ?? 0}. Backup: ${data.backupPath ?? 'see ~/.shieldcortex/backups/'}`, {
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
        <Trash2 size={16} className="text-[var(--sc-coral)]" />
        <h3 className="text-lg font-semibold text-[var(--sc-text-primary)]">Threshold Prune</h3>
      </div>
      <p className="mt-2 text-sm text-[var(--sc-text-secondary)]">
        Permanently delete memories below a salience threshold older than N days. Always preview
        first; backup is automatic before any delete.
      </p>

      {/* Sliders */}
      <div className="mt-4 grid gap-4 md:grid-cols-2">
        <div>
          <div className="flex items-center justify-between text-xs">
            <span className="text-[var(--sc-text-muted)]">Salience ≤</span>
            <span className="font-mono text-[var(--sc-text-primary)]">{salienceLte.toFixed(2)}</span>
          </div>
          <input
            type="range" min={0} max={0.5} step={0.05}
            value={salienceLte}
            onChange={(e) => setSalienceLte(parseFloat(e.target.value))}
            className="mt-1 w-full accent-[var(--sc-coral)]"
            aria-label="Salience threshold"
          />
          <div className="mt-1 flex gap-1">
            {SALIENCE_PRESETS.map((v) => (
              <button
                key={v}
                type="button"
                onClick={() => setSalienceLte(v)}
                className={`rounded border px-1.5 py-0.5 text-[10px] transition ${
                  salienceLte === v
                    ? 'border-[var(--sc-coral)] text-[var(--sc-coral)]'
                    : 'border-[var(--sc-border)] text-[var(--sc-text-muted)] hover:text-[var(--sc-text-primary)]'
                }`}
              >
                {v}
              </button>
            ))}
          </div>
        </div>

        <div>
          <div className="flex items-center justify-between text-xs">
            <span className="text-[var(--sc-text-muted)]">Older than (days)</span>
            <span className="font-mono text-[var(--sc-text-primary)]">{ageDaysGte}</span>
          </div>
          <input
            type="range" min={1} max={365} step={1}
            value={ageDaysGte}
            onChange={(e) => setAgeDaysGte(parseInt(e.target.value, 10))}
            className="mt-1 w-full accent-[var(--sc-coral)]"
            aria-label="Age threshold"
          />
          <div className="mt-1 flex gap-1">
            {AGE_PRESETS.map((v) => (
              <button
                key={v}
                type="button"
                onClick={() => setAgeDaysGte(v)}
                className={`rounded border px-1.5 py-0.5 text-[10px] transition ${
                  ageDaysGte === v
                    ? 'border-[var(--sc-coral)] text-[var(--sc-coral)]'
                    : 'border-[var(--sc-border)] text-[var(--sc-text-muted)] hover:text-[var(--sc-text-primary)]'
                }`}
              >
                {v}d
              </button>
            ))}
          </div>
        </div>
      </div>

      {/* Scope + pinned */}
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

        <label className="ml-auto inline-flex items-center gap-2 text-[var(--sc-text-secondary)]">
          <input
            type="checkbox"
            checked={excludePinned}
            onChange={(e) => setExcludePinned(e.target.checked)}
            className="accent-[var(--sc-cyan)]"
          />
          Exclude pinned
        </label>
      </div>

      {/* Preview output */}
      {preview && (
        <div className="mt-4 rounded-lg border border-[var(--sc-border)] bg-[var(--sc-bg-deep)]/50 p-3">
          <div className="flex items-center justify-between">
            <span className="text-sm font-semibold text-[var(--sc-text-primary)]">
              {preview.matched} memories match
            </span>
            <span className="text-[10px] text-[var(--sc-text-muted)]">
              showing first {preview.sample.length}
            </span>
          </div>
          {preview.sample.length === 0 ? (
            <div className="mt-2 text-xs text-[var(--sc-text-muted)]">Nothing to prune at these thresholds.</div>
          ) : (
            <ul className="mt-2 max-h-48 space-y-1 overflow-y-auto text-xs">
              {preview.sample.map((s) => (
                <li key={s.id} className="flex items-baseline gap-2 text-[var(--sc-text-secondary)]">
                  <span className="font-mono text-[10px] text-[var(--sc-text-muted)]">#{s.id}</span>
                  <span className="truncate flex-1 text-[var(--sc-text-primary)]">{s.title}</span>
                  <span className="text-[10px] text-[var(--sc-text-muted)]">
                    {s.project ?? '(no project)'} · sal {s.salience.toFixed(2)} · {s.ageDays}d
                  </span>
                </li>
              ))}
            </ul>
          )}
        </div>
      )}

      {/* Actions */}
      <div className="mt-4 flex flex-wrap gap-2">
        <Button variant="outline" size="sm" onClick={onPreview} disabled={prune.isPending} pulse={prune.isPending && prune.variables?.dryRun}>
          <Eye size={13} />
          {prune.isPending && prune.variables?.dryRun ? 'Previewing' : 'Preview'}
        </Button>
        <Button
          variant="coral"
          size="sm"
          onClick={onExecute}
          disabled={!preview || preview.matched === 0 || prune.isPending}
          pulse={prune.isPending && prune.variables?.dryRun === false}
        >
          <Trash2 size={13} />
          {prune.isPending && prune.variables?.dryRun === false
            ? 'Deleting'
            : preview ? `Delete ${preview.matched}` : 'Delete'}
        </Button>
      </div>
    </GlassCard>
  );
}
