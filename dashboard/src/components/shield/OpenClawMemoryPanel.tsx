'use client';

import { useState } from 'react';
import { Loader2 } from 'lucide-react';
import { useCloudStatus, useUpdateCloudConfig } from '@/hooks/useCloudStatus';
import { Input } from '@/components/ui/input';
import { Button } from '@/components/ui/button';

function clamp(value: number, min: number, max: number): number {
  return Math.max(min, Math.min(max, value));
}

interface OpenClawMemoryFormProps {
  initialAutoMemory: boolean;
  initialDedupe: boolean;
  initialNoveltyThreshold: number;
  initialMaxRecent: number;
}

function OpenClawMemoryForm({ initialAutoMemory, initialDedupe, initialNoveltyThreshold, initialMaxRecent }: OpenClawMemoryFormProps) {
  const update = useUpdateCloudConfig();
  const [autoMemory, setAutoMemory] = useState(initialAutoMemory);
  const [dedupe, setDedupe] = useState(initialDedupe);
  const [noveltyThreshold, setNoveltyThreshold] = useState(String(initialNoveltyThreshold));
  const [maxRecent, setMaxRecent] = useState(String(initialMaxRecent));

  const isSaving = update.isPending;

  const handleSave = () => {
    const threshold = clamp(Number.parseFloat(noveltyThreshold), 0.6, 0.99);
    const recent = Math.floor(clamp(Number.parseInt(maxRecent, 10), 50, 1000));

    update.mutate({
      openclawAutoMemory: autoMemory,
      openclawAutoMemoryDedupe: dedupe,
      openclawAutoMemoryNoveltyThreshold: Number.isFinite(threshold) ? threshold : 0.88,
      openclawAutoMemoryMaxRecent: Number.isFinite(recent) ? recent : 300,
    });
  };

  return (
    <div className="mt-4 space-y-3">
      <div className="flex items-center justify-between">
        <span className="text-xs text-[var(--sc-text-secondary)]">Auto-memory extraction</span>
        <button
          type="button"
          onClick={() => setAutoMemory(!autoMemory)}
          className={`h-6 w-11 rounded-full transition-colors ${autoMemory ? 'bg-[var(--sc-cyan)]' : 'bg-[var(--sc-bg-elevated)]'}`}
        >
          <span
            className={`block h-5 w-5 rounded-full bg-white transition-transform ${autoMemory ? 'translate-x-5' : 'translate-x-0.5'}`}
          />
        </button>
      </div>

      <div className="flex items-center justify-between">
        <span className="text-xs text-[var(--sc-text-secondary)]">Novelty dedupe</span>
        <button
          type="button"
          onClick={() => setDedupe(!dedupe)}
          disabled={!autoMemory}
          className={`h-6 w-11 rounded-full transition-colors ${dedupe && autoMemory ? 'bg-[var(--sc-cyan)]' : 'bg-[var(--sc-bg-elevated)]'} ${!autoMemory ? 'opacity-50 cursor-not-allowed' : ''}`}
        >
          <span
            className={`block h-5 w-5 rounded-full bg-white transition-transform ${(dedupe && autoMemory) ? 'translate-x-5' : 'translate-x-0.5'}`}
          />
        </button>
      </div>

      <div className="grid grid-cols-2 gap-2">
        <div>
          <label className="block text-[11px] text-[var(--sc-text-muted)] mb-1">Novelty threshold</label>
          <Input
            type="number"
            step="0.01"
            min={0.6}
            max={0.99}
            value={noveltyThreshold}
            disabled={!autoMemory || !dedupe}
            onChange={(e) => setNoveltyThreshold(e.target.value)}
            className="h-8 text-xs bg-[var(--sc-bg-elevated)] border-[var(--sc-border)]"
          />
        </div>
        <div>
          <label className="block text-[11px] text-[var(--sc-text-muted)] mb-1">Max recent records</label>
          <Input
            type="number"
            step="1"
            min={50}
            max={1000}
            value={maxRecent}
            disabled={!autoMemory || !dedupe}
            onChange={(e) => setMaxRecent(e.target.value)}
            className="h-8 text-xs bg-[var(--sc-bg-elevated)] border-[var(--sc-border)]"
          />
        </div>
      </div>

      <div className="flex items-center justify-between pt-1">
        <span className="text-[11px] text-[var(--sc-text-muted)]">
          Default: dedupe on, threshold 0.88, max 300
        </span>
        <Button
          size="sm"
          onClick={handleSave}
          disabled={isSaving}
          className="h-8 text-xs bg-[var(--sc-cyan)] hover:bg-[var(--sc-cyan-mid)] text-[var(--sc-text-primary)]"
        >
          {isSaving ? <Loader2 size={12} className="animate-spin" /> : null}
          Save
        </Button>
      </div>
    </div>
  );
}

export function OpenClawMemoryPanel() {
  const { data, isLoading } = useCloudStatus();
  const cfg = data?.openclawMemory;

  // Key resets the form when server data changes
  const formKey = cfg ? `${cfg.autoMemory}-${cfg.dedupe}-${cfg.noveltyThreshold}-${cfg.maxRecent}` : 'default';

  return (
    <div className="bg-[var(--sc-bg-surface)] border border-[var(--sc-border)] rounded-xl p-4">
      <h3 className="text-sm font-medium text-[var(--sc-text-primary)]">OpenClaw Memory</h3>
      <p className="text-xs text-[var(--sc-text-muted)] mt-1">
        Configure how ShieldCortex complements native OpenClaw memory.
      </p>
      <p className="text-[11px] text-[var(--sc-text-muted)] mt-1">
        Changes apply on next OpenClaw gateway restart.
      </p>

      {isLoading ? (
        <div className="text-xs text-[var(--sc-text-muted)] mt-4 animate-pulse">Loading settings...</div>
      ) : (
        <OpenClawMemoryForm
          key={formKey}
          initialAutoMemory={cfg?.autoMemory ?? false}
          initialDedupe={cfg?.dedupe ?? true}
          initialNoveltyThreshold={cfg?.noveltyThreshold ?? 0.88}
          initialMaxRecent={cfg?.maxRecent ?? 300}
        />
      )}
    </div>
  );
}
