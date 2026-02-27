'use client';

import { useEffect, useState } from 'react';
import { Loader2 } from 'lucide-react';
import { useCloudStatus, useUpdateCloudConfig } from '@/hooks/useCloudStatus';
import { Input } from '@/components/ui/input';
import { Button } from '@/components/ui/button';

function clamp(value: number, min: number, max: number): number {
  return Math.max(min, Math.min(max, value));
}

export function OpenClawMemoryPanel() {
  const { data, isLoading } = useCloudStatus();
  const update = useUpdateCloudConfig();
  const [autoMemory, setAutoMemory] = useState(false);
  const [dedupe, setDedupe] = useState(true);
  const [noveltyThreshold, setNoveltyThreshold] = useState('0.88');
  const [maxRecent, setMaxRecent] = useState('300');

  useEffect(() => {
    const cfg = data?.openclawMemory;
    if (!cfg) return;
    setAutoMemory(cfg.autoMemory);
    setDedupe(cfg.dedupe);
    setNoveltyThreshold(String(cfg.noveltyThreshold));
    setMaxRecent(String(cfg.maxRecent));
  }, [data]);

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
    <div className="bg-slate-900 border border-slate-800 rounded-xl p-4">
      <h3 className="text-sm font-medium text-slate-300">OpenClaw Memory</h3>
      <p className="text-xs text-slate-500 mt-1">
        Configure how ShieldCortex complements native OpenClaw memory.
      </p>
      <p className="text-[11px] text-slate-600 mt-1">
        Changes apply on next OpenClaw gateway restart.
      </p>

      {isLoading ? (
        <div className="text-xs text-slate-500 mt-4 animate-pulse">Loading settings...</div>
      ) : (
        <div className="mt-4 space-y-3">
          <div className="flex items-center justify-between">
            <span className="text-xs text-slate-400">Auto-memory extraction</span>
            <button
              type="button"
              onClick={() => setAutoMemory(!autoMemory)}
              className={`h-6 w-11 rounded-full transition-colors ${autoMemory ? 'bg-cyan-500' : 'bg-slate-700'}`}
            >
              <span
                className={`block h-5 w-5 rounded-full bg-white transition-transform ${autoMemory ? 'translate-x-5' : 'translate-x-0.5'}`}
              />
            </button>
          </div>

          <div className="flex items-center justify-between">
            <span className="text-xs text-slate-400">Novelty dedupe</span>
            <button
              type="button"
              onClick={() => setDedupe(!dedupe)}
              disabled={!autoMemory}
              className={`h-6 w-11 rounded-full transition-colors ${dedupe && autoMemory ? 'bg-emerald-500' : 'bg-slate-700'} ${!autoMemory ? 'opacity-50 cursor-not-allowed' : ''}`}
            >
              <span
                className={`block h-5 w-5 rounded-full bg-white transition-transform ${(dedupe && autoMemory) ? 'translate-x-5' : 'translate-x-0.5'}`}
              />
            </button>
          </div>

          <div className="grid grid-cols-2 gap-2">
            <div>
              <label className="block text-[11px] text-slate-500 mb-1">Novelty threshold</label>
              <Input
                type="number"
                step="0.01"
                min={0.6}
                max={0.99}
                value={noveltyThreshold}
                disabled={!autoMemory || !dedupe}
                onChange={(e) => setNoveltyThreshold(e.target.value)}
                className="h-8 text-xs bg-slate-800 border-slate-700"
              />
            </div>
            <div>
              <label className="block text-[11px] text-slate-500 mb-1">Max recent records</label>
              <Input
                type="number"
                step="1"
                min={50}
                max={1000}
                value={maxRecent}
                disabled={!autoMemory || !dedupe}
                onChange={(e) => setMaxRecent(e.target.value)}
                className="h-8 text-xs bg-slate-800 border-slate-700"
              />
            </div>
          </div>

          <div className="flex items-center justify-between pt-1">
            <span className="text-[11px] text-slate-500">
              Default: dedupe on, threshold 0.88, max 300
            </span>
            <Button
              size="sm"
              onClick={handleSave}
              disabled={isSaving}
              className="h-8 text-xs bg-cyan-600 hover:bg-cyan-500 text-white"
            >
              {isSaving ? <Loader2 size={12} className="animate-spin" /> : null}
              Save
            </Button>
          </div>
        </div>
      )}
    </div>
  );
}
