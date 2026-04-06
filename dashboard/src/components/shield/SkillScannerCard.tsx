'use client';

import { useState } from 'react';
import { FileSearch, Loader2, ArrowRight, CheckCircle2, XCircle } from 'lucide-react';
import { useSkillScanAll } from '@/hooks/useSkillScan';
import { useDashboardStore } from '@/lib/store';
import type { SkillScanAllResponse } from '@/types/skills';

export function SkillScannerCard() {
  const scanAll = useSkillScanAll();
  const { setViewMode } = useDashboardStore();
  const [result, setResult] = useState<SkillScanAllResponse | null>(null);

  const handleScan = () => {
    scanAll.mutate(undefined, {
      onSuccess: (data) => setResult(data),
    });
  };

  const safeCount = result ? result.files.filter((f) => f.safe).length : 0;
  const threatCount = result?.threatCount ?? 0;

  return (
    <div className="bg-[var(--sc-bg-surface)] border border-[var(--sc-border)] rounded-xl p-4">
      <div className="flex items-center justify-between mb-3">
        <h3 className="text-sm font-medium text-[var(--sc-text-primary)]">Skill Scanner</h3>
        <button
          onClick={handleScan}
          disabled={scanAll.isPending}
          className="flex items-center gap-1.5 px-3 py-1.5 bg-[var(--sc-cyan)] hover:bg-[var(--sc-cyan-mid)] disabled:opacity-50 rounded-lg text-xs font-medium text-[var(--sc-text-primary)] transition-colors"
        >
          {scanAll.isPending ? (
            <Loader2 size={12} className="animate-spin" />
          ) : (
            <FileSearch size={12} />
          )}
          Scan All
        </button>
      </div>

      {result ? (
        <div>
          {/* Stats row */}
          <div className="flex items-center gap-4 mb-3">
            <div className="flex items-center gap-1.5">
              <CheckCircle2 size={14} className="text-[var(--sc-cyan)]" />
              <span className="text-sm font-medium text-[var(--sc-cyan)]">{safeCount}</span>
              <span className="text-[10px] text-[var(--sc-text-muted)]">safe</span>
            </div>
            {threatCount > 0 && (
              <div className="flex items-center gap-1.5">
                <XCircle size={14} className="text-[var(--sc-coral)]" />
                <span className="text-sm font-medium text-[var(--sc-coral)]">{threatCount}</span>
                <span className="text-[10px] text-[var(--sc-text-muted)]">threats</span>
              </div>
            )}
            <span className="text-[10px] text-[var(--sc-text-muted)]">
              {new Date(result.scannedAt).toLocaleTimeString()}
            </span>
          </div>

          {/* View all link */}
          <button
            onClick={() => setViewMode('skills')}
            className="flex items-center gap-1 text-xs text-[var(--sc-cyan)] hover:text-[var(--sc-cyan)] transition-colors"
          >
            View all results
            <ArrowRight size={12} />
          </button>
        </div>
      ) : !scanAll.isPending ? (
        /* Empty state */
        <div className="text-center py-3">
          <FileSearch size={20} className="text-[var(--sc-text-muted)] mx-auto mb-1.5" />
          <p className="text-[10px] text-[var(--sc-text-muted)]">
            Scan agent instruction files for threats
          </p>
        </div>
      ) : (
        <div className="flex items-center justify-center py-4">
          <Loader2 size={16} className="text-[var(--sc-cyan)] animate-spin" />
        </div>
      )}
    </div>
  );
}
