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
    <div className="bg-slate-900 border border-slate-800 rounded-xl p-4">
      <div className="flex items-center justify-between mb-3">
        <h3 className="text-sm font-medium text-slate-300">Skill Scanner</h3>
        <button
          onClick={handleScan}
          disabled={scanAll.isPending}
          className="flex items-center gap-1.5 px-3 py-1.5 bg-cyan-600 hover:bg-cyan-500 disabled:opacity-50 rounded-lg text-xs font-medium text-white transition-colors"
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
              <CheckCircle2 size={14} className="text-green-400" />
              <span className="text-sm font-medium text-green-400">{safeCount}</span>
              <span className="text-[10px] text-slate-500">safe</span>
            </div>
            {threatCount > 0 && (
              <div className="flex items-center gap-1.5">
                <XCircle size={14} className="text-red-400" />
                <span className="text-sm font-medium text-red-400">{threatCount}</span>
                <span className="text-[10px] text-slate-500">threats</span>
              </div>
            )}
            <span className="text-[10px] text-slate-600">
              {new Date(result.scannedAt).toLocaleTimeString()}
            </span>
          </div>

          {/* View all link */}
          <button
            onClick={() => setViewMode('skills')}
            className="flex items-center gap-1 text-xs text-cyan-400 hover:text-cyan-300 transition-colors"
          >
            View all results
            <ArrowRight size={12} />
          </button>
        </div>
      ) : !scanAll.isPending ? (
        /* Empty state */
        <div className="text-center py-3">
          <FileSearch size={20} className="text-slate-600 mx-auto mb-1.5" />
          <p className="text-[10px] text-slate-500">
            Scan agent instruction files for threats
          </p>
        </div>
      ) : (
        <div className="flex items-center justify-center py-4">
          <Loader2 size={16} className="text-cyan-400 animate-spin" />
        </div>
      )}
    </div>
  );
}
