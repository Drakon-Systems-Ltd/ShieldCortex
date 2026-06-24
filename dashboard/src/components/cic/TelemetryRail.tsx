'use client';

import { useActivityTrend } from '@/hooks/useActivityTrend';
import { sparkline } from '@/lib/cic/sparkline';

/**
 * Ambient telemetry band above the command rail: live 7-day sparklines of memory
 * activity (cyan) and threats blocked (coral) — the console quietly breathing with
 * real data. Block-char sparklines keep it terminal-native.
 */
export function TelemetryRail() {
  const { memoryTrend, threatTrend } = useActivityTrend();
  return (
    <div className="flex items-center gap-6 border-t border-[var(--cic-border)] bg-[var(--cic-surface)]/40 px-4 py-1 font-mono text-[11px] text-[var(--cic-text-faint)]">
      <span className="flex items-center gap-2" title="memories created per day, last 7 days">
        <span>MEMORY·7d</span>
        <span className="cic-bloom tracking-tight text-[var(--cic-cyan)]">{sparkline(memoryTrend) || '·······'}</span>
      </span>
      <span className="flex items-center gap-2" title="threats blocked per day, last 7 days">
        <span>THREAT·7d</span>
        <span className="cic-bloom tracking-tight text-[var(--cic-coral)]">{sparkline(threatTrend) || '·······'}</span>
      </span>
    </div>
  );
}
