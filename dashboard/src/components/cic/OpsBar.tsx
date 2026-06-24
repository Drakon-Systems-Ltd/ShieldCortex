'use client';

import { useEffect, useState } from 'react';
import { useStats } from '@/hooks/useMemories';
import { useAuditStats } from '@/hooks/useDefence';
import { useWebSocketStatus } from '@/components/MemoryWebSocketProvider';
import { EcosystemStrip } from './EcosystemStrip';
import { ShieldBar } from './ShieldBar';
import { ThemeToggle } from '@/components/ds/ThemeToggle';
import { Logo } from '@/components/ds/Logo';

function Counter({ label, value, colour }: { label: string; value: number; colour: string }) {
  return (
    <span className="flex items-center gap-1" title={label}>
      <span className="text-[var(--cic-text-faint)]">{label}</span>
      <span className="cic-bloom tabular-nums" style={{ color: colour }}>
        {value.toLocaleString()}
      </span>
    </span>
  );
}

/**
 * The top ops/status strip — a ship's console header. Brand · ecosystem sensors ·
 * shield integrity · live counters · WS link pulse · clock. All values are real;
 * everything degrades to 0 / "no signals" while data loads.
 */
export function OpsBar() {
  const audit = useAuditStats('24h');
  const stats = useStats();
  const { isConnected } = useWebSocketStatus();
  const [clock, setClock] = useState('');

  // Client-only clock — avoids an SSR/client time mismatch.
  useEffect(() => {
    const tick = () => setClock(new Date().toTimeString().slice(0, 8));
    tick();
    const id = setInterval(tick, 1000);
    return () => clearInterval(id);
  }, []);

  const a = audit.data;
  const sources = a?.topSources ?? [];

  return (
    <header className="flex items-center gap-5 overflow-x-auto border-b border-[var(--cic-border)] bg-[var(--cic-surface)]/80 px-4 py-2 font-mono text-xs whitespace-nowrap">
      <span className="flex shrink-0 items-center gap-2">
        <Logo size={18} className="shrink-0" />
        <span className="cic-bloom font-semibold tracking-[0.18em] text-[var(--cic-cyan)]">
          SHIELDCORTEX·CIC
        </span>
      </span>
      <EcosystemStrip sources={sources} />
      <ShieldBar blocked={a?.blockedCount ?? 0} />
      <span className="ml-auto flex shrink-0 items-center gap-4">
        <Counter label="SCANNED" value={a?.totalOperations ?? 0} colour="var(--cic-text-dim)" />
        <Counter label="BLOCKED" value={a?.blockedCount ?? 0} colour="var(--cic-coral)" />
        <Counter label="QUAR" value={a?.quarantinedCount ?? 0} colour="var(--cic-amber)" />
        <Counter label="MEMORIES" value={stats.data?.total ?? 0} colour="var(--cic-cyan)" />
        <span className="flex items-center gap-1.5" title={isConnected ? 'live link up' : 'link down'}>
          <span
            className={isConnected ? 'pulse-cyan' : 'pulse-coral'}
            style={{ color: isConnected ? 'var(--cic-cyan)' : 'var(--cic-coral)' }}
            aria-hidden
          >
            ◉
          </span>
          <span className="text-[var(--cic-text-faint)]">{isConnected ? 'LINK' : 'DOWN'}</span>
        </span>
        <span className="tabular-nums text-[var(--cic-text-muted)]" suppressHydrationWarning>
          {clock}
        </span>
        <ThemeToggle />
      </span>
    </header>
  );
}
