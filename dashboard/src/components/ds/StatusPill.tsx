'use client';

import { cn } from '@/lib/utils';

export type StatusPillState = 'ok' | 'warn' | 'fail' | 'info' | 'off' | 'unknown' | 'unavailable';

interface StatusPillProps {
  state: StatusPillState;
  children: React.ReactNode;
  className?: string;
}

/**
 * Honest status pill (doctor `[ok] [!] [x] [i]` semantics, brief §3.3/§13.4).
 * Distinct states: `off` (explicitly disabled — neutral grey, never green),
 * `unknown` (state not yet determined) and `unavailable` (the status fetch
 * itself failed) are different claims and render differently.
 */
const STYLES: Record<StatusPillState, string> = {
  ok: 'bg-[var(--sc-ok-soft)] text-[var(--sc-ok)]',
  warn: 'bg-[var(--sc-warn-soft)] text-[var(--sc-warn)]',
  fail: 'bg-[var(--sc-danger-soft)] text-[var(--sc-danger)]',
  info: 'bg-[var(--sc-primary-soft)] text-[var(--sc-primary)]',
  off: 'bg-[var(--sc-surface-2)] text-[var(--sc-off)]',
  unknown: 'bg-[var(--sc-surface-2)] text-[var(--sc-text-muted)] italic',
  unavailable: 'bg-[var(--sc-warn-soft)] text-[var(--sc-warn)] italic',
};

const GLYPH: Record<StatusPillState, string> = {
  ok: '✓',
  warn: '!',
  fail: '✕',
  info: 'i',
  off: '○',
  unknown: '?',
  unavailable: '?',
};

export function StatusPill({ state, children, className }: StatusPillProps) {
  return (
    <span
      className={cn(
        'inline-flex items-center gap-1 rounded-full px-2 py-0.5 text-[11px] font-medium',
        STYLES[state],
        className,
      )}
    >
      <span aria-hidden>{GLYPH[state]}</span>
      {children}
    </span>
  );
}
