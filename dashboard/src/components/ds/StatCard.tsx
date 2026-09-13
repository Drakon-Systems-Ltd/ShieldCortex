'use client';

import type { LucideIcon } from 'lucide-react';
import { TrendingDown, TrendingUp } from 'lucide-react';
import { cn } from '@/lib/utils';

interface StatCardProps {
  label: string;
  value: string | number;
  icon: LucideIcon;
  trend?: { value: number; label: string };
  /** Legacy accents map to v2 semantics: coral→danger, cyan→neutral. */
  accent?: 'coral' | 'cyan' | 'amber' | 'muted';
  className?: string;
}

const ACCENT_VALUE = {
  coral: 'text-[var(--sc-danger)]',
  cyan: 'text-[var(--sc-text)]',
  amber: 'text-[var(--sc-warn)]',
  muted: 'text-[var(--sc-text)]',
} as const;

/** Stat tile: label, tabular value, optional trend delta. */
export function StatCard({ label, value, icon: Icon, trend, accent = 'cyan', className }: StatCardProps) {
  return (
    <div
      className={cn(
        'rounded-lg border border-[var(--sc-border)] bg-[var(--sc-surface)] p-4 shadow-[var(--sc-shadow-card)]',
        className,
      )}
    >
      <div className="flex items-center justify-between gap-2">
        <span className="truncate text-xs text-[var(--sc-text-muted)]">{label}</span>
        <Icon size={15} aria-hidden className="shrink-0 text-[var(--sc-text-muted)]" />
      </div>
      <div className={cn('mt-1.5 text-2xl font-semibold tabular-nums', ACCENT_VALUE[accent])}>{value}</div>
      {trend && (
        <div className="mt-1 flex items-center gap-1 text-[11px] text-[var(--sc-text-muted)]">
          {trend.value >= 0 ? (
            <TrendingUp size={12} aria-hidden className="text-[var(--sc-ok)]" />
          ) : (
            <TrendingDown size={12} aria-hidden className="text-[var(--sc-danger)]" />
          )}
          <span className="tabular-nums">{trend.value >= 0 ? '+' : ''}{trend.value}</span>
          <span>{trend.label}</span>
        </div>
      )}
    </div>
  );
}
