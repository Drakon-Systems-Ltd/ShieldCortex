'use client';

import { cn } from '@/lib/utils';
import type { LucideIcon } from 'lucide-react';

interface StatCardProps {
  label: string;
  value: string | number;
  icon: LucideIcon;
  trend?: { value: number; label: string };
  accent?: 'coral' | 'cyan' | 'amber' | 'muted';
  className?: string;
}

const ACCENT_VALUE = {
  coral: 'text-[var(--term-electric-fg)]',
  cyan: 'text-[var(--term-neon-fg)]',
  amber: 'text-[var(--term-warn)]',
  muted: 'text-[var(--term-text)]',
} as const;

const TREND_UP = 'text-[var(--term-neon-fg)]';
const TREND_DOWN = 'text-[var(--term-danger)]';

export function StatCard({ label, value, icon: Icon, trend, accent = 'cyan', className }: StatCardProps) {
  return (
    <div
      className={cn(
        'flex items-center justify-between gap-3 px-4 py-2 border-b border-[var(--term-border)] last:border-0',
        className,
      )}
    >
      <div className="flex items-center gap-3 min-w-0">
        <Icon size={14} className="text-[var(--term-text-muted)] shrink-0" aria-hidden />
        <span className="text-xs uppercase tracking-wider text-[var(--term-text-muted)] truncate">
          {label}
        </span>
      </div>
      <div className="flex items-baseline gap-2 shrink-0">
        <span className={cn('text-base tabular-nums', ACCENT_VALUE[accent])}>{value}</span>
        {trend && (
          <span className={cn('text-xs tabular-nums', trend.value >= 0 ? TREND_UP : TREND_DOWN)}>
            {trend.value >= 0 ? '+' : ''}{trend.value}%
          </span>
        )}
      </div>
    </div>
  );
}
