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

const TERMINAL_ACCENT_VALUE = {
  coral: 'text-[var(--term-electric-fg)]',
  cyan: 'text-[var(--term-neon-fg)]',
  amber: 'text-[var(--term-warn)]',
  muted: 'text-[var(--term-text)]',
} as const;

const TERMINAL_TREND_UP = 'text-[var(--term-neon-fg)]';
const TERMINAL_TREND_DOWN = 'text-[var(--term-danger)]';

const GLASS_ACCENT_STYLES = {
  coral: {
    icon: 'text-[var(--sc-coral)]',
    iconBg: 'bg-[var(--sc-coral)]/10',
    trendUp: 'text-[var(--sc-coral)]',
    trendDown: 'text-[var(--sc-cyan)]',
  },
  cyan: {
    icon: 'text-[var(--sc-cyan)]',
    iconBg: 'bg-[var(--sc-cyan)]/10',
    trendUp: 'text-[var(--sc-cyan)]',
    trendDown: 'text-[var(--sc-coral)]',
  },
  amber: {
    icon: 'text-[var(--sc-amber)]',
    iconBg: 'bg-[var(--sc-amber)]/10',
    trendUp: 'text-[var(--sc-amber)]',
    trendDown: 'text-[var(--sc-text-muted)]',
  },
  muted: {
    icon: 'text-[var(--sc-text-secondary)]',
    iconBg: 'bg-[var(--sc-surface-interactive)]',
    trendUp: 'text-[var(--sc-cyan)]',
    trendDown: 'text-[var(--sc-coral)]',
  },
} as const;

export function StatCard({ label, value, icon: Icon, trend, accent = 'cyan', className }: StatCardProps) {
  const glassStyles = GLASS_ACCENT_STYLES[accent];

  return (
    <>
      {/* Terminal: key = value row, density-friendly. */}
      <div
        className={cn(
          'theme-glass:hidden flex items-center justify-between gap-3 px-4 py-2 border-b border-[var(--term-border)] last:border-0',
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
          <span className={cn('text-base tabular-nums', TERMINAL_ACCENT_VALUE[accent])}>{value}</span>
          {trend && (
            <span className={cn('text-xs tabular-nums', trend.value >= 0 ? TERMINAL_TREND_UP : TERMINAL_TREND_DOWN)}>
              {trend.value >= 0 ? '+' : ''}{trend.value}%
            </span>
          )}
        </div>
      </div>

      {/* Glass: original centred icon-and-number card. */}
      <div className={cn('hidden theme-glass:block glass-card p-5', className)}>
        <div className="flex items-start justify-between">
          <div className="min-w-0">
            <p className="text-xs font-medium uppercase tracking-wider text-[var(--sc-text-muted)]">{label}</p>
            <p className="mt-2 text-2xl font-bold text-[var(--sc-text-primary)]">{value}</p>
            {trend && (
              <p className={cn('mt-1 text-xs', trend.value >= 0 ? glassStyles.trendUp : glassStyles.trendDown)}>
                {trend.value >= 0 ? '+' : ''}{trend.value}% {trend.label}
              </p>
            )}
          </div>
          <div className={cn('rounded-xl p-2.5', glassStyles.iconBg)}>
            <Icon size={20} className={glassStyles.icon} />
          </div>
        </div>
      </div>
    </>
  );
}
