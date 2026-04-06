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

const ACCENT_STYLES = {
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
};

export function StatCard({ label, value, icon: Icon, trend, accent = 'cyan', className }: StatCardProps) {
  const styles = ACCENT_STYLES[accent];

  return (
    <div className={cn('glass-card p-5', className)}>
      <div className="flex items-start justify-between">
        <div className="min-w-0">
          <p className="text-xs font-medium uppercase tracking-wider text-[var(--sc-text-muted)]">{label}</p>
          <p className="mt-2 text-2xl font-bold text-[var(--sc-text-primary)]">{value}</p>
          {trend && (
            <p className={cn('mt-1 text-xs', trend.value >= 0 ? styles.trendUp : styles.trendDown)}>
              {trend.value >= 0 ? '+' : ''}{trend.value}% {trend.label}
            </p>
          )}
        </div>
        <div className={cn('rounded-xl p-2.5', styles.iconBg)}>
          <Icon size={20} className={styles.icon} />
        </div>
      </div>
    </div>
  );
}
