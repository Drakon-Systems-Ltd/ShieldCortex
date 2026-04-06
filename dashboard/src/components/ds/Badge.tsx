'use client';

import { cn } from '@/lib/utils';

type BadgeVariant = 'critical' | 'high' | 'medium' | 'low' | 'safe' | 'info' | 'coral' | 'cyan' | 'amber' | 'muted';

interface BadgeProps {
  children: React.ReactNode;
  variant?: BadgeVariant;
  className?: string;
  dot?: boolean;
  pulse?: boolean;
}

const VARIANT_STYLES: Record<BadgeVariant, string> = {
  critical: 'bg-[var(--sc-coral)]/15 text-[var(--sc-coral)] border-[var(--sc-coral)]/30',
  high: 'bg-[var(--sc-coral-mid)]/15 text-[var(--sc-coral-mid)] border-[var(--sc-coral-mid)]/30',
  medium: 'bg-[var(--sc-amber)]/15 text-[var(--sc-amber)] border-[var(--sc-amber)]/30',
  low: 'bg-[var(--sc-cyan-mid)]/15 text-[var(--sc-cyan-mid)] border-[var(--sc-cyan-mid)]/30',
  safe: 'bg-[var(--sc-cyan)]/15 text-[var(--sc-cyan)] border-[var(--sc-cyan)]/30',
  info: 'bg-[var(--sc-text-muted)]/15 text-[var(--sc-text-secondary)] border-[var(--sc-text-muted)]/30',
  coral: 'bg-[var(--sc-coral)]/15 text-[var(--sc-coral)] border-[var(--sc-coral)]/30',
  cyan: 'bg-[var(--sc-cyan)]/15 text-[var(--sc-cyan)] border-[var(--sc-cyan)]/30',
  amber: 'bg-[var(--sc-amber)]/15 text-[var(--sc-amber)] border-[var(--sc-amber)]/30',
  muted: 'bg-[var(--sc-surface-interactive)] text-[var(--sc-text-secondary)] border-[var(--sc-border)]',
};

const DOT_COLOURS: Record<BadgeVariant, string> = {
  critical: 'bg-[var(--sc-coral)]',
  high: 'bg-[var(--sc-coral-mid)]',
  medium: 'bg-[var(--sc-amber)]',
  low: 'bg-[var(--sc-cyan-mid)]',
  safe: 'bg-[var(--sc-cyan)]',
  info: 'bg-[var(--sc-text-muted)]',
  coral: 'bg-[var(--sc-coral)]',
  cyan: 'bg-[var(--sc-cyan)]',
  amber: 'bg-[var(--sc-amber)]',
  muted: 'bg-[var(--sc-text-muted)]',
};

export function Badge({ children, variant = 'muted', className, dot = false, pulse = false }: BadgeProps) {
  return (
    <span
      className={cn(
        'inline-flex items-center gap-1.5 rounded-full border px-2.5 py-0.5 text-[11px] font-semibold uppercase tracking-wider',
        VARIANT_STYLES[variant],
        className,
      )}
    >
      {dot && (
        <span className={cn('h-1.5 w-1.5 rounded-full', DOT_COLOURS[variant], pulse && 'animate-pulse')} />
      )}
      {children}
    </span>
  );
}

/** Map risk level string to badge variant */
export function riskVariant(risk: string): BadgeVariant {
  const r = risk.toUpperCase();
  if (r === 'CRITICAL') return 'critical';
  if (r === 'HIGH') return 'high';
  if (r === 'MEDIUM') return 'medium';
  if (r === 'LOW') return 'low';
  if (r === 'SAFE') return 'safe';
  return 'info';
}
