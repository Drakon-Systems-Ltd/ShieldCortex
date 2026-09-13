'use client';

import { cn } from '@/lib/utils';

type BadgeVariant = 'critical' | 'high' | 'medium' | 'low' | 'safe' | 'info' | 'coral' | 'cyan' | 'amber' | 'muted';

interface BadgeProps {
  children: React.ReactNode;
  variant?: BadgeVariant;
  className?: string;
  dot?: boolean;
  /** Legacy no-op; v2 badges do not pulse. */
  pulse?: boolean;
}

// Semantic pills: red = threat/fail, amber = pending/warn, green = safe,
// blue = info/low, neutral = muted. Legacy aliases coral→danger, cyan→ok.
const VARIANT_STYLES: Record<BadgeVariant, string> = {
  critical: 'bg-[var(--sc-danger-soft)] text-[var(--sc-danger)]',
  high: 'bg-[var(--sc-danger-soft)] text-[var(--sc-danger)]',
  medium: 'bg-[var(--sc-warn-soft)] text-[var(--sc-warn)]',
  low: 'bg-[var(--sc-primary-soft)] text-[var(--sc-primary)]',
  safe: 'bg-[var(--sc-ok-soft)] text-[var(--sc-ok)]',
  info: 'bg-[var(--sc-surface-2)] text-[var(--sc-text-muted)]',
  coral: 'bg-[var(--sc-danger-soft)] text-[var(--sc-danger)]',
  cyan: 'bg-[var(--sc-ok-soft)] text-[var(--sc-ok)]',
  amber: 'bg-[var(--sc-warn-soft)] text-[var(--sc-warn)]',
  muted: 'bg-[var(--sc-surface-2)] text-[var(--sc-text-muted)]',
};

const DOT_COLOURS: Record<BadgeVariant, string> = {
  critical: 'bg-[var(--sc-danger)]',
  high: 'bg-[var(--sc-danger)]',
  medium: 'bg-[var(--sc-warn)]',
  low: 'bg-[var(--sc-primary)]',
  safe: 'bg-[var(--sc-ok)]',
  info: 'bg-[var(--sc-text-muted)]',
  coral: 'bg-[var(--sc-danger)]',
  cyan: 'bg-[var(--sc-ok)]',
  amber: 'bg-[var(--sc-warn)]',
  muted: 'bg-[var(--sc-text-muted)]',
};

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

export function Badge({ children, variant = 'info', className, dot = false, pulse: _pulse }: BadgeProps) {
  return (
    <span
      className={cn(
        'inline-flex items-center gap-1.5 rounded-full px-2 py-0.5 text-[11px] font-medium',
        VARIANT_STYLES[variant],
        className,
      )}
    >
      {dot && <span aria-hidden className={cn('h-1.5 w-1.5 rounded-full', DOT_COLOURS[variant])} />}
      {children}
    </span>
  );
}
