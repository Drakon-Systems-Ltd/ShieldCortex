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

// Bracket-wrapped terminal status labels: [INFO], [BLOCK], [ALLOW] etc.
// Colours map onto the terminal palette — danger red for critical/high,
// warn yellow for medium, neon for safe/cyan, electric for low/info.
const VARIANT_STYLES: Record<BadgeVariant, string> = {
  critical: 'text-[var(--term-danger)]',
  high: 'text-[var(--term-danger)]',
  medium: 'text-[var(--term-warn)]',
  low: 'text-[var(--term-electric-fg)]',
  safe: 'text-[var(--term-neon-fg)]',
  info: 'text-[var(--term-text-muted)]',
  coral: 'text-[var(--term-electric-fg)]',
  cyan: 'text-[var(--term-neon-fg)]',
  amber: 'text-[var(--term-warn)]',
  muted: 'text-[var(--term-text-muted)]',
};

const DOT_COLOURS: Record<BadgeVariant, string> = {
  critical: 'bg-[var(--term-danger)]',
  high: 'bg-[var(--term-danger)]',
  medium: 'bg-[var(--term-warn)]',
  low: 'bg-[var(--term-electric)]',
  safe: 'bg-[var(--term-neon)]',
  info: 'bg-[var(--term-text-muted)]',
  coral: 'bg-[var(--term-electric)]',
  cyan: 'bg-[var(--term-neon)]',
  amber: 'bg-[var(--term-warn)]',
  muted: 'bg-[var(--term-text-muted)]',
};

export function Badge({ children, variant = 'muted', className, dot = false, pulse = false }: BadgeProps) {
  return (
    <span
      className={cn(
        'inline-flex items-center gap-1.5 px-1 text-[11px] font-semibold uppercase tracking-wider whitespace-nowrap',
        VARIANT_STYLES[variant],
        className,
      )}
    >
      {dot && (
        <span
          className={cn('h-1.5 w-1.5 rounded-full', DOT_COLOURS[variant], pulse && 'animate-pulse')}
          aria-hidden
        />
      )}
      <span className="text-[var(--term-text-muted)]" aria-hidden>[</span>
      <span>{children}</span>
      <span className="text-[var(--term-text-muted)]" aria-hidden>]</span>
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
