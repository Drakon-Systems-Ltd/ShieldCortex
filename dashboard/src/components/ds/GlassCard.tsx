'use client';

import { cn } from '@/lib/utils';

interface GlassCardProps {
  children: React.ReactNode;
  className?: string;
  hover?: boolean;
  hoverCyan?: boolean;
  strong?: boolean;
  severity?: 'critical' | 'high' | 'medium' | 'low' | 'safe' | 'info';
  onClick?: () => void;
  selected?: boolean;
  /** Optional card header title. */
  title?: string;
  /** Optional bottom strip (e.g. "142 entities · last tick 3m ago"). */
  statusLine?: React.ReactNode;
  /** Suppress inner padding — use when children render their own table/scrollable region. */
  bodyPadding?: boolean;
}

const SEVERITY_CLASS: Record<string, string> = {
  critical: 'severity-critical',
  high: 'severity-high',
  medium: 'severity-medium',
  low: 'severity-low',
  safe: 'severity-safe',
  info: 'severity-info',
};

/**
 * v2 Card (legacy name kept — many call sites). Flat surface, 1px border,
 * subtle shadow; optional title header and status footer. No blur, no glow.
 */
export function GlassCard({
  children,
  className,
  hover = false,
  hoverCyan = false,
  strong: _strong = false,
  severity,
  onClick,
  selected = false,
  title,
  statusLine,
  bodyPadding = true,
}: GlassCardProps) {
  return (
    <div
      onClick={onClick}
      className={cn(
        'rounded-lg border border-[var(--sc-border)] bg-[var(--sc-surface)] shadow-[var(--sc-shadow-card)] transition-colors',
        (hover || hoverCyan || onClick) && 'cursor-pointer hover:border-[var(--sc-border-strong)]',
        selected && 'border-[var(--sc-primary)] ring-1 ring-[var(--sc-primary)]',
        severity && SEVERITY_CLASS[severity],
        className,
      )}
    >
      {title && (
        <div className="flex items-center gap-2 border-b border-[var(--sc-border)] px-4 py-2.5">
          <span className="text-xs font-medium text-[var(--sc-text-dim)]">{title}</span>
        </div>
      )}
      <div className={cn(bodyPadding && 'p-4')}>{children}</div>
      {statusLine && (
        <div className="border-t border-[var(--sc-border)] px-4 py-2 text-[11px] text-[var(--sc-text-muted)]">
          {statusLine}
        </div>
      )}
    </div>
  );
}
