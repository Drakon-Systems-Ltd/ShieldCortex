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
  /** Render terminal-window chrome (traffic lights + monospace title bar). */
  title?: string;
  /** Optional bottom strip (e.g. "ws connected · 142 entities · last tick 3m ago"). */
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
  const handleKey = onClick
    ? (e: React.KeyboardEvent) => {
        if (e.key === 'Enter' || e.key === ' ') {
          e.preventDefault();
          onClick();
        }
      }
    : undefined;

  return (
    <div
      className={cn(
        'glass-card overflow-hidden',
        hover && 'glass-card-hover cursor-pointer',
        hoverCyan && 'glass-card-hover-cyan cursor-pointer',
        onClick && !hover && !hoverCyan && 'cursor-pointer',
        severity && SEVERITY_CLASS[severity],
        selected && 'border-[var(--term-electric)]',
        className,
      )}
      onClick={onClick}
      onKeyDown={handleKey}
      role={onClick ? 'button' : undefined}
      tabIndex={onClick ? 0 : undefined}
    >
      {/* Tactical title bar — terminal mode only. Reads as a ship's-console
          system readout: a glowing region marker + the system name + a live dot.
          Glass mode renders no chrome (children sit directly in the body). */}
      {title !== undefined && (
        <div className="flex items-center gap-2 border-b border-[var(--term-border)] bg-[var(--term-surface-2)]/50 px-4 py-1.5 theme-glass:hidden">
          <span aria-hidden className="cic-bloom text-[var(--cic-cyan)]">▸</span>
          <span className="cic-bloom select-none truncate text-xs font-semibold uppercase tracking-[0.14em] text-[var(--cic-cyan)]">
            {title}
          </span>
          <span aria-hidden className="ml-auto h-1.5 w-1.5 shrink-0 rounded-full bg-[var(--cic-cyan)]/60" />
        </div>
      )}
      <div className={cn(bodyPadding ? 'p-5' : '')}>{children}</div>
      {statusLine !== undefined && (
        <div className="px-4 py-2 text-xs border-t border-[var(--term-border)] bg-[var(--term-surface-2)] text-[var(--term-text-muted)] theme-glass:hidden">
          {statusLine}
        </div>
      )}
    </div>
  );
}
