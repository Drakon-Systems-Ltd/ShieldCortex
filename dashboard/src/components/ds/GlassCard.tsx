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
  strong = false,
  severity,
  onClick,
  selected = false,
}: GlassCardProps) {
  return (
    <div
      className={cn(
        strong ? 'glass-card-strong' : 'glass-card',
        hover && 'glass-card-hover cursor-pointer',
        hoverCyan && 'glass-card-hover-cyan cursor-pointer',
        onClick && !hover && !hoverCyan && 'cursor-pointer',
        severity && SEVERITY_CLASS[severity],
        selected && 'border-[var(--sc-cyan)] shadow-[0_0_20px_var(--sc-glow-cyan)]',
        className,
      )}
      onClick={onClick}
      onKeyDown={onClick ? (e) => {
        if (e.key === 'Enter' || e.key === ' ') {
          e.preventDefault();
          onClick();
        }
      } : undefined}
      role={onClick ? 'button' : undefined}
      tabIndex={onClick ? 0 : undefined}
    >
      {children}
    </div>
  );
}
