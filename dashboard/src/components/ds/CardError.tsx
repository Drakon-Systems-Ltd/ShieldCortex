'use client';

import { AlertTriangle } from 'lucide-react';
import { cn } from '@/lib/utils';

interface CardErrorProps {
  message?: string;
  onRetry?: () => void;
  /** Render just the icon+message+retry row, to drop inside an existing card
   *  body. Default wraps it in a bordered surface card (for early-returns). */
  inline?: boolean;
  className?: string;
}

/**
 * Consistent error/empty fallback for dashboard data cards (Phase 1). Several
 * cards used to render blank (return null) or a perpetual "Loading…" on a failed
 * fetch — a silent void with no reason. This surfaces the failure with an
 * optional retry, mirroring the LicenseStatusCard chrome.
 */
export function CardError({ message = 'Failed to load', onRetry, inline = false, className }: CardErrorProps) {
  const row = (
    <div className="flex items-center gap-2" role="alert">
      <AlertTriangle size={14} className="text-[var(--sc-coral)] shrink-0" />
      <span className="text-xs text-[var(--sc-text-muted)]">{message}</span>
      {onRetry && (
        <button type="button" onClick={onRetry} className="ml-auto text-xs text-[var(--sc-cyan)] hover:underline">
          Retry
        </button>
      )}
    </div>
  );
  if (inline) return <div className={className}>{row}</div>;
  return (
    <div className={cn('bg-[var(--sc-bg-surface)] border border-[var(--sc-border)] rounded-xl p-4', className)}>
      {row}
    </div>
  );
}
