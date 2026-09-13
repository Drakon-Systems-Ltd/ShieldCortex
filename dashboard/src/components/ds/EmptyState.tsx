'use client';

import type { LucideIcon } from 'lucide-react';
import { cn } from '@/lib/utils';

interface EmptyStateProps {
  icon?: LucideIcon;
  /** One sentence explaining why this is empty and what fills it. */
  message: React.ReactNode;
  /** One CTA (button or copyable command). */
  action?: React.ReactNode;
  className?: string;
}

/** Empty state: icon, one sentence, one CTA (brief §5). */
export function EmptyState({ icon: Icon, message, action, className }: EmptyStateProps) {
  return (
    <div className={cn('flex flex-col items-center justify-center gap-3 rounded-lg border border-dashed border-[var(--sc-border)] px-6 py-12 text-center', className)}>
      {Icon && <Icon size={24} aria-hidden className="text-[var(--sc-text-muted)]" />}
      <p className="max-w-md text-sm text-[var(--sc-text-muted)]">{message}</p>
      {action}
    </div>
  );
}

/** A copyable CLI command, for empty states that name the fix. */
export function CopyableCommand({ command }: { command: string }) {
  return (
    <button
      type="button"
      onClick={() => { void navigator.clipboard?.writeText(command); }}
      title="Copy command"
      className="rounded-md border border-[var(--sc-border)] bg-[var(--sc-surface-2)] px-3 py-1.5 font-mono text-xs text-[var(--sc-text)] transition-colors hover:border-[var(--sc-border-strong)] focus-visible:outline-2 focus-visible:outline-[var(--sc-focus)]"
    >
      {command}
    </button>
  );
}
