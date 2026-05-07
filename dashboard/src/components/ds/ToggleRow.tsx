'use client';

import type { ReactNode } from 'react';
import { Loader2 } from 'lucide-react';
import { cn } from '@/lib/utils';

export interface ToggleRowProps {
  label: string;
  description: ReactNode;
  checked: boolean;
  pending?: boolean;
  disabled?: boolean;
  docsUrl?: string;
  onChange: (next: boolean) => void;
}

export function ToggleRow({
  label,
  description,
  checked,
  pending = false,
  disabled = false,
  docsUrl,
  onChange,
}: ToggleRowProps) {
  const isInteractive = !disabled && !pending;
  return (
    <label
      className={cn(
        'flex items-start gap-4 border border-[var(--term-border)] bg-[var(--term-surface)] p-4 rounded-md transition-colors',
        isInteractive && 'cursor-pointer hover:border-[var(--term-electric)]',
        !isInteractive && 'opacity-70 cursor-not-allowed',
      )}
    >
      <div className="min-w-0 flex-1">
        <div className="text-sm text-[var(--term-text)]">
          <span className="text-[var(--term-text-muted)]" aria-hidden>›</span> {label}
        </div>
        <div className="mt-1 text-xs leading-5 text-[var(--term-text-muted)]">
          {description}
          {docsUrl && (
            <>
              {' '}
              <a
                href={docsUrl}
                target="_blank"
                rel="noopener noreferrer"
                className="text-[var(--term-electric-fg)] hover:underline"
                onClick={(e) => e.stopPropagation()}
              >
                docs →
              </a>
            </>
          )}
        </div>
      </div>

      {/* Terminal: [on]/[off] text pill. */}
      <div className="flex shrink-0 items-center gap-2 self-start pt-0.5 theme-glass:hidden">
        {pending && (
          <Loader2 size={12} className="animate-spin text-[var(--term-text-muted)]" aria-hidden />
        )}
        <span
          className={cn(
            'font-mono text-xs uppercase tracking-wider',
            checked ? 'text-[var(--term-neon-fg)]' : 'text-[var(--term-text-muted)]',
          )}
        >
          {checked ? '[on]' : '[off]'}
        </span>
      </div>

      {/* Glass: original animated slider toggle. */}
      <div className="relative hidden h-6 w-11 shrink-0 items-center theme-glass:flex" aria-hidden="true">
        {pending && (
          <Loader2 size={12} className="absolute -left-5 top-1.5 animate-spin text-[var(--sc-text-muted)]" />
        )}
        <span
          className={cn(
            'absolute inset-0 rounded-full transition-colors',
            checked ? 'bg-[var(--sc-cyan)]' : 'bg-[var(--sc-bg-elevated)] border border-[var(--sc-border)]',
          )}
        />
        <span
          className={cn(
            'absolute top-0.5 h-5 w-5 rounded-full bg-white shadow transition-transform',
            checked ? 'translate-x-5' : 'translate-x-0.5',
          )}
        />
      </div>

      <input
        type="checkbox"
        checked={checked}
        disabled={!isInteractive}
        onChange={(e) => onChange(e.target.checked)}
        className="sr-only"
      />
    </label>
  );
}
