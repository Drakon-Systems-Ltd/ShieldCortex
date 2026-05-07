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

      <div className="flex shrink-0 items-center gap-2 self-start pt-0.5">
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
