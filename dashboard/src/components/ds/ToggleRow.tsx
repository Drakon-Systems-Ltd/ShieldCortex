'use client';

import type { ReactNode } from 'react';
import { Loader2 } from 'lucide-react';
import { cn } from '@/lib/utils';

export interface ToggleRowProps {
  label: string;
  description: ReactNode;
  /** One line stating what flipping this off/on actually means (brief §3.4). */
  consequence?: ReactNode;
  checked: boolean;
  pending?: boolean;
  disabled?: boolean;
  docsUrl?: string;
  onChange: (next: boolean) => void;
}

/** Settings toggle: label, one-line description, consequence line, slider. */
export function ToggleRow({
  label,
  description,
  consequence,
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
        'flex items-start gap-4 rounded-lg border border-[var(--sc-border)] bg-[var(--sc-surface)] p-4 transition-colors',
        isInteractive && 'cursor-pointer hover:border-[var(--sc-border-strong)]',
        !isInteractive && 'cursor-not-allowed opacity-70',
        'focus-within:outline-2 focus-within:outline-[var(--sc-focus)]',
      )}
    >
      <div className="min-w-0 flex-1">
        <div className="text-sm font-medium text-[var(--sc-text)]">{label}</div>
        <div className="mt-1 text-xs leading-5 text-[var(--sc-text-muted)]">
          {description}
          {docsUrl && (
            <>
              {' '}
              <a
                href={docsUrl}
                target="_blank"
                rel="noopener noreferrer"
                className="text-[var(--sc-primary)] hover:underline"
                onClick={(e) => e.stopPropagation()}
              >
                docs →
              </a>
            </>
          )}
        </div>
        {consequence && (
          <div className="mt-1 text-xs leading-5 text-[var(--sc-text-dim)]">{consequence}</div>
        )}
      </div>

      <div className="relative flex h-6 w-11 shrink-0 items-center self-start" aria-hidden="true">
        {pending && (
          <Loader2 size={12} className="absolute -left-5 top-1.5 animate-spin text-[var(--sc-text-muted)] motion-reduce:animate-none" />
        )}
        <span
          className={cn(
            'absolute inset-0 rounded-full transition-colors',
            checked ? 'bg-[var(--sc-primary)]' : 'border border-[var(--sc-border)] bg-[var(--sc-surface-2)]',
          )}
        />
        <span
          className={cn(
            'absolute top-0.5 h-5 w-5 rounded-full bg-white shadow transition-transform motion-reduce:transition-none',
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
