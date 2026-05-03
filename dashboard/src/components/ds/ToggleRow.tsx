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
        'flex items-start gap-4 rounded-lg border border-[var(--sc-border)] bg-[var(--sc-bg-deep)]/50 p-4 transition-colors',
        isInteractive && 'cursor-pointer hover:border-[var(--sc-text-muted)]',
        !isInteractive && 'opacity-70 cursor-not-allowed',
      )}
    >
      <div className="min-w-0 flex-1">
        <div className="text-sm font-semibold text-[var(--sc-text-primary)]">{label}</div>
        <div className="mt-1 text-xs leading-5 text-[var(--sc-text-secondary)]">
          {description}
          {docsUrl && (
            <>
              {' '}
              <a
                href={docsUrl}
                target="_blank"
                rel="noopener noreferrer"
                className="text-[var(--sc-cyan)] hover:underline"
                onClick={(e) => e.stopPropagation()}
              >
                Learn more
              </a>
            </>
          )}
        </div>
      </div>

      <div className="relative flex h-6 w-11 shrink-0 items-center" aria-hidden="true">
        {pending && (
          <Loader2
            size={12}
            className="absolute -left-5 top-1.5 animate-spin text-[var(--sc-text-muted)]"
          />
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
