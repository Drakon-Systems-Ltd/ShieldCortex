'use client';

import { cn } from '@/lib/utils';
import { forwardRef } from 'react';

type ButtonVariant =
  | 'primary'
  | 'secondary'
  | 'ghost'
  | 'danger'
  | 'outline'
  // Legacy aliases (pre-v2 call sites): coral was the old brand-primary,
  // cyan the secondary accent. They map onto the v2 variants.
  | 'coral'
  | 'cyan';

interface ButtonProps extends React.ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: ButtonVariant;
  size?: 'sm' | 'md' | 'lg';
  /** Legacy no-ops kept so old call sites compile; v2 has no glow/pulse. */
  glow?: boolean;
  pulse?: boolean;
}

const VARIANT: Record<'primary' | 'secondary' | 'ghost' | 'danger' | 'outline', string> = {
  primary:
    'bg-[var(--sc-primary)] text-[var(--sc-primary-fg)] border border-transparent hover:bg-[var(--sc-primary-hover)]',
  secondary:
    'bg-[var(--sc-surface-2)] text-[var(--sc-text)] border border-[var(--sc-border)] hover:border-[var(--sc-border-strong)]',
  ghost:
    'bg-transparent text-[var(--sc-text-muted)] border border-transparent hover:bg-[var(--sc-surface-2)] hover:text-[var(--sc-text)]',
  danger:
    'bg-transparent text-[var(--sc-danger)] border border-[var(--sc-danger)] hover:bg-[var(--sc-danger-soft)]',
  outline:
    'bg-transparent text-[var(--sc-text-dim)] border border-[var(--sc-border)] hover:border-[var(--sc-border-strong)] hover:text-[var(--sc-text)]',
};

const SIZE = {
  sm: 'h-7 px-2.5 text-xs',
  md: 'h-8 px-3 text-sm',
  lg: 'h-9 px-4 text-sm',
};

function resolveVariant(v: ButtonVariant): keyof typeof VARIANT {
  if (v === 'coral') return 'primary';
  if (v === 'cyan') return 'secondary';
  return v;
}

export const Button = forwardRef<HTMLButtonElement, ButtonProps>(
  ({ variant = 'primary', size = 'md', glow: _glow, pulse: _pulse, className, children, ...props }, ref) => {
    return (
      <button
        ref={ref}
        className={cn(
          'inline-flex items-center justify-center gap-1.5 rounded-md font-medium transition-colors focus-visible:outline-2 focus-visible:outline-offset-1 focus-visible:outline-[var(--sc-focus)] disabled:pointer-events-none disabled:opacity-50',
          VARIANT[resolveVariant(variant)],
          SIZE[size],
          className,
        )}
        {...props}
      >
        {children}
      </button>
    );
  },
);
Button.displayName = 'Button';
