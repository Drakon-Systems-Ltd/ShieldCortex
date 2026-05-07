'use client';

import { cn } from '@/lib/utils';
import { forwardRef } from 'react';

interface ButtonProps extends React.ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: 'coral' | 'cyan' | 'ghost' | 'outline';
  size?: 'sm' | 'md' | 'lg';
  glow?: boolean;
  /** Pulsing edge — kept as a prop for API compatibility; renders a left-side
      blinking caret instead of a glow ring. */
  pulse?: boolean;
}

// All four legacy variants map onto a smaller terminal vocabulary:
//   coral / cyan → primary (electric)
//   ghost / outline → ghost (muted bracket)
const VARIANT_STYLES: Record<NonNullable<ButtonProps['variant']>, string> = {
  coral:
    'border border-[var(--term-electric)] text-[var(--term-electric-fg)] bg-transparent hover:bg-[var(--term-electric)]/10',
  cyan:
    'border border-[var(--term-neon)] text-[var(--term-neon-fg)] bg-transparent hover:bg-[var(--term-neon)]/10',
  ghost:
    'border border-transparent text-[var(--term-text-muted)] bg-transparent hover:text-[var(--term-text)] hover:border-[var(--term-border)]',
  outline:
    'border border-[var(--term-border)] text-[var(--term-text-dim)] bg-transparent hover:border-[var(--term-text-muted)] hover:text-[var(--term-text)]',
};

const SIZE_STYLES = {
  sm: 'px-2 py-1 text-xs',
  md: 'px-3 py-1.5 text-sm',
  lg: 'px-4 py-2 text-sm',
};

export const Button = forwardRef<HTMLButtonElement, ButtonProps>(
  (
    {
      variant = 'coral',
      size = 'md',
      glow: _glow = false,
      pulse = false,
      className,
      children,
      ...props
    },
    ref,
  ) => {
    return (
      <button
        ref={ref}
        className={cn(
          'inline-flex items-center justify-center gap-2 rounded-md font-mono transition-colors',
          'focus-visible:outline-1 focus-visible:outline-offset-2 focus-visible:outline-[var(--term-electric)]',
          pulse ? 'disabled:pointer-events-none' : 'disabled:pointer-events-none disabled:opacity-50',
          VARIANT_STYLES[variant],
          SIZE_STYLES[size],
          className,
        )}
        type="button"
        {...props}
      >
        {pulse && <span className="cli-cursor" aria-hidden />}
        <span className="text-[var(--term-text-muted)]" aria-hidden>[</span>
        <span className="leading-none">{children}</span>
        <span className="text-[var(--term-text-muted)]" aria-hidden>]</span>
      </button>
    );
  },
);
Button.displayName = 'Button';
