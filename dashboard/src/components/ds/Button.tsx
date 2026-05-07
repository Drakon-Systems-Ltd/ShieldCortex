'use client';

import { cn } from '@/lib/utils';
import { forwardRef } from 'react';

interface ButtonProps extends React.ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: 'coral' | 'cyan' | 'ghost' | 'outline';
  size?: 'sm' | 'md' | 'lg';
  glow?: boolean;
  /** Pulsing edge — terminal renders a blinking caret prefix; glass renders the
      cyan-glow-pulse animation around the button. */
  pulse?: boolean;
}

// Terminal: bracket-bordered transparent buttons. Glass overrides
// (gradient/glow/lift) apply only under [data-theme="glass"] via theme-glass:
// custom-variant utilities defined in globals.css.
const TERMINAL_VARIANT: Record<NonNullable<ButtonProps['variant']>, string> = {
  coral: 'border border-[var(--term-electric)] text-[var(--term-electric-fg)] bg-transparent hover:bg-[var(--term-electric)]/10',
  cyan: 'border border-[var(--term-neon)] text-[var(--term-neon-fg)] bg-transparent hover:bg-[var(--term-neon)]/10',
  ghost: 'border border-transparent text-[var(--term-text-muted)] bg-transparent hover:text-[var(--term-text)] hover:border-[var(--term-border)]',
  outline: 'border border-[var(--term-border)] text-[var(--term-text-dim)] bg-transparent hover:border-[var(--term-text-muted)] hover:text-[var(--term-text)]',
};

const TERMINAL_SIZE = {
  sm: 'px-2 py-1 text-xs',
  md: 'px-3 py-1.5 text-sm',
  lg: 'px-4 py-2 text-sm',
};

const GLASS_VARIANT: Record<NonNullable<ButtonProps['variant']>, string> = {
  coral: 'theme-glass:border-0 theme-glass:bg-gradient-to-br theme-glass:from-[var(--sc-coral)] theme-glass:to-[var(--sc-coral-dark)] theme-glass:text-white theme-glass:hover:shadow-[0_8px_30px_var(--sc-glow-coral-mid)]',
  cyan: 'theme-glass:border-0 theme-glass:bg-[var(--sc-cyan)] theme-glass:text-[var(--sc-bg-deep)] theme-glass:hover:bg-[var(--sc-cyan-mid)]',
  ghost: 'theme-glass:bg-transparent theme-glass:text-[var(--sc-text-secondary)] theme-glass:hover:bg-[var(--sc-surface-interactive)]',
  outline: 'theme-glass:bg-transparent theme-glass:border theme-glass:border-[var(--sc-border)] theme-glass:text-[var(--sc-text-secondary)]',
};

const GLASS_SIZE = {
  sm: 'theme-glass:px-3 theme-glass:py-1.5 theme-glass:text-xs theme-glass:rounded-lg',
  md: 'theme-glass:px-4 theme-glass:py-2 theme-glass:text-sm theme-glass:rounded-xl',
  lg: 'theme-glass:px-6 theme-glass:py-3 theme-glass:text-sm theme-glass:rounded-xl',
};

export const Button = forwardRef<HTMLButtonElement, ButtonProps>(
  (
    {
      variant = 'coral',
      size = 'md',
      glow = false,
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
          TERMINAL_VARIANT[variant],
          TERMINAL_SIZE[size],
          'theme-glass:font-semibold theme-glass:transition-all theme-glass:hover:-translate-y-0.5',
          GLASS_VARIANT[variant],
          GLASS_SIZE[size],
          glow && variant === 'coral' && 'theme-glass:glow-coral-subtle',
          glow && variant === 'cyan' && 'theme-glass:glow-cyan-subtle',
          pulse && 'theme-glass:glow-cyan-pulse',
          className,
        )}
        type="button"
        {...props}
      >
        {/* Terminal label: brackets + optional caret. */}
        <span className="inline-flex items-center gap-2 theme-glass:hidden">
          {pulse && <span className="cli-cursor" aria-hidden />}
          <span className="text-[var(--term-text-muted)]" aria-hidden>[</span>
          <span className="leading-none">{children}</span>
          <span className="text-[var(--term-text-muted)]" aria-hidden>]</span>
        </span>
        {/* Glass label: bare content. */}
        <span className="hidden theme-glass:inline-flex items-center gap-2">
          {children}
        </span>
      </button>
    );
  },
);
Button.displayName = 'Button';
