'use client';

import { cn } from '@/lib/utils';
import { forwardRef } from 'react';

interface ButtonProps extends React.ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: 'coral' | 'cyan' | 'ghost' | 'outline';
  size?: 'sm' | 'md' | 'lg';
  glow?: boolean;
  /** Pulsing cyan edge ring; use to signal a button is "working" without a spinner. */
  pulse?: boolean;
}

const VARIANT_STYLES = {
  coral: 'bg-gradient-to-br from-[var(--sc-coral)] to-[var(--sc-coral-dark)] text-white hover:shadow-[0_8px_30px_var(--sc-glow-coral-mid)] active:translate-y-0',
  cyan: 'bg-[var(--sc-cyan)] text-[var(--sc-bg-deep)] hover:bg-[var(--sc-cyan-mid)] hover:shadow-[0_8px_30px_var(--sc-glow-cyan-mid)]',
  ghost: 'bg-transparent text-[var(--sc-text-secondary)] hover:bg-[var(--sc-surface-interactive)] hover:text-[var(--sc-text-primary)]',
  outline: 'bg-transparent border border-[var(--sc-border)] text-[var(--sc-text-secondary)] hover:border-[var(--sc-text-muted)] hover:text-[var(--sc-text-primary)]',
};

const SIZE_STYLES = {
  sm: 'px-3 py-1.5 text-xs rounded-lg',
  md: 'px-4 py-2 text-sm rounded-xl',
  lg: 'px-6 py-3 text-sm rounded-xl',
};

export const Button = forwardRef<HTMLButtonElement, ButtonProps>(
  ({ variant = 'coral', size = 'md', glow = false, pulse = false, className, children, ...props }, ref) => {
    return (
      <button
        ref={ref}
        className={cn(
          'inline-flex items-center justify-center gap-2 font-semibold transition-all',
          'hover:-translate-y-0.5 active:translate-y-0',
          'focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-[var(--sc-cyan)]',
          // Pulse should remain visible even when disabled (we disable buttons
          // during the in-flight mutation), so override the disabled opacity.
          pulse ? 'disabled:pointer-events-none' : 'disabled:pointer-events-none disabled:opacity-50',
          VARIANT_STYLES[variant],
          SIZE_STYLES[size],
          glow && variant === 'coral' && 'glow-coral-subtle',
          glow && variant === 'cyan' && 'glow-cyan-subtle',
          pulse && 'glow-cyan-pulse',
          className,
        )}
        type="button"
        {...props}
      >
        {children}
      </button>
    );
  },
);
Button.displayName = 'Button';
