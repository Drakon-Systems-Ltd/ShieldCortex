'use client';

import { useTheme, type Theme } from '@/hooks/useTheme';
import { cn } from '@/lib/utils';

const OPTIONS: Array<{ id: Theme; label: string }> = [
  { id: 'terminal', label: 'terminal' },
  { id: 'glass', label: 'glass' },
];

/**
 * Two-button switcher for the visual theme. Reads `<html data-theme>` via
 * the useTheme hook and writes back through it (which also persists to
 * localStorage). Tiny and discoverable without dominating the chrome.
 */
export function ThemeToggle({ className }: { className?: string }) {
  const [theme, setTheme] = useTheme();
  return (
    <div
      role="group"
      aria-label="Theme"
      className={cn('inline-flex items-center gap-1', className)}
    >
      {OPTIONS.map((opt) => {
        const active = theme === opt.id;
        return (
          <button
            key={opt.id}
            type="button"
            onClick={(e) => { e.stopPropagation(); setTheme(opt.id); }}
            className={cn(
              'px-1.5 py-0.5 text-[11px] font-mono transition-colors',
              active
                ? 'text-[var(--term-electric-fg)] theme-glass:text-[var(--sc-cyan)]'
                : 'text-[var(--term-text-muted)] hover:text-[var(--term-text)] theme-glass:hover:text-[var(--sc-text-primary)]',
              'theme-glass:rounded theme-glass:uppercase theme-glass:tracking-[0.12em]',
              active && 'theme-glass:bg-[var(--sc-cyan)]/20',
            )}
          >
            <span className="theme-glass:hidden">[{opt.label}]</span>
            <span className="hidden theme-glass:inline">{opt.label}</span>
          </button>
        );
      })}
    </div>
  );
}
