'use client';

import { Monitor, Terminal } from 'lucide-react';
import { useTheme } from '@/hooks/useTheme';

/**
 * Theme toggle — switches between the CIC `terminal` console and the `glass`
 * shell. Rendered in BOTH shells' chrome so the choice is always reversible:
 * without this, a user whose `sc-theme` is persisted to `glass` has no UI path
 * back to terminal (the `theme` command lives only in the terminal rail).
 */
export function ThemeToggle({ className = '' }: { className?: string }) {
  const [theme, setTheme] = useTheme();
  const next = theme === 'terminal' ? 'glass' : 'terminal';

  return (
    <button
      type="button"
      onClick={() => setTheme(next)}
      aria-label={`Switch to ${next} theme`}
      title={`Theme: ${theme} — click to switch to ${next}`}
      className={`inline-flex items-center gap-1.5 px-1.5 py-0.5 text-[11px] font-mono text-[var(--sc-text-muted)] hover:text-[var(--sc-text-primary)] transition-colors ${className}`}
    >
      {theme === 'terminal' ? <Terminal size={12} /> : <Monitor size={12} />}
      <span>{theme === 'terminal' ? 'TERM' : 'GLASS'}</span>
    </button>
  );
}
