'use client';

export type Theme = 'terminal' | 'glass';

/**
 * The dashboard is glass-only (the Terminal theme was removed in the 2026-06
 * cleanup). Kept as a stable no-op shim for the remaining consumer (Toast) so
 * its call sites don't churn; always reports `glass`, setter is a no-op.
 */
export function useTheme(): [Theme, (next: Theme) => void] {
  return ['glass', () => {}];
}
