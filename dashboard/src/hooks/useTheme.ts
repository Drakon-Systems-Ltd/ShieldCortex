'use client';

import { useSyncExternalStore } from 'react';

export type Theme = 'terminal' | 'glass';

const STORAGE_KEY = 'sc-theme';
const DEFAULT_THEME: Theme = 'terminal';

function readDomTheme(): Theme {
  if (typeof document === 'undefined') return DEFAULT_THEME;
  const t = document.documentElement.dataset.theme;
  return t === 'glass' || t === 'terminal' ? t : DEFAULT_THEME;
}

function subscribe(callback: () => void): () => void {
  const observer = new MutationObserver(callback);
  observer.observe(document.documentElement, {
    attributes: true,
    attributeFilter: ['data-theme'],
  });
  return () => observer.disconnect();
}

/**
 * Read + write the active visual theme.
 *
 * Source of truth is `<html data-theme="…">`, set by the inline bootstrap
 * script in `app/layout.tsx` to avoid FOUC on first paint. The hook reads
 * via `useSyncExternalStore` so the DOM-first value flows in without a
 * post-hydration setState (which trips `react-hooks/set-state-in-effect`).
 * `setTheme` writes both DOM and localStorage so future loads pick up the choice.
 */
export function useTheme(): [Theme, (next: Theme) => void] {
  const theme = useSyncExternalStore(subscribe, readDomTheme, () => DEFAULT_THEME);

  const setTheme = (next: Theme) => {
    if (typeof document !== 'undefined') {
      document.documentElement.dataset.theme = next;
    }
    try { localStorage.setItem(STORAGE_KEY, next); } catch { /* noop */ }
  };

  return [theme, setTheme];
}
