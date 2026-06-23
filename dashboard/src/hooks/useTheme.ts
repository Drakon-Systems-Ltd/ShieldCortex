'use client';

import { useSyncExternalStore } from 'react';

export type Theme = 'terminal' | 'glass';

const THEME_KEY = 'sc-theme';
const DEFAULT_THEME: Theme = 'terminal';

/**
 * Theme state. The CIC `terminal` look is the default; `glass` is kept as a
 * selectable alternate. The active theme lives on `<html data-theme>` (set
 * pre-hydration by the bootstrap script in layout.tsx, persisted to localStorage
 * `sc-theme`), so reading the attribute is the single source of truth and avoids
 * an SSR/client hydration mismatch.
 */
function read(): Theme {
  if (typeof document === 'undefined') return DEFAULT_THEME;
  return document.documentElement.getAttribute('data-theme') === 'glass' ? 'glass' : 'terminal';
}

function subscribe(onChange: () => void): () => void {
  if (typeof window === 'undefined') return () => {};
  window.addEventListener('sc-theme-change', onChange);
  window.addEventListener('storage', onChange);
  return () => {
    window.removeEventListener('sc-theme-change', onChange);
    window.removeEventListener('storage', onChange);
  };
}

export function useTheme(): [Theme, (next: Theme) => void] {
  const theme = useSyncExternalStore(subscribe, read, () => DEFAULT_THEME);

  const setTheme = (next: Theme) => {
    if (typeof document === 'undefined') return;
    try {
      window.localStorage.setItem(THEME_KEY, next);
    } catch {
      /* storage unavailable */
    }
    document.documentElement.setAttribute('data-theme', next);
    window.dispatchEvent(new Event('sc-theme-change'));
  };

  return [theme, setTheme];
}
