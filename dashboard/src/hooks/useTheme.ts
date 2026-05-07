'use client';

import { useEffect, useState } from 'react';

export type Theme = 'terminal' | 'glass';

const STORAGE_KEY = 'sc-theme';
const DEFAULT_THEME: Theme = 'terminal';

function readDomTheme(): Theme {
  if (typeof document === 'undefined') return DEFAULT_THEME;
  const t = document.documentElement.dataset.theme;
  return t === 'glass' || t === 'terminal' ? t : DEFAULT_THEME;
}

/**
 * Read + write the active visual theme.
 *
 * Source of truth is `<html data-theme="…">`, set by the inline bootstrap
 * script in `app/layout.tsx` to avoid FOUC on first paint. The hook syncs
 * to it via MutationObserver, and `setTheme` writes both DOM and
 * localStorage so future loads pick up the choice.
 */
export function useTheme(): [Theme, (next: Theme) => void] {
  const [theme, setLocal] = useState<Theme>(DEFAULT_THEME);

  useEffect(() => {
    setLocal(readDomTheme());
    const observer = new MutationObserver(() => setLocal(readDomTheme()));
    observer.observe(document.documentElement, {
      attributes: true,
      attributeFilter: ['data-theme'],
    });
    return () => observer.disconnect();
  }, []);

  const setTheme = (next: Theme) => {
    if (typeof document !== 'undefined') {
      document.documentElement.dataset.theme = next;
    }
    try { localStorage.setItem(STORAGE_KEY, next); } catch { /* noop */ }
  };

  return [theme, setTheme];
}
