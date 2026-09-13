'use client';

import { useSyncExternalStore } from 'react';

/** User preference — `system` follows the OS. */
export type ThemePreference = 'light' | 'dark' | 'system';
/** What is actually applied to the page. */
export type ResolvedTheme = 'light' | 'dark';

const THEME_KEY = 'sc-theme';
const DEFAULT_PREFERENCE: ThemePreference = 'system';

/**
 * v2 theme state. The preference lives in localStorage `sc-theme`
 * (`light | dark | system`); the *resolved* theme is the `dark` class on
 * `<html>`, set pre-hydration by the bootstrap script in layout.tsx and kept
 * in sync here. Legacy values (`terminal`, `glass`) migrate to `dark` — both
 * old shells were dark.
 */
export function normalisePreference(raw: string | null): ThemePreference {
  if (raw === 'light' || raw === 'dark' || raw === 'system') return raw;
  if (raw === 'terminal' || raw === 'glass') return 'dark';
  return DEFAULT_PREFERENCE;
}

export function resolvePreference(pref: ThemePreference, systemDark: boolean): ResolvedTheme {
  if (pref === 'system') return systemDark ? 'dark' : 'light';
  return pref;
}

function readPreference(): ThemePreference {
  if (typeof window === 'undefined') return DEFAULT_PREFERENCE;
  try {
    return normalisePreference(window.localStorage.getItem(THEME_KEY));
  } catch {
    return DEFAULT_PREFERENCE;
  }
}

function readResolved(): ResolvedTheme {
  if (typeof document === 'undefined') return 'dark';
  return document.documentElement.classList.contains('dark') ? 'dark' : 'light';
}

function systemPrefersDark(): boolean {
  if (typeof window === 'undefined' || !window.matchMedia) return true;
  return window.matchMedia('(prefers-color-scheme: dark)').matches;
}

function applyResolved(resolved: ResolvedTheme): void {
  document.documentElement.classList.toggle('dark', resolved === 'dark');
  document.documentElement.style.colorScheme = resolved;
}

function subscribe(onChange: () => void): () => void {
  if (typeof window === 'undefined') return () => {};
  const media = window.matchMedia?.('(prefers-color-scheme: dark)');
  const onSystemChange = () => {
    if (readPreference() === 'system') {
      applyResolved(resolvePreference('system', systemPrefersDark()));
    }
    onChange();
  };
  window.addEventListener('sc-theme-change', onChange);
  window.addEventListener('storage', onChange);
  media?.addEventListener?.('change', onSystemChange);
  return () => {
    window.removeEventListener('sc-theme-change', onChange);
    window.removeEventListener('storage', onChange);
    media?.removeEventListener?.('change', onSystemChange);
  };
}

export function setThemePreference(next: ThemePreference): void {
  if (typeof document === 'undefined') return;
  try {
    window.localStorage.setItem(THEME_KEY, next);
  } catch {
    /* storage unavailable */
  }
  applyResolved(resolvePreference(next, systemPrefersDark()));
  window.dispatchEvent(new Event('sc-theme-change'));
}

export function useTheme(): [ThemePreference, (next: ThemePreference) => void, ResolvedTheme] {
  const pref = useSyncExternalStore(subscribe, readPreference, () => DEFAULT_PREFERENCE);
  const resolved = useSyncExternalStore(subscribe, readResolved, () => 'dark' as ResolvedTheme);
  return [pref, setThemePreference, resolved];
}

/** Resolved theme only — for canvas painting and other value consumers. */
export function useResolvedTheme(): ResolvedTheme {
  return useSyncExternalStore(subscribe, readResolved, () => 'dark' as ResolvedTheme);
}
