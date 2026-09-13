'use client';

import { Monitor, Moon, Sun } from 'lucide-react';
import { useTheme, type ThemePreference } from '@/hooks/useTheme';

const ORDER: ThemePreference[] = ['light', 'dark', 'system'];
const META: Record<ThemePreference, { label: string; Icon: typeof Sun }> = {
  light: { label: 'Light', Icon: Sun },
  dark: { label: 'Dark', Icon: Moon },
  system: { label: 'System', Icon: Monitor },
};

/**
 * Theme toggle — cycles light → dark → system. `system` follows the OS
 * preference live. Rendered in the top bar.
 */
export function ThemeToggle({ className = '' }: { className?: string }) {
  const [pref, setPref] = useTheme();
  const next = ORDER[(ORDER.indexOf(pref) + 1) % ORDER.length];
  const { label, Icon } = META[pref];

  return (
    <button
      type="button"
      onClick={() => setPref(next)}
      aria-label={`Theme: ${label}. Switch to ${META[next].label}`}
      title={`Theme: ${label} — click for ${META[next].label}`}
      className={`inline-flex h-8 items-center gap-1.5 rounded-md px-2 text-xs text-[var(--sc-text-muted)] transition-colors hover:bg-[var(--sc-surface-2)] hover:text-[var(--sc-text)] focus-visible:outline-2 focus-visible:outline-[var(--sc-focus)] ${className}`}
    >
      <Icon size={14} aria-hidden />
      <span>{label}</span>
    </button>
  );
}
