'use client';

import { useRef } from 'react';
import { Lock } from 'lucide-react';
import { cn } from '@/lib/utils';

export interface TabItem {
  id: string;
  label: string;
  icon?: React.ReactNode;
  locked?: boolean;
  count?: number;
}

interface TabBarProps {
  tabs: TabItem[];
  activeTab: string;
  onChange: (id: string) => void;
  className?: string;
  'aria-label'?: string;
}

/** Underline tabs — section tabs live inside pages, not the sidebar. */
export function TabBar({ tabs, activeTab, onChange, className, 'aria-label': ariaLabel }: TabBarProps) {
  const listRef = useRef<HTMLDivElement>(null);
  // Arrow keys move between tabs (Opus §3 keyboard); Tab leaves the list.
  const onKeyDown = (e: React.KeyboardEvent<HTMLDivElement>) => {
    const i = tabs.findIndex((t) => t.id === activeTab);
    const last = tabs.length - 1;
    const next =
      e.key === 'ArrowRight' ? (i >= last ? 0 : i + 1)
      : e.key === 'ArrowLeft' ? (i <= 0 ? last : i - 1)
      : e.key === 'Home' ? 0
      : e.key === 'End' ? last
      : null;
    if (next === null || !tabs[next]) return;
    e.preventDefault();
    onChange(tabs[next].id);
    listRef.current?.querySelectorAll<HTMLButtonElement>('[role="tab"]')[next]?.focus();
  };
  return (
    <div
      ref={listRef}
      role="tablist"
      aria-label={ariaLabel}
      onKeyDown={onKeyDown}
      className={cn('flex items-center gap-1 overflow-x-auto border-b border-[var(--sc-border)] scrollbar-hide', className)}
    >
      {tabs.map((tab, idx) => {
        const active = tab.id === activeTab;
        const focusable = active || (idx === 0 && !tabs.some((t) => t.id === activeTab));
        return (
          <button
            key={tab.id}
            role="tab"
            type="button"
            aria-selected={active}
            tabIndex={focusable ? 0 : -1}
            onClick={() => onChange(tab.id)}
            className={cn(
              '-mb-px flex items-center gap-1.5 whitespace-nowrap border-b-2 px-3 py-2 text-sm transition-colors focus-visible:outline-2 focus-visible:-outline-offset-2 focus-visible:outline-[var(--sc-focus)]',
              active
                ? 'border-[var(--sc-primary)] font-medium text-[var(--sc-text)]'
                : 'border-transparent text-[var(--sc-text-muted)] hover:text-[var(--sc-text)]',
            )}
          >
            {tab.icon}
            {tab.label}
            {typeof tab.count === 'number' && (
              <span
                className={cn(
                  'rounded-full px-1.5 text-xs tabular-nums',
                  active ? 'bg-[var(--sc-primary-soft)] text-[var(--sc-primary)]' : 'bg-[var(--sc-surface-2)] text-[var(--sc-text-muted)]',
                )}
              >
                {tab.count}
              </span>
            )}
            {tab.locked && <Lock size={11} aria-label="Requires an Enterprise licence" className="text-[var(--sc-text-muted)]" />}
          </button>
        );
      })}
    </div>
  );
}
