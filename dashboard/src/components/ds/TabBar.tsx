'use client';

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
}

/** Underline tabs — section tabs live inside pages, not the sidebar. */
export function TabBar({ tabs, activeTab, onChange, className }: TabBarProps) {
  return (
    <div
      role="tablist"
      className={cn('flex items-center gap-1 overflow-x-auto border-b border-[var(--sc-border)] scrollbar-hide', className)}
    >
      {tabs.map((tab) => {
        const active = tab.id === activeTab;
        return (
          <button
            key={tab.id}
            role="tab"
            type="button"
            aria-selected={active}
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
                  'rounded-full px-1.5 text-[10px] tabular-nums',
                  active ? 'bg-[var(--sc-primary-soft)] text-[var(--sc-primary)]' : 'bg-[var(--sc-surface-2)] text-[var(--sc-text-muted)]',
                )}
              >
                {tab.count}
              </span>
            )}
            {tab.locked && <Lock size={11} aria-label="Requires a Pro licence" className="text-[var(--sc-text-muted)]" />}
          </button>
        );
      })}
    </div>
  );
}
