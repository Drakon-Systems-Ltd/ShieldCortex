'use client';

import { cn } from '@/lib/utils';
import { Lock } from 'lucide-react';

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

export function TabBar({ tabs, activeTab, onChange, className }: TabBarProps) {
  return (
    <div
      className={cn(
        'flex items-center gap-4 overflow-x-auto border-b border-[var(--term-border)] px-1 scrollbar-hide',
        // Glass restores the rounded-pill container background.
        'theme-glass:gap-1 theme-glass:rounded-xl theme-glass:border-0 theme-glass:bg-[var(--sc-bg-surface)] theme-glass:p-1',
        className,
      )}
      role="tablist"
    >
      {tabs.map((tab) => {
        const active = tab.id === activeTab;
        return (
          <button
            key={tab.id}
            type="button"
            role="tab"
            aria-selected={active ? 'true' : 'false'}
            onClick={() => onChange(tab.id)}
            className={cn(
              'relative flex shrink-0 items-center gap-2 px-1 py-2 text-xs font-mono transition-colors',
              'focus-visible:outline-1 focus-visible:outline-offset-2 focus-visible:outline-[var(--term-electric)]',
              active
                ? 'text-[var(--term-electric-fg)]'
                : 'text-[var(--term-text-muted)] hover:text-[var(--term-text)]',
              // Glass: rounded-pill chrome, system font, semibold.
              'theme-glass:font-medium theme-glass:font-sans theme-glass:rounded-lg theme-glass:px-3 theme-glass:py-2 sm:theme-glass:px-4 sm:theme-glass:text-sm',
              active && 'theme-glass:bg-[var(--sc-bg-elevated)] theme-glass:text-[var(--sc-text-primary)]',
              !active && 'theme-glass:hover:text-[var(--sc-text-secondary)]',
            )}
          >
            {tab.icon}
            <span>{tab.label}</span>
            {tab.locked && <Lock size={11} className="text-[var(--term-warn)] theme-glass:text-[var(--sc-coral)]" />}
            {tab.count !== undefined && tab.count > 0 && (
              <span className="text-[var(--term-text-muted)] theme-glass:ml-0.5 theme-glass:rounded-full theme-glass:bg-[var(--sc-coral)]/15 theme-glass:px-1.5 theme-glass:py-0.5 theme-glass:text-[10px] theme-glass:font-bold theme-glass:text-[var(--sc-coral)]">
                <span className="theme-glass:hidden">({tab.count})</span>
                <span className="hidden theme-glass:inline">{tab.count}</span>
              </span>
            )}
            {/* Terminal: bottom underline indicator. Glass mode hides it
                because the active state is conveyed by the pill background. */}
            {active && (
              <span
                aria-hidden
                className="absolute -bottom-px left-0 right-0 h-px bg-[var(--term-electric)] theme-glass:hidden"
              />
            )}
          </button>
        );
      })}
    </div>
  );
}
