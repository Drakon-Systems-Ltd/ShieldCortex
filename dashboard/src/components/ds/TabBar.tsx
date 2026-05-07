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
            )}
          >
            {tab.icon}
            <span>{tab.label}</span>
            {tab.locked && <Lock size={11} className="text-[var(--term-warn)]" />}
            {tab.count !== undefined && tab.count > 0 && (
              <span className="text-[var(--term-text-muted)]">({tab.count})</span>
            )}
            {active && (
              <span
                aria-hidden
                className="absolute -bottom-px left-0 right-0 h-px bg-[var(--term-electric)]"
              />
            )}
          </button>
        );
      })}
    </div>
  );
}
