'use client';

import { cn } from '@/lib/utils';
import { Lock } from 'lucide-react';
import { motion } from 'framer-motion';

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
    <div className={cn('flex items-center gap-1 overflow-x-auto rounded-xl bg-[var(--sc-bg-surface)] p-1 scrollbar-hide', className)} role="tablist">
      {tabs.map((tab) => {
        const active = tab.id === activeTab;
        return (
          <button
            key={tab.id}
            role="tab"
            aria-selected={active}
            onClick={() => onChange(tab.id)}
            className={cn(
              'relative flex shrink-0 items-center gap-2 rounded-lg px-3 py-2 text-xs font-medium transition-all sm:px-4 sm:text-sm',
              'focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-[var(--sc-cyan)]',
              active
                ? 'text-[var(--sc-text-primary)]'
                : 'text-[var(--sc-text-muted)] hover:text-[var(--sc-text-secondary)]',
            )}
          >
            {active && (
              <motion.div
                layoutId="activeTab"
                className="absolute inset-0 rounded-lg bg-[var(--sc-bg-elevated)]"
                style={{ borderRadius: 8 }}
                transition={{ type: 'spring', bounce: 0.2, duration: 0.4 }}
              />
            )}
            <span className="relative z-10 flex items-center gap-2">
              {tab.icon}
              {tab.label}
              {tab.locked && <Lock size={12} className="text-[var(--sc-coral)]" />}
              {tab.count !== undefined && tab.count > 0 && (
                <span className="ml-0.5 rounded-full bg-[var(--sc-coral)]/15 px-1.5 py-0.5 text-[10px] font-bold text-[var(--sc-coral)]">
                  {tab.count}
                </span>
              )}
            </span>
          </button>
        );
      })}
    </div>
  );
}
