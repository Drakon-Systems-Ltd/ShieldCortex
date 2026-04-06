'use client';

import { cn } from '@/lib/utils';
import type { TabItem } from './TabBar';
import { TabBar } from './TabBar';

interface PageHeaderProps {
  eyebrow?: string;
  title: string;
  subtitle?: string;
  actions?: React.ReactNode;
  tabs?: TabItem[];
  activeTab?: string;
  onTabChange?: (id: string) => void;
  className?: string;
}

export function PageHeader({
  eyebrow,
  title,
  subtitle,
  actions,
  tabs,
  activeTab,
  onTabChange,
  className,
}: PageHeaderProps) {
  return (
    <div className={cn('space-y-4', className)}>
      <div className="flex flex-col gap-3 sm:flex-row sm:items-start sm:justify-between sm:gap-4">
        <div className="min-w-0">
          {eyebrow && (
            <p className="text-[10px] font-semibold uppercase tracking-[0.2em] text-[var(--sc-coral)] sm:text-[11px]">
              {eyebrow}
            </p>
          )}
          <h1 className="mt-1 text-xl font-bold text-[var(--sc-text-primary)] sm:text-2xl">{title}</h1>
          {subtitle && (
            <p className="mt-1 text-xs text-[var(--sc-text-secondary)] sm:text-sm">{subtitle}</p>
          )}
        </div>
        {actions && <div className="flex shrink-0 items-center gap-2">{actions}</div>}
      </div>
      {tabs && activeTab && onTabChange && (
        <TabBar tabs={tabs} activeTab={activeTab} onChange={onTabChange} />
      )}
    </div>
  );
}
