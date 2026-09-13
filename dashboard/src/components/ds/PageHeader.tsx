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

/** v2 page header: title, one-line description, actions right, optional tabs. */
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
      <div className="flex flex-col gap-2 sm:flex-row sm:items-start sm:justify-between sm:gap-4">
        <div className="min-w-0">
          {eyebrow && (
            <p className="text-[11px] uppercase tracking-wider text-[var(--sc-text-muted)]">{eyebrow}</p>
          )}
          <h1 className="truncate text-lg font-semibold text-[var(--sc-text)]">{title}</h1>
          {subtitle && <p className="mt-0.5 text-sm text-[var(--sc-text-muted)]">{subtitle}</p>}
        </div>
        {actions && <div className="flex shrink-0 items-center gap-2">{actions}</div>}
      </div>
      {tabs && activeTab !== undefined && onTabChange && (
        <TabBar tabs={tabs} activeTab={activeTab} onChange={onTabChange} />
      )}
    </div>
  );
}
