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
  // Render the title as a mono prompt line: `$ shieldcortex <title>` with a
  // blinking caret. Subtitle / eyebrow render as `# comment` lines beneath.
  return (
    <div className={cn('space-y-3', className)}>
      <div className="flex flex-col gap-2 sm:flex-row sm:items-start sm:justify-between sm:gap-4">
        <div className="min-w-0">
          {eyebrow && (
            <p className="text-[11px] uppercase tracking-wider text-[var(--term-text-muted)]">
              <span className="text-[var(--term-electric-fg)]">›</span> {eyebrow}
            </p>
          )}
          <h1 className="mt-1 flex items-baseline flex-wrap gap-2 text-base font-mono text-[var(--term-text)] sm:text-lg">
            <span className="text-[var(--term-electric-fg)]" aria-hidden>$</span>
            <span>shieldcortex</span>
            <span className="text-[var(--term-text-dim)]">{title.toLowerCase()}</span>
            <span className="cli-cursor text-[var(--term-electric-fg)]" aria-hidden />
          </h1>
          {subtitle && (
            <p className="mt-1 text-xs text-[var(--term-text-muted)]">
              <span aria-hidden>#</span> {subtitle}
            </p>
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
