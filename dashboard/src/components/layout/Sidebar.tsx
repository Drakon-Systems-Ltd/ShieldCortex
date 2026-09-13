'use client';

import Link from 'next/link';
import { usePathname } from 'next/navigation';
import { PanelLeftClose, PanelLeftOpen } from 'lucide-react';
import { NAV_ITEMS } from '@/components/layout/route-config';
import { useDashboardStore } from '@/lib/store';
import { Logo } from '@/components/ds/Logo';
import { cn } from '@/lib/utils';

/**
 * v2 sidebar: five labelled top-level items, collapsible to icons (240px ↔
 * 56px). Section tabs live inside pages, not here. Active state = the longest
 * matching href so /memory/replay lights Memory.
 */
export function Sidebar() {
  const pathname = usePathname();
  const { sidebarPinned: collapsed, toggleSidebarPinned: toggleCollapsed } = useDashboardStore();

  const activeHref = NAV_ITEMS
    .filter((n) => pathname === n.href || pathname.startsWith(n.href + '/'))
    .sort((a, b) => b.href.length - a.href.length)[0]?.href;

  return (
    <nav
      aria-label="Primary"
      className={cn(
        'flex h-full shrink-0 flex-col border-r border-[var(--sc-border)] bg-[var(--sidebar)] transition-[width] duration-150 ease-out motion-reduce:transition-none',
        collapsed ? 'w-14' : 'w-60',
      )}
    >
      <div className={cn('flex h-14 items-center border-b border-[var(--sc-border)]', collapsed ? 'justify-center' : 'gap-2 px-4')}>
        <Logo size={22} />
        {!collapsed && (
          <span className="truncate text-sm font-semibold text-[var(--sc-text)]">ShieldCortex</span>
        )}
      </div>

      <ul className="flex-1 space-y-1 overflow-y-auto p-2">
        {NAV_ITEMS.map(({ href, label, icon: Icon }) => {
          const active = href === activeHref;
          return (
            <li key={href}>
              <Link
                href={href}
                aria-current={active ? 'page' : undefined}
                title={collapsed ? label : undefined}
                className={cn(
                  'flex items-center gap-3 rounded-md px-3 py-2 text-sm transition-colors focus-visible:outline-2 focus-visible:outline-[var(--sc-focus)]',
                  collapsed && 'justify-center px-0',
                  active
                    ? 'bg-[var(--sc-primary-soft)] font-medium text-[var(--sc-primary)]'
                    : 'text-[var(--sc-text-dim)] hover:bg-[var(--sc-surface-2)] hover:text-[var(--sc-text)]',
                )}
              >
                <Icon size={17} aria-hidden className="shrink-0" />
                {!collapsed && <span className="truncate">{label}</span>}
              </Link>
            </li>
          );
        })}
      </ul>

      <div className="border-t border-[var(--sc-border)] p-2">
        <button
          type="button"
          onClick={toggleCollapsed}
          aria-label={collapsed ? 'Expand sidebar' : 'Collapse sidebar'}
          className={cn(
            'flex w-full items-center gap-3 rounded-md px-3 py-2 text-sm text-[var(--sc-text-muted)] transition-colors hover:bg-[var(--sc-surface-2)] hover:text-[var(--sc-text)] focus-visible:outline-2 focus-visible:outline-[var(--sc-focus)]',
            collapsed && 'justify-center px-0',
          )}
        >
          {collapsed ? <PanelLeftOpen size={17} aria-hidden /> : <PanelLeftClose size={17} aria-hidden />}
          {!collapsed && <span>Collapse</span>}
        </button>
      </div>
    </nav>
  );
}
