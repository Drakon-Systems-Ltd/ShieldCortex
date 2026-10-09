'use client';

import Link from 'next/link';
import { usePathname } from 'next/navigation';
import { PanelLeftClose, PanelLeftOpen } from 'lucide-react';
import { activeNavHref, visibleNavItems } from '@/components/layout/route-config';
import { useDashboardStore } from '@/lib/store';
import { Logo } from '@/components/ds/Logo';
import { useNeedsYou } from '@/hooks/useNeedsYou';
import { needsYouBadge } from '@/lib/needs-you';
import { cn } from '@/lib/utils';

/**
 * v2 sidebar: the five-item spine (Opus §2), collapsible to icons (240px ↔
 * 56px). Section tabs live inside pages, not here. Active state = the longest
 * matching href (or an item's `also` page) so /memory/replay lights Memory and
 * /xray lights Protection. Needs you carries a count of confirmed waiting items:
 * "N" only when exact, "N+" when a list is a floor or could not be refreshed,
 * "?" when nothing is confirmed and a list failed (#692).
 */
export function Sidebar() {
  const pathname = usePathname();
  const { sidebarPinned: collapsed, toggleSidebarPinned: toggleCollapsed, projectFilter } = useDashboardStore();

  const navItems = visibleNavItems();
  const activeHref = activeNavHref(pathname, navItems);
  const badge = needsYouBadge(useNeedsYou(projectFilter));

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
          <span className="min-w-0 leading-tight">
            <span className="block truncate text-base font-semibold text-[var(--sc-text)]">ShieldCortex</span>
            <span className="block truncate text-xs text-[var(--sc-text-muted)]">On this computer</span>
          </span>
        )}
      </div>

      <ul className="flex-1 space-y-1 overflow-y-auto p-2">
        {navItems.map(({ href, label, icon: Icon }) => {
          const active = href === activeHref;
          const count = href === '/needs-you' ? badge : undefined;
          return (
            <li key={href}>
              <Link
                href={href}
                aria-current={active ? 'page' : undefined}
                aria-label={count ? `${label}, ${count.label}` : undefined}
                title={collapsed ? label : undefined}
                className={cn(
                  'relative flex items-center gap-3 rounded-md px-3 py-2.5 text-sm transition-colors focus-visible:outline-2 focus-visible:outline-[var(--sc-focus)]',
                  collapsed && 'justify-center px-0',
                  active
                    ? 'bg-[var(--sc-primary-soft)] font-semibold text-[var(--sc-text)] shadow-[inset_3px_0_0_var(--sc-primary)]'
                    : 'text-[var(--sc-text-dim)] hover:bg-[var(--sc-surface-2)] hover:text-[var(--sc-text)]',
                )}
              >
                <Icon size={18} aria-hidden className={cn('shrink-0', active && 'text-[var(--sc-primary)]')} />
                {!collapsed && <span className="truncate">{label}</span>}
                {count !== undefined && (
                  <span
                    aria-hidden
                    className={cn(
                      'rounded-full bg-[var(--sc-warn-soft)] px-2 text-xs font-semibold tabular-nums text-[var(--sc-warn)]',
                      collapsed ? 'absolute right-0.5 top-0.5 px-1' : 'ml-auto',
                    )}
                  >
                    {count.text}
                  </span>
                )}
              </Link>
            </li>
          );
        })}
      </ul>

      <div className="border-t border-[var(--sc-border)] p-2">
        {!collapsed && (
          <p className="px-3 pb-2 pt-1 text-xs text-[var(--sc-text-muted)]">Data stays on this computer</p>
        )}
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
