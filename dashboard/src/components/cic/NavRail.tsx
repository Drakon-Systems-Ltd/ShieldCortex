'use client';

import { useState } from 'react';
import Link from 'next/link';
import { usePathname } from 'next/navigation';
import { NAV_ITEMS } from '@/components/layout/route-config';
import { useWebSocketStatus } from '@/components/MemoryWebSocketProvider';
import { REGIONS, type CicRegion } from '@/lib/cic/regions';

// Which cortical region each nav destination belongs to (drives the active glow).
const HREF_REGION: Record<string, CicRegion> = {
  '/overview': 'memory',
  '/memory': 'memory',
  '/memory/replay': 'integrity',
  '/protection': 'defence',
  '/xray': 'defence',
  '/settings': 'integrity',
};

function regionFor(href: string): CicRegion {
  return HREF_REGION[href] ?? 'memory';
}

/**
 * The CIC nav rail — the deleted terminal sidebar, reborn. Systems list with a
 * `▸` active marker glowing in the destination's cortical colour, collapsible to
 * an icon strip, with a live `link` status footer.
 */
export function NavRail() {
  const pathname = usePathname();
  const { isConnected } = useWebSocketStatus();
  const [collapsed, setCollapsed] = useState(false);

  return (
    <aside
      className={`flex shrink-0 flex-col border-r border-[var(--cic-border)] bg-[var(--cic-surface)]/60 font-mono transition-[width] duration-200 ${
        collapsed ? 'w-14' : 'w-56'
      }`}
    >
      <button
        type="button"
        onClick={() => setCollapsed((c) => !c)}
        className="flex h-11 items-center gap-2 px-4 text-left text-[var(--cic-text-muted)] hover:text-[var(--cic-text)]"
        aria-label={collapsed ? 'expand navigation' : 'collapse navigation'}
      >
        <span className="cic-bloom text-[var(--cic-cyan)]">$</span>
        {!collapsed && <span className="text-sm text-[var(--cic-text-dim)]">shieldcortex</span>}
      </button>

      <nav className="flex flex-1 flex-col gap-0.5 px-2 py-2">
        {NAV_ITEMS.map((item) => {
          const active = pathname === item.href || (item.href !== '/overview' && pathname.startsWith(item.href));
          const region = REGIONS[regionFor(item.href)];
          const Icon = item.icon;
          return (
            <Link
              key={item.href}
              href={item.href}
              title={item.label}
              className={`flex items-center gap-2 rounded px-2 py-1.5 text-sm transition-colors ${
                active
                  ? 'bg-[var(--cic-surface-2)] text-[var(--cic-text)]'
                  : 'text-[var(--cic-text-muted)] hover:text-[var(--cic-text)]'
              }`}
              style={active ? { color: `var(${region.token})` } : undefined}
            >
              <span className="w-2 shrink-0" style={active ? { color: `var(${region.token})` } : undefined}>
                {active ? '▸' : ''}
              </span>
              {Icon ? <Icon size={14} className="shrink-0" /> : null}
              {!collapsed && <span className="truncate">{item.label}</span>}
            </Link>
          );
        })}
      </nav>

      <div className="flex items-center gap-2 border-t border-[var(--cic-border)] px-4 py-2 text-xs">
        <span
          className={isConnected ? 'pulse-cyan' : 'pulse-coral'}
          style={{ color: isConnected ? 'var(--cic-cyan)' : 'var(--cic-coral)' }}
          aria-hidden
        >
          ◉
        </span>
        {!collapsed && (
          <span className="text-[var(--cic-text-faint)]">{isConnected ? 'link.up' : 'link.down'}</span>
        )}
      </div>
    </aside>
  );
}
