'use client';

import Link from 'next/link';
import { usePathname } from 'next/navigation';
import { Menu, Pin, PinOff, X } from 'lucide-react';
import { cn } from '@/lib/utils';
import { Logo } from '@/components/ds/Logo';
import { NAV_ITEMS } from '@/components/layout/route-config';
import { useDashboardStore } from '@/lib/store';
import { useVersion } from '@/hooks/useMemories';
import { useWebSocketStatus } from '@/components/MemoryWebSocketProvider';
import { useState } from 'react';

function isActive(pathname: string, href: string): boolean {
  if (href === '/overview') return pathname === '/overview' || pathname === '/';
  return pathname === href || pathname.startsWith(`${href}/`);
}

export function SidebarGlass() {
  const pathname = usePathname();
  const { sidebarPinned, toggleSidebarPinned } = useDashboardStore();
  const [hovered, setHovered] = useState(false);
  const [mobileOpenFor, setMobileOpenFor] = useState<string | null>(null);
  const mobileOpen = mobileOpenFor === pathname;
  // Reflects the real shared connection — the old module-level checker opened
  // its own token-less socket and was permanently stuck "Disconnected" (4401).
  const { isConnected: wsConnected } = useWebSocketStatus();
  const { data: versionData } = useVersion();
  const expanded = sidebarPinned || hovered || mobileOpen;

  return (
    <>
      {/* Mobile hamburger — visible only on small screens */}
      <button
        onClick={() => setMobileOpenFor(pathname)}
        className="fixed left-3 top-3 z-50 flex h-10 w-10 items-center justify-center rounded-xl bg-[var(--sc-bg-surface)] border border-[var(--sc-border)] text-[var(--sc-text-secondary)] md:hidden"
        aria-label="Open navigation"
      >
        <Menu size={18} />
      </button>

      {/* Mobile backdrop */}
      {mobileOpen && (
        <div
          className="fixed inset-0 z-40 bg-black/50 backdrop-blur-sm md:hidden"
          onClick={() => setMobileOpenFor(null)}
        />
      )}

      {/* Sidebar */}
      <aside
        className={cn(
          'z-50 flex shrink-0 flex-col border-r border-[var(--sc-border)] bg-[var(--sc-bg-deep)] transition-all duration-300',
          // Mobile: fixed overlay, hidden by default
          'fixed inset-y-0 left-0 md:relative',
          mobileOpen ? 'translate-x-0' : '-translate-x-full md:translate-x-0',
          expanded ? 'w-60' : 'w-16',
        )}
        onMouseEnter={() => setHovered(true)}
        onMouseLeave={() => setHovered(false)}
      >
        {/* Logo */}
        <div className="flex h-16 items-center gap-3 border-b border-[var(--sc-border)] px-4">
          <Logo size={44} className="shrink-0" />
          <div className={cn('overflow-hidden whitespace-nowrap transition-all duration-300', expanded ? 'w-auto opacity-100' : 'w-0 opacity-0')}>
            <div className="text-[11px] font-semibold uppercase tracking-[0.2em] text-[var(--sc-coral)]">ShieldCortex</div>
            <div className="text-xs text-[var(--sc-text-muted)]">Dashboard</div>
          </div>
          {/* Mobile close button */}
          {mobileOpen && (
            <button
              onClick={() => setMobileOpenFor(null)}
              className="ml-auto text-[var(--sc-text-muted)] hover:text-[var(--sc-text-secondary)] md:hidden"
              aria-label="Close navigation"
            >
              <X size={18} />
            </button>
          )}
        </div>

        {/* Nav items */}
        <nav className="flex-1 space-y-1 px-2 py-4" role="navigation" aria-label="Main navigation">
          {NAV_ITEMS.map((item) => {
            const Icon = item.icon;
            const active = isActive(pathname, item.href);
            return (
              <Link
                key={item.href}
                href={item.href}
                aria-current={active ? 'page' : undefined}
                className={cn(
                  'relative flex items-center gap-3 rounded-xl px-3 py-2.5 transition-all duration-200 focus-visible:outline-2 focus-visible:outline-offset-2 focus-visible:outline-[var(--sc-cyan)]',
                  active
                    ? 'bg-[var(--sc-surface-interactive)] text-[var(--sc-text-primary)]'
                    : 'text-[var(--sc-text-muted)] hover:bg-[var(--sc-surface-interactive)] hover:text-[var(--sc-text-secondary)]',
                )}
              >
                {active && (
                  <div className="absolute left-0 top-1/2 h-5 w-0.5 -translate-y-1/2 rounded-r bg-[var(--sc-coral)]" />
                )}
                <Icon size={18} className={cn('shrink-0', active && 'text-[var(--sc-coral)]')} />
                <span className={cn(
                  'overflow-hidden whitespace-nowrap text-sm font-medium transition-all duration-300',
                  expanded ? 'w-auto opacity-100' : 'w-0 opacity-0',
                )}>
                  {item.label}
                </span>
              </Link>
            );
          })}
        </nav>

        {/* Bottom section */}
        <div className="space-y-2 border-t border-[var(--sc-border)] px-2 py-3">
          {/* Pin toggle */}
          {expanded && (
            <button
              onClick={toggleSidebarPinned}
              className="hidden w-full items-center gap-3 rounded-xl px-3 py-2 text-[var(--sc-text-muted)] transition-colors hover:bg-[var(--sc-surface-interactive)] hover:text-[var(--sc-text-secondary)] md:flex"
              aria-label={sidebarPinned ? 'Unpin sidebar' : 'Pin sidebar'}
            >
              {sidebarPinned ? <PinOff size={16} /> : <Pin size={16} />}
              <span className="text-xs">{sidebarPinned ? 'Unpin' : 'Pin sidebar'}</span>
            </button>
          )}

          {/* WebSocket status */}
          <div className="flex items-center gap-3 px-3 py-1">
            <span
              className={cn(
                'h-2 w-2 shrink-0 rounded-full',
                wsConnected ? 'bg-[var(--sc-cyan)] pulse-cyan' : 'bg-[var(--sc-coral)] pulse-coral',
              )}
              aria-label={wsConnected ? 'Real-time connected' : 'Real-time disconnected'}
            />
            <span className={cn(
              'overflow-hidden whitespace-nowrap text-[11px] text-[var(--sc-text-muted)] transition-all duration-300',
              expanded ? 'w-auto opacity-100' : 'w-0 opacity-0',
            )}>
              {wsConnected ? 'Connected' : 'Disconnected'}
            </span>
          </div>
          <div className={cn(
            'overflow-hidden whitespace-nowrap px-3 font-mono text-[10px] text-[var(--sc-text-muted)] transition-all duration-300',
            expanded ? 'opacity-100' : 'h-0 opacity-0',
          )}>
            v{versionData?.version ?? '...'}
          </div>
        </div>
      </aside>
    </>
  );
}
