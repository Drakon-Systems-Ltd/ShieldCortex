'use client';

import Link from 'next/link';
import { usePathname } from 'next/navigation';
import { Menu, Pin, PinOff, X } from 'lucide-react';
import { cn } from '@/lib/utils';
import { NAV_ITEMS } from '@/components/layout/route-config';
import { useDashboardStore } from '@/lib/store';
import { useVersion } from '@/hooks/useMemories';
import { useCallback, useState, useSyncExternalStore } from 'react';

function isActive(pathname: string, href: string): boolean {
  if (href === '/overview') return pathname === '/overview' || pathname === '/';
  return pathname === href || pathname.startsWith(`${href}/`);
}

let _wsConnected = false;
const _wsListeners = new Set<() => void>();
function _notifyWs() { _wsListeners.forEach((l) => l()); }

function checkWs() {
  try {
    const ws = new WebSocket('ws://localhost:3001/ws/events');
    ws.onopen = () => { _wsConnected = true; _notifyWs(); ws.close(); };
    ws.onerror = () => { _wsConnected = false; _notifyWs(); };
  } catch { _wsConnected = false; _notifyWs(); }
}

if (typeof window !== 'undefined') {
  checkWs();
  setInterval(checkWs, 15000);
}

function useWsConnected() {
  const subscribe = useCallback((cb: () => void) => {
    _wsListeners.add(cb);
    return () => { _wsListeners.delete(cb); };
  }, []);
  return useSyncExternalStore(subscribe, () => _wsConnected, () => false);
}

export function SidebarTerminal() {
  const pathname = usePathname();
  const { sidebarPinned, toggleSidebarPinned } = useDashboardStore();
  const [hovered, setHovered] = useState(false);
  const [mobileOpenFor, setMobileOpenFor] = useState<string | null>(null);
  const mobileOpen = mobileOpenFor === pathname;
  const wsConnected = useWsConnected();
  const { data: versionData } = useVersion();
  const expanded = sidebarPinned || hovered || mobileOpen;

  return (
    <>
      {/* Mobile hamburger */}
      <button
        type="button"
        onClick={() => setMobileOpenFor(pathname)}
        className="fixed left-3 top-3 z-50 flex h-10 w-10 items-center justify-center rounded-md bg-[var(--term-surface)] border border-[var(--term-border)] text-[var(--term-text-muted)] md:hidden"
        aria-label="Open navigation"
      >
        <Menu size={18} />
      </button>

      {mobileOpen && (
        <button
          type="button"
          aria-label="Close navigation backdrop"
          className="fixed inset-0 z-40 bg-black/50 md:hidden"
          onClick={() => setMobileOpenFor(null)}
        />
      )}

      <aside
        className={cn(
          'z-50 flex shrink-0 flex-col border-r border-[var(--term-border)] bg-[var(--term-bg)] transition-[width] duration-200',
          'fixed inset-y-0 left-0 md:relative',
          mobileOpen ? 'translate-x-0' : '-translate-x-full md:translate-x-0',
          expanded ? 'w-60' : 'w-14',
        )}
        onMouseEnter={() => setHovered(true)}
        onMouseLeave={() => setHovered(false)}
      >
        {/* Header — terminal prompt */}
        <div className="flex h-12 items-center gap-2 border-b border-[var(--term-border)] px-3">
          <span className="text-[var(--term-electric-fg)] font-mono text-sm" aria-hidden>$</span>
          <div className={cn('overflow-hidden whitespace-nowrap transition-opacity duration-200', expanded ? 'opacity-100' : 'opacity-0')}>
            <span className="font-mono text-sm text-[var(--term-text)]">shieldcortex</span>
            <span className="cli-cursor text-[var(--term-electric-fg)] ml-1" aria-hidden />
          </div>
          {mobileOpen && (
            <button
              type="button"
              onClick={() => setMobileOpenFor(null)}
              className="ml-auto text-[var(--term-text-muted)] hover:text-[var(--term-text)] md:hidden"
              aria-label="Close navigation"
            >
              <X size={18} />
            </button>
          )}
        </div>

        {/* Nav items — mono list, `>` prefix on active */}
        <nav className="flex-1 overflow-y-auto py-3 px-1.5 font-mono text-sm" role="navigation" aria-label="Main navigation">
          {NAV_ITEMS.map((item) => {
            const Icon = item.icon;
            const active = isActive(pathname, item.href);
            return (
              <Link
                key={item.href}
                href={item.href}
                aria-current={active ? 'page' : undefined}
                className={cn(
                  'group flex items-center gap-2 rounded-sm px-2 py-1.5 transition-colors',
                  'focus-visible:outline-1 focus-visible:outline-offset-1 focus-visible:outline-[var(--term-electric)]',
                  active
                    ? 'text-[var(--term-electric-fg)] bg-[var(--term-surface-2)]'
                    : 'text-[var(--term-text-muted)] hover:text-[var(--term-text)]',
                )}
              >
                <span
                  className={cn('w-3 shrink-0 select-none', active ? 'text-[var(--term-electric-fg)]' : 'text-transparent')}
                  aria-hidden
                >
                  {active ? '>' : ' '}
                </span>
                <Icon size={14} className="shrink-0" aria-hidden />
                <span className={cn('overflow-hidden whitespace-nowrap transition-opacity duration-200', expanded ? 'opacity-100' : 'opacity-0')}>
                  {item.label}
                </span>
              </Link>
            );
          })}
        </nav>

        {/* Bottom — pin toggle, ws status, version */}
        <div className="space-y-1 border-t border-[var(--term-border)] px-1.5 py-2 font-mono">
          {expanded && (
            <button
              type="button"
              onClick={toggleSidebarPinned}
              className="hidden w-full items-center gap-2 rounded-sm px-2 py-1.5 text-xs text-[var(--term-text-muted)] transition-colors hover:text-[var(--term-text)] md:flex"
              aria-label={sidebarPinned ? 'Unpin sidebar' : 'Pin sidebar'}
            >
              {sidebarPinned ? <PinOff size={12} /> : <Pin size={12} />}
              <span>{sidebarPinned ? 'unpin' : 'pin'}</span>
            </button>
          )}

          <div className="flex items-center gap-2 px-2 py-1 text-[11px]">
            <span
              className={cn(
                'h-1.5 w-1.5 shrink-0 rounded-full',
                wsConnected ? 'bg-[var(--term-neon)] pulse-cyan' : 'bg-[var(--term-danger)] pulse-coral',
              )}
              aria-label={wsConnected ? 'Real-time connected' : 'Real-time disconnected'}
            />
            <span className={cn('overflow-hidden whitespace-nowrap text-[var(--term-text-muted)] transition-opacity duration-200', expanded ? 'opacity-100' : 'opacity-0')}>
              ws={wsConnected ? 'connected' : 'down'}
            </span>
          </div>

          <div className={cn('overflow-hidden whitespace-nowrap px-2 text-[10px] text-[var(--term-text-faint)] transition-opacity duration-200', expanded ? 'opacity-100' : 'opacity-0')}>
            v{versionData?.version ?? '...'}
          </div>
        </div>
      </aside>
    </>
  );
}
