'use client';

import Link from 'next/link';
import { usePathname } from 'next/navigation';
import { MemoryWebSocketProvider } from '@/components/MemoryWebSocketProvider';
import { Sidebar } from '@/components/layout/Sidebar';
import { TopBar } from '@/components/layout/TopBar';
import { NAV_ITEMS } from '@/components/layout/route-config';
import { cn } from '@/lib/utils';

/**
 * v2 shell: one shell, one token set. Sidebar (collapsible) · top bar
 * (project filter, ⌘K palette, connection dot, theme toggle) · content column
 * capped at 1400px with 24px gutters. One authenticated WebSocket for the
 * whole dashboard, scoped here so it never opens on bare/auth routes.
 */
export function AppShell({ children }: { children: React.ReactNode }) {
  return (
    <MemoryWebSocketProvider>
      <div className="flex h-dvh w-full overflow-hidden bg-[var(--sc-bg)] text-[var(--sc-text)]">
        <div className="hidden md:flex">
          <Sidebar />
        </div>
        <div className="flex min-w-0 flex-1 flex-col">
          <TopBar />
          <main className="min-w-0 flex-1 overflow-auto">
            <div className="mx-auto w-full max-w-[1400px] px-6 py-6">{children}</div>
          </main>
          {/* Mobile nav: the sidebar collapses to a bottom bar below md. */}
          <MobileNav />
        </div>
      </div>
    </MemoryWebSocketProvider>
  );
}

function MobileNav() {
  const pathname = usePathname();
  const activeHref = NAV_ITEMS
    .filter((n) => pathname === n.href || pathname.startsWith(n.href + '/'))
    .sort((a, b) => b.href.length - a.href.length)[0]?.href;

  return (
    <nav aria-label="Primary" className="flex shrink-0 border-t border-[var(--sc-border)] bg-[var(--sc-surface)] md:hidden">
      {NAV_ITEMS.map(({ href, label, icon: Icon }) => {
        const active = href === activeHref;
        return (
          <Link
            key={href}
            href={href}
            aria-current={active ? 'page' : undefined}
            className={cn(
              'flex flex-1 flex-col items-center gap-0.5 py-2 text-[10px] focus-visible:outline-2 focus-visible:outline-[var(--sc-focus)]',
              active ? 'text-[var(--sc-primary)]' : 'text-[var(--sc-text-muted)]',
            )}
          >
            <Icon size={17} aria-hidden />
            <span>{label}</span>
          </Link>
        );
      })}
    </nav>
  );
}
