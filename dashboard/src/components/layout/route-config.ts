import type { LucideIcon } from 'lucide-react';
import { HIDDEN_ROUTES, isHiddenRoute, type HiddenRoute } from '@/components/layout/hidden-routes';
import {
  Database,
  Home,
  Inbox,
  Settings,
  Shield,
} from 'lucide-react';

export interface NavItem {
  href: string;
  label: string;
  icon: LucideIcon;
  /** Other kept pages that live under this item and light it when open. */
  also?: readonly string[];
}

// The five-item spine shared with Cloud (Opus design §2): Home · Needs you ·
// Memory · Protection · Settings. Replay lives under Memory and the skill &
// package scanner (/xray) under Protection; both keep their own routes and
// are reached from their section's tab bar.
export const NAV_ITEMS: NavItem[] = [
  { href: '/overview', label: 'Home', icon: Home },
  { href: '/needs-you', label: 'Needs you', icon: Inbox },
  { href: '/memory', label: 'Memory', icon: Database },
  { href: '/protection', label: 'Protection', icon: Shield, also: ['/xray'] },
  { href: '/settings', label: 'Settings', icon: Settings },
];

const under = (pathname: string, href: string) => pathname === href || pathname.startsWith(href + '/');

/** The nav item to mark `aria-current` for `pathname`: the longest match. */
export function activeNavHref(pathname: string, items: readonly NavItem[]): string | undefined {
  let best: { href: string; len: number } | undefined;
  for (const n of items) {
    for (const p of [n.href, ...(n.also ?? [])]) {
      if (under(pathname, p) && (!best || p.length > best.len)) best = { href: n.href, len: p.length };
    }
  }
  return best?.href;
}

/** Nav items minus anything in the hidden-routes config. */
export function visibleNavItems(hidden: readonly HiddenRoute[] = HIDDEN_ROUTES): NavItem[] {
  return NAV_ITEMS.filter((n) => !isHiddenRoute(n.href, null, hidden));
}
