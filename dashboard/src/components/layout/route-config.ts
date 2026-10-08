import type { LucideIcon } from 'lucide-react';
import { HIDDEN_ROUTES, isHiddenRoute, type HiddenRoute } from '@/components/layout/hidden-routes';
import {
  Database,
  Home,
  ScanSearch,
  Settings,
  Shield,
} from 'lucide-react';

export interface NavItem {
  href: string;
  label: string;
  icon: LucideIcon;
}

// Five top-level sections (brief §4). Replay lives under Memory
// (/memory/replay stays routable; it is reached from the Memory tabs).
export const NAV_ITEMS: NavItem[] = [
  { href: '/overview', label: 'Overview', icon: Home },
  { href: '/memory', label: 'Memory', icon: Database },
  { href: '/protection', label: 'Protection', icon: Shield },
  { href: '/xray', label: 'X-Ray', icon: ScanSearch },
  { href: '/settings', label: 'Settings', icon: Settings },
];

/** Nav items minus anything in the hidden-routes config. */
export function visibleNavItems(hidden: readonly HiddenRoute[] = HIDDEN_ROUTES): NavItem[] {
  return NAV_ITEMS.filter((n) => !isHiddenRoute(n.href, null, hidden));
}
