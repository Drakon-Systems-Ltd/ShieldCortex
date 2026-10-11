/**
 * The single hidden-routes config for the local dashboard.
 *
 * A hidden route is taken out of navigation (sidebar, mobile bar, page tab
 * bars) and a direct URL to it is redirected server-side (next.config.ts
 * `redirects()`) to the nearest kept page. The page code stays in the tree:
 * to un-hide something, delete its line here.
 *
 * `tab` scopes an entry to one tab of a tabbed page (`/protection?tab=x`);
 * without it the whole path is hidden. A hidden tab falls back to the page's
 * default tab rather than redirecting (see hiddenRouteRedirects).
 *
 * Dependency-free on purpose: next.config.ts imports this file at build time.
 */
export interface HiddenRoute {
  path: string;
  tab?: string;
  redirectTo: string;
  reason: string;
}

// The v1 per-page URLs. v2 folded each one into a tab of a kept page
// (CHANGELOG "Dashboard v2"); they stay reachable as redirects only so old
// bookmarks and docs links land somewhere real.
const V1_URL = 'v1 page folded into a v2 tab (CHANGELOG: Dashboard v2)';

export const HIDDEN_ROUTES: readonly HiddenRoute[] = [
  { path: '/admin', redirectTo: '/settings?tab=admin', reason: V1_URL },
  { path: '/cloud', redirectTo: '/settings?tab=cloud', reason: V1_URL },
  { path: '/memory/capture', redirectTo: '/memory', reason: 'capture tab retired; folded into Library' },
  { path: '/memory/graph', redirectTo: '/memory?tab=graph', reason: V1_URL },
  { path: '/memory/recall', redirectTo: '/memory?tab=recall', reason: V1_URL },
  { path: '/memory/review', redirectTo: '/memory?tab=review', reason: V1_URL },
  { path: '/memory/timeline', redirectTo: '/memory?tab=timeline', reason: V1_URL },
  { path: '/protection/audit', redirectTo: '/protection?tab=audit', reason: V1_URL },
  { path: '/protection/intercepts', redirectTo: '/protection?tab=intercepts', reason: V1_URL },
  { path: '/protection/iron-dome', redirectTo: '/protection', reason: 'Iron Dome tab renamed Status (the default tab)' },
  { path: '/protection/policies', redirectTo: '/protection?tab=policies', reason: V1_URL },
  { path: '/protection/quarantine', redirectTo: '/protection?tab=quarantine', reason: V1_URL },
  { path: '/supply-chain', redirectTo: '/xray', reason: 'Supply Chain section folded into X-Ray' },
  { path: '/supply-chain/xray', redirectTo: '/xray', reason: 'duplicate of /xray' },
];

/** True when `path` (optionally one `tab` of it) is hidden. */
export function isHiddenRoute(path: string, tab?: string | null, hidden: readonly HiddenRoute[] = HIDDEN_ROUTES): boolean {
  return hidden.some((r) => r.path === path && (r.tab === undefined || r.tab === (tab ?? undefined)));
}

/** Drop hidden tabs from a page's tab bar. */
export function visibleTabs<T extends { id: string }>(path: string, tabs: T[], hidden: readonly HiddenRoute[] = HIDDEN_ROUTES): T[] {
  return tabs.filter((t) => !hidden.some((r) => r.path === path && r.tab === t.id));
}

interface NextRedirect {
  source: string;
  destination: string;
  permanent: false;
}

/**
 * next.config.ts `redirects()` entries: temporary, so un-hiding takes effect
 * at once. Path-level entries only — a hidden tab is dropped from its page's
 * tab bar and its `?tab=` value is treated as unknown, so the page falls back
 * to its default tab (Next would pass the original `?tab=` through a redirect).
 */
export function hiddenRouteRedirects(hidden: readonly HiddenRoute[] = HIDDEN_ROUTES): NextRedirect[] {
  return hidden
    .filter((r) => r.tab === undefined)
    .map((r) => ({ source: r.path, destination: r.redirectTo, permanent: false as const }));
}
