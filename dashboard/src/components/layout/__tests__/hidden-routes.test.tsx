import fs from 'fs';
import path from 'path';
import { act, render, renderHook, screen, within } from '@testing-library/react';
import {
  HIDDEN_ROUTES,
  hiddenRouteRedirects,
  isHiddenRoute,
  visibleTabs,
  type HiddenRoute,
} from '@/components/layout/hidden-routes';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { NAV_ITEMS, activeNavHref, visibleNavItems } from '@/components/layout/route-config';
import { PROTECTION_TAB_DEFS, protectionTabHref, protectionTabs } from '@/components/protection/protection-tabs';
import { MEMORY_TAB_DEFS, memoryTabHref, memoryTabs } from '@/components/memory/memory-tabs';
import nextConfig from '../../../../next.config';

const mockReplace = jest.fn();
const mockPush = jest.fn();
let mockPathname = '/overview';
let mockSearch = '';
jest.mock('next/navigation', () => ({
  usePathname: () => mockPathname,
  useSearchParams: () => new URLSearchParams(mockSearch),
  useRouter: () => ({ replace: mockReplace, push: mockPush, prefetch: jest.fn(), back: jest.fn() }),
}));
// Lets a test hide a route for the components under test, as a config edit would.
let mockHidden: HiddenRoute[] | null = null;
jest.mock('@/components/layout/hidden-routes', () => {
  const actual = jest.requireActual('@/components/layout/hidden-routes');
  return {
    ...actual,
    get HIDDEN_ROUTES() {
      return mockHidden ?? actual.HIDDEN_ROUTES;
    },
  };
});
jest.mock('@/lib/store', () => ({
  useDashboardStore: () => ({ sidebarPinned: false, toggleSidebarPinned: jest.fn(), projectFilter: null }),
}));

// The sidebar's Needs you count reads three queues; fetch never settles here,
// so the badge stays off and the nav renders as it would before data lands.
beforeAll(() => {
  global.fetch = jest.fn(() => new Promise<Response>(() => {})) as jest.Mock;
});
function withQuery(ui: React.ReactElement) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return <QueryClientProvider client={client}>{ui}</QueryClientProvider>;
}

const APP_DIR = path.join(__dirname, '../../../app/(dashboard)');
const pageExists = (route: string) => fs.existsSync(path.join(APP_DIR, route, 'page.tsx'));
const KEPT_PAGES = ['/overview', '/needs-you', '/memory', '/memory/replay', '/protection', '/xray', '/settings'];

describe('hidden-routes config', () => {
  it('sends every hidden route to a kept page that exists', () => {
    for (const r of HIDDEN_ROUTES) {
      const target = new URL(r.redirectTo, 'http://x');
      expect(pageExists(target.pathname)).toBe(true);
      expect(isHiddenRoute(target.pathname, target.searchParams.get('tab'))).toBe(false);
      expect(r.reason.length).toBeGreaterThan(0);
    }
  });

  it('never hides a kept page', () => {
    for (const p of KEPT_PAGES) {
      expect(pageExists(p)).toBe(true);
      expect(isHiddenRoute(p)).toBe(false);
    }
  });

  it('scopes tab entries to that tab only', () => {
    const hidden: HiddenRoute[] = [{ path: '/protection', tab: 'intercepts', redirectTo: '/protection', reason: 't' }];
    expect(isHiddenRoute('/protection', 'intercepts', hidden)).toBe(true);
    expect(isHiddenRoute('/protection', 'audit', hidden)).toBe(false);
    expect(isHiddenRoute('/protection', null, hidden)).toBe(false);
    expect(visibleTabs('/protection', [{ id: 'audit' }, { id: 'intercepts' }], hidden)).toEqual([{ id: 'audit' }]);
  });
});

describe('hidden URLs redirect', () => {
  it('next.config redirects() covers every path-level hidden route, temporarily', async () => {
    const redirects = await nextConfig.redirects!();
    expect(redirects).toEqual(hiddenRouteRedirects());
    for (const r of HIDDEN_ROUTES.filter((h) => !h.tab)) {
      expect(redirects).toContainEqual({ source: r.path, destination: r.redirectTo, permanent: false });
    }
  });

  it('emits no server redirect for a tab-scoped entry (the page falls back instead)', () => {
    expect(hiddenRouteRedirects([{ path: '/xray', tab: 'watch', redirectTo: '/xray', reason: 't' }])).toEqual([]);
  });
});

describe('the five-item spine (Opus design §2)', () => {
  it('nav is exactly Home · Needs you · Memory · Protection · Settings', () => {
    expect(NAV_ITEMS.map((n) => n.label)).toEqual(['Home', 'Needs you', 'Memory', 'Protection', 'Settings']);
    for (const n of NAV_ITEMS) expect(pageExists(n.href)).toBe(true);
  });

  it('the sidebar renders exactly those five links', async () => {
    const { Sidebar } = await import('@/components/layout/Sidebar');
    render(withQuery(<Sidebar />));
    const nav = screen.getByRole('navigation', { name: 'Primary' });
    expect(within(nav).getAllByRole('link').map((a) => a.textContent)).toEqual(['Home', 'Needs you', 'Memory', 'Protection', 'Settings']);
  });

  it('pages that moved under a section light that section', () => {
    expect(activeNavHref('/xray', NAV_ITEMS)).toBe('/protection');
    expect(activeNavHref('/memory/replay', NAV_ITEMS)).toBe('/memory');
    expect(activeNavHref('/needs-you', NAV_ITEMS)).toBe('/needs-you');
    expect(activeNavHref('/overview', NAV_ITEMS)).toBe('/overview');
  });

  it('every route that left the nav is still reachable from its section tab bar', () => {
    expect(protectionTabs().map((t) => t.id)).toEqual(PROTECTION_TAB_DEFS.map((t) => t.id));
    expect(protectionTabHref('scanner')).toBe('/xray');
    expect(protectionTabHref('status')).toBe('/protection');
    expect(protectionTabHref('quarantine')).toBe('/protection?tab=quarantine');
    expect(memoryTabHref('replay')).toBe('/memory/replay');
  });

  it('old v1 URLs still redirect to a kept page (no route lost)', async () => {
    const redirects = await nextConfig.redirects!();
    expect(redirects.map((r) => r.source).sort()).toEqual([
      '/admin', '/cloud', '/memory/capture', '/memory/graph', '/memory/recall', '/memory/review', '/memory/timeline',
      '/protection/audit', '/protection/intercepts', '/protection/iron-dome', '/protection/policies', '/protection/quarantine',
      '/supply-chain', '/supply-chain/xray',
    ]);
    for (const r of redirects) expect(pageExists(new URL(r.destination, 'http://x').pathname)).toBe(true);
  });
});

describe('hidden routes are absent from nav', () => {
  it('visibleNavItems drops a hidden top-level route', () => {
    expect(visibleNavItems()).toEqual(NAV_ITEMS);
    const hidden: HiddenRoute[] = [{ path: '/needs-you', redirectTo: '/overview', reason: 't' }];
    expect(visibleNavItems(hidden).map((n) => n.href)).not.toContain('/needs-you');
  });

  it('the sidebar links no hidden route', async () => {
    const { Sidebar } = await import('@/components/layout/Sidebar');
    render(withQuery(<Sidebar />));
    const nav = screen.getByRole('navigation', { name: 'Primary' });
    const hrefs = within(nav).getAllByRole('link').map((a) => a.getAttribute('href'));
    expect(hrefs).toEqual(NAV_ITEMS.map((n) => n.href));
    for (const r of HIDDEN_ROUTES) expect(hrefs).not.toContain(r.path);
  });

  it('the sidebar drops an item once its route is hidden', async () => {
    const { Sidebar } = await import('@/components/layout/Sidebar');
    mockHidden = [{ path: '/needs-you', redirectTo: '/overview', reason: 't' }];
    try {
      render(withQuery(<Sidebar />));
    } finally {
      mockHidden = null;
    }
    expect(screen.queryByRole('link', { name: /Needs you/ })).not.toBeInTheDocument();
    expect(screen.getByRole('link', { name: /Memory/ })).toBeInTheDocument();
  });
});

describe('Memory tabs (Replay consolidated into the Memory tab bar)', () => {
  it('lists Replay and routes it to its own page', () => {
    expect(memoryTabs().map((t) => t.id)).toEqual(MEMORY_TAB_DEFS.map((t) => t.id));
    expect(memoryTabs().map((t) => t.id)).toContain('replay');
    expect(memoryTabHref('replay')).toBe('/memory/replay');
    expect(memoryTabHref('library')).toBe('/memory');
    expect(memoryTabHref('graph')).toBe('/memory?tab=graph');
  });
});

describe('useUrlTab', () => {
  beforeEach(() => {
    mockReplace.mockClear();
    mockPathname = '/protection';
  });

  async function renderTab() {
    const { useUrlTab } = await import('@/hooks/useUrlTab');
    const { result } = renderHook(() =>
      useUrlTab('/protection', ['status', 'audit', 'intercepts'] as const, 'status', { dome: 'status' }),
    );
    render(<span data-testid="tab">{result.current[0]}</span>);
    return () => result.current;
  }

  it('honours a valid deep link', async () => {
    mockSearch = 'tab=audit';
    await renderTab();
    expect(screen.getByTestId('tab')).toHaveTextContent('audit');
  });

  it('falls back to the default tab for an unknown id', async () => {
    mockSearch = 'tab=nope';
    await renderTab();
    expect(screen.getByTestId('tab')).toHaveTextContent('status');
  });

  it('rewrites the URL on click so a deep link does not pin the tab', async () => {
    mockSearch = 'tab=audit';
    const api = await renderTab();
    act(() => api()[1]('intercepts'));
    expect(mockReplace).toHaveBeenCalledWith('/protection?tab=intercepts', { scroll: false });
    act(() => api()[1]('status'));
    expect(mockReplace).toHaveBeenLastCalledWith('/protection', { scroll: false });
  });
});
