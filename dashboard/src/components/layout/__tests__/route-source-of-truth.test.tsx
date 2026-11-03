import fs from 'fs';
import path from 'path';
import { render, screen } from '@testing-library/react';
import type { HiddenRoute } from '@/components/layout/hidden-routes';
import { TabBar } from '@/components/ds/TabBar';

// #689: the hidden-routes config is the one place a hidden URL's redirect
// comes from. These tests resolve a URL the way Next does — next.config
// `redirects()` first, then a page file — so deleting a config line has to
// change the result, with no page stub quietly redirecting behind it.

// Test-owned seam: lets a test stand in an edited config for the default
// argument the call sites use (the real module reads its own constant).
let mockHidden: HiddenRoute[] | null = null;
jest.mock('@/components/layout/hidden-routes', () => {
  const actual = jest.requireActual('@/components/layout/hidden-routes');
  const list = () => mockHidden ?? actual.HIDDEN_ROUTES;
  return {
    ...actual,
    get HIDDEN_ROUTES() {
      return list();
    },
    isHiddenRoute: (p: string, tab?: string | null, hidden?: readonly HiddenRoute[]) => actual.isHiddenRoute(p, tab, hidden ?? list()),
    visibleTabs: (p: string, tabs: { id: string }[], hidden?: readonly HiddenRoute[]) => actual.visibleTabs(p, tabs, hidden ?? list()),
    hiddenRouteRedirects: (hidden?: readonly HiddenRoute[]) => actual.hiddenRouteRedirects(hidden ?? list()),
  };
});

const APP_DIR = path.join(__dirname, '../../../app');
const ROUTE_GROUP = path.join(APP_DIR, '(dashboard)');
const pageFor = (route: string) =>
  [path.join(ROUTE_GROUP, route, 'page.tsx'), path.join(APP_DIR, route, 'page.tsx')].find((f) => fs.existsSync(f));

type Resolution = { redirect: string } | { page: string } | { notFound: true };

/** What a request for `route` hits: a config redirect, a page, or a 404. */
async function resolve(route: string): Promise<Resolution> {
  const { default: nextConfig } = await import('../../../../next.config');
  const hit = (await nextConfig.redirects!()).find((r) => r.source === route);
  if (hit) return { redirect: hit.destination };
  const page = pageFor(route);
  return page ? { page } : { notFound: true };
}

afterEach(() => {
  mockHidden = null;
});

describe('hidden routes have one source of truth (#689)', () => {
  it("every hidden route resolves to exactly its config target", async () => {
    const { HIDDEN_ROUTES } = await import('@/components/layout/hidden-routes');
    expect(HIDDEN_ROUTES.length).toBeGreaterThan(0);
    for (const r of HIDDEN_ROUTES.filter((h) => !h.tab)) {
      expect(await resolve(r.path)).toEqual({ redirect: r.redirectTo });
    }
  });

  it('no page file sits behind a hidden path (nothing else can redirect it)', async () => {
    const { HIDDEN_ROUTES } = await import('@/components/layout/hidden-routes');
    for (const r of HIDDEN_ROUTES.filter((h) => !h.tab)) expect(pageFor(r.path)).toBeUndefined();
  });

  it('no page in the app calls redirect() itself, except the root landing page', () => {
    const offenders: string[] = [];
    const walk = (dir: string) => {
      for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
        const f = path.join(dir, e.name);
        if (e.isDirectory()) walk(f);
        else if (/\.tsx?$/.test(e.name) && /\bredirect\(/.test(fs.readFileSync(f, 'utf8'))) offenders.push(path.relative(APP_DIR, f));
      }
    };
    walk(APP_DIR);
    expect(offenders).toEqual(['page.tsx']);
  });

  it('deleting a config line stops that redirect and un-hides the path', async () => {
    const { HIDDEN_ROUTES, isHiddenRoute } = await import('@/components/layout/hidden-routes');
    const removed = HIDDEN_ROUTES.find((r) => r.path === '/protection/audit')!;
    expect(await resolve(removed.path)).toEqual({ redirect: removed.redirectTo });

    mockHidden = HIDDEN_ROUTES.filter((r) => r !== removed);
    expect(await resolve(removed.path)).toEqual({ notFound: true });
    expect(isHiddenRoute(removed.path)).toBe(false);
    // The rest of the config is untouched by the edit.
    for (const r of mockHidden) expect(await resolve(r.path)).toEqual({ redirect: r.redirectTo });
  });

  it('changing a config target changes where the route resolves', async () => {
    const { HIDDEN_ROUTES } = await import('@/components/layout/hidden-routes');
    mockHidden = HIDDEN_ROUTES.map((r) => (r.path === '/cloud' ? { ...r, redirectTo: '/overview' } : r));
    expect(await resolve('/cloud')).toEqual({ redirect: '/overview' });
  });
});

describe('tab-scoped hiding through a rendered tab bar', () => {
  async function renderProtectionTabs() {
    const { protectionTabs } = await import('@/components/protection/protection-tabs');
    render(<TabBar tabs={protectionTabs()} activeTab="status" onChange={() => {}} aria-label="Protection" />);
    return screen.getAllByRole('tab').map((t) => t.textContent);
  }

  it('shows every Protection tab with today\'s config', async () => {
    const { PROTECTION_TAB_DEFS } = await import('@/components/protection/protection-tabs');
    expect(await renderProtectionTabs()).toEqual(PROTECTION_TAB_DEFS.map((t) => t.label));
  });

  it('drops a tab once a tab-scoped config entry hides it, and only that tab', async () => {
    const { HIDDEN_ROUTES } = await import('@/components/layout/hidden-routes');
    const { PROTECTION_TAB_DEFS } = await import('@/components/protection/protection-tabs');
    mockHidden = [...HIDDEN_ROUTES, { path: '/protection', tab: 'audit', redirectTo: '/protection', reason: 't' }];
    const labels = await renderProtectionTabs();
    expect(labels).not.toContain('Memory checks');
    expect(labels).toEqual(PROTECTION_TAB_DEFS.filter((t) => t.id !== 'audit').map((t) => t.label));
    // A tab-scoped entry never becomes a server redirect.
    expect(await resolve('/protection')).toEqual({ page: expect.stringContaining('protection') });
  });
});
