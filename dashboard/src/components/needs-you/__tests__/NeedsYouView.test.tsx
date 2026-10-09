import { act, render, screen, within } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { NeedsYouView } from '@/components/needs-you/NeedsYouView';

let mockProject: string | null = null;
jest.mock('@/lib/store', () => ({
  useDashboardStore: (sel?: (s: Record<string, unknown>) => unknown) => {
    const state = { projectFilter: mockProject, sidebarPinned: false, toggleSidebarPinned: () => undefined };
    return sel ? sel(state) : state;
  },
}));
jest.mock('next/navigation', () => ({ usePathname: () => '/needs-you' }));

type Reply = unknown | 'fail' | { status: number; body: unknown };
type Route = [RegExp, Reply];
let routes: Route[] = [];
function json(status: number, body: unknown) {
  return {
    ok: status < 400,
    status,
    headers: new Headers({ 'content-type': 'application/json' }),
    json: async () => body,
    text: async () => JSON.stringify(body),
  };
}
function mockApi(next: Route[]) {
  routes = next;
  global.fetch = jest.fn(async (url: string) => {
    if (url.includes('/api/auth/session-token')) return json(200, { token: 't' });
    const hit = routes.find(([re]) => re.test(url));
    if (!hit || hit[1] === 'fail') return json(500, { error: 'boom' });
    const r = hit[1] as { status?: number; body?: unknown };
    if (typeof r === 'object' && r !== null && typeof r.status === 'number' && 'body' in r) return json(r.status, r.body);
    return json(200, hit[1]);
  }) as unknown as typeof fetch;
}
const fetchedUrls = () => (global.fetch as jest.Mock).mock.calls.map((c) => String(c[0]));

function newClient() {
  return new QueryClient({ defaultOptions: { queries: { retry: false } } });
}
function renderView(client = newClient()) {
  render(<QueryClientProvider client={client}><NeedsYouView /></QueryClientProvider>);
  return client;
}

const section = (name: RegExp) => screen.getByRole('region', { name });

const exactCoverage = (contradictions = 0, duplicates = 0) => ({
  unit: 'pairs', limit: 20,
  contradictions: { found: contradictions, capped: false, scanWindow: 200, candidates: 10, scanPartial: false },
  duplicates: { found: duplicates, capped: false },
});
const review = (contradictions: number, duplicates: number, coverage: unknown = exactCoverage(contradictions, duplicates)) => ({
  summary: { contradictions, duplicates }, pairCoverage: coverage, sections: {},
});
const stats = (n: number, store = 'ok') => ({ total: n, new: n, reviewed: 0, ignored: 0, resolved: 0, quarantined: 0, store });
const ZERO: Route[] = [
  [/\/api\/v1\/quarantine/, { total: 0, items: [] }],
  [/\/api\/review\/queue/, review(0, 0)],
  [/\/api\/xray\/findings\/stats/, stats(0)],
];
const withRoute = (base: Route[], re: RegExp, reply: Reply): Route[] => base.map(([r, v]) => [r, String(r) === String(re) ? reply : v]);

beforeEach(() => { mockProject = null; });

describe('Needs you', () => {
  it('lists real held-back, memory and scanner counts, with units, linking to where you decide', async () => {
    mockApi([
      [/\/api\/v1\/quarantine/, { total: 2, items: [{ id: 1, title: 'Odd instruction in a memory', reason: 'Looks like an injected instruction' }] }],
      [/\/api\/review\/queue/, review(1, 3)],
      [/\/api\/xray\/findings\/stats/, stats(4)],
    ]);
    renderView();
    expect(await within(section(/Held back/)).findByText('2 waiting')).toBeInTheDocument();
    expect(within(section(/Held back/)).getByText('Odd instruction in a memory')).toBeInTheDocument();
    expect(within(section(/Held back/)).getByRole('link', { name: /Review held-back items/ })).toHaveAttribute('href', '/protection?tab=quarantine');
    expect(await within(section(/Memories to check/)).findByText('4 pairs')).toBeInTheDocument();
    expect(within(section(/Memories to check/)).getByText(/One memory can be in more than one pair/)).toBeInTheDocument();
    expect(within(section(/Memories to check/)).getByRole('link')).toHaveAttribute('href', '/memory?tab=review');
    expect(await within(section(/Scanner findings/)).findByText('4 new')).toBeInTheDocument();
    expect(within(section(/Scanner findings/)).getByRole('link')).toHaveAttribute('href', '/xray?tab=findings');
  });

  it('says held actions are coming and where to answer them for now; no decision controls', () => {
    mockApi([]);
    renderView();
    const held = section(/Actions waiting for a yes/);
    expect(within(held).getByText(/coming soon/)).toBeInTheDocument();
    expect(within(held).getByText(/answer them in your approval channel \(Telegram or OpenClaw\)/)).toBeInTheDocument();
    expect(within(held).queryByRole('button')).toBeNull();
  });

  it('a failed source says it could not load: never a fake zero, never the empty state', async () => {
    mockApi(withRoute(ZERO, /\/api\/v1\/quarantine/, 'fail'));
    renderView();
    // useQuarantine retries twice (1s + 2s backoff) before reporting the failure.
    expect(await within(section(/Held back/)).findByText(/Couldn't load this list/, {}, { timeout: 8000 })).toBeInTheDocument();
    expect(screen.queryByText(/^Nothing needs you/)).toBeNull();
    expect(screen.getByText(/Some lists couldn't be checked/)).toBeInTheDocument();
  }, 15000);

  it('shows the scoped empty state only when every source confirmed an exact zero', async () => {
    mockApi(ZERO);
    renderView();
    expect(await screen.findByText(/^Nothing needs you in the lists the dashboard can check/)).toBeInTheDocument();
    expect(screen.getByText(/Actions waiting for a yes are answered in your approval channel/)).toBeInTheDocument();
  });

  // #692 — stale all-clear: confirmed zeros, then one refresh fails.
  it('withdraws the all-clear when a confirmed zero goes stale after a failed refresh', async () => {
    mockApi(ZERO);
    const client = renderView();
    expect(await screen.findByText(/^Nothing needs you/)).toBeInTheDocument();

    mockApi(withRoute(ZERO, /\/api\/review\/queue/, 'fail'));
    await act(async () => { await client.refetchQueries({ queryKey: ['review-queue'] }); });

    expect(await within(section(/Memories to check/)).findByText('0 pairs · last known')).toBeInTheDocument();
    expect(screen.queryByText(/^Nothing needs you/)).toBeNull();
    expect(screen.getByText(/Some lists couldn't be checked/)).toBeInTheDocument();
    expect(within(section(/Memories to check/)).queryByText('Nothing here right now.')).toBeNull();
    expect(within(section(/Memories to check/)).getByRole('link', { name: /Check memories/ })).toBeInTheDocument();
  });

  it('labels a stale positive as last known, not a current count', async () => {
    mockApi(withRoute(ZERO, /\/api\/xray\/findings\/stats/, stats(4)));
    const client = renderView();
    expect(await within(section(/Scanner findings/)).findByText('4 new')).toBeInTheDocument();

    mockApi(withRoute(ZERO, /\/api\/xray\/findings\/stats/, 'fail'));
    await act(async () => { await client.refetchQueries({ queryKey: ['xray-findings-stats'] }); });

    expect(await within(section(/Scanner findings/)).findByText('4 new · last known')).toBeInTheDocument();
    expect(within(section(/Scanner findings/)).getByText(/latest check failed, so it may have changed/)).toBeInTheDocument();
  });

  // #692 — bounded pair counts.
  it('marks capped pair counts as a floor and says why', async () => {
    mockApi(withRoute(ZERO, /\/api\/review\/queue/, review(20, 20, {
      unit: 'pairs', limit: 20,
      contradictions: { found: 20, capped: true, scanWindow: 200, candidates: 900, scanPartial: true },
      duplicates: { found: 20, capped: true },
    })));
    renderView();
    const memories = section(/Memories to check/);
    expect(await within(memories).findByText('40+ pairs')).toBeInTheDocument();
    expect(within(memories).getByText(/Only the first 20 pairs of each kind are counted/)).toBeInTheDocument();
    expect(within(memories).getByText(/compares only the 200 most important\s+of 900 memories/)).toBeInTheDocument();
  });

  it('a zero from a sampled contradiction check is not a full all-clear', async () => {
    mockApi(withRoute(ZERO, /\/api\/review\/queue/, review(0, 0, {
      unit: 'pairs', limit: 20,
      contradictions: { found: 0, capped: false, scanWindow: 200, candidates: 500, scanPartial: true },
      duplicates: { found: 0, capped: false },
    })));
    renderView();
    expect(await screen.findByText(/this is not a full all-clear/)).toBeInTheDocument();
    expect(screen.queryByText(/^Nothing needs you/)).toBeNull();
    expect(within(section(/Memories to check/)).getByText('0+ pairs')).toBeInTheDocument();
  });

  // #692 — an unreadable scanner store is unavailable, not zero.
  it('an unreadable scanner store is unavailable with the reason, and the findings page stays reachable', async () => {
    mockApi(withRoute(ZERO, /\/api\/xray\/findings\/stats/, {
      status: 503,
      body: { error: 'The scanner findings file exists but could not be read or parsed', store: 'unreadable' },
    }));
    renderView();
    const scanner = section(/Scanner findings/);
    expect(await within(scanner).findByText("couldn't load")).toBeInTheDocument();
    expect(within(scanner).getByText(/could not be read or parsed/)).toBeInTheDocument();
    expect(within(scanner).getByRole('link', { name: /Look at findings/ })).toHaveAttribute('href', '/xray?tab=findings');
    expect(screen.queryByText(/^Nothing needs you/)).toBeNull();
  });

  it('a never-created scanner store is a real zero', async () => {
    mockApi(withRoute(ZERO, /\/api\/xray\/findings\/stats/, stats(0, 'absent')));
    renderView();
    expect(await screen.findByText(/^Nothing needs you/)).toBeInTheDocument();
  });

  // #692 — project scope.
  it('scopes held-back and memories to the selected project and says scanner findings are machine-wide', async () => {
    mockProject = 'alpha';
    mockApi([
      [/\/api\/v1\/quarantine/, { total: 0, items: [] }],
      [/\/api\/review\/queue/, review(0, 0)],
      [/\/api\/xray\/findings\/stats/, stats(7)],
    ]);
    renderView();
    expect(await within(section(/Scanner findings/)).findByText('7 new')).toBeInTheDocument();
    expect(screen.getByText(/Held back and memories to check: project alpha\. Scanner findings: this whole computer\./)).toBeInTheDocument();
    expect(within(section(/Scanner findings/)).getByText(/the project filter does not apply to them/)).toBeInTheDocument();
    const urls = fetchedUrls();
    expect(urls.find((u) => u.includes('/api/review/queue'))).toMatch(/project=alpha/);
    expect(urls.find((u) => u.includes('/api/v1/quarantine'))).toMatch(/project=alpha/);
    expect(urls.find((u) => u.includes('/api/xray/findings/stats'))).not.toMatch(/project=/);
  });

  // #692 — freshness while the socket is down: the review queue polls.
  it('picks up new review work without navigation while the socket is disconnected', async () => {
    jest.useFakeTimers();
    try {
      mockApi(ZERO);
      renderView();
      expect(await screen.findByText(/^Nothing needs you/)).toBeInTheDocument();
      mockApi(withRoute(ZERO, /\/api\/review\/queue/, review(0, 2)));
      await act(async () => { jest.advanceTimersByTime(61_000); });
      expect(await within(section(/Memories to check/)).findByText('2 pairs')).toBeInTheDocument();
      expect(screen.queryByText(/^Nothing needs you/)).toBeNull();
    } finally {
      jest.useRealTimers();
    }
  });
});

describe('Needs you sidebar badge', () => {
  async function renderSidebar(client = newClient()) {
    const { Sidebar } = await import('@/components/layout/Sidebar');
    render(<QueryClientProvider client={client}><Sidebar /></QueryClientProvider>);
    return client;
  }
  const navLink = () => screen.getByRole('link', { name: /^Needs you/ });

  it('shows an exact count only when every list confirmed an exact number', async () => {
    mockApi(withRoute(ZERO, /\/api\/xray\/findings\/stats/, stats(3)));
    await renderSidebar();
    expect(await screen.findByRole('link', { name: 'Needs you, 3 waiting' })).toHaveTextContent('3');
    const nav = screen.getByRole('navigation', { name: 'Primary' });
    expect(within(nav).getAllByRole('link')).toHaveLength(5);
  });

  it('a stale positive is not announced as a current count', async () => {
    mockApi(withRoute(ZERO, /\/api\/xray\/findings\/stats/, stats(3)));
    const client = await renderSidebar();
    expect(await screen.findByRole('link', { name: 'Needs you, 3 waiting' })).toBeInTheDocument();

    mockApi(withRoute(ZERO, /\/api\/xray\/findings\/stats/, 'fail'));
    await act(async () => { await client.refetchQueries({ queryKey: ['xray-findings-stats'] }); });
    expect(await screen.findByRole('link', { name: "Needs you, some lists couldn't be checked" })).toHaveTextContent('?');
  });

  it('a confirmed zero that goes stale stops looking all-clear', async () => {
    mockApi(ZERO);
    const client = await renderSidebar();
    // Wait until all three confirmed (no badge for an exact zero).
    await act(async () => { await client.refetchQueries(); });
    expect(navLink()).not.toHaveAttribute('aria-label');

    mockApi(withRoute(ZERO, /\/api\/review\/queue/, 'fail'));
    await act(async () => { await client.refetchQueries({ queryKey: ['review-queue'] }); });
    expect(await screen.findByRole('link', { name: "Needs you, some lists couldn't be checked" })).toBeInTheDocument();
  });

  it('a capped pair count is announced as a floor', async () => {
    mockApi(withRoute(ZERO, /\/api\/review\/queue/, review(20, 0, {
      unit: 'pairs', limit: 20,
      contradictions: { found: 20, capped: true, scanWindow: 200, candidates: 50, scanPartial: false },
      duplicates: { found: 0, capped: false },
    })));
    await renderSidebar();
    expect(await screen.findByRole('link', { name: 'Needs you, at least 20 waiting' })).toHaveTextContent('20+');
  });
});
