import { act, render, screen, waitFor, within } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import type { ReactNode } from 'react';
import { NeedsYouView } from '@/components/needs-you/NeedsYouView';
import { Sidebar } from '@/components/layout/Sidebar';
import { MemoryWebSocketProvider } from '@/components/MemoryWebSocketProvider';
import { useMemoryWebSocket } from '@/lib/websocket';

/**
 * #692 R2 — freshness paths the first fix missed, driven through the real
 * socket client and React Query with a fake WebSocket and a fake API:
 *   - an event that lands while the first fetch is still in flight, whose
 *     response was computed before the event (no later events follow);
 *   - a quick disconnect → missed quarantine event → reconnect, with no
 *     defence_event replayed and no time for the disconnected poll.
 */
jest.mock('@/lib/store', () => ({
  useDashboardStore: (sel?: (s: Record<string, unknown>) => unknown) => {
    const state = { projectFilter: null, sidebarPinned: false, toggleSidebarPinned: () => undefined };
    return sel ? sel(state) : state;
  },
}));
jest.mock('next/navigation', () => ({ usePathname: () => '/needs-you' }));

class FakeSocket {
  static all: FakeSocket[] = [];
  static get last() { return FakeSocket.all[FakeSocket.all.length - 1]; }
  static OPEN = 1;
  readyState = 0;
  onopen?: () => void;
  onmessage?: (e: { data: string }) => void;
  onclose?: (e: { code: number }) => void;
  onerror?: () => void;
  constructor(public url: string) { FakeSocket.all.push(this); }
  close() { /* test double */ }
}

const exactCoverage = { unit: 'pairs', limit: 20, contradictions: { found: 0, capped: false, scanWindow: 200, candidates: 10, scanPartial: false }, duplicates: { found: 0, capped: false } };
const review = (duplicates: number) => ({
  summary: { contradictions: 0, duplicates }, sections: {},
  pairCoverage: { ...exactCoverage, duplicates: { found: duplicates, capped: false } },
});
const stats = (n: number) => ({ total: n, new: n, reviewed: 0, ignored: 0, resolved: 0, quarantined: 0, store: 'ok' });

/** What the server would answer right now. */
const server = { quarantine: 0, duplicates: 0, findings: 0 };
/** When set, the next request to a matching path is held until released. */
let hold: { match: RegExp; release?: () => void } | undefined;

function reply(body: unknown) {
  return { ok: true, status: 200, headers: new Headers({ 'content-type': 'application/json' }), json: async () => body, text: async () => JSON.stringify(body) };
}

beforeEach(() => {
  FakeSocket.all = [];
  Object.assign(server, { quarantine: 0, duplicates: 0, findings: 0 });
  hold = undefined;
  (global as unknown as { WebSocket: unknown }).WebSocket = FakeSocket;
  jest.spyOn(console, 'log').mockImplementation(() => undefined);
  global.fetch = jest.fn(async (url: string) => {
    if (url.includes('/api/auth/session-token')) return reply({ token: 't' });
    // The body is computed when the request is served, like a real server;
    // a held request answers later with this (by then outdated) snapshot.
    let body: unknown;
    if (url.includes('/api/v1/quarantine')) body = { total: server.quarantine, items: [] };
    else if (url.includes('/api/review/queue')) body = review(server.duplicates);
    else if (url.includes('/api/xray/findings/stats')) body = stats(server.findings);
    else return { ...reply({ error: 'boom' }), ok: false, status: 500 };
    if (hold && !hold.release && hold.match.test(url)) {
      const h = hold;
      await new Promise<void>((resolve) => { h.release = resolve; });
    }
    return reply(body);
  }) as unknown as typeof fetch;
});

afterEach(() => jest.restoreAllMocks());

const newClient = () => new QueryClient({ defaultOptions: { queries: { retry: false } } });
const section = (name: RegExp) => screen.getByRole('region', { name });
const send = (type: string) => act(async () => { FakeSocket.last!.onmessage!({ data: JSON.stringify({ type }) }); });

describe('an event during the first fetch is not lost (#692 R2, F2)', () => {
  /** The real socket client without the provider, so no open-time refetch masks the race. */
  function SocketOnly({ children }: { children: ReactNode }) {
    useMemoryWebSocket();
    return <>{children}</>;
  }

  it.each([
    ['memory_created', /\/api\/review\/queue/, () => { server.duplicates = 2; }, /Memories to check/, '2 pairs'],
    ['defence_event', /\/api\/v1\/quarantine/, () => { server.quarantine = 1; }, /Held back/, '1 waiting'],
    ['xray_detection', /\/api\/xray\/findings\/stats/, () => { server.findings = 3; }, /Scanner findings/, '3 new'],
  ])('%s while the first response is in flight replaces the pre-event zero', async (event, path, change, name, text) => {
    hold = { match: path };
    render(
      <QueryClientProvider client={newClient()}>
        <SocketOnly><NeedsYouView /></SocketOnly>
      </QueryClientProvider>,
    );
    // The first request has been served (zero snapshot) but not delivered.
    await waitFor(() => expect(hold!.release).toBeDefined());
    await waitFor(() => expect(FakeSocket.last?.onmessage).toBeDefined());

    change();
    await send(event);
    await act(async () => { hold!.release!(); });

    // No further events and no navigation: the page must still reach the post-event count.
    expect(await within(section(name)).findByText(text)).toBeInTheDocument();
    expect(screen.queryByText(/^Nothing needs you/)).toBeNull();
  });
});

describe('a socket reconnect reconciles every Needs you list (#692 R2, F3)', () => {
  function renderApp() {
    render(
      <QueryClientProvider client={newClient()}>
        <MemoryWebSocketProvider>
          <Sidebar />
          <NeedsYouView />
        </MemoryWebSocketProvider>
      </QueryClientProvider>,
    );
  }
  const openLatest = () => act(async () => { FakeSocket.last!.onopen!(); });

  it('a quarantine item created while briefly disconnected shows on the page and badge after reconnect', async () => {
    renderApp();
    await waitFor(() => expect(FakeSocket.last?.onopen).toBeDefined());
    await openLatest();
    expect(await screen.findByText(/^Nothing needs you/)).toBeInTheDocument();

    // Drop only the socket; an item is held back while no client is listening.
    await act(async () => { FakeSocket.last!.onclose!({ code: 1006 }); });
    server.quarantine = 1;

    // Reconnect after the 1s backoff — well before the 30s disconnected poll.
    await waitFor(() => expect(FakeSocket.all).toHaveLength(2), { timeout: 3000 });
    await waitFor(() => expect(FakeSocket.last?.onopen).toBeDefined());
    await openLatest();

    expect(await within(section(/Held back/)).findByText('1 waiting')).toBeInTheDocument();
    expect(screen.queryByText(/^Nothing needs you/)).toBeNull();
    expect(screen.getByRole('link', { name: 'Needs you, 1 waiting' })).toHaveTextContent('1');
  }, 10000);

  it('a snapshot from before the reconnect is not shown as a current all-clear while it is rechecked', async () => {
    renderApp();
    await waitFor(() => expect(FakeSocket.last?.onopen).toBeDefined());
    await openLatest();
    expect(await screen.findByText(/^Nothing needs you/)).toBeInTheDocument();

    await act(async () => { FakeSocket.last!.onclose!({ code: 1006 }); });
    hold = { match: /\/api\/v1\/quarantine/ };
    await waitFor(() => expect(FakeSocket.all).toHaveLength(2), { timeout: 3000 });
    await waitFor(() => expect(FakeSocket.last?.onopen).toBeDefined());
    await openLatest();

    // The recheck is in flight: the old zero is not current evidence.
    await waitFor(() => expect(hold!.release).toBeDefined());
    expect(screen.queryByText(/^Nothing needs you/)).toBeNull();

    await act(async () => { hold!.release!(); });
    expect(await screen.findByText(/^Nothing needs you/)).toBeInTheDocument();
  }, 10000);
});
