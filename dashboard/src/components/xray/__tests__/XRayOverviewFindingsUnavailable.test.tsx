import { act, render, screen, waitFor, within } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { XRayOverview } from '@/components/xray/XRayOverview';

// Open straight on the Findings tab (`/xray?tab=findings`).
jest.mock('next/navigation', () => ({
  usePathname: () => '/xray',
  useRouter: () => ({ replace: jest.fn(), push: jest.fn() }),
  useSearchParams: () => new URLSearchParams('tab=findings'),
}));
jest.mock('@/components/MemoryWebSocketProvider', () => ({ useWebSocketEvent: () => undefined }));

type Route = [RegExp, { status: number; body: unknown }];
function json(status: number, body: unknown) {
  return {
    ok: status < 400,
    status,
    headers: new Headers({ 'content-type': 'application/json' }),
    json: async () => body,
    text: async () => JSON.stringify(body),
  };
}
function mockApi(routes: Route[]) {
  global.fetch = jest.fn(async (url: string) => {
    if (url.includes('/api/auth/session-token')) return json(200, { token: 't' });
    const hit = routes.find(([re]) => re.test(url));
    // Everything the page polls besides findings: an empty, successful reply.
    return hit ? json(hit[1].status, hit[1].body) : json(200, {});
  }) as unknown as typeof fetch;
}
function renderView() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(<QueryClientProvider client={client}><XRayOverview /></QueryClientProvider>);
  return client;
}
const findingsTab = () => screen.getByRole('tab', { name: /Findings/ });

const UNREADABLE = { error: 'The scanner findings file exists but could not be read or parsed', store: 'unreadable' };

describe('X-Ray findings when the findings store is unreadable', () => {
  it('shows "couldn\'t load" with the server message and no count on the Findings tab', async () => {
    mockApi([
      [/\/api\/xray\/findings\/stats/, { status: 503, body: UNREADABLE }],
      [/\/api\/xray\/findings/, { status: 503, body: UNREADABLE }],
    ]);
    renderView();
    expect(await screen.findByText(`Failed to load findings: ${UNREADABLE.error}`)).toBeInTheDocument();
    expect(findingsTab()).toHaveTextContent(/^Findings$/);
    expect(within(findingsTab()).queryByText('0')).not.toBeInTheDocument();
    expect(screen.queryByText(/\d+ total/)).not.toBeInTheDocument();
  });

  it('shows the real count on the Findings tab when the store is readable', async () => {
    mockApi([
      [/\/api\/xray\/findings\/stats/, { status: 200, body: { total: 3, new: 3, reviewed: 0, ignored: 0, resolved: 0, quarantined: 0, store: 'ok' } }],
      [/\/api\/xray\/findings/, { status: 200, body: { findings: [] } }],
    ]);
    renderView();
    expect(await within(findingsTab()).findByText('3')).toBeInTheDocument();
    expect(screen.queryByText(/Failed to load findings/)).not.toBeInTheDocument();
  });

  // A refresh that fails after a good one must not keep the old count as
  // current: react-query keeps the last data on error, the page drops it.
  it('drops a previously loaded count when a stats refresh comes back 503', async () => {
    mockApi([
      [/\/api\/xray\/findings\/stats/, { status: 200, body: { total: 3, new: 3, reviewed: 0, ignored: 0, resolved: 0, quarantined: 0, store: 'ok' } }],
      [/\/api\/xray\/findings/, { status: 200, body: { findings: [] } }],
    ]);
    const client = renderView();
    expect(await within(findingsTab()).findByText('3')).toBeInTheDocument();
    expect(screen.getByText('3 total')).toBeInTheDocument();

    mockApi([
      [/\/api\/xray\/findings\/stats/, { status: 503, body: UNREADABLE }],
      [/\/api\/xray\/findings/, { status: 503, body: UNREADABLE }],
    ]);
    await act(async () => { await client.refetchQueries({ queryKey: ['xray-findings-stats'] }); });

    await waitFor(() => expect(findingsTab()).toHaveTextContent(/^Findings$/));
    expect(screen.queryByText(/\d+ total/)).not.toBeInTheDocument();
  });
});
