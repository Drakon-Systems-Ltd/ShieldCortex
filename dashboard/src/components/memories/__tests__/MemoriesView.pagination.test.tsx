import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { act, fireEvent, render, screen, waitFor } from '@testing-library/react';
import '@testing-library/jest-dom';
import { authFetch } from '../../../lib/auth';
import { useDashboardStore } from '../../../lib/store';
import { MemoriesView } from '../MemoriesView';

jest.mock('@/lib/auth', () => ({ authFetch: jest.fn() }));

// Already in recent-access order, deliberately opposite the default creation sort.
const rows = Array.from({ length: 1001 }, (_, i) => ({
  id: i + 1, title: `Row ${i + 1}`, content: '', tags: [], salience: 0.5,
  createdAt: new Date(i * 1000).toISOString(), lastAccessed: new Date((1001 - i) * 1000).toISOString(),
  project: i >= 900 ? 'p1' : 'p2', type: i >= 900 ? 'short_term' : 'long_term',
  category: i >= 900 ? 'note' : 'error',
}));

type Body = { memories: unknown; pagination?: Record<string, unknown> };

function mount(prepare?: (source: { mangle?: (body: Body, offset: number) => unknown }) => void) {
  const requests: URLSearchParams[] = [];
  const source = {
    rows,
    failing: new Set<number>(),
    failAll: false,
    /** Resolves when the held response may go out. */
    hold: undefined as Promise<void> | undefined,
    /** Rewrites a response body; return undefined to leave it alone. */
    mangle: undefined as ((body: Body, offset: number) => unknown) | undefined,
  };
  prepare?.(source);
  jest.mocked(authFetch).mockImplementation(async input => {
    const { pathname, searchParams: params } = new URL(String(input));
    const json = (body: unknown) => ({ ok: true, json: async () => body } as Response);
    if (pathname === '/api/capture/openclaw/sessions') return json({ sessions: [] });
    if (pathname !== '/api/memories') throw new Error(`Unexpected endpoint: ${pathname}`);
    requests.push(params);
    const offset = Number(params.get('offset'));
    const limit = Number(params.get('limit'));
    if (source.hold) await source.hold;
    if (source.failAll || source.failing.has(offset)) return { ok: false, json: async () => ({}) } as Response;
    let matches = source.rows.filter(row => (['project', 'type', 'category'] as const).every(
      key => !params.has(key) || params.get(key) === row[key],
    ));
    if (params.get('mode') === 'search') matches = matches.slice(0, 3);
    const body: Body = { memories: matches.slice(offset, offset + limit),
      pagination: { offset, limit, total: matches.length, hasMore: offset + limit < matches.length } };
    return json(source.mangle?.(body, offset) ?? body);
  });
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(<QueryClientProvider client={client}><MemoriesView /></QueryClientProvider>);
  return { requests, source, client };
}

const button = (name: 'Previous' | 'Next' | 'Retry') => screen.getByRole('button', { name });
const next = () => fireEvent.click(button('Next'));
const previous = () => fireEvent.click(button('Previous'));
const titles = () => screen.queryAllByRole('heading', { level: 3 }).map(h => h.textContent);
const offsets = (requests: URLSearchParams[]) => requests.map(p => Number(p.get('offset')));
/** Unavailable steps stay focusable: aria-disabled, never the disabled attribute. */
const expectSteps = (state: { Previous: boolean; Next: boolean }) => {
  for (const name of ['Previous', 'Next'] as const) {
    expect(button(name)).toHaveAttribute('aria-disabled', String(!state[name]));
    expect(button(name)).toBeEnabled();
    expect(button(name)).toHaveAttribute('type', 'button');
  }
};
beforeEach(() => useDashboardStore.setState({ projectFilter: null, typeFilter: null, categoryFilter: null }));

it('browses beyond row 1000 without accumulating cards', async () => {
  const { requests } = mount();
  for (let offset = 0; offset <= 1000; offset += 50) {
    await screen.findByText(`Showing ${offset + 1}–${Math.min(offset + 50, 1001)} of 1001`);
    if (offset < 1000) next();
  }
  expect(titles()).toEqual(['Row 1001']);
  expectSteps({ Previous: true, Next: false });
  expect(requests.map(p => [p.get('mode'), Number(p.get('offset')), p.get('limit')]))
    .toEqual(Array.from({ length: 21 }, (_, i) => ['recent', i * 50, '50']));
// 21 pages of 50 cards in jsdom: over the 5 s default on a slow or busy host.
}, 30_000);

it('next and previous replace the page; sorting only reorders its cards', async () => {
  const { requests } = mount();
  await screen.findByText('Showing 1–50 of 1001');
  expectSteps({ Previous: false, Next: true });
  // The order is live, so the view says so instead of implying a stable walk.
  expect(screen.getByText(/can repeat or be missed between pages/)).toBeInTheDocument();
  const original = titles();
  fireEvent.change(screen.getByLabelText('Sort this page'), { target: { value: 'oldest' } });
  expect(titles()).toEqual([...original].reverse());
  next();
  // The new page hasn't arrived: no further step is offered and no stale card stays.
  expect(screen.getByRole('status')).toHaveTextContent('Loading rows 51–100…');
  expectSteps({ Previous: false, Next: false });
  expect(titles()).toEqual([]);
  next();
  previous();
  await screen.findByText('Showing 51–100 of 1001');
  expect(titles()).toEqual(rows.slice(50, 100).map(row => row.title));
  previous();
  await screen.findByText('Showing 1–50 of 1001');
  expect(titles()).toEqual([...original].reverse());
  expect(offsets(requests)).toEqual([0, 50, 0]);
});

it('keeps keyboard focus on the pressed control through a pending step and at the last page', async () => {
  const { requests, source } = mount();
  await screen.findByText('Showing 1–50 of 1001');
  let release = () => {};
  source.hold = new Promise<void>(resolve => { release = resolve; });
  const nextButton = button('Next');
  nextButton.focus();
  fireEvent.click(nextButton);
  expect(screen.getByRole('status')).toHaveTextContent('Loading rows 51–100…');
  // Same element, still focused: it was neither unmounted nor disabled.
  expect(button('Next')).toBe(nextButton);
  expect(nextButton).toHaveFocus();
  expectSteps({ Previous: false, Next: false });
  source.hold = undefined;
  await act(async () => release());
  await screen.findByText('Showing 51–100 of 1001');
  expect(nextButton).toHaveFocus();
  // The focused control works again without being found a second time.
  fireEvent.click(nextButton);
  await screen.findByText('Showing 101–150 of 1001');
  expect(nextButton).toHaveFocus();

  source.rows = rows.slice(0, 160);
  fireEvent.click(nextButton);
  await screen.findByText('Showing 151–160 of 160');
  expect(button('Next')).toBe(nextButton);
  expect(nextButton).toHaveFocus();
  expectSteps({ Previous: true, Next: false });
  fireEvent.click(nextButton);

  const previousButton = button('Previous');
  previousButton.focus();
  fireEvent.click(previousButton);
  expect(previousButton).toHaveFocus();
  await screen.findByText('Showing 101–150 of 160');
  expect(button('Previous')).toBe(previousButton);
  expect(previousButton).toHaveFocus();
  expect(offsets(requests)).toEqual([0, 50, 100, 150, 100]);
});

it('keeps Previous usable after a page fails to load', async () => {
  const { requests, source } = mount();
  await screen.findByText('Showing 1–50 of 1001');
  source.failing.add(50);
  next();
  expect(await screen.findByRole('alert')).toHaveTextContent('Failed to load memories: Failed to fetch memories');
  expect(screen.getByRole('status')).toHaveTextContent('Rows 51–100 did not load');
  expect(titles()).toEqual([]);
  expectSteps({ Previous: true, Next: false });
  next();
  expect(offsets(requests)).toEqual([0, 50]);

  previous();
  await screen.findByText('Showing 1–50 of 1001');
  expect(titles()).toEqual(rows.slice(0, 50).reverse().map(row => row.title));
  expect(screen.queryByRole('alert')).not.toBeInTheDocument();

  next();
  await screen.findByRole('alert');
  source.failing.clear();
  fireEvent.click(button('Retry'));
  await screen.findByText('Showing 51–100 of 1001');
  expect(screen.queryByRole('alert')).not.toBeInTheDocument();
  expectSteps({ Previous: true, Next: true });
});

it('keeps the loaded page and its controls when a refresh fails', async () => {
  const { source, client } = mount();
  await screen.findByText('Showing 1–50 of 1001');
  next();
  await screen.findByText('Showing 51–100 of 1001');
  const loaded = titles();
  source.failAll = true;
  await act(() => client.invalidateQueries({ queryKey: ['memories'] }));
  expect(await screen.findByRole('alert')).toHaveTextContent(
    'Could not refresh memories: Failed to fetch memories. Showing the page loaded earlier.');
  expect(screen.getByRole('status')).toHaveTextContent('Showing 51–100 of 1001');
  expect(screen.getByRole('button', { name: 'All 1001' })).toBeInTheDocument();
  expect(titles()).toEqual(loaded);
  expectSteps({ Previous: true, Next: true });

  // A page loaded earlier is still shown when its refresh fails too.
  previous();
  expect(await screen.findByRole('alert')).toHaveTextContent('Could not refresh memories');
  expect(screen.getByRole('status')).toHaveTextContent('Showing 1–50 of 1001');
  expect(titles()).toHaveLength(50);

  source.failAll = false;
  fireEvent.click(button('Retry'));
  await waitFor(() => expect(screen.queryByRole('alert')).not.toBeInTheDocument());
  expect(screen.getByRole('status')).toHaveTextContent('Showing 1–50 of 1001');
});

const page = (body: Body) => body.pagination as Record<string, unknown>;
it.each<[string, (body: Body) => unknown]>([
  ['no pagination object', body => ({ memories: body.memories })],
  ['a null total', body => ({ ...body, pagination: { ...page(body), total: null } })],
  ['a negative total', body => ({ ...body, pagination: { ...page(body), total: -1 } })],
  ['a fractional total', body => ({ ...body, pagination: { ...page(body), total: 1000.5 } })],
  ['a total smaller than the rows shown', body => ({ ...body, pagination: { ...page(body), total: 60 } })],
  ['a string offset', body => ({ ...body, pagination: { ...page(body), offset: '50' } })],
  ['another page\'s offset', body => ({ ...body, pagination: { ...page(body), offset: 0 } })],
  ['a page size other than the fixed 50', body => ({ ...body, pagination: { ...page(body), limit: 10 } })],
  ['a non-boolean hasMore', body => ({ ...body, pagination: { ...page(body), hasMore: 'yes' } })],
  ['more rows than the page size', body => ({ ...body, memories: rows.slice(0, 51) })],
  ['no memory list', body => ({ pagination: body.pagination })],
])('reports %s as unusable page information and keeps Previous usable', async (_name, mangle) => {
  const { requests, source } = mount();
  await screen.findByText('Showing 1–50 of 1001');
  source.mangle = (body, offset) => (offset === 50 ? mangle(body) : undefined);
  next();
  expect(await screen.findByRole('alert')).toHaveTextContent(/^The server returned unusable page information \(.+\), so this page is not shown\./);
  expect(screen.getByRole('status')).toHaveTextContent('Rows 51–100 unavailable');
  expect(screen.getByRole('button', { name: 'All' })).toBeInTheDocument();
  expect(titles()).toEqual([]);
  expectSteps({ Previous: true, Next: false });
  next();
  expect(offsets(requests)).toEqual([0, 50]);
  previous();
  await screen.findByText('Showing 1–50 of 1001');
  expect(screen.queryByRole('alert')).not.toBeInTheDocument();
});

it('recovers from unusable page information on the first page with Retry', async () => {
  const { source } = mount(initial => {
    initial.mangle = body => ({ ...body, pagination: { ...page(body), total: undefined } });
  });
  expect(await screen.findByRole('alert')).toHaveTextContent('unusable page information');
  expect(screen.getByRole('status')).toHaveTextContent('Rows 1–50 unavailable');
  expectSteps({ Previous: false, Next: false });
  source.mangle = undefined;
  fireEvent.click(button('Retry'));
  await screen.findByText('Showing 1–50 of 1001');
  expect(screen.queryByRole('alert')).not.toBeInTheDocument();
});

it('keeps the pager and Library page errors off the Sessions tab', async () => {
  mount(initial => { initial.mangle = body => ({ memories: body.memories }); });
  expect(await screen.findByRole('alert')).toHaveTextContent('unusable page information');
  fireEvent.click(screen.getByRole('button', { name: /^Sessions/ }));
  expect(screen.getByText(/^No OpenClaw sessions found/)).toBeInTheDocument();
  expect(screen.queryByRole('alert')).not.toBeInTheDocument();
  expect(screen.queryByRole('status')).not.toBeInTheDocument();
  expect(screen.queryByRole('button', { name: 'Next' })).not.toBeInTheDocument();
});

it.each([['project', 'p1'], ['type', 'short_term'], ['category', 'note']])(
  'changing the %s filter resets before fetching in both directions', async (key, value) => {
    const { requests } = mount();
    await screen.findByText('Showing 1–50 of 1001');
    next();
    await screen.findByText('Showing 51–100 of 1001');
    act(() => useDashboardStore.setState({ [`${key}Filter`]: value }));
    await screen.findByText('Showing 1–50 of 101');
    expect(screen.getByRole('button', { name: 'All 101' })).toBeInTheDocument();
    expect(titles()).toEqual(rows.slice(900, 950).reverse().map(row => row.title));
    act(() => useDashboardStore.setState({ [`${key}Filter`]: null }));
    await screen.findByText('Showing 1–50 of 1001');
    expect(requests.map(p => [p.get(key), Number(p.get('offset'))])).toEqual([
      [null, 0], [null, 50], [value, 0], [null, 0],
    ]);
  },
);

it('keeps search bounded and sortable, restarts browse on clear and reports zero matches', async () => {
  const { requests } = mount();
  await screen.findByText('Showing 1–50 of 1001');
  next();
  await screen.findByText('Showing 51–100 of 1001');
  const search = screen.getByLabelText('Search memories');
  fireEvent.change(search, { target: { value: 'term' } });
  expect(screen.getByRole('status')).toHaveTextContent('Searching…');
  await screen.findByText('3 results returned (up to 1000)');
  expect(screen.queryByText('Next')).not.toBeInTheDocument();
  expect(screen.queryByText('Previous')).not.toBeInTheDocument();
  expect(screen.queryByText(/can repeat or be missed between pages/)).not.toBeInTheDocument();
  const params = requests[2];
  expect([params.get('mode'), params.get('query'), params.get('limit')]).toEqual(['search', 'term', '1000']);
  fireEvent.change(screen.getByLabelText('Sort memories'), { target: { value: 'oldest' } });
  expect(titles()).toEqual(['Row 1', 'Row 2', 'Row 3']);
  fireEvent.change(search, { target: { value: '' } });
  await screen.findByText('Showing 1–50 of 1001');
  expect(offsets(requests)).toEqual([0, 50, 0, 0]);
  act(() => useDashboardStore.getState().setCategoryFilter('missing'));
  await screen.findByText('0 matches');
  expectSteps({ Previous: false, Next: false });
});

it('steps by the fixed 50 and returns from pages emptied by a refresh to the last page with rows', async () => {
  const { requests, source, client } = mount();
  await screen.findByText('Showing 1–50 of 1001');
  next();
  await screen.findByText('Showing 51–100 of 1001');
  next();
  await screen.findByText('Showing 101–150 of 1001');
  source.rows = rows.slice(0, 7);
  await act(() => client.invalidateQueries({ queryKey: ['memories'] }));
  await screen.findByText('No rows on this page (7 matches)');
  expectSteps({ Previous: true, Next: false });
  // One press, not one per emptied page.
  previous();
  await screen.findByText('Showing 1–7 of 7');
  expectSteps({ Previous: false, Next: false });
  expect(offsets(requests)).toEqual([0, 50, 100, 100, 0]);
});
