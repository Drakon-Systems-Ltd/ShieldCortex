import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { act, fireEvent, render, screen } from '@testing-library/react';
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

function mount() {
  const requests: URLSearchParams[] = [];
  const source = { rows, maxPage: Infinity };
  jest.mocked(authFetch).mockImplementation(async input => {
    const { pathname, searchParams: params } = new URL(String(input));
    const json = (body: unknown) => ({ ok: true, json: async () => body } as Response);
    if (pathname === '/api/capture/openclaw/sessions') return json({ sessions: [] });
    if (pathname !== '/api/memories') throw new Error(`Unexpected endpoint: ${pathname}`);
    requests.push(params);
    let matches = source.rows.filter(row => (['project', 'type', 'category'] as const).every(
      key => !params.has(key) || params.get(key) === row[key],
    ));
    if (params.get('mode') === 'search') matches = matches.slice(0, 3);
    const offset = Number(params.get('offset'));
    const limit = Math.min(Number(params.get('limit')), source.maxPage);
    return json({ memories: matches.slice(offset, offset + limit),
      pagination: { offset, limit, total: matches.length, hasMore: offset + limit < matches.length } });
  });
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(<QueryClientProvider client={client}><MemoriesView /></QueryClientProvider>);
  return { requests, source, client };
}

const next = () => fireEvent.click(screen.getByText('Next'));
const titles = () => screen.getAllByRole('heading', { level: 3 }).map(h => h.textContent);
const offsets = (requests: URLSearchParams[]) => requests.map(p => Number(p.get('offset')));
beforeEach(() => useDashboardStore.setState({ projectFilter: null, typeFilter: null, categoryFilter: null }));

it('browses beyond row 1000 without accumulating cards', async () => {
  const { requests } = mount();
  for (let offset = 0; offset <= 1000; offset += 50) {
    await screen.findByText(`Showing ${offset + 1}–${Math.min(offset + 50, 1001)} of 1001`);
    if (offset < 1000) next();
  }
  expect(titles()).toEqual(['Row 1001']);
  expect(screen.getByText('Next')).toBeDisabled();
  expect(requests.map(p => [p.get('mode'), Number(p.get('offset')), p.get('limit')]))
    .toEqual(Array.from({ length: 21 }, (_, i) => ['recent', i * 50, '50']));
});

it('next and previous replace the page; sorting only reorders its cards', async () => {
  const { requests } = mount();
  await screen.findByText('Showing 1–50 of 1001');
  expect(screen.getByText('Previous')).toBeDisabled();
  const original = titles();
  fireEvent.change(screen.getByLabelText('Sort this page'), { target: { value: 'oldest' } });
  expect(titles()).toEqual([...original].reverse());
  next();
  // The new query hasn't resolved; the previous response must not offer another step.
  expect(screen.queryByText('Next')).not.toBeInTheDocument();
  expect(screen.queryByText('Previous')).not.toBeInTheDocument();
  await screen.findByText('Showing 51–100 of 1001');
  expect(titles()).toEqual(rows.slice(50, 100).map(row => row.title));
  fireEvent.click(screen.getByText('Previous'));
  await screen.findByText('Showing 1–50 of 1001');
  expect(titles()).toEqual([...original].reverse());
  expect(offsets(requests)).toEqual([0, 50, 0]);
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
  await screen.findByText('3 results returned (up to 1000)');
  expect(screen.queryByText('Next')).not.toBeInTheDocument();
  expect(screen.queryByText('Previous')).not.toBeInTheDocument();
  const params = requests[2];
  expect([params.get('mode'), params.get('query'), params.get('limit')]).toEqual(['search', 'term', '1000']);
  fireEvent.change(screen.getByLabelText('Sort memories'), { target: { value: 'oldest' } });
  expect(titles()).toEqual(['Row 1', 'Row 2', 'Row 3']);
  fireEvent.change(search, { target: { value: '' } });
  await screen.findByText('Showing 1–50 of 1001');
  expect(offsets(requests)).toEqual([0, 50, 0, 0]);
  act(() => useDashboardStore.getState().setCategoryFilter('missing'));
  await screen.findByText('0 matches');
  expect(screen.getByText('Next')).toBeDisabled();
  expect(screen.getByText('Previous')).toBeDisabled();
});

it('steps by the returned limit and can navigate back from a page emptied by a refresh', async () => {
  const { requests, source, client } = mount();
  await screen.findByText('Showing 1–50 of 1001');
  source.maxPage = 10;
  await act(() => client.invalidateQueries({ queryKey: ['memories'] }));
  await screen.findByText('Showing 1–10 of 1001');
  next();
  await screen.findByText('Showing 11–20 of 1001');
  source.rows = rows.slice(0, 7);
  await act(() => client.invalidateQueries({ queryKey: ['memories'] }));
  await screen.findByText('No rows on this page (7 matches)');
  expect(screen.getByText('Next')).toBeDisabled();
  fireEvent.click(screen.getByText('Previous'));
  await screen.findByText('Showing 1–7 of 7');
  expect(offsets(requests)).toEqual([0, 0, 10, 10, 0]);
});
