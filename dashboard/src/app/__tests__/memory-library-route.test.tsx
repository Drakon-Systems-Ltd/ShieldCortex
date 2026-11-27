import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { fireEvent, render, screen } from '@testing-library/react';
import MemoryPage from '@/app/(dashboard)/memory/page';
import { hiddenRouteRedirects, isHiddenRoute } from '@/components/layout/hidden-routes';
import { memoryTabHref } from '@/components/memory/memory-tabs';
import { authFetch } from '@/lib/auth';

// The Library pager where it ships: the real /memory page, on the tab a
// visitor lands on, with the step controls as a keyboard user meets them.
// MemoriesView.pagination.test.tsx covers the pager's behaviour in depth.
let mockSearch = '';
jest.mock('next/navigation', () => ({
  usePathname: () => '/memory',
  useSearchParams: () => new URLSearchParams(mockSearch),
  useRouter: () => ({ replace: jest.fn(), push: jest.fn(), prefetch: jest.fn(), back: jest.fn() }),
  redirect: jest.fn(),
}));
jest.mock('@/lib/auth', () => ({ authFetch: jest.fn() }));

const rows = Array.from({ length: 120 }, (_, i) => ({
  id: i + 1, title: `Row ${i + 1}`, content: '', tags: [], salience: 0.5, type: 'long_term', category: 'note',
  createdAt: new Date(i * 1000).toISOString(), lastAccessed: new Date((120 - i) * 1000).toISOString(),
}));

beforeAll(() => {
  class NoopObserver { observe() {} unobserve() {} disconnect() {} }
  (global as unknown as { ResizeObserver: unknown }).ResizeObserver = NoopObserver;
  window.matchMedia = window.matchMedia ?? ((q: string) => ({
    matches: false, media: q, onchange: null, addListener() {}, removeListener() {},
    addEventListener() {}, removeEventListener() {}, dispatchEvent: () => false,
  })) as unknown as typeof window.matchMedia;
});

function open(search: string) {
  mockSearch = search;
  const requests: URLSearchParams[] = [];
  jest.mocked(authFetch).mockImplementation(async input => {
    const { pathname, searchParams: params } = new URL(String(input));
    const json = (body: unknown) => ({ ok: true, json: async () => body } as Response);
    if (pathname === '/api/capture/openclaw/sessions') return json({ sessions: [] });
    // Everything else the page asks for stays loading; only the list is under test.
    if (pathname !== '/api/memories') return new Promise<Response>(() => {});
    requests.push(params);
    const offset = Number(params.get('offset'));
    const limit = Number(params.get('limit'));
    return json({ memories: rows.slice(offset, offset + limit),
      pagination: { offset, limit, total: rows.length, hasMore: offset + limit < rows.length } });
  });
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  render(<QueryClientProvider client={client}><MemoryPage /></QueryClientProvider>);
  return requests;
}

const step = (name: 'Previous' | 'Next') => screen.getByRole('button', { name });
const query = (params: URLSearchParams) => [params.get('mode'), params.get('limit'), Number(params.get('offset'))];

describe('Library on the /memory route', () => {
  it('is the default tab of a kept route', () => {
    expect(memoryTabHref('library')).toBe('/memory');
    expect(isHiddenRoute('/memory')).toBe(false);
    expect(isHiddenRoute('/memory', 'library')).toBe(false);
    expect(hiddenRouteRedirects().filter(r => r.source === '/memory')).toEqual([]);
    expect(hiddenRouteRedirects()).toContainEqual({ source: '/memory/capture', destination: '/memory', permanent: false });
  });

  it.each([
    ['/memory', ''],
    ['/memory?tab=library', 'tab=library'],
    ['/memory?tab=capture, the retired tab folded into Library', 'tab=capture'],
  ])('%s pages the Library 50 rows at a time with focusable step buttons', async (_url, search) => {
    const requests = open(search);
    expect(await screen.findByRole('heading', { name: /^Memory$/ })).toBeInTheDocument();
    expect(screen.getByRole('tab', { name: /^Search & browse/ })).toHaveAttribute('aria-selected', 'true');
    expect(await screen.findByRole('status')).toHaveTextContent('Showing 1–50 of 120');
    expect(screen.getByRole('button', { name: 'All 120' })).toBeInTheDocument();
    expect(screen.getAllByRole('heading', { level: 3 })).toHaveLength(50);

    // Native buttons that never take `disabled`, so they keep their place in
    // the tab order; an unavailable step is announced through aria-disabled.
    for (const name of ['Previous', 'Next'] as const) {
      expect(step(name).tagName).toBe('BUTTON');
      expect(step(name)).toHaveAttribute('type', 'button');
      expect(step(name)).toBeEnabled();
    }
    expect(step('Previous')).toHaveAttribute('aria-disabled', 'true');
    expect(step('Next')).toHaveAttribute('aria-disabled', 'false');

    fireEvent.click(step('Next'));
    await screen.findByText('Showing 51–100 of 120');
    fireEvent.click(step('Next'));
    await screen.findByText('Showing 101–120 of 120');
    expect(screen.getAllByRole('heading', { level: 3 })).toHaveLength(20);
    expect(step('Previous')).toHaveAttribute('aria-disabled', 'false');
    expect(step('Next')).toHaveAttribute('aria-disabled', 'true');
    fireEvent.click(step('Previous'));
    await screen.findByText('Showing 51–100 of 120');
    // The last request revalidates the page shown from cache on the way back.
    expect(requests.map(query)).toEqual([
      ['recent', '50', 0], ['recent', '50', 50], ['recent', '50', 100], ['recent', '50', 50],
    ]);
  });

  it('/memory?tab=files does not mount the Library pager', async () => {
    const requests = open('tab=files');
    expect(await screen.findByRole('tab', { name: /^Files/ })).toHaveAttribute('aria-selected', 'true');
    expect(screen.queryByRole('button', { name: 'Next' })).not.toBeInTheDocument();
    expect(requests).toEqual([]);
  });
});
