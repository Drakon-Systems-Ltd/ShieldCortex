import { render, screen } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';

// Kept routes still mount after the hidden-routes change. Fetch never settles,
// so each page renders its loading state — the point is the page tree and its
// tab bar, not the data.
jest.mock('next/navigation', () => ({
  usePathname: () => '/',
  useSearchParams: () => new URLSearchParams(''),
  useRouter: () => ({ replace: jest.fn(), push: jest.fn(), prefetch: jest.fn(), back: jest.fn() }),
  redirect: jest.fn(),
}));

beforeAll(() => {
  global.fetch = jest.fn(() => new Promise<Response>(() => {})) as jest.Mock;
  class NoopObserver { observe() {} unobserve() {} disconnect() {} }
  (global as unknown as { ResizeObserver: unknown }).ResizeObserver = NoopObserver;
  window.matchMedia = window.matchMedia ?? ((q: string) => ({
    matches: false, media: q, onchange: null, addListener() {}, removeListener() {},
    addEventListener() {}, removeEventListener() {}, dispatchEvent: () => false,
  })) as unknown as typeof window.matchMedia;
});

function renderPage(Page: React.ComponentType) {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(
    <QueryClientProvider client={client}>
      <Page />
    </QueryClientProvider>,
  );
}

const KEPT: [string, () => Promise<{ default: React.ComponentType }>, RegExp, string[]][] = [
  ['/overview', () => import('@/app/(dashboard)/overview/page'), /Overview/, []],
  ['/memory', () => import('@/app/(dashboard)/memory/page'), /Memory Operations/, ['Library', 'Replay', 'Files']],
  ['/memory/replay', () => import('@/app/(dashboard)/memory/replay/page'), /^Replay$/, ['Library', 'Timeline']],
  ['/protection', () => import('@/app/(dashboard)/protection/page'), /^Protection$/, ['Status', 'Audit', 'Intercepts']],
  ['/xray', () => import('@/app/(dashboard)/xray/page'), /X-Ray Scanner/, ['Scanner', 'Findings']],
  ['/settings', () => import('@/app/(dashboard)/settings/page'), /^Settings$/, ['Cloud Sync', 'Licence', 'Admin']],
];

describe('kept routes still render', () => {
  it.each(KEPT)('%s', async (_route, load, heading, tabs) => {
    const { default: Page } = await load();
    renderPage(Page);
    expect(await screen.findByRole('heading', { name: heading })).toBeInTheDocument();
    for (const t of tabs) expect(screen.getByRole('tab', { name: new RegExp(t) })).toBeInTheDocument();
  });
});
