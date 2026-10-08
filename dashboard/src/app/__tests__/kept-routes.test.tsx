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
  ['/overview', () => import('@/app/(dashboard)/overview/page'), /^Home$/, []],
  ['/needs-you', () => import('@/app/(dashboard)/needs-you/page'), /^Needs you$/, []],
  ['/memory', () => import('@/app/(dashboard)/memory/page'), /^Memory$/, ['Search & browse', 'Map', 'Replay', 'Files']],
  ['/memory/replay', () => import('@/app/(dashboard)/memory/replay/page'), /^Replay$/, ['Search & browse', 'Timeline']],
  ['/protection', () => import('@/app/(dashboard)/protection/page'), /^Protection$/, ['Protection level', 'Activity', 'Held back', 'Rules', 'Skill & package scanner']],
  ['/xray', () => import('@/app/(dashboard)/xray/page'), /^Skill & package scanner$/, ['Activity', 'Scan', 'Findings']],
  ['/settings', () => import('@/app/(dashboard)/settings/page'), /^Settings$/, ['Cloud sync', 'Licence', 'Maintenance']],
];

describe('kept routes still render', () => {
  it.each(KEPT)('%s', async (_route, load, heading, tabs) => {
    const { default: Page } = await load();
    renderPage(Page);
    expect(await screen.findByRole('heading', { name: heading })).toBeInTheDocument();
    // Whole tab name (plus an optional count), so "Activity" is not "Scan activity".
    const exact = (t: string) => new RegExp(`^${t.replace(/[.*+?^${}()|[\]\\&]/g, '\\$&')}\\s*\\d*$`);
    for (const t of tabs) expect(screen.getAllByRole('tab', { name: exact(t) }).length).toBeGreaterThan(0);
  });
});
