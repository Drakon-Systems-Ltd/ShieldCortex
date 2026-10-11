import { render, screen, within } from '@testing-library/react';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { NeedsYouView } from '@/components/needs-you/NeedsYouView';

jest.mock('@/lib/store', () => ({
  useDashboardStore: (sel?: (s: { projectFilter: null }) => unknown) => (sel ? sel({ projectFilter: null }) : { projectFilter: null }),
}));

type Route = [RegExp, unknown | 'fail'];
function mockApi(routes: Route[]) {
  global.fetch = jest.fn(async (url: string) => {
    if (url.includes('/api/auth/session-token')) return { ok: true, status: 200, json: async () => ({ token: 't' }) };
    const hit = routes.find(([re]) => re.test(url));
    if (!hit || hit[1] === 'fail') return { ok: false, status: 500, json: async () => ({ error: 'boom' }) };
    return { ok: true, status: 200, json: async () => hit[1] };
  }) as unknown as typeof fetch;
}

function renderView() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  return render(<QueryClientProvider client={client}><NeedsYouView /></QueryClientProvider>);
}

const section = (name: RegExp) => screen.getByRole('region', { name });

describe('Needs you', () => {
  it('lists real held-back, memory and scanner counts with links to where you decide', async () => {
    mockApi([
      [/\/api\/v1\/quarantine/, { total: 2, items: [{ id: 1, title: 'Odd instruction in a memory', reason: 'Looks like an injected instruction' }] }],
      [/\/api\/review\/queue/, { summary: { contradictions: 1, duplicates: 3 }, sections: {} }],
      [/\/api\/xray\/findings\/stats/, { total: 4, new: 4, reviewed: 0, ignored: 0, resolved: 0, quarantined: 0 }],
    ]);
    renderView();
    expect(await within(section(/Held back/)).findByText('2 waiting')).toBeInTheDocument();
    expect(within(section(/Held back/)).getByText('Odd instruction in a memory')).toBeInTheDocument();
    expect(within(section(/Held back/)).getByRole('link', { name: /Review held-back items/ })).toHaveAttribute('href', '/protection?tab=quarantine');
    expect(await within(section(/Memories to check/)).findByText('4 waiting')).toBeInTheDocument();
    expect(within(section(/Memories to check/)).getByRole('link')).toHaveAttribute('href', '/memory?tab=review');
    expect(await within(section(/Scanner findings/)).findByText('4 waiting')).toBeInTheDocument();
    expect(within(section(/Scanner findings/)).getByRole('link')).toHaveAttribute('href', '/xray?tab=findings');
  });

  it('says held actions are coming and where to answer them for now', () => {
    mockApi([]);
    renderView();
    const held = section(/Actions waiting for a yes/);
    expect(within(held).getByText(/coming soon/)).toBeInTheDocument();
    expect(within(held).getByText(/answer them in your approval channel \(Telegram or OpenClaw\)/)).toBeInTheDocument();
    expect(within(held).queryByRole('button')).toBeNull();
  });

  it('a failed source says it could not load: never a fake zero, never the empty state', async () => {
    mockApi([
      [/\/api\/v1\/quarantine/, 'fail'],
      [/\/api\/review\/queue/, { summary: { contradictions: 0, duplicates: 0 }, sections: {} }],
      [/\/api\/xray\/findings\/stats/, { total: 0, new: 0, reviewed: 0, ignored: 0, resolved: 0, quarantined: 0 }],
    ]);
    renderView();
    // useQuarantine retries twice (1s + 2s backoff) before reporting the failure.
    expect(await within(section(/Held back/)).findByText(/Couldn't load this list/, {}, { timeout: 8000 })).toBeInTheDocument();
    expect(screen.queryByText(/^Nothing needs you/)).toBeNull();
  }, 15000);

  it('shows the empty state only when every source confirmed zero', async () => {
    mockApi([
      [/\/api\/v1\/quarantine/, { total: 0, items: [] }],
      [/\/api\/review\/queue/, { summary: { contradictions: 0, duplicates: 0 }, sections: {} }],
      [/\/api\/xray\/findings\/stats/, { total: 0, new: 0, reviewed: 0, ignored: 0, resolved: 0, quarantined: 0 }],
    ]);
    renderView();
    expect(await screen.findByText(/^Nothing needs you/)).toBeInTheDocument();
  });
});
