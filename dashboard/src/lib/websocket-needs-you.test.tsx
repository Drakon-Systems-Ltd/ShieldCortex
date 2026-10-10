import { act, renderHook, waitFor } from '@testing-library/react';
import { QueryClient, QueryClientProvider, useQuery } from '@tanstack/react-query';
import type { ReactNode } from 'react';
import { useMemoryWebSocket } from './websocket';

/**
 * #692 — the Needs you badge is always mounted, and the review queue has no
 * poll while the socket is connected, so socket events must invalidate it.
 * Drives the real useMemoryWebSocket with a fake WebSocket.
 */
class FakeSocket {
  static last: FakeSocket | undefined;
  static OPEN = 1;
  readyState = 0;
  onopen?: () => void;
  onmessage?: (e: { data: string }) => void;
  onclose?: (e: { code: number }) => void;
  onerror?: () => void;
  constructor(public url: string) { FakeSocket.last = this; }
  close() { /* test double */ }
}

beforeAll(() => {
  (global as unknown as { WebSocket: unknown }).WebSocket = FakeSocket;
  global.fetch = jest.fn(async () => ({ ok: true, status: 200, json: async () => ({ token: 't' }) })) as unknown as typeof fetch;
  jest.spyOn(console, 'log').mockImplementation(() => undefined);
});

function setup() {
  const client = new QueryClient({ defaultOptions: { queries: { retry: false } } });
  const wrapper = ({ children }: { children: ReactNode }) => <QueryClientProvider client={client}>{children}</QueryClientProvider>;
  let served = 0;
  const reviewFetch = jest.fn(async () => ({ pairs: served }));
  const statsFetch = jest.fn(async () => ({ new: served }));
  const { result } = renderHook(() => {
    useMemoryWebSocket();
    return {
      review: useQuery({ queryKey: ['review-queue', null], queryFn: reviewFetch }),
      stats: useQuery({ queryKey: ['xray-findings-stats'], queryFn: statsFetch }),
    };
  }, { wrapper });
  return { result, reviewFetch, statsFetch, setServed: (n: number) => { served = n; } };
}

const send = (type: string) => act(async () => { FakeSocket.last!.onmessage!({ data: JSON.stringify({ type }) }); });

describe('socket events keep Needs you fresh (#692)', () => {
  it.each(['memory_created', 'memory_updated', 'memory_deleted', 'consolidation_complete', 'predictive_consolidation'])(
    '%s refreshes the review queue without navigation',
    async (type) => {
      const { result, setServed } = setup();
      await waitFor(() => expect(result.current.review.data).toEqual({ pairs: 0 }));
      await waitFor(() => expect(FakeSocket.last?.onmessage).toBeDefined());
      setServed(3);
      await send(type);
      await waitFor(() => expect(result.current.review.data).toEqual({ pairs: 3 }));
    },
  );

  it('xray_detection refreshes the scanner finding stats (not only the list)', async () => {
    const { result, setServed } = setup();
    await waitFor(() => expect(result.current.stats.data).toEqual({ new: 0 }));
    await waitFor(() => expect(FakeSocket.last?.onmessage).toBeDefined());
    setServed(2);
    await send('xray_detection');
    await waitFor(() => expect(result.current.stats.data).toEqual({ new: 2 }));
  });
});
