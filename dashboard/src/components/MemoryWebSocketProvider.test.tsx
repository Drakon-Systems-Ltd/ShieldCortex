import { act, render, screen } from '@testing-library/react';
import { useEffect } from 'react';
import type { WebSocketMessage } from '@/lib/websocket';
import {
  MemoryWebSocketProvider,
  useMemoryWebSocketContext,
  useWebSocketStatus,
  useWebSocketEvent,
} from './MemoryWebSocketProvider';

// Control the single underlying connection: capture the onMessage fan-out
// dispatcher the provider hands to useMemoryWebSocket, and the status it reads.
jest.mock('@/lib/websocket', () => ({
  __esModule: true,
  useMemoryWebSocket: jest.fn(),
}));

import { useMemoryWebSocket } from '@/lib/websocket';
const mockHook = useMemoryWebSocket as jest.Mock;

let dispatch: ((msg: WebSocketMessage) => void) | undefined;
const reconnectSpy = jest.fn();

function primeHook(status: { isConnected?: boolean; connectionFailed?: boolean; lastEvent?: unknown } = {}) {
  mockHook.mockImplementation((opts: { onMessage?: (m: WebSocketMessage) => void }) => {
    dispatch = opts?.onMessage;
    return {
      isConnected: status.isConnected ?? false,
      connectionFailed: status.connectionFailed ?? false,
      lastEvent: status.lastEvent ?? null,
      reconnect: reconnectSpy,
    };
  });
}

beforeEach(() => {
  mockHook.mockReset();
  dispatch = undefined;
  reconnectSpy.mockClear();
});

function Recorder({ sink }: { sink: WebSocketMessage[] }) {
  const { subscribe } = useMemoryWebSocketContext();
  useEffect(() => subscribe((m) => sink.push(m)), [subscribe, sink]);
  return null;
}

describe('MemoryWebSocketProvider', () => {
  it('opens exactly one underlying connection regardless of subscriber count', () => {
    primeHook();
    render(
      <MemoryWebSocketProvider>
        <Recorder sink={[]} />
        <Recorder sink={[]} />
        <Recorder sink={[]} />
      </MemoryWebSocketProvider>,
    );
    expect(mockHook).toHaveBeenCalledTimes(1);
  });

  it('fans one message out to every subscriber', () => {
    primeHook();
    const a: WebSocketMessage[] = [];
    const b: WebSocketMessage[] = [];
    render(
      <MemoryWebSocketProvider>
        <Recorder sink={a} />
        <Recorder sink={b} />
      </MemoryWebSocketProvider>,
    );

    const msg: WebSocketMessage = { type: 'defence_event', data: { foo: 1 } };
    act(() => dispatch?.(msg));

    expect(a).toEqual([msg]);
    expect(b).toEqual([msg]);
  });

  it('stops delivering to a subscriber after it unsubscribes (unmounts)', () => {
    primeHook();
    const sink: WebSocketMessage[] = [];

    function Toggle({ show }: { show: boolean }) {
      return (
        <MemoryWebSocketProvider>
          {show && <Recorder sink={sink} />}
        </MemoryWebSocketProvider>
      );
    }

    const { rerender } = render(<Toggle show />);
    act(() => dispatch?.({ type: 'memory_created' }));
    expect(sink).toHaveLength(1);

    rerender(<Toggle show={false} />);
    act(() => dispatch?.({ type: 'memory_created' }));
    expect(sink).toHaveLength(1); // no further delivery after unmount
  });

  it('exposes the underlying connection status through useWebSocketStatus', () => {
    primeHook({ isConnected: true });
    function StatusProbe() {
      const { isConnected } = useWebSocketStatus();
      return <span>{isConnected ? 'connected' : 'disconnected'}</span>;
    }
    render(
      <MemoryWebSocketProvider>
        <StatusProbe />
      </MemoryWebSocketProvider>,
    );
    expect(screen.getByText('connected')).toBeInTheDocument();
  });

  it('useWebSocketEvent delivers messages and detaches on unmount', () => {
    primeHook();
    const seen: string[] = [];

    function Listener() {
      useWebSocketEvent((m) => seen.push(m.type));
      return null;
    }
    function Host({ show }: { show: boolean }) {
      return (
        <MemoryWebSocketProvider>
          {show && <Listener />}
        </MemoryWebSocketProvider>
      );
    }

    const { rerender } = render(<Host show />);
    act(() => dispatch?.({ type: 'xray_detection' }));
    expect(seen).toEqual(['xray_detection']);

    rerender(<Host show={false} />);
    act(() => dispatch?.({ type: 'xray_detection' }));
    expect(seen).toEqual(['xray_detection']); // detached
  });

  it('useWebSocketEvent always invokes the latest handler (no stale closure)', () => {
    primeHook();
    const calls: number[] = [];

    function Listener({ tag }: { tag: number }) {
      useWebSocketEvent(() => calls.push(tag));
      return null;
    }

    const { rerender } = render(
      <MemoryWebSocketProvider>
        <Listener tag={1} />
      </MemoryWebSocketProvider>,
    );
    rerender(
      <MemoryWebSocketProvider>
        <Listener tag={2} />
      </MemoryWebSocketProvider>,
    );

    act(() => dispatch?.({ type: 'memory_updated' }));
    expect(calls).toEqual([2]); // latest handler, subscribed once
  });
});
