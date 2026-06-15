import { act, render } from '@testing-library/react';
import type { WebSocketMessage } from '@/lib/websocket';
import type { PulseDriver } from '@/components/graph/constellation/pulse';
import { MemoryWebSocketProvider } from '@/components/MemoryWebSocketProvider';
import { useGraphPulse } from './useGraphPulse';

jest.mock('@/lib/websocket', () => ({
  __esModule: true,
  useMemoryWebSocket: jest.fn(),
}));
import { useMemoryWebSocket } from '@/lib/websocket';
const mockHook = useMemoryWebSocket as jest.Mock;
let dispatch: ((m: WebSocketMessage) => void) | undefined;

function primeHook(isConnected: boolean) {
  mockHook.mockImplementation((opts: { onMessage?: (m: WebSocketMessage) => void }) => {
    dispatch = opts?.onMessage;
    return { isConnected, connectionFailed: false, lastEvent: null, reconnect: jest.fn() };
  });
}

beforeEach(() => {
  mockHook.mockReset();
  dispatch = undefined;
});

afterEach(() => {
  jest.useRealTimers();
  // @ts-expect-error test cleanup
  delete global.fetch;
});

function makeDriver() {
  return { dispatch: jest.fn() } as unknown as PulseDriver & { dispatch: jest.Mock };
}

function Harness({ driver, enabled = true }: { driver: PulseDriver; enabled?: boolean }) {
  useGraphPulse(driver, enabled);
  return null;
}

function renderPulse(driver: PulseDriver, enabled = true) {
  return render(
    <MemoryWebSocketProvider>
      <Harness driver={driver} enabled={enabled} />
    </MemoryWebSocketProvider>,
  );
}

describe('useGraphPulse — live dispatch via the shared connection', () => {
  it('dispatches memory.created pulses for each entity id', () => {
    primeHook(true);
    const driver = makeDriver();
    renderPulse(driver);

    act(() => dispatch?.({ type: 'memory_created', data: { entity_ids: [1, 2] } }));

    expect(driver.dispatch).toHaveBeenCalledWith({ type: 'memory.created', entityId: '1' });
    expect(driver.dispatch).toHaveBeenCalledWith({ type: 'memory.created', entityId: '2' });
  });

  it('maps memory_accessed to memory.accessed', () => {
    primeHook(true);
    const driver = makeDriver();
    renderPulse(driver);

    act(() => dispatch?.({ type: 'memory_accessed', data: { entity_ids: [7] } }));

    expect(driver.dispatch).toHaveBeenCalledWith({ type: 'memory.accessed', entityId: '7' });
  });

  it('ignores events that are not memory created/accessed', () => {
    primeHook(true);
    const driver = makeDriver();
    renderPulse(driver);

    act(() => dispatch?.({ type: 'defence_event', data: { entity_ids: [1] } }));

    expect(driver.dispatch).not.toHaveBeenCalled();
  });
});

describe('useGraphPulse — polling fallback gated on connection', () => {
  it('does NOT poll while the socket is connected', () => {
    jest.useFakeTimers();
    global.fetch = jest.fn();
    primeHook(true);
    renderPulse(makeDriver());

    act(() => jest.advanceTimersByTime(30_000));

    expect(global.fetch).not.toHaveBeenCalled();
  });

  it('polls when the socket is down', () => {
    jest.useFakeTimers();
    global.fetch = jest.fn().mockResolvedValue({ ok: true, json: async () => ({ memories: [] }) });
    primeHook(false);
    renderPulse(makeDriver());

    act(() => jest.advanceTimersByTime(10_000));

    expect(global.fetch).toHaveBeenCalledTimes(1);
  });
});
