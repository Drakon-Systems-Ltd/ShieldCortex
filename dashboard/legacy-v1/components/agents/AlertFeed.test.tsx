import { act, render, screen } from '@testing-library/react';
import type { WebSocketMessage } from '@/lib/websocket';
import { MemoryWebSocketProvider } from '@/components/MemoryWebSocketProvider';
import { AlertFeed } from './AlertFeed';

// Drive the shared connection: AlertFeed must receive defence_events through the
// authenticated provider, not its own (token-less, 4401'd) socket.
jest.mock('@/lib/websocket', () => ({
  __esModule: true,
  useMemoryWebSocket: jest.fn(),
}));
import { useMemoryWebSocket } from '@/lib/websocket';
const mockHook = useMemoryWebSocket as jest.Mock;
let dispatch: ((m: WebSocketMessage) => void) | undefined;

beforeEach(() => {
  mockHook.mockReset();
  dispatch = undefined;
  mockHook.mockImplementation((opts: { onMessage?: (m: WebSocketMessage) => void }) => {
    dispatch = opts?.onMessage;
    return { isConnected: true, connectionFailed: false, lastEvent: null, reconnect: jest.fn() };
  });
});

function renderFeed(props: { agentFilter?: string } = {}) {
  return render(
    <MemoryWebSocketProvider>
      <AlertFeed {...props} />
    </MemoryWebSocketProvider>,
  );
}

function defenceEvent(over: Record<string, unknown> = {}): WebSocketMessage {
  return {
    type: 'defence_event',
    data: {
      source_type: 'agent',
      source_identifier: 'agent:rogue',
      firewall_result: 'BLOCK',
      trust_score: 0.2,
      reason: 'prompt injection',
      timestamp: '2026-06-15T00:00:00.000Z',
      ...over,
    },
  };
}

describe('AlertFeed', () => {
  it('shows the listening placeholder before any event', () => {
    renderFeed();
    expect(screen.getByText(/Listening for defence events/i)).toBeInTheDocument();
  });

  it('renders a row when a defence_event arrives on the shared connection', () => {
    renderFeed();
    act(() => dispatch?.(defenceEvent()));
    expect(screen.getByText('BLOCK')).toBeInTheDocument();
    expect(screen.getByText(/agent:rogue/)).toBeInTheDocument();
  });

  it('ignores non-defence events', () => {
    renderFeed();
    act(() => dispatch?.({ type: 'memory_created', data: {} }));
    expect(screen.getByText(/Listening for defence events/i)).toBeInTheDocument();
  });

  it('honours agentFilter', () => {
    renderFeed({ agentFilter: 'agent:keep' });
    act(() => dispatch?.(defenceEvent({ source_identifier: 'agent:other' })));
    expect(screen.getByText(/Listening for defence events/i)).toBeInTheDocument();

    act(() => dispatch?.(defenceEvent({ source_identifier: 'agent:keep', firewall_result: 'QUARANTINE' })));
    expect(screen.getByText('QUARANTINE')).toBeInTheDocument();
  });
});
