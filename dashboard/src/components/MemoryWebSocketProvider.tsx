'use client';

/**
 * MemoryWebSocketProvider
 *
 * One authenticated WebSocket for the whole dashboard. Before this, several
 * components opened their own sockets — three of them token-less, so the server
 * closed them with 4401 and their features (defence feed, connection dot, graph
 * pulse) ran silently broken. This provider holds a single `useMemoryWebSocket`
 * (which carries the auth token and drives React Query invalidation) and fans
 * every message out to subscribers, so every consumer rides the one connection
 * that actually authenticates.
 *
 * Mounted in AppShell — inside QueryClientProvider (the hook needs it) and
 * dashboard-only (no socket on bare/auth routes).
 */

import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useRef,
} from 'react';
import {
  useMemoryWebSocket,
  type WebSocketEventType,
  type WebSocketMessage,
} from '@/lib/websocket';

type Subscriber = (msg: WebSocketMessage) => void;

interface LastEvent {
  type: WebSocketEventType;
  data?: unknown;
  timestamp: string;
}

interface MemoryWebSocketContextValue {
  /** Register a message handler; returns an unsubscribe fn. */
  subscribe: (cb: Subscriber) => () => void;
  isConnected: boolean;
  connectionFailed: boolean;
  lastEvent: LastEvent | null;
  reconnect: () => void;
}

const noop = () => {};

// Default value degrades gracefully outside a provider: no live events, polling
// stays on (isConnected=false), nothing throws.
const defaultValue: MemoryWebSocketContextValue = {
  subscribe: () => noop,
  isConnected: false,
  connectionFailed: false,
  lastEvent: null,
  reconnect: noop,
};

const MemoryWebSocketContext = createContext<MemoryWebSocketContextValue>(defaultValue);

export function MemoryWebSocketProvider({ children }: { children: React.ReactNode }) {
  const subscribersRef = useRef<Set<Subscriber>>(new Set());

  // Single fan-out dispatcher handed to the one underlying connection.
  const dispatch = useCallback((msg: WebSocketMessage) => {
    // Snapshot so a subscriber that unsubscribes mid-dispatch can't corrupt the
    // iteration, and one throwing handler can't starve the others.
    for (const cb of Array.from(subscribersRef.current)) {
      try {
        cb(msg);
      } catch {
        /* a misbehaving subscriber must not break the rest */
      }
    }
  }, []);

  const { isConnected, connectionFailed, lastEvent, reconnect } = useMemoryWebSocket({
    onMessage: dispatch,
  });

  const subscribe = useCallback((cb: Subscriber) => {
    subscribersRef.current.add(cb);
    return () => {
      subscribersRef.current.delete(cb);
    };
  }, []);

  const value = useMemo<MemoryWebSocketContextValue>(
    () => ({ subscribe, isConnected, connectionFailed, lastEvent, reconnect }),
    [subscribe, isConnected, connectionFailed, lastEvent, reconnect],
  );

  return (
    <MemoryWebSocketContext.Provider value={value}>
      {children}
    </MemoryWebSocketContext.Provider>
  );
}

export function useMemoryWebSocketContext(): MemoryWebSocketContextValue {
  return useContext(MemoryWebSocketContext);
}

/** Connection status for indicators + poll gating. */
export function useWebSocketStatus(): {
  isConnected: boolean;
  connectionFailed: boolean;
  reconnect: () => void;
} {
  const { isConnected, connectionFailed, reconnect } = useMemoryWebSocketContext();
  return { isConnected, connectionFailed, reconnect };
}

/**
 * Subscribe a handler to the shared connection for the component's lifetime.
 * Subscribes once (stable `subscribe`) and always calls the latest handler via
 * a ref, so re-renders don't churn the subscription or capture stale closures.
 */
export function useWebSocketEvent(handler: Subscriber): void {
  const { subscribe } = useMemoryWebSocketContext();
  const handlerRef = useRef(handler);
  useEffect(() => {
    handlerRef.current = handler;
  });
  useEffect(() => subscribe((msg) => handlerRef.current(msg)), [subscribe]);
}
