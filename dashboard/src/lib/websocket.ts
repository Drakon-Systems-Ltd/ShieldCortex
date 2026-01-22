/**
 * WebSocket client for real-time memory updates
 *
 * Connects to the visualization server's WebSocket endpoint
 * and dispatches events to React Query for cache invalidation.
 */

import { useEffect, useRef, useCallback, useState } from 'react';
import { useQueryClient } from '@tanstack/react-query';

const WS_URL = process.env.NEXT_PUBLIC_WS_URL || 'ws://localhost:3001/ws/events';

export type WebSocketEventType =
  | 'initial_state'
  | 'memory_created'
  | 'memory_updated'
  | 'memory_deleted'
  | 'consolidation_complete'
  | 'decay_tick';

interface WebSocketMessage {
  type: WebSocketEventType;
  data?: unknown;
}

interface UseMemoryWebSocketOptions {
  enabled?: boolean;
  onMessage?: (event: WebSocketMessage) => void;
}

/**
 * Hook to connect to memory WebSocket and handle real-time updates
 */
export function useMemoryWebSocket(options: UseMemoryWebSocketOptions = {}) {
  const { enabled = true, onMessage } = options;
  const queryClient = useQueryClient();
  const wsRef = useRef<WebSocket | null>(null);
  const reconnectTimeoutRef = useRef<NodeJS.Timeout | null>(null);
  const [isConnected, setIsConnected] = useState(false);
  const [lastEvent, setLastEvent] = useState<WebSocketEventType | null>(null);

  const connect = useCallback(() => {
    if (!enabled || wsRef.current?.readyState === WebSocket.OPEN) return;

    try {
      const ws = new WebSocket(WS_URL);
      wsRef.current = ws;

      ws.onopen = () => {
        setIsConnected(true);
        console.log('[WebSocket] Connected to memory server');
      };

      ws.onmessage = (event) => {
        try {
          const message = JSON.parse(event.data) as WebSocketMessage;
          setLastEvent(message.type);

          // Notify external handler
          onMessage?.(message);

          // Invalidate relevant queries based on event type
          switch (message.type) {
            case 'initial_state':
              // Full state received, refresh everything
              queryClient.invalidateQueries({ queryKey: ['memories'] });
              queryClient.invalidateQueries({ queryKey: ['stats'] });
              queryClient.invalidateQueries({ queryKey: ['links'] });
              break;

            case 'memory_created':
            case 'memory_updated':
            case 'memory_deleted':
              // Memory changed, refresh memories list
              queryClient.invalidateQueries({ queryKey: ['memories'] });
              queryClient.invalidateQueries({ queryKey: ['stats'] });
              break;

            case 'consolidation_complete':
              // Major changes, refresh everything
              queryClient.invalidateQueries({ queryKey: ['memories'] });
              queryClient.invalidateQueries({ queryKey: ['stats'] });
              queryClient.invalidateQueries({ queryKey: ['links'] });
              break;

            case 'decay_tick':
              // Just decay scores updated, soft refresh
              // We don't invalidate here to avoid constant refetches
              // The dashboard can handle this via the onMessage callback
              break;
          }
        } catch (err) {
          console.error('[WebSocket] Failed to parse message:', err);
        }
      };

      ws.onerror = (error) => {
        console.error('[WebSocket] Error:', error);
      };

      ws.onclose = () => {
        setIsConnected(false);
        console.log('[WebSocket] Disconnected');

        // Attempt to reconnect after 5 seconds
        if (enabled) {
          reconnectTimeoutRef.current = setTimeout(() => {
            console.log('[WebSocket] Attempting to reconnect...');
            connect();
          }, 5000);
        }
      };
    } catch (err) {
      console.error('[WebSocket] Failed to connect:', err);
    }
  }, [enabled, queryClient, onMessage]);

  // Connect on mount
  useEffect(() => {
    if (enabled) {
      connect();
    }

    return () => {
      if (reconnectTimeoutRef.current) {
        clearTimeout(reconnectTimeoutRef.current);
      }
      if (wsRef.current) {
        wsRef.current.close();
        wsRef.current = null;
      }
    };
  }, [enabled, connect]);

  return {
    isConnected,
    lastEvent,
    reconnect: connect,
  };
}
