'use client';

import { useEffect, useRef } from 'react';
import type { PulseDriver } from '@/components/graph/constellation/pulse';

const API_BASE = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:3001';
const POLL_INTERVAL_MS = 10_000;

/**
 * Subscribes the given PulseDriver to /ws/events and dispatches
 * memory.created / memory.accessed events to it. On WS failure it falls back
 * to polling GET /api/memories?mode=recent every 10 seconds, synthesising
 * memory.created events from rows newer than the last seen created_at.
 */
export function useGraphPulse(
  driver: PulseDriver | null,
  enabled: boolean = true,
): void {
  const lastSeenRef = useRef<string | null>(null);

  useEffect(() => {
    if (!driver || !enabled) return;

    let ws: WebSocket | null = null;
    let pollTimer: ReturnType<typeof setInterval> | null = null;
    let cancelled = false;

    const dispatchEvent = (raw: unknown): void => {
      if (!driver) return;
      // Server contract (set by Task 7.5 in this plan):
      //   memory_created  → data: { memory, entity_ids: number[] }
      //   memory_accessed → data: { memoryId, memory, newSalience, entity_ids: number[] }
      const obj = raw as { type?: string; data?: { entity_ids?: number[] } };
      if (!obj?.type || !obj.data) return;
      const pulseType =
        obj.type === 'memory_created'  ? 'memory.created' :
        obj.type === 'memory_accessed' ? 'memory.accessed' : null;
      if (!pulseType) return;
      const ids = obj.data.entity_ids ?? [];
      for (const id of ids) driver.dispatch({ type: pulseType, entityId: String(id) });
    };

    const startPolling = (): void => {
      if (pollTimer) return;
      pollTimer = setInterval(() => {
        if (cancelled) return;
        const since = lastSeenRef.current;
        fetch(`${API_BASE}/api/memories?mode=recent&limit=50`, { credentials: 'include' })
          .then((r) => (r.ok ? r.json() : null))
          .then((data) => {
            if (!data || cancelled) return;
            // Server contract (Task 7.5): each memory row carries entity_ids: number[].
            const rows: Array<{ created_at?: string; entity_ids?: number[] }> = data.memories ?? [];
            for (const row of rows) {
              if (since && row.created_at && row.created_at <= since) continue;
              for (const id of row.entity_ids ?? []) {
                driver.dispatch({ type: 'memory.created', entityId: String(id) });
              }
            }
            if (rows[0]?.created_at) lastSeenRef.current = rows[0].created_at;
          })
          .catch(() => { /* silent — fallback already; nothing to escalate */ });
      }, POLL_INTERVAL_MS);
    };

    const connect = (): void => {
      try {
        const wsUrl = API_BASE.replace(/^http/, 'ws') + '/ws/events';
        ws = new WebSocket(wsUrl);
        ws.onmessage = (e) => {
          try { dispatchEvent(JSON.parse(e.data)); } catch { /* ignore non-JSON */ }
        };
        ws.onerror = startPolling;
        ws.onclose = () => { if (!cancelled) startPolling(); };
      } catch {
        startPolling();
      }
    };

    connect();

    return () => {
      cancelled = true;
      ws?.close();
      if (pollTimer) clearInterval(pollTimer);
    };
  }, [driver, enabled]);
}
