'use client';

import { useEffect, useRef } from 'react';
import type { PulseDriver } from '@/components/graph/constellation/pulse';
import { useMemoryWebSocketContext } from '@/components/MemoryWebSocketProvider';

const API_BASE = process.env.NEXT_PUBLIC_API_URL || 'http://localhost:3001';
const POLL_INTERVAL_MS = 10_000;

/**
 * Drives a PulseDriver from memory events on the shared, authenticated
 * WebSocket. When the socket is down it falls back to polling
 * GET /api/memories?mode=recent, synthesising memory.created pulses from rows
 * newer than the last seen created_at.
 *
 * The fallback is gated on `!isConnected` (the live "currently down" flag) — NOT
 * the give-up flag — so a brief drop resumes live pulses on reconnect and the
 * poll stops the instant the socket is back (no double-source flicker).
 */
export function useGraphPulse(driver: PulseDriver | null, enabled: boolean = true): void {
  const { subscribe, isConnected } = useMemoryWebSocketContext();
  const lastSeenRef = useRef<string | null>(null);

  // Live path — dispatch pulses from the shared connection's memory events.
  useEffect(() => {
    if (!driver || !enabled) return;
    return subscribe((msg) => {
      // Server contract: memory_created / memory_accessed carry entity_ids: number[].
      const obj = msg as { type?: string; data?: { entity_ids?: number[] } };
      if (!obj?.type || !obj.data) return;
      const pulseType =
        obj.type === 'memory_created' ? 'memory.created' :
        obj.type === 'memory_accessed' ? 'memory.accessed' : null;
      if (!pulseType) return;
      for (const id of obj.data.entity_ids ?? []) {
        driver.dispatch({ type: pulseType, entityId: String(id) });
      }
    });
  }, [driver, enabled, subscribe]);

  // Fallback path — poll only while the socket is down.
  useEffect(() => {
    if (!driver || !enabled || isConnected) return;
    let cancelled = false;
    const timer = setInterval(() => {
      const since = lastSeenRef.current;
      fetch(`${API_BASE}/api/memories?mode=recent&limit=50`, { credentials: 'include' })
        .then((r) => (r.ok ? r.json() : null))
        .then((data) => {
          if (!data || cancelled) return;
          const rows: Array<{ created_at?: string; entity_ids?: number[] }> = data.memories ?? [];
          for (const row of rows) {
            if (since && row.created_at && row.created_at <= since) continue;
            for (const id of row.entity_ids ?? []) {
              driver.dispatch({ type: 'memory.created', entityId: String(id) });
            }
          }
          if (rows[0]?.created_at) lastSeenRef.current = rows[0].created_at;
        })
        .catch(() => { /* silent — already on fallback; nothing to escalate */ });
    }, POLL_INTERVAL_MS);

    return () => {
      cancelled = true;
      clearInterval(timer);
    };
  }, [driver, enabled, isConnected]);
}
