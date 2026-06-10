/**
 * Phase 17 B3: WebSocket server hardening for the localhost dashboard socket.
 *
 * The `ws` server had no heartbeat, no payload cap, and no connection limit:
 *   - dead sockets leaked (no ping/pong liveness check),
 *   - an unbounded inbound frame could be buffered,
 *   - unlimited connections could pile up.
 *
 * The live server wiring (maxPayload option, cap check in the connection
 * handler, interval cleared on shutdown) is integration-level — booting the
 * full Express+ws server in jest is impractical. What's unit-testable, and
 * what these tests cover, is the heartbeat helper and the exported config
 * constants the server is wired with.
 */
import { afterEach, describe, expect, it, jest } from '@jest/globals';
import {
  setupWebSocketHeartbeat,
  WS_MAX_PAYLOAD,
  WS_MAX_CONNECTIONS,
  WS_HEARTBEAT_MS,
} from '../visualization-server.js';

type FakeSocket = {
  isAlive?: boolean;
  pingCalls: number;
  terminateCalls: number;
  ping: () => void;
  terminate: () => void;
};

function makeSocket(isAlive: boolean | undefined): FakeSocket {
  const s: FakeSocket = {
    isAlive,
    pingCalls: 0,
    terminateCalls: 0,
    ping() { this.pingCalls++; },
    terminate() { this.terminateCalls++; },
  };
  return s;
}

/** Minimal stand-in for the bits of WebSocketServer the heartbeat touches. */
function makeWss(sockets: Set<FakeSocket>) {
  let closeHandler: (() => void) | null = null;
  return {
    clients: sockets as unknown as Set<unknown>,
    on(event: string, cb: () => void) {
      if (event === 'close') closeHandler = cb;
    },
    fireClose() { closeHandler?.(); },
  };
}

describe('B3: WebSocket hardening', () => {
  afterEach(() => {
    jest.useRealTimers();
  });

  it('exposes sane config constants for a localhost dashboard socket', () => {
    expect(WS_MAX_PAYLOAD).toBe(1024 * 1024);
    expect(WS_MAX_CONNECTIONS).toBe(50);
    expect(WS_HEARTBEAT_MS).toBeGreaterThan(0);
  });

  it('heartbeat pings live sockets and terminates ones that missed the prior ping', () => {
    jest.useFakeTimers();
    const live = makeSocket(true);
    const dead = makeSocket(false); // already failed to pong since last tick
    const sockets = new Set<FakeSocket>([live, dead]);
    const wss = makeWss(sockets);

    const interval = setupWebSocketHeartbeat(wss as never, 1000);

    jest.advanceTimersByTime(1000);

    // The dead socket is terminated, never pinged.
    expect(dead.terminateCalls).toBe(1);
    expect(dead.pingCalls).toBe(0);

    // The live socket is pinged and flipped to awaiting-pong (isAlive=false).
    expect(live.pingCalls).toBe(1);
    expect(live.terminateCalls).toBe(0);
    expect(live.isAlive).toBe(false);

    clearInterval(interval);
  });

  it('clears the heartbeat interval when the server closes', () => {
    jest.useFakeTimers();
    const live = makeSocket(true);
    const sockets = new Set<FakeSocket>([live]);
    const wss = makeWss(sockets);

    setupWebSocketHeartbeat(wss as never, 1000);

    // Server closes — the interval must stop firing.
    wss.fireClose();

    live.isAlive = true;
    live.pingCalls = 0;
    jest.advanceTimersByTime(5000);

    expect(live.pingCalls).toBe(0); // no further pings after close
  });
});
