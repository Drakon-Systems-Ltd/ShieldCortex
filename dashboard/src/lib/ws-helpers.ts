/**
 * Pure helpers for the real-time WebSocket layer.
 *
 * Kept free of React so the connection/auth policy is unit-testable on its own
 * and shared between the socket client (close-code handling) and the data hooks
 * (poll gating).
 */

/**
 * WebSocket close codes that mean the cached session token is no longer valid.
 *
 * The visualization server closes with 4401 when the token is absent or fails
 * validation (e.g. after a restart that rotated the session secret). 1008 /
 * 4001 / 4003 are policy/auth rejections. On any of these the client must drop
 * the cached token and fetch a fresh one before reconnecting — otherwise it
 * loops forever presenting the same dead token. 4429 (connection cap) and the
 * normal-closure codes leave the token valid.
 */
const TOKEN_INVALIDATING_CLOSE_CODES = new Set([1008, 4001, 4003, 4401]);

export function shouldInvalidateTokenOnClose(code: number): boolean {
  return TOKEN_INVALIDATING_CLOSE_CODES.has(code);
}

/**
 * Refetch interval for a query whose cache the WebSocket already invalidates.
 *
 * When the socket is connected, real-time invalidation keeps the data fresh, so
 * background polling is pure overhead (and races the invalidation → flicker).
 * Return `false` to disable the poll while connected; fall back to the given
 * interval only when the socket is down.
 */
export function wsGatedInterval(isConnected: boolean, intervalMs: number): number | false {
  return isConnected ? false : intervalMs;
}
