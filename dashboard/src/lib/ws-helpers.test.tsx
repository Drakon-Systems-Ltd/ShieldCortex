import { shouldInvalidateTokenOnClose, wsGatedInterval } from './ws-helpers';

describe('shouldInvalidateTokenOnClose', () => {
  // The server rejects bad/absent tokens with 4401 and a generic policy
  // violation with 1008/4001/4003. On any of those the cached token is dead
  // (e.g. server restarted with a fresh session secret) and must be refetched.
  it.each([1008, 4001, 4003, 4401])('invalidates on auth close code %i', (code) => {
    expect(shouldInvalidateTokenOnClose(code)).toBe(true);
  });

  // Normal closes and the connection-cap close are NOT auth failures — the
  // token is still valid, so we must keep it and just reconnect.
  it.each([1000, 1001, 1006, 4429])('keeps the token on non-auth close code %i', (code) => {
    expect(shouldInvalidateTokenOnClose(code)).toBe(false);
  });
});

describe('wsGatedInterval', () => {
  it('disables polling when the websocket is connected (WS drives freshness)', () => {
    expect(wsGatedInterval(true, 30000)).toBe(false);
  });

  it('falls back to the polling interval when the websocket is down', () => {
    expect(wsGatedInterval(false, 30000)).toBe(30000);
  });

  it('preserves the caller-supplied interval', () => {
    expect(wsGatedInterval(false, 60000)).toBe(60000);
  });
});
