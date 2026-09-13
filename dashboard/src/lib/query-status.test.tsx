import {
  combineStatus,
  countText,
  firewallPill,
  guardPill,
  operationsPill,
  pillFor,
  queryStatus,
  scanningPill,
  type FirewallMode,
} from './query-status';

describe('queryStatus (review item 5 — one honest mapping from React Query state)', () => {
  it('maps the four states', () => {
    expect(queryStatus({ data: undefined, isError: false })).toBe('pending');
    expect(queryStatus({ data: undefined, isError: true })).toBe('unavailable');
    expect(queryStatus({ data: { x: 1 }, isError: true })).toBe('stale');
    expect(queryStatus({ data: { x: 1 }, isError: false })).toBe('confirmed');
    // A real zero/false/empty payload is still data, not "pending".
    expect(queryStatus({ data: 0, isError: false })).toBe('confirmed');
    expect(queryStatus({ data: null, isError: false })).toBe('confirmed');
  });

  it('combineStatus takes the worst', () => {
    expect(combineStatus('confirmed', 'stale')).toBe('stale');
    expect(combineStatus('stale', 'pending', 'confirmed')).toBe('pending');
    expect(combineStatus('pending', 'unavailable')).toBe('unavailable');
    expect(combineStatus()).toBe('confirmed');
  });
});

describe('pillFor', () => {
  const ok = { state: 'ok' as const, text: 'on' };
  it('never renders green while pending or unavailable', () => {
    expect(pillFor('pending', ok)).toEqual({ state: 'unknown', text: 'checking…' });
    expect(pillFor('unavailable', ok)).toEqual({ state: 'unavailable', text: 'unavailable' });
  });
  it('downgrades a stale ok to warn but keeps a stale problem coloured as a problem', () => {
    expect(pillFor('stale', ok)).toEqual({ state: 'warn', text: 'on · stale (refetch failed)' });
    expect(pillFor('stale', { state: 'fail', text: 'emergency stop' }).state).toBe('fail');
    expect(pillFor('stale', { state: 'off', text: 'off' }).state).toBe('off');
  });
  it('passes a confirmed pill through', () => {
    expect(pillFor('confirmed', ok)).toBe(ok);
  });
});

describe('countText', () => {
  it("never fabricates a zero: '…' pending, '—' unavailable, number otherwise", () => {
    expect(countText(undefined, 'pending')).toBe('…');
    expect(countText(undefined, 'unavailable')).toBe('—');
    expect(countText(5, 'unavailable')).toBe('—');
    expect(countText(0, 'confirmed')).toBe('0');
    expect(countText(1234, 'stale')).toBe('1,234');
  });
});

describe('firewallPill', () => {
  it('tampered is never green, in any mode or status', () => {
    for (const mode of ['strict', 'balanced', 'permissive'] as FirewallMode[]) {
      for (const status of ['confirmed', 'stale'] as const) {
        const p = firewallPill(status, { mode, tampered: true });
        expect(p.state).toBe('fail');
        expect(p.text).toContain('tampered');
      }
    }
  });
  it('labels permissive honestly as advisory, not "enforced"', () => {
    const p = firewallPill('confirmed', { mode: 'permissive', tampered: false });
    expect(p.state).toBe('warn');
    expect(p.text).toContain('advisory');
    expect(p.text).not.toContain('enforced');
  });
  it('strict/balanced are enforced and green only when confirmed', () => {
    expect(firewallPill('confirmed', { mode: 'strict', tampered: false })).toEqual({ state: 'ok', text: 'enforced (strict)' });
    expect(firewallPill('stale', { mode: 'balanced', tampered: false }).state).toBe('warn');
    expect(firewallPill('pending', undefined)).toEqual({ state: 'unknown', text: 'checking…' });
    expect(firewallPill('unavailable', undefined)).toEqual({ state: 'unavailable', text: 'unavailable' });
  });
});

describe('guard / scanning / operations pills', () => {
  it('guard and scanning derive from enabled, overridden by status', () => {
    expect(guardPill('confirmed', true)).toEqual({ state: 'ok', text: 'on' });
    expect(guardPill('confirmed', false)).toEqual({ state: 'off', text: 'off' });
    expect(guardPill('pending', undefined).state).toBe('unknown');
    expect(guardPill('unavailable', undefined).state).toBe('unavailable');
    expect(scanningPill('confirmed', true)).toEqual({ state: 'ok', text: 'on (injection scanner)' });
    expect(scanningPill('confirmed', false).state).toBe('off');
    expect(scanningPill('stale', true).state).toBe('warn');
  });
  it('operations: emergency stop beats paused beats mode', () => {
    expect(operationsPill('confirmed', { killSwitchActive: true, paused: true, mode: 'x' })).toEqual({ state: 'fail', text: 'emergency stop' });
    expect(operationsPill('confirmed', { paused: true, mode: 'x' })).toEqual({ state: 'warn', text: 'paused' });
    expect(operationsPill('confirmed', { mode: 'autonomous' })).toEqual({ state: 'ok', text: 'autonomous' });
    expect(operationsPill('unavailable', undefined).state).toBe('unavailable');
  });
});
