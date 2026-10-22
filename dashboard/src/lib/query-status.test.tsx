import {
  combineStatus,
  countText,
  firewallPill,
  ironDomePill,
  operationsPill,
  pillFor,
  queryStatus,
  scanningPill,
  updateCheckOutcome,
  updateCheckRow,
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

describe('Iron Dome / scanning / operations pills', () => {
  it('Iron Dome and scanning derive from enabled, overridden by status', () => {
    expect(ironDomePill('confirmed', true)).toEqual({ state: 'ok', text: 'on' });
    expect(ironDomePill('confirmed', false)).toEqual({ state: 'off', text: 'off' });
    expect(ironDomePill('pending', undefined)).toEqual({ state: 'unknown', text: 'checking…' });
    expect(ironDomePill('unavailable', undefined)).toEqual({ state: 'unavailable', text: 'unavailable' });
    expect(scanningPill('confirmed', true)).toEqual({ state: 'ok', text: 'on (injection scanner)' });
    expect(scanningPill('confirmed', false).state).toBe('off');
    expect(scanningPill('stale', true).state).toBe('warn');
  });
  it('Iron Dome: a malformed enabled is unknown, never truthy-on (#693)', () => {
    for (const bad of ['true', 'false', 1, null, undefined, {}]) {
      expect(ironDomePill('confirmed', bad)).toEqual({ state: 'unknown', text: 'unknown (unreadable status)' });
      expect(scanningPill('confirmed', bad).state).toBe('unknown');
    }
  });
  it('Iron Dome: a failed refetch does not keep a last-known "on" (#693)', () => {
    expect(ironDomePill('stale', true)).toEqual({ state: 'warn', text: 'unconfirmed · refetch failed' });
    expect(ironDomePill('stale', true).text).not.toMatch(/\bon\b/);
    expect(ironDomePill('stale', false)).toEqual({ state: 'off', text: 'off · stale (refetch failed)' });
  });
  it('operations: emergency stop beats paused beats mode', () => {
    expect(operationsPill('confirmed', { killSwitchActive: true, paused: true, mode: 'x' })).toEqual({ state: 'fail', text: 'emergency stop' });
    expect(operationsPill('confirmed', { paused: true, mode: 'x' })).toEqual({ state: 'warn', text: 'paused' });
    expect(operationsPill('confirmed', { mode: 'autonomous' })).toEqual({ state: 'ok', text: 'autonomous' });
    expect(operationsPill('unavailable', undefined).state).toBe('unavailable');
  });
});

describe('update check display (#631)', () => {
  const base = { currentVersion: '5.3.1', runningVersion: '5.3.1' };

  it('a disabled check is shown as off, never as up to date or available', () => {
    const data = { ...base, latestVersion: null, updateAvailable: false, checkStatus: 'disabled' as const, checkDisabledBy: 'config' as const };
    expect(updateCheckOutcome(data)).toBe('disabled');
    expect(updateCheckRow(data)).toEqual({
      kind: 'notice',
      text: 'Automatic update check is off (dashboardUpdateCheck: false) — running v5.3.1; newer releases are not looked up.',
    });
  });

  it('names the env switch when that is what disabled it', () => {
    const row = updateCheckRow({ ...base, latestVersion: null, updateAvailable: false, checkStatus: 'disabled', checkDisabledBy: 'env' });
    expect(row).toMatchObject({ kind: 'notice' });
    expect((row as { text: string }).text).toContain('SHIELDCORTEX_SKIP_UPDATE_CHECK');
  });

  it('disabled wins even over a stale updateAvailable flag', () => {
    expect(updateCheckOutcome({ ...base, latestVersion: '9.9.9', updateAvailable: true, checkStatus: 'disabled' })).toBe('disabled');
  });

  it('a failed lookup is unavailable, not clear', () => {
    expect(updateCheckRow({ ...base, latestVersion: null, updateAvailable: false, checkStatus: 'failed' })).toEqual({ kind: 'unavailable' });
  });

  it('a newer version is an actionable item', () => {
    expect(updateCheckRow({ ...base, latestVersion: '9.9.9', updateAvailable: true, checkStatus: 'ok' })).toEqual({
      kind: 'item',
      label: 'Newer version available — v9.9.9',
      detail: 'Running v5.3.1.',
    });
  });

  it('only a registry answer with no newer version is up to date (no row)', () => {
    expect(updateCheckOutcome({ ...base, latestVersion: '5.3.1', updateAvailable: false, checkStatus: 'ok' })).toBe('up-to-date');
    expect(updateCheckRow({ ...base, latestVersion: '5.3.1', updateAvailable: false, checkStatus: 'ok' })).toEqual({ kind: 'none' });
  });

  it('servers that predate checkStatus: null latestVersion was a failed lookup', () => {
    expect(updateCheckOutcome({ ...base, latestVersion: null, updateAvailable: false })).toBe('failed');
    expect(updateCheckOutcome({ ...base, latestVersion: '5.3.1', updateAvailable: false })).toBe('up-to-date');
    expect(updateCheckOutcome({ ...base, latestVersion: '9.9.9', updateAvailable: true })).toBe('update-available');
  });
});
