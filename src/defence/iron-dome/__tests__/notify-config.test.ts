/**
 * ShieldCortex — operator-notify configuration (#143).
 *
 * Same trust-boundary discipline as broker-config.ts, which this deliberately
 * mirrors: config lives on disk, and on a box the agent has already been
 * talked into misusing, "on disk" means "reachable". So: allowlist the
 * fields, bound the numbers, treat anything unrecognised as absent, and —
 * the one rule that matters — **default OFF** (issue #143 requirement 7:
 * nothing changes for an operator who has not opted in).
 */
import { describe, it, expect } from '@jest/globals';
import { normaliseNotifyConfig, DEFAULT_NOTIFY_CONFIG } from '../notify-config.js';

describe('normaliseNotifyConfig — default off', () => {
  it('is disabled with no config at all', () => {
    expect(normaliseNotifyConfig(undefined).enabled).toBe(false);
  });

  it('is disabled for null, an array, or a primitive', () => {
    expect(normaliseNotifyConfig(null).enabled).toBe(false);
    expect(normaliseNotifyConfig([1, 2, 3]).enabled).toBe(false);
    expect(normaliseNotifyConfig('enabled').enabled).toBe(false);
    expect(normaliseNotifyConfig(42).enabled).toBe(false);
  });

  it('requires enabled to be the literal boolean true, not merely truthy', () => {
    expect(normaliseNotifyConfig({ enabled: 'true' }).enabled).toBe(false);
    expect(normaliseNotifyConfig({ enabled: 1 }).enabled).toBe(false);
    expect(normaliseNotifyConfig({ enabled: 'yes' }).enabled).toBe(false);
    expect(normaliseNotifyConfig({ enabled: true }).enabled).toBe(true);
  });

  it('matches the exported default exactly when given nothing', () => {
    expect(normaliseNotifyConfig({})).toEqual(DEFAULT_NOTIFY_CONFIG);
  });
});

describe('normaliseNotifyConfig — webhookUrl validation', () => {
  it('accepts an https URL', () => {
    const cfg = normaliseNotifyConfig({ enabled: true, webhookUrl: 'https://ops.example.com/hook' });
    expect(cfg.webhookUrl).toBe('https://ops.example.com/hook');
  });

  it('accepts an http URL (local relay, e.g. localhost bridge)', () => {
    const cfg = normaliseNotifyConfig({ enabled: true, webhookUrl: 'http://127.0.0.1:8787/notify' });
    expect(cfg.webhookUrl).toBe('http://127.0.0.1:8787/notify');
  });

  it.each([
    'javascript:alert(1)',
    'file:///etc/passwd',
    'data:text/html,<script>evil()</script>',
    'ftp://example.com/x',
    'not-a-url-at-all',
    '',
  ])('rejects a non-http(s) or malformed URL: %s', (bad) => {
    const cfg = normaliseNotifyConfig({ enabled: true, webhookUrl: bad });
    expect(cfg.webhookUrl).toBeUndefined();
  });

  it('rejects a non-string webhookUrl', () => {
    expect(normaliseNotifyConfig({ enabled: true, webhookUrl: 12345 }).webhookUrl).toBeUndefined();
    expect(normaliseNotifyConfig({ enabled: true, webhookUrl: { url: 'https://x' } }).webhookUrl).toBeUndefined();
  });

  it('rejects an implausibly long webhookUrl rather than truncating it silently', () => {
    const huge = 'https://example.com/' + 'a'.repeat(5_000);
    expect(normaliseNotifyConfig({ enabled: true, webhookUrl: huge }).webhookUrl).toBeUndefined();
  });
});

describe('normaliseNotifyConfig — webhookSecret (#143)', () => {
  // Without a secret the webhook channel can only ever send UNAUTHENTICATED
  // POSTs, and any receiver worth pointing it at — one that can page a human
  // or re-run a killed job — has to reject unsigned requests. The channel has
  // always been able to sign; until now nothing could give it the key.
  it('accepts a plausible key and hands it through', () => {
    expect(normaliseNotifyConfig({ enabled: true, webhookSecret: 's3cret-key' }).webhookSecret).toBe('s3cret-key');
  });

  it('is absent by default — signing is opt-in, exactly like everything else here', () => {
    expect(normaliseNotifyConfig({ enabled: true }).webhookSecret).toBeUndefined();
    expect(DEFAULT_NOTIFY_CONFIG.webhookSecret).toBeUndefined();
  });

  it('drops a non-string rather than signing over "[object Object]"', () => {
    for (const junk of [12345, { secret: 'x' }, ['x'], true, null]) {
      expect(normaliseNotifyConfig({ enabled: true, webhookSecret: junk }).webhookSecret).toBeUndefined();
    }
  });

  it('drops an over-long value rather than truncating it into a key nothing shares', () => {
    // A silently truncated key produces a signature the receiver can never
    // reproduce — a 401 with no explanation. Absent is the honest state.
    const huge = 'k'.repeat(5_000);
    expect(normaliseNotifyConfig({ enabled: true, webhookSecret: huge }).webhookSecret).toBeUndefined();
  });

  it('treats empty or whitespace-only as absent, and trims the surrounding whitespace a config file collects', () => {
    expect(normaliseNotifyConfig({ enabled: true, webhookSecret: '' }).webhookSecret).toBeUndefined();
    expect(normaliseNotifyConfig({ enabled: true, webhookSecret: '   \n' }).webhookSecret).toBeUndefined();
    expect(normaliseNotifyConfig({ enabled: true, webhookSecret: '  abc123\n' }).webhookSecret).toBe('abc123');
  });

  it('survives without a webhookUrl — a key configured before the URL is not silently thrown away', () => {
    expect(normaliseNotifyConfig({ enabled: true, webhookSecret: 'abc' }).webhookSecret).toBe('abc');
  });
});

describe('normaliseNotifyConfig — timeoutMs bounds', () => {
  it('defaults when absent, non-numeric, or out of range', () => {
    expect(normaliseNotifyConfig({ enabled: true }).timeoutMs).toBe(DEFAULT_NOTIFY_CONFIG.timeoutMs);
    expect(normaliseNotifyConfig({ enabled: true, timeoutMs: 'soon' }).timeoutMs).toBe(DEFAULT_NOTIFY_CONFIG.timeoutMs);
    expect(normaliseNotifyConfig({ enabled: true, timeoutMs: -5 }).timeoutMs).toBe(DEFAULT_NOTIFY_CONFIG.timeoutMs);
    expect(normaliseNotifyConfig({ enabled: true, timeoutMs: 999_999_999 }).timeoutMs).toBe(DEFAULT_NOTIFY_CONFIG.timeoutMs);
    expect(normaliseNotifyConfig({ enabled: true, timeoutMs: Infinity }).timeoutMs).toBe(DEFAULT_NOTIFY_CONFIG.timeoutMs);
    expect(normaliseNotifyConfig({ enabled: true, timeoutMs: NaN }).timeoutMs).toBe(DEFAULT_NOTIFY_CONFIG.timeoutMs);
  });

  it('#331 defaults dnpDigestWindowMs to 15m and accepts 0 disable', () => {
    expect(normaliseNotifyConfig({ enabled: true }).dnpDigestWindowMs).toBe(DEFAULT_NOTIFY_CONFIG.dnpDigestWindowMs);
    expect(normaliseNotifyConfig({ enabled: true, dnpDigestWindowMs: 0 }).dnpDigestWindowMs).toBe(0);
    expect(normaliseNotifyConfig({ enabled: true, dnpDigestWindowMs: 120_000 }).dnpDigestWindowMs).toBe(120_000);
    expect(normaliseNotifyConfig({ enabled: true, dnpDigestWindowMs: 'bypassPermissions' }).dnpDigestWindowMs)
      .toBe(DEFAULT_NOTIFY_CONFIG.dnpDigestWindowMs);
  });

  it('honours an in-range override', () => {
    expect(normaliseNotifyConfig({ enabled: true, timeoutMs: 3_000 }).timeoutMs).toBe(3_000);
  });
});

describe('normaliseNotifyConfig — total function', () => {
  it('never throws on hostile input shapes', () => {
    const hostiles: unknown[] = [
      { enabled: true, webhookUrl: { toString: () => { throw new Error('boom'); } } },
      { __proto__: { enabled: true } },
      { enabled: true, timeoutMs: { valueOf: () => 1 } },
      { enabled: true, webhookSecret: { toString: () => { throw new Error('boom'); } } },
      JSON.parse('{"enabled":true,"webhookUrl":"https://x.com","extra":{"a":[1,2,{"b":3}]}}'),
    ];
    for (const h of hostiles) {
      expect(() => normaliseNotifyConfig(h)).not.toThrow();
    }
  });

  it('drops unrecognised keys rather than passing them through', () => {
    const cfg = normaliseNotifyConfig({ enabled: true, webhookUrl: 'https://x.com', evilOverride: 'anything' });
    expect((cfg as unknown as Record<string, unknown>).evilOverride).toBeUndefined();
  });
});

describe('normaliseNotifyConfig — openclaw channel flag (#143 native cards)', () => {
  it('defaults OFF and arms only on exactly true', () => {
    expect(normaliseNotifyConfig({ enabled: true }).openclaw).toBe(false);
    expect(normaliseNotifyConfig({ enabled: true, openclaw: true }).openclaw).toBe(true);
  });

  it('truthy-but-not-true never arms it', () => {
    for (const junk of ['true', 1, {}, [], 'yes']) {
      expect(normaliseNotifyConfig({ enabled: true, openclaw: junk }).openclaw).toBe(false);
    }
  });
});
