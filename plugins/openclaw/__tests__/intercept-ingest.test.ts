import { syncInterceptEvent } from '../intercept-ingest.js';
import type { InterceptAuditEntry } from '../interceptor.js';

function makeEntry(overrides: Partial<InterceptAuditEntry> = {}): InterceptAuditEntry {
  return {
    type: 'intercept',
    tool: 'remember',
    severity: 'high',
    firewallResult: 'BLOCK',
    threats: ['x'],
    anomalyScore: 0.9,
    trustScore: 0.1,
    sensitivityLevel: 'INTERNAL',
    fragmentationScore: null,
    pipelineDurationMs: 5,
    action: 'auto_deny',
    outcome: 'auto_denied',
    preview: 'SECRET',
    ts: '2026-06-11T06:00:00.000Z',
    ...overrides,
  };
}

describe('syncInterceptEvent', () => {
  const realFetch = global.fetch;
  let calls: { url: string; init: any; body: any }[];

  beforeEach(() => {
    calls = [];
    // @ts-expect-error test stub
    global.fetch = (url: string, init: any) => {
      calls.push({ url, init, body: JSON.parse(init.body) });
      return Promise.resolve({ ok: true });
    };
  });

  afterEach(() => {
    global.fetch = realFetch;
  });

  it('POSTs canonical {entries:[...]} to /v1/audit/ingest', async () => {
    syncInterceptEvent(makeEntry(), {
      cloudEnabled: true,
      cloudApiKey: 'sc_live_x',
      cloudBaseUrl: 'https://api.shieldcortex.ai',
    });
    await new Promise((r) => setTimeout(r, 0));

    expect(calls).toHaveLength(1);
    expect(calls[0].url).toBe('https://api.shieldcortex.ai/v1/audit/ingest');
    expect(Array.isArray(calls[0].body.entries)).toBe(true);
    expect(calls[0].body.events).toBeUndefined();

    const entry = calls[0].body.entries[0];
    expect(entry.firewall_result).toBe('BLOCK');
    expect(entry.trust_score).toBe(0.1);
    expect(entry.sensitivity_level).toBe('INTERNAL');
    expect(entry.anomaly_score).toBe(0.9);
    expect(entry.threat_indicators).toEqual(['x']);
    expect(entry.pipeline_duration_ms).toBe(5);
    expect(entry.source_type).toBe('openclaw-interceptor');
    expect(entry.timestamp).toBe('2026-06-11T06:00:00.000Z');
  });

  it('sends the bearer token and JSON content-type', async () => {
    syncInterceptEvent(makeEntry(), {
      cloudEnabled: true,
      cloudApiKey: 'sc_live_x',
      cloudBaseUrl: 'https://api.shieldcortex.ai',
    });
    await new Promise((r) => setTimeout(r, 0));

    expect(calls[0].init.method).toBe('POST');
    expect(calls[0].init.headers.Authorization).toBe('Bearer sc_live_x');
    expect(calls[0].init.headers['Content-Type']).toBe('application/json');
  });

  it('never leaks content/preview in the serialized body (privacy)', async () => {
    syncInterceptEvent(makeEntry({ preview: 'SECRET' }), {
      cloudEnabled: true,
      cloudApiKey: 'sc_live_x',
      cloudBaseUrl: 'https://api.shieldcortex.ai',
    });
    await new Promise((r) => setTimeout(r, 0));

    const serialized = JSON.stringify(calls[0].body);
    expect(serialized).not.toContain('SECRET');
    expect(serialized).not.toContain('preview');
    expect(serialized).not.toContain('content');
  });

  it('does NOT POST when cloudEnabled is false', async () => {
    syncInterceptEvent(makeEntry(), {
      cloudEnabled: false,
      cloudApiKey: 'sc_live_x',
      cloudBaseUrl: 'https://api.shieldcortex.ai',
    });
    await new Promise((r) => setTimeout(r, 0));
    expect(calls).toHaveLength(0);
  });

  it('does NOT POST when cloudApiKey is missing', async () => {
    syncInterceptEvent(makeEntry(), {
      cloudEnabled: true,
      cloudApiKey: '',
      cloudBaseUrl: 'https://api.shieldcortex.ai',
    });
    await new Promise((r) => setTimeout(r, 0));
    expect(calls).toHaveLength(0);
  });
});
