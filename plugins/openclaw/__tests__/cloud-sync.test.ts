import { cloudSync } from '../cloud-sync.js';

describe('cloudSync (realtime threat egress)', () => {
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

  const realtimeThreat = () => ({
    type: 'threat',
    hook: 'llm_input',
    sessionId: 'sess-1',
    model: 'claude',
    reason: 'prompt injection',
    preview: 'SECRET',
    content: 'SECRET',
    ts: '2026-06-11T06:01:00.000Z',
  });

  const cfg = {
    cloudEnabled: true,
    cloudApiKey: 'sc_live_x',
    cloudBaseUrl: 'https://api.shieldcortex.ai',
  };

  it('POSTs canonical {entries:[...]} to /v1/audit/ingest (NOT /v1/threats)', async () => {
    cloudSync(realtimeThreat(), cfg);
    await new Promise((r) => setTimeout(r, 0));

    expect(calls).toHaveLength(1);
    expect(calls[0].url).toBe('https://api.shieldcortex.ai/v1/audit/ingest');
    expect(calls[0].url).not.toContain('/v1/threats');
    expect(Array.isArray(calls[0].body.entries)).toBe(true);

    const entry = calls[0].body.entries[0];
    expect(entry.firewall_result).toBe('QUARANTINE');
    expect(entry.source_type).toBe('llm_input');
    expect(entry.source_identifier).toBe('claude');
    expect(entry.reason).toBe('prompt injection');
    expect(entry.timestamp).toBe('2026-06-11T06:01:00.000Z');
  });

  it('sends the bearer token and JSON content-type', async () => {
    cloudSync(realtimeThreat(), cfg);
    await new Promise((r) => setTimeout(r, 0));

    expect(calls[0].init.method).toBe('POST');
    expect(calls[0].init.headers.Authorization).toBe('Bearer sc_live_x');
    expect(calls[0].init.headers['Content-Type']).toBe('application/json');
  });

  it('never leaks content/preview in the serialized body (privacy)', async () => {
    cloudSync(realtimeThreat(), cfg);
    await new Promise((r) => setTimeout(r, 0));

    const serialized = JSON.stringify(calls[0].body);
    expect(serialized).not.toContain('SECRET');
    expect(serialized).not.toContain('preview');
    expect(serialized).not.toContain('content');
    expect(serialized).not.toContain('/v1/threats');
  });

  it('falls back to the production base URL when none is configured', async () => {
    cloudSync(realtimeThreat(), { cloudEnabled: true, cloudApiKey: 'sc_live_x' });
    await new Promise((r) => setTimeout(r, 0));
    expect(calls[0].url).toBe('https://api.shieldcortex.ai/v1/audit/ingest');
  });

  it('does NOT POST when cloudEnabled is false', async () => {
    cloudSync(realtimeThreat(), { ...cfg, cloudEnabled: false });
    await new Promise((r) => setTimeout(r, 0));
    expect(calls).toHaveLength(0);
  });

  it('does NOT POST when cloudApiKey is missing', async () => {
    cloudSync(realtimeThreat(), { ...cfg, cloudApiKey: '' });
    await new Promise((r) => setTimeout(r, 0));
    expect(calls).toHaveLength(0);
  });
});
