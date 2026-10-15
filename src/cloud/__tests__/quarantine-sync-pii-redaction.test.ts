import { afterEach, beforeEach, describe, expect, it, jest } from '@jest/globals';

/**
 * #510 / internal #89 regression guard for the AUTOMATIC quarantine sync path.
 *
 * `syncQuarantineToCloud` receives the LIVE pipeline text (pipeline.ts step 9,
 * store.ts sub-agent hold), not the write-redacted `quarantine` row. The shared
 * gate (`prepareQuarantineSyncPayload`) must therefore run the same
 * write-time PII redactor every persistence boundary uses BEFORE credential
 * redaction, on both the outbound body and the payload persisted to the local
 * retry queue on failure. Opting in to sensitive sync (`excludeSensitive:
 * false`) is NOT a PII-redaction opt-out; the only opt-out is the redactor's
 * own `SHIELDCORTEX_PII_REDACTION=off`, which must keep working.
 *
 * These tests capture the complete outbound `fetch` body. Every identifier is
 * synthetic (example.com, an Ofcom drama-range phone number, an NI-shaped
 * string, a token-SHAPED string assembled at runtime so no credential-looking
 * literal sits in the repository).
 */

type Controls = {
  projectMode: 'all' | 'include' | 'exclude';
  projects: string[];
  contentMode: 'full' | 'metadata';
  excludeSensitive: boolean;
};

let controls: Controls;
let enqueueFailedQuarantineSync: jest.Mock;

async function loadModule() {
  jest.unstable_mockModule('../config.js', () => ({
    getCloudConfig: () => ({
      cloudEnabled: true,
      cloudApiKey: 'sc_test_key',
      cloudBaseUrl: 'https://api.shieldcortex.test',
    }),
    getCloudSyncControls: () => controls,
    getDeviceId: () => 'device-test',
    getDeviceName: () => 'unit-host',
    isSensitiveLevel: (level: string | null | undefined) => {
      if (!level) return false;
      const n = level.trim().toUpperCase();
      return n.length > 0 && n !== 'PUBLIC' && n !== 'INTERNAL';
    },
    shouldSyncProject: () => true,
  }));
  enqueueFailedQuarantineSync = jest.fn();
  jest.unstable_mockModule('../sync-queue.js', () => ({
    enqueueFailedQuarantineSync,
    enqueueMemoryOutbox: jest.fn(() => ({ inserted: true, id: 1 })),
    enqueueGraphOutbox: jest.fn(() => ({ inserted: true, id: 1 })),
  }));
  return import('../quarantine-sync.js');
}

function captureFetch(outcome: 'ok' | 'reject' = 'ok'): { bodies: string[]; called: () => number } {
  const bodies: string[] = [];
  const fetchMock = jest.fn(async (_url: string, init?: { body?: string }) => {
    if (init?.body) bodies.push(init.body);
    if (outcome === 'reject') throw new Error('ECONNRESET');
    return { ok: true, status: 200, json: async () => ({}) };
  });
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  (globalThis as any).fetch = fetchMock;
  return { bodies, called: () => fetchMock.mock.calls.length };
}

const EMAIL = 'jane.doe@example.com';
const PHONE = '+44 7700 900123';
const NI = 'QQ123456C';
const SSN = '123-45-6789';
// GitHub-token SHAPE only (prefix + 36 filler characters), built at runtime.
const TOKEN = ['ghp', 'a'.repeat(36)].join('_');
const PROBE_CONTENT = `Customer record: email ${EMAIL} or call ${PHONE}, NI ${NI}, SSN ${SSN}, token ${TOKEN}`;
const PROBE_TITLE = `contact ${EMAIL}`;
const RAW_VALUES = [EMAIL, PHONE, NI, SSN, TOKEN];
const REDACTED_CONTENT =
  'Customer record: email [REDACTED:email] or call [REDACTED:phone], NI [REDACTED:ni-number], SSN [REDACTED:ssn], token [REDACTED-api_key-github]';

const baseEntry = {
  source_type: 'agent',
  source_identifier: 'unit-test',
  reason: 'injection suspected',
  threat_indicators: ['pattern-a'],
  anomaly_score: 0.9,
  firewall_result: 'QUARANTINE',
  project: 'proj-a',
};

const originalPIIFlag = process.env.SHIELDCORTEX_PII_REDACTION;
const originalFetch = globalThis.fetch;

describe('automatic quarantine sync redacts PII before anything leaves the device (#510)', () => {
  beforeEach(() => {
    jest.resetModules();
    delete process.env.SHIELDCORTEX_PII_REDACTION;
    // User has opted IN to sensitive sync with full content: the most
    // permissive controls. PII redaction must still apply.
    controls = { projectMode: 'all', projects: [], contentMode: 'full', excludeSensitive: false };
  });

  afterEach(() => {
    globalThis.fetch = originalFetch;
    if (originalPIIFlag === undefined) delete process.env.SHIELDCORTEX_PII_REDACTION;
    else process.env.SHIELDCORTEX_PII_REDACTION = originalPIIFlag;
    jest.clearAllMocks();
  });

  it('the captured outbound body carries no raw email / phone / NI / SSN / credential', async () => {
    const { syncQuarantineToCloud } = await loadModule();
    const { bodies, called } = captureFetch();

    syncQuarantineToCloud({
      ...baseEntry,
      original_content: PROBE_CONTENT,
      original_title: PROBE_TITLE,
      sensitivity_level: 'RESTRICTED',
    });
    await new Promise((r) => setTimeout(r, 10));

    expect(called()).toBe(1);
    const raw = bodies[0];
    for (const value of RAW_VALUES) expect(raw).not.toContain(value);

    const body = JSON.parse(raw) as Record<string, unknown>;
    expect(body.original_content).toBe(REDACTED_CONTENT);
    expect(body.original_title).toBe('contact [REDACTED:email]');
    // Full-content mode: the metadata-only flag stays false; redaction is in-place.
    expect(body.content_redacted).toBe(false);
    expect(body.sensitivity_level).toBe('RESTRICTED');
  });

  it('a failed send queues only the redacted payload for retry, never the live text', async () => {
    const { syncQuarantineToCloud } = await loadModule();
    const { bodies } = captureFetch('reject');

    syncQuarantineToCloud({
      ...baseEntry,
      original_content: PROBE_CONTENT,
      original_title: PROBE_TITLE,
      sensitivity_level: 'RESTRICTED',
    });
    await new Promise((r) => setTimeout(r, 10));

    expect(enqueueFailedQuarantineSync).toHaveBeenCalledTimes(1);
    const queued = JSON.stringify(enqueueFailedQuarantineSync.mock.calls[0][0]);
    for (const value of RAW_VALUES) expect(queued).not.toContain(value);
    expect(queued).toContain('[REDACTED:ni-number]');
    // And the attempted body was the same redacted payload.
    for (const value of RAW_VALUES) expect(bodies[0]).not.toContain(value);
  });

  it('the shared helper itself returns the redacted payload (same gate the bulk route uses)', async () => {
    const { prepareQuarantineSyncPayload } = await loadModule();
    const payload = prepareQuarantineSyncPayload(
      { ...baseEntry, original_content: PROBE_CONTENT, original_title: PROBE_TITLE, sensitivity_level: 'RESTRICTED' },
      controls,
    );
    expect(payload).not.toBeNull();
    const text = JSON.stringify(payload);
    for (const value of RAW_VALUES) expect(text).not.toContain(value);
    expect(payload?.original_content).toBe(REDACTED_CONTENT);
  });

  it('PII-redaction-off control: SHIELDCORTEX_PII_REDACTION=off ships identifiers raw, credentials still redacted', async () => {
    process.env.SHIELDCORTEX_PII_REDACTION = 'off';
    const { syncQuarantineToCloud } = await loadModule();
    const { bodies, called } = captureFetch();

    syncQuarantineToCloud({
      ...baseEntry,
      original_content: PROBE_CONTENT,
      original_title: PROBE_TITLE,
      sensitivity_level: 'RESTRICTED',
    });
    await new Promise((r) => setTimeout(r, 10));

    expect(called()).toBe(1);
    const body = JSON.parse(bodies[0]) as Record<string, string>;
    // The redactor's explicit opt-out is honoured...
    for (const value of [EMAIL, PHONE, NI, SSN]) expect(body.original_content).toContain(value);
    expect(body.original_title).toContain(EMAIL);
    expect(body.original_content).not.toContain('[REDACTED:');
    // ...but credential redaction is unconditional.
    expect(body.original_content).not.toContain(TOKEN);
    expect(body.original_content).toContain('[REDACTED-api_key-github]');
  });

  it('inclusion control: a bare vendor contact with no identifier beside it stays readable', async () => {
    const { syncQuarantineToCloud } = await loadModule();
    const { bodies, called } = captureFetch();

    syncQuarantineToCloud({
      ...baseEntry,
      original_content: 'Vendor contact: sales@example.com for renewals',
      original_title: 'vendor',
      sensitivity_level: 'INTERNAL',
    });
    await new Promise((r) => setTimeout(r, 10));

    expect(called()).toBe(1);
    const body = JSON.parse(bodies[0]) as Record<string, string>;
    expect(body.original_content).toBe('Vendor contact: sales@example.com for renewals');
    expect(body.original_title).toBe('vendor');
  });
});
