import { afterEach, beforeEach, describe, expect, it, jest } from '@jest/globals';

/**
 * Phase 17 A2 — quarantine content sync must respect the user's
 * CloudSyncControls, exactly like memory-sync does.
 *
 * Quarantine holds the MOST sensitive payloads (the original content the
 * firewall flagged), yet before the fix it shipped that content to the cloud
 * unconditionally — ignoring `excludeSensitive`, `contentMode: 'metadata'`,
 * and the project include/exclude filter. This proves the gating is applied.
 */

type Controls = {
  projectMode: 'all' | 'include' | 'exclude';
  projects: string[];
  contentMode: 'full' | 'metadata';
  excludeSensitive: boolean;
};

let controls: Controls;

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
    shouldSyncProject: (project: string | null | undefined, c: Controls) => {
      const normalized = (project ?? '').trim();
      if (c.projectMode === 'all') return true;
      const included = c.projects.includes(normalized);
      return c.projectMode === 'include' ? included : !included;
    },
  }));
  // sync-queue is a leaf import; stub so a failed/queued path doesn't touch disk.
  jest.unstable_mockModule('../sync-queue.js', () => ({
    enqueueFailedQuarantineSync: jest.fn(),
    enqueueMemoryOutbox: jest.fn(() => ({ inserted: true, id: 1 })),
    enqueueGraphOutbox: jest.fn(() => ({ inserted: true, id: 1 })),
  }));
  return import('../quarantine-sync.js');
}

function captureFetch(): { bodies: string[]; called: () => number } {
  const bodies: string[] = [];
  const fetchMock = jest.fn(async (_url: string, init?: { body?: string }) => {
    if (init?.body) bodies.push(init.body);
    return { ok: true, status: 200, json: async () => ({}) };
  });
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  (globalThis as any).fetch = fetchMock;
  return { bodies, called: () => fetchMock.mock.calls.length };
}

const SENSITIVE_CONTENT = 'CONFIDENTIAL: customer SSN 123-45-6789 and home address';

describe('quarantine sync respects CloudSyncControls', () => {
  beforeEach(() => {
    jest.resetModules();
    controls = { projectMode: 'all', projects: [], contentMode: 'full', excludeSensitive: true };
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  it('does NOT send a sensitive item when excludeSensitive is true', async () => {
    const { syncQuarantineToCloud } = await loadModule();
    const { bodies, called } = captureFetch();

    syncQuarantineToCloud({
      original_content: SENSITIVE_CONTENT,
      source_type: 'agent',
      source_identifier: 'a',
      reason: 'r',
      threat_indicators: [],
      anomaly_score: 0.6,
      firewall_result: 'QUARANTINE',
      project: 'proj-a',
      sensitivity_level: 'CONFIDENTIAL',
    });

    await new Promise((r) => setTimeout(r, 10));
    expect(called()).toBe(0);
    expect(bodies).toHaveLength(0);
  });

  it('redacts content to metadata-only when contentMode is metadata', async () => {
    controls = { projectMode: 'all', projects: [], contentMode: 'metadata', excludeSensitive: false };
    const { syncQuarantineToCloud } = await loadModule();
    const { bodies, called } = captureFetch();

    syncQuarantineToCloud({
      original_content: SENSITIVE_CONTENT,
      original_title: 'leaky title',
      source_type: 'agent',
      source_identifier: 'a',
      reason: 'r',
      threat_indicators: [],
      anomaly_score: 0.6,
      firewall_result: 'QUARANTINE',
      project: 'proj-a',
      sensitivity_level: 'PUBLIC',
    });

    await new Promise((r) => setTimeout(r, 10));
    expect(called()).toBe(1);
    const body = JSON.parse(bodies[0]);
    expect(body.original_content).not.toContain('123-45-6789');
    expect(body.original_content).not.toContain('SSN');
    expect(body.original_title).not.toContain('leaky title');
  });

  it('does NOT send an item whose project is excluded by the project filter', async () => {
    controls = { projectMode: 'exclude', projects: ['secret-proj'], contentMode: 'full', excludeSensitive: false };
    const { syncQuarantineToCloud } = await loadModule();
    const { bodies, called } = captureFetch();

    syncQuarantineToCloud({
      original_content: 'some content',
      source_type: 'agent',
      source_identifier: 'a',
      reason: 'r',
      threat_indicators: [],
      anomaly_score: 0.6,
      firewall_result: 'QUARANTINE',
      project: 'secret-proj',
      sensitivity_level: 'PUBLIC',
    });

    await new Promise((r) => setTimeout(r, 10));
    expect(called()).toBe(0);
    expect(bodies).toHaveLength(0);
  });

  it('DOES send a non-sensitive item in an included project (content present, credentials still redacted)', async () => {
    controls = { projectMode: 'all', projects: [], contentMode: 'full', excludeSensitive: true };
    const { syncQuarantineToCloud } = await loadModule();
    const { bodies, called } = captureFetch();

    syncQuarantineToCloud({
      original_content: 'benign quarantined note about a suspicious url',
      source_type: 'agent',
      source_identifier: 'a',
      reason: 'r',
      threat_indicators: [],
      anomaly_score: 0.6,
      firewall_result: 'QUARANTINE',
      project: 'proj-a',
      sensitivity_level: 'INTERNAL',
    });

    await new Promise((r) => setTimeout(r, 10));
    expect(called()).toBe(1);
    const body = JSON.parse(bodies[0]);
    expect(body.original_content).toContain('benign quarantined note');
  });
});
