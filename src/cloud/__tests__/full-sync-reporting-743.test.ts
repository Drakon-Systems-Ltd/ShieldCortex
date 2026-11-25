/**
 * #743 — transport-level regression for the reporting fix.
 *
 * Full sync and live dispatch are driven against a mocked fetch and a stub
 * database object (no SQLite file, no network). What is pinned:
 *   - the HTTP status reaches the full-sync summary, split permanent vs
 *     transient vs local skip;
 *   - queue writes are unchanged: every failed memory record / graph batch is
 *     still inserted 'pending', exactly as before;
 *   - no response body is read;
 *   - live dispatch logs one status-only line per process for a permanent
 *     refusal, nothing for transient failures, and never acks a failed row.
 */
import { afterEach, beforeEach, describe, expect, it, jest } from '@jest/globals';

const API_KEY = 'sc_test_key_743_not_real';
const BASE_URL = 'https://cloud.example.invalid';
const BODY_SENTINEL = 'BODY-SENTINEL-743';

let cloudEnabled = true;

jest.unstable_mockModule('../config.js', () => ({
  getCloudConfig: () => ({ cloudEnabled, cloudApiKey: API_KEY, cloudBaseUrl: BASE_URL }),
  getCloudSyncControls: () => ({ excludeSensitive: true, contentMode: 'full' }),
  getDeviceId: () => 'device-743',
  getDeviceName: () => 'device-name-743',
  isSensitiveLevel: () => false,
  shouldSyncProject: () => true,
  updateLastSyncAt: () => {},
}));

interface QueueInsert { sql: string; args: unknown[] }
const inserts: QueueInsert[] = [];
const updates: string[] = [];
let memoryRows: Record<string, unknown>[] = [];

const fakeDb = {
  prepare(sql: string) {
    return {
      all: () => (/FROM memories/.test(sql) && !/JOIN/.test(sql) ? memoryRows : []),
      get: () => (/COUNT\(\*\)/.test(sql) ? { c: inserts.length } : undefined),
      run: (...args: unknown[]) => {
        if (/INSERT/.test(sql) && /sync_queue/.test(sql)) {
          inserts.push({ sql, args });
          return { changes: 1, lastInsertRowid: inserts.length };
        }
        if (/UPDATE sync_queue/.test(sql)) updates.push(sql);
        return { changes: 0, lastInsertRowid: 0 };
      },
    };
  },
};

jest.unstable_mockModule('../../database/init.js', () => ({
  getDatabase: () => fakeDb,
}));

const { syncAllMemoriesToCloud, dispatchMemoryOutboxBestEffort } = await import('../memory-sync.js');
const { syncAllGraphToCloud, dispatchGraphOutboxBestEffort, buildEnvelope } = await import('../graph-sync.js');
const { formatFullSyncSummary } = await import('../send-outcome.js');

function makeRows(n: number): Record<string, unknown>[] {
  return Array.from({ length: n }, (_, i) => ({
    id: i + 1,
    uuid: `uuid-743-${i + 1}`,
    type: 'short_term',
    category: 'note',
    title: `title ${i + 1}`,
    content: `content ${i + 1}`,
    project: null,
    tags: '[]',
    salience: 0.5,
    scope: 'project',
    transferable: 0,
    trust_score: 0.9,
    sensitivity_level: 'INTERNAL',
    source: null,
    metadata: '{}',
    cloud_excluded: 0,
    created_at: '2026-11-01T00:00:00.000Z',
    updated_at: '2026-11-01T00:00:00.000Z',
  }));
}

type Reply = { status: number } | 'network' | 'abort';
interface FakeResponse { ok: boolean; status: number; text: jest.Mock; json: jest.Mock }
const responses: FakeResponse[] = [];

/** Queue of replies per route; the last one repeats. */
function mockFetch(routes: { memories?: Reply[]; graph?: Reply[] }) {
  const cursors = { memories: 0, graph: 0 };
  globalThis.fetch = jest.fn(async (url: unknown) => {
    const route = String(url).endsWith('/v1/sync/graph') ? 'graph' : 'memories';
    const list = routes[route] ?? [{ status: 200 }];
    const reply = list[Math.min(cursors[route]++, list.length - 1)];
    if (reply === 'network') throw new TypeError('fetch failed');
    if (reply === 'abort') {
      const err = new Error('aborted');
      err.name = 'AbortError';
      throw err;
    }
    const res: FakeResponse = {
      ok: reply.status >= 200 && reply.status < 300,
      status: reply.status,
      text: jest.fn(async () => BODY_SENTINEL),
      json: jest.fn(async () => ({ error: BODY_SENTINEL })),
    };
    responses.push(res);
    return res;
  }) as unknown as typeof globalThis.fetch;
}

function memoryInserts(): QueueInsert[] {
  return inserts.filter((i) => JSON.parse(String(i.args[0])).kind === 'memory');
}
function graphInserts(): QueueInsert[] {
  return inserts.filter((i) => JSON.parse(String(i.args[0])).kind === 'graph');
}

describe('#743 full sync reports the HTTP status class', () => {
  let originalFetch: typeof globalThis.fetch;

  beforeEach(() => {
    originalFetch = globalThis.fetch;
    inserts.length = 0;
    updates.length = 0;
    responses.length = 0;
    cloudEnabled = true;
    memoryRows = makeRows(120); // 3 memory batches of 50/50/20; 1 graph prune batch
  });

  afterEach(() => {
    globalThis.fetch = originalFetch;
    jest.restoreAllMocks();
  });

  async function runFullSync() {
    const memory = await syncAllMemoriesToCloud();
    const graph = await syncAllGraphToCloud();
    return { memory, graph, lines: formatFullSyncSummary(memory, graph) };
  }

  function expectQueueWritesUnchanged(memoryFailed: number, graphFailed: number) {
    // Same as before the fix: one pending legacy row per failed record /
    // failed graph batch, no delivery key, nothing marked failed up front.
    expect(memoryInserts()).toHaveLength(memoryFailed);
    expect(graphInserts()).toHaveLength(graphFailed);
    for (const i of inserts) {
      expect(i.sql).toMatch(/'pending'/);
      expect(i.sql).not.toMatch(/delivery_key/);
    }
  }

  it('402: rejected, not "queued for retry"; rows still queued pending; body never read', async () => {
    mockFetch({ memories: [{ status: 402 }], graph: [{ status: 402 }] });
    const { memory, graph, lines } = await runFullSync();

    expect(memory).toMatchObject({ total: 120, synced: 0, failed: 120 });
    expect(memory.failures).toEqual({
      permanent: 120, transient: 0, skipped: 0, permanentStatus: 402, mixedPermanentStatus: false,
    });
    expect(graph).toMatchObject({ failedBatches: 1 });
    expect(graph.failures).toMatchObject({ permanent: 1, permanentStatus: 402 });
    expectQueueWritesUnchanged(120, 1);

    const text = lines.join('\n');
    expect(text).not.toMatch(/queued for retry/);
    expect(text).not.toMatch(/not queued/i);
    expect(lines[0]).toBe('Finished. 0/120 memories synced, 120 rejected by the cloud (HTTP 402).');
    expect(lines).toHaveLength(3);
    expect(text).not.toContain(BASE_URL);
    expect(text).not.toContain(API_KEY);
    expect(text).not.toContain(BODY_SENTINEL);
    for (const r of responses) {
      expect(r.text).not.toHaveBeenCalled();
      expect(r.json).not.toHaveBeenCalled();
    }
  });

  it('429: transient, "queued for retry"', async () => {
    mockFetch({ memories: [{ status: 429 }], graph: [{ status: 200 }] });
    const { memory, lines } = await runFullSync();
    expect(memory.failures).toMatchObject({ permanent: 0, transient: 120 });
    expectQueueWritesUnchanged(120, 0);
    expect(lines).toEqual([
      'Finished. 0/120 memories synced, 120 queued for retry.',
      'Graph replica: 0 entities, 0 relationships, 0 memory links.',
    ]);
  });

  it('503: transient, "queued for retry" for memories and graph', async () => {
    mockFetch({ memories: [{ status: 503 }], graph: [{ status: 503 }] });
    const { lines } = await runFullSync();
    expectQueueWritesUnchanged(120, 1);
    expect(lines).toEqual([
      'Finished. 0/120 memories synced, 120 queued for retry.',
      'Graph replica: 0 entities, 0 relationships, 0 memory links, 1 batch queued for retry.',
    ]);
  });

  it('network error and abort: transient, no status printed', async () => {
    mockFetch({ memories: ['network', 'abort', 'network'], graph: ['network'] });
    const { memory, lines } = await runFullSync();
    expect(memory.failures).toMatchObject({ permanent: 0, transient: 120, permanentStatus: null });
    expectQueueWritesUnchanged(120, 1);
    expect(lines[0]).toBe('Finished. 0/120 memories synced, 120 queued for retry.');
    expect(lines.join('\n')).not.toMatch(/HTTP/);
  });

  it('mixed batches: 200, 402, 503 are each counted in their own class', async () => {
    mockFetch({ memories: [{ status: 200 }, { status: 402 }, { status: 503 }], graph: [{ status: 429 }] });
    const { memory, graph, lines } = await runFullSync();
    expect(memory).toMatchObject({ total: 120, synced: 50, failed: 70 });
    expect(memory.failures).toMatchObject({ permanent: 50, transient: 20, skipped: 0, permanentStatus: 402 });
    expect(graph.failures).toMatchObject({ permanent: 0, transient: 1 });
    expectQueueWritesUnchanged(70, 1);
    expect(lines[0]).toBe(
      'Finished. 50/120 memories synced, 20 queued for retry, 50 rejected by the cloud (HTTP 402).',
    );
    expect(lines[1]).toBe('Graph replica: 0 entities, 0 relationships, 0 memory links, 1 batch queued for retry.');
    expect(lines).toHaveLength(3);
  });

  it('local skip (cloud disabled mid-run) makes no request and is not reported as a cloud refusal', async () => {
    mockFetch({});
    cloudEnabled = false;
    const { memory, lines } = await runFullSync();
    expect(globalThis.fetch).not.toHaveBeenCalled();
    expect(memory.failures).toMatchObject({ permanent: 0, transient: 0, skipped: 120 });
    expectQueueWritesUnchanged(120, 1);
    expect(lines[0]).toBe('Finished. 0/120 memories synced, 120 not sent (cloud sync not configured locally).');
    expect(lines.join('\n')).not.toMatch(/rejected|HTTP|queued for retry/);
  });
});

describe('#743 live dispatch: one status-only diagnostic per process', () => {
  let originalFetch: typeof globalThis.fetch;

  beforeEach(() => {
    originalFetch = globalThis.fetch;
    inserts.length = 0;
    updates.length = 0;
    responses.length = 0;
    cloudEnabled = true;
    memoryRows = makeRows(1);
  });

  afterEach(() => {
    globalThis.fetch = originalFetch;
    jest.restoreAllMocks();
  });

  const record = {
    external_id: 'live-743',
    local_id: 1,
    type: 'short_term',
    category: 'note',
    title: 'secret-title-743',
    content: 'secret-content-743',
    project: null,
    tags: [] as string[],
    salience: 0.5,
    scope: 'project',
    transferable: false,
    trust_score: null as number | null,
    sensitivity_level: 'INTERNAL',
    source: null as string | null,
    metadata: {} as Record<string, unknown>,
    cloud_excluded: false,
    created_at: '2026-11-01T00:00:00.000Z',
    updated_at: '2026-11-01T00:00:00.000Z',
    deleted_at: null as string | null,
  };
  const settle = () => new Promise((r) => setTimeout(r, 20));

  it('transient first, then repeated permanent refusals across memory and graph: exactly one line', async () => {
    const errors = jest.spyOn(console, 'error').mockImplementation(() => {});
    const graphEnvelope = buildEnvelope([], [], [], ['live-743']);

    for (const reply of [{ status: 503 }, { status: 429 }, 'network', 'abort'] as Reply[]) {
      mockFetch({ memories: [reply], graph: [reply] });
      dispatchMemoryOutboxBestEffort(record, 'memory:live-743:a');
      dispatchGraphOutboxBestEffort(graphEnvelope, 'graph:live-743:a');
      await settle();
    }
    expect(errors).not.toHaveBeenCalled();

    mockFetch({ memories: [{ status: 402 }], graph: [{ status: 403 }] });
    dispatchMemoryOutboxBestEffort(record, 'memory:live-743:b');
    await settle();
    dispatchMemoryOutboxBestEffort(record, 'memory:live-743:c');
    dispatchGraphOutboxBestEffort(graphEnvelope, 'graph:live-743:b');
    await settle();

    expect(errors).toHaveBeenCalledTimes(1);
    const line = errors.mock.calls[0].map(String).join(' ');
    expect(line).toMatch(/HTTP 402/);
    for (const forbidden of [BASE_URL, API_KEY, BODY_SENTINEL, 'secret-title-743', 'secret-content-743', 'live-743']) {
      expect(line).not.toContain(forbidden);
    }
    // No ack and no extra enqueue: the outbox row stays pending, as before.
    expect(updates).toHaveLength(0);
    expect(inserts).toHaveLength(0);
    for (const r of responses) {
      expect(r.text).not.toHaveBeenCalled();
      expect(r.json).not.toHaveBeenCalled();
    }
  });

  it('a successful dispatch still acks its row and logs nothing', async () => {
    const errors = jest.spyOn(console, 'error').mockImplementation(() => {});
    mockFetch({ memories: [{ status: 200 }] });
    dispatchMemoryOutboxBestEffort(record, 'memory:live-743:ok');
    await settle();
    expect(updates).toHaveLength(1);
    expect(errors).not.toHaveBeenCalled();
  });
});
