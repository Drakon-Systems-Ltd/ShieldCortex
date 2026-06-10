import { afterEach, beforeEach, describe, expect, it, jest } from '@jest/globals';
import { closeDatabase, getDatabase, initDatabase } from '../database/init.js';
import { mkdtempSync, rmSync } from 'fs';
import { join } from 'path';
import { tmpdir } from 'os';
import {
  enqueueFailedSync,
  processRetryQueue,
  type SyncEntry,
} from '../cloud/sync-queue.js';

/**
 * Phase 8b — durable offline queue.
 *
 * Before this work the retry queue marked any row `failed` after 3 attempts
 * (~210s of backoff). A laptop offline overnight permanently lost every
 * queued audit/quarantine/memory/graph sync. These tests pin the new contract:
 *
 *   1. Transient errors (network/timeout/5xx/429) keep retrying with capped
 *      (≤1h) exponential backoff until the 7-day TTL purge — they NEVER
 *      hit a permanent 3-attempt fail.
 *   2. Permanent errors (HTTP 4xx) fail fast on the first attempt — retrying
 *      a 400/401/403/404/422 is pointless.
 *   3. `failed` rows left behind by the old logic (or a 5xx blip) are
 *      resurrected IF their last_error was transient; genuine 4xx stay failed.
 *   4. processRetryQueue honours a maxRows budget so MCP-profile workers
 *      don't do unbounded network work on every light tick.
 */

function makeAuditEntry(overrides: Partial<SyncEntry> = {}): SyncEntry {
  return {
    source_type: 'agent',
    source_identifier: 'durability-test',
    trust_score: 0.8,
    sensitivity_level: 'INTERNAL',
    firewall_result: 'BLOCK',
    anomaly_score: 0.4,
    threat_indicators: ['prompt_injection'],
    reason: 'unit test',
    pipeline_duration_ms: 12,
    device_id: 'device-test',
    device_name: 'unit-test-host',
    platform: 'darwin/arm64',
    timestamp: new Date().toISOString(),
    ...overrides,
  };
}

const ONE_HOUR_MS = 60 * 60 * 1000;

describe('Cloud sync queue — durability (Phase 8b)', () => {
  let configDir: string;
  let originalFetch: typeof globalThis.fetch;

  beforeEach(async () => {
    configDir = mkdtempSync(join(tmpdir(), 'shieldcortex-durability-test-'));
    process.env.SHIELDCORTEX_CONFIG_DIR = configDir;
    initDatabase(join(configDir, 'memories.db'));
    originalFetch = globalThis.fetch;

    // Real setter so the integrity signature + cache invalidation are correct.
    const { setCloudConfig } = await import('../cloud/config.js');
    setCloudConfig({
      cloudEnabled: true,
      cloudApiKey: 'sc_test_durability_unit_test',
      cloudBaseUrl: 'https://example.invalid',
    });
  });

  afterEach(() => {
    globalThis.fetch = originalFetch;
    delete process.env.SHIELDCORTEX_CONFIG_DIR;
    closeDatabase();
    rmSync(configDir, { recursive: true, force: true });
    jest.restoreAllMocks();
  });

  function rowStatus(): { status: string; attempts: number; next_retry_at: string; last_error: string | null } {
    return getDatabase()
      .prepare('SELECT status, attempts, next_retry_at, last_error FROM sync_queue ORDER BY id LIMIT 1')
      .get() as { status: string; attempts: number; next_retry_at: string; last_error: string | null };
  }

  // Force the row to be immediately due so the next processRetryQueue picks it
  // up without waiting for real backoff time to elapse.
  function makeRowDue(): void {
    getDatabase()
      .prepare(`UPDATE sync_queue SET next_retry_at = ? WHERE status = 'pending'`)
      .run(new Date(Date.now() - 1000).toISOString());
  }

  it('keeps a row pending (NOT failed) across a long transient outage, then syncs on recovery', async () => {
    enqueueFailedSync(makeAuditEntry());

    // Network is down — fetch rejects with a network error. Run more times than
    // the old max_attempts (3) to prove there is no permanent-fail by count.
    globalThis.fetch = jest.fn().mockRejectedValue(
      new TypeError('fetch failed'),
    ) as unknown as typeof globalThis.fetch;

    for (let i = 0; i < 6; i++) {
      makeRowDue();
      const res = await processRetryQueue();
      expect(res.permanentlyFailed).toBe(0);
      const row = rowStatus();
      expect(row.status).toBe('pending');
      // next_retry_at is in the future and capped at <= 1h ahead.
      const delta = new Date(row.next_retry_at).getTime() - Date.now();
      expect(delta).toBeGreaterThan(0);
      expect(delta).toBeLessThanOrEqual(ONE_HOUR_MS + 2000);
    }

    // attempts kept incrementing for observability even though never failed.
    expect(rowStatus().attempts).toBeGreaterThanOrEqual(6);

    // Network recovers — row should sync.
    globalThis.fetch = jest.fn().mockResolvedValue(
      new Response(JSON.stringify({ ingested: 1 }), { status: 200 }),
    ) as unknown as typeof globalThis.fetch;

    makeRowDue();
    const recovered = await processRetryQueue();
    expect(recovered.succeeded).toBe(1);
    expect(rowStatus().status).toBe('synced');
  });

  it('caps transient backoff at 1h even after many attempts', async () => {
    enqueueFailedSync(makeAuditEntry());
    // Pre-age attempts so 2^attempts*30s would blow well past an hour.
    getDatabase().prepare(`UPDATE sync_queue SET attempts = 20`).run();

    globalThis.fetch = jest.fn().mockRejectedValue(
      new TypeError('fetch failed'),
    ) as unknown as typeof globalThis.fetch;

    makeRowDue();
    await processRetryQueue();
    const row = rowStatus();
    expect(row.status).toBe('pending');
    const delta = new Date(row.next_retry_at).getTime() - Date.now();
    expect(delta).toBeLessThanOrEqual(ONE_HOUR_MS + 2000);
    expect(delta).toBeGreaterThan(ONE_HOUR_MS - 60_000); // pinned at the cap
  });

  it('treats a timeout (AbortError) as transient, not permanent', async () => {
    enqueueFailedSync(makeAuditEntry());
    const abortErr = new Error('This operation was aborted');
    abortErr.name = 'AbortError';
    globalThis.fetch = jest.fn().mockRejectedValue(abortErr) as unknown as typeof globalThis.fetch;

    makeRowDue();
    const res = await processRetryQueue();
    expect(res.permanentlyFailed).toBe(0);
    expect(rowStatus().status).toBe('pending');
  });

  it('fails fast (permanent) on an HTTP 4xx after a single attempt', async () => {
    enqueueFailedSync(makeAuditEntry());
    globalThis.fetch = jest.fn().mockResolvedValue(
      new Response('bad request', { status: 400 }),
    ) as unknown as typeof globalThis.fetch;

    makeRowDue();
    const res = await processRetryQueue();
    expect(res.permanentlyFailed).toBe(1);
    const row = rowStatus();
    expect(row.status).toBe('failed');
    expect(row.last_error).toMatch(/^HTTP 4\d\d/);
  });

  it('retries an HTTP 5xx as transient (does not fail by count)', async () => {
    enqueueFailedSync(makeAuditEntry());
    getDatabase().prepare(`UPDATE sync_queue SET attempts = 5`).run();
    globalThis.fetch = jest.fn().mockResolvedValue(
      new Response('server error', { status: 503 }),
    ) as unknown as typeof globalThis.fetch;

    makeRowDue();
    const res = await processRetryQueue();
    expect(res.permanentlyFailed).toBe(0);
    expect(res.failed).toBe(1);
    expect(rowStatus().status).toBe('pending');
  });

  it('resurrects a transiently-failed row (HTTP 503) and syncs it', async () => {
    const db = getDatabase();
    const now = new Date().toISOString();
    // A row marked failed by the OLD 3-attempt logic, on a 5xx (transient).
    db.prepare(`
      INSERT INTO sync_queue (payload, attempts, max_attempts, next_retry_at, status, last_error, created_at)
      VALUES (?, 3, 3, ?, 'failed', 'HTTP 503', ?)
    `).run(JSON.stringify({ kind: 'audit', entry: makeAuditEntry() }), now, now);

    globalThis.fetch = jest.fn().mockResolvedValue(
      new Response(JSON.stringify({ ingested: 1 }), { status: 200 }),
    ) as unknown as typeof globalThis.fetch;

    const res = await processRetryQueue();
    // Resurrected to pending, then processed + synced in the same call.
    expect(res.succeeded).toBe(1);
    expect(rowStatus().status).toBe('synced');
  });

  it('does NOT resurrect a permanently-failed row (HTTP 404)', async () => {
    const db = getDatabase();
    const now = new Date().toISOString();
    db.prepare(`
      INSERT INTO sync_queue (payload, attempts, max_attempts, next_retry_at, status, last_error, created_at)
      VALUES (?, 3, 3, ?, 'failed', 'HTTP 404', ?)
    `).run(JSON.stringify({ kind: 'audit', entry: makeAuditEntry() }), now, now);

    globalThis.fetch = jest.fn().mockResolvedValue(
      new Response(JSON.stringify({ ingested: 1 }), { status: 200 }),
    ) as unknown as typeof globalThis.fetch;

    await processRetryQueue();
    expect(rowStatus().status).toBe('failed');
  });

  it('does NOT resurrect a transiently-failed row older than the 7-day TTL', async () => {
    const db = getDatabase();
    const eightDaysAgo = new Date(Date.now() - 8 * 24 * 60 * 60 * 1000).toISOString();
    db.prepare(`
      INSERT INTO sync_queue (payload, attempts, max_attempts, next_retry_at, status, last_error, created_at)
      VALUES (?, 3, 3, ?, 'failed', 'HTTP 503', ?)
    `).run(JSON.stringify({ kind: 'audit', entry: makeAuditEntry() }), eightDaysAgo, eightDaysAgo);

    globalThis.fetch = jest.fn().mockResolvedValue(
      new Response(JSON.stringify({ ingested: 1 }), { status: 200 }),
    ) as unknown as typeof globalThis.fetch;

    await processRetryQueue();
    expect(rowStatus().status).toBe('failed');
  });

  it('processes at most maxRows pending entries per call (budget)', async () => {
    for (let i = 0; i < 10; i++) {
      enqueueFailedSync(makeAuditEntry({ source_identifier: `e${i}` }));
    }
    makeRowDue();
    getDatabase()
      .prepare(`UPDATE sync_queue SET next_retry_at = ? WHERE status = 'pending'`)
      .run(new Date(Date.now() - 1000).toISOString());

    const fetchMock = jest.fn().mockResolvedValue(
      new Response(JSON.stringify({ ingested: 1 }), { status: 200 }),
    ) as unknown as typeof globalThis.fetch;
    globalThis.fetch = fetchMock;

    const res = await processRetryQueue({ maxRows: 3 });
    expect(res.processed).toBe(3);
    expect((fetchMock as unknown as jest.Mock).mock.calls.length).toBe(3);

    const remaining = getDatabase()
      .prepare(`SELECT COUNT(*) AS c FROM sync_queue WHERE status = 'pending'`)
      .get() as { c: number };
    expect(remaining.c).toBe(7);
  });
});
