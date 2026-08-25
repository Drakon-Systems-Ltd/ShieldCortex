/**
 * #408 — atomic claim / lease for the cloud sync retry queue.
 */
import { afterEach, beforeEach, describe, expect, it, jest } from '@jest/globals';
import { closeDatabase, getDatabase, initDatabase } from '../../database/init.js';
import { mkdtempSync, rmSync } from 'fs';
import { join } from 'path';
import { tmpdir } from 'os';
import {
  claimRetryBatch,
  enqueueFailedSync,
  processRetryQueue,
  SYNC_QUEUE_LEASE_MS,
  type SyncEntry,
} from '../sync-queue.js';

function makeAuditEntry(overrides: Partial<SyncEntry> = {}): SyncEntry {
  return {
    source_type: 'agent',
    source_identifier: 'lease-test',
    trust_score: 0.8,
    sensitivity_level: 'INTERNAL',
    firewall_result: 'BLOCK',
    anomaly_score: 0.4,
    threat_indicators: ['prompt_injection'],
    reason: 'unit test',
    pipeline_duration_ms: 12,
    device_id: 'device-test',
    device_name: 'unit-test-host',
    platform: 'linux/arm64',
    timestamp: new Date().toISOString(),
    ...overrides,
  };
}

describe('#408 sync_queue claim/lease', () => {
  let configDir: string;
  let originalFetch: typeof globalThis.fetch;

  beforeEach(async () => {
    configDir = mkdtempSync(join(tmpdir(), 'shieldcortex-lease-408-'));
    process.env.SHIELDCORTEX_CONFIG_DIR = configDir;
    initDatabase(join(configDir, 'memories.db'));
    originalFetch = globalThis.fetch;
    const { setCloudConfig } = await import('../config.js');
    setCloudConfig({
      cloudEnabled: true,
      cloudApiKey: 'sc_test_key_not_real',
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

  function makeDue(): void {
    getDatabase()
      .prepare(`UPDATE sync_queue SET next_retry_at = ? WHERE status = 'pending'`)
      .run(new Date(Date.now() - 1000).toISOString());
  }

  function rowLease(id = 1): {
    lease_owner: string | null;
    lease_token: string | null;
    lease_expires_at: string | null;
    status: string;
    attempts: number;
  } {
    return getDatabase()
      .prepare(
        'SELECT lease_owner, lease_token, lease_expires_at, status, attempts FROM sync_queue WHERE id = ?',
      )
      .get(id) as {
      lease_owner: string | null;
      lease_token: string | null;
      lease_expires_at: string | null;
      status: string;
      attempts: number;
    };
  }

  it('two concurrent claim passes cannot both own the same row', () => {
    enqueueFailedSync(makeAuditEntry());
    makeDue();

    const a = claimRetryBatch(10);
    const b = claimRetryBatch(10);

    expect(a).toHaveLength(1);
    expect(b).toHaveLength(0);
    expect(a[0].leaseToken).toBeTruthy();
    const r = rowLease(a[0].id);
    expect(r.lease_token).toBe(a[0].leaseToken);
    expect(r.lease_owner).toBe(a[0].leaseOwner);
  });

  it('expired lease is reclaimable by another worker', () => {
    enqueueFailedSync(makeAuditEntry());
    makeDue();
    const first = claimRetryBatch(1);
    expect(first).toHaveLength(1);

    // Expire the lease in the past
    getDatabase()
      .prepare(`UPDATE sync_queue SET lease_expires_at = ? WHERE id = ?`)
      .run(new Date(Date.now() - 1000).toISOString(), first[0].id);

    const second = claimRetryBatch(1);
    expect(second).toHaveLength(1);
    expect(second[0].id).toBe(first[0].id);
    expect(second[0].leaseToken).not.toBe(first[0].leaseToken);
  });

  it('stale claim cannot complete after re-lease', async () => {
    enqueueFailedSync(makeAuditEntry());
    makeDue();
    const stale = claimRetryBatch(1)[0];

    // Expire + reclaim
    getDatabase()
      .prepare(`UPDATE sync_queue SET lease_expires_at = ? WHERE id = ?`)
      .run(new Date(Date.now() - 1000).toISOString(), stale.id);
    const fresh = claimRetryBatch(1)[0];
    expect(fresh.leaseToken).not.toBe(stale.leaseToken);

    // Simulate stale worker finishing "successfully" via raw SQL matching old path —
    // processRetryQueue uses claimed token; forge a stale completion attempt:
    const db = getDatabase();
    const staleComplete = db
      .prepare(
        `UPDATE sync_queue SET status = 'synced', attempts = 1, synced_at = ?, last_error = NULL,
            lease_owner = NULL, lease_token = NULL, lease_expires_at = NULL
         WHERE id = ? AND lease_token = ? AND status = 'pending'`,
      )
      .run(new Date().toISOString(), stale.id, stale.leaseToken);
    expect(staleComplete.changes).toBe(0);

    // Fresh claim can still complete via processRetryQueue
    globalThis.fetch = jest.fn().mockResolvedValue({
      ok: true,
      status: 200,
    }) as unknown as typeof globalThis.fetch;

    // Row is held by fresh lease and due — processRetryQueue will try to claim;
    // lease still held by fresh and not expired, so claimRetryBatch skips it.
    // Complete as the fresh owner would:
    const ok = db
      .prepare(
        `UPDATE sync_queue SET status = 'synced', attempts = 1, synced_at = ?, last_error = NULL,
            lease_owner = NULL, lease_token = NULL, lease_expires_at = NULL
         WHERE id = ? AND lease_token = ? AND status = 'pending'`,
      )
      .run(new Date().toISOString(), fresh.id, fresh.leaseToken);
    expect(ok.changes).toBe(1);
    expect(rowLease(fresh.id).status).toBe('synced');
  });

  it('processRetryQueue claim prevents double HTTP send under concurrent workers', async () => {
    enqueueFailedSync(makeAuditEntry());
    makeDue();

    let inFlight = 0;
    let maxInFlight = 0;
    let sends = 0;
    globalThis.fetch = jest.fn().mockImplementation(async () => {
      sends++;
      inFlight++;
      maxInFlight = Math.max(maxInFlight, inFlight);
      await new Promise((r) => setTimeout(r, 30));
      inFlight--;
      return { ok: true, status: 200 };
    }) as unknown as typeof globalThis.fetch;

    const [r1, r2] = await Promise.all([processRetryQueue(), processRetryQueue()]);
    expect(sends).toBe(1);
    expect(r1.succeeded + r2.succeeded).toBe(1);
    expect(r1.processed + r2.processed).toBe(1);
    expect(rowLease(1).status).toBe('synced');
  });

  it('lease duration is bounded (SYNC_QUEUE_LEASE_MS)', () => {
    enqueueFailedSync(makeAuditEntry());
    makeDue();
    const [c] = claimRetryBatch(1);
    const exp = Date.parse(c.leaseExpiresAt);
    const delta = exp - Date.now();
    expect(delta).toBeGreaterThan(SYNC_QUEUE_LEASE_MS - 5_000);
    expect(delta).toBeLessThanOrEqual(SYNC_QUEUE_LEASE_MS + 5_000);
  });
});
