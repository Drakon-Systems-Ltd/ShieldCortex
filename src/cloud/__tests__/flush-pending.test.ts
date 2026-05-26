import { afterEach, beforeEach, describe, expect, it, jest } from '@jest/globals';
import { closeDatabase, initDatabase } from '../../database/init.js';
import { mkdtempSync, rmSync } from 'fs';
import { join } from 'path';
import { tmpdir } from 'os';

/**
 * Regression: v4.24.1 fixed the gate, but on headless Linux servers the
 * CLI scan's fire-and-forget POST to /v1/audit/ingest was killed when
 * `process.exit()` ran ~1s after the scan completed. The Mac dashboard
 * daemon hid the bug because it kept the process alive. v4.24.2 introduces
 * `flushPendingCloudSync()` for CLI entry points to drain pending POSTs
 * before exit.
 *
 * These tests pin the contract:
 *   1. syncToCloud registers an in-flight promise (tracked via pendingCloudSyncCount).
 *   2. flushPendingCloudSync awaits all in-flight promises.
 *   3. flushPendingCloudSync respects its maxWaitMs timeout when the
 *      network is slow / hung.
 *   4. flushPendingCloudSync is a cheap no-op when nothing is in flight.
 */

describe('flushPendingCloudSync', () => {
  let configDir: string;
  let originalFetch: typeof globalThis.fetch;
  let dbPath: string;

  beforeEach(async () => {
    configDir = mkdtempSync(join(tmpdir(), 'shieldcortex-flush-test-'));
    process.env.SHIELDCORTEX_CONFIG_DIR = configDir;
    dbPath = join(configDir, 'memories.db');
    initDatabase(dbPath);
    originalFetch = globalThis.fetch;

    // Use the real config setter so the integrity signature + cache
    // invalidation are handled correctly. Direct file writes get rejected
    // by the tamper guard.
    const { setCloudConfig } = await import('../config.js');
    setCloudConfig({
      cloudEnabled: true,
      cloudApiKey: 'sc_test_flush_pending_unit_test',
      cloudBaseUrl: 'https://example.invalid',
    });
  });

  afterEach(() => {
    globalThis.fetch = originalFetch;
    delete process.env.SHIELDCORTEX_CONFIG_DIR;
    closeDatabase();
    rmSync(configDir, { recursive: true, force: true });
    jest.useRealTimers();
  });

  it('is a no-op when nothing is in flight', async () => {
    const { flushPendingCloudSync, pendingCloudSyncCount } = await import('../sync.js');
    expect(pendingCloudSyncCount()).toBe(0);
    const t0 = Date.now();
    await flushPendingCloudSync(50);
    // Should return essentially instantly — well under the 50ms cap.
    expect(Date.now() - t0).toBeLessThan(40);
  });

  it('tracks syncToCloud calls and drains them on flush', async () => {
    // Mock fetch to a controlled promise we resolve manually.
    let resolveFetch: (v: Response) => void = () => {};
    globalThis.fetch = jest.fn().mockImplementation(
      () => new Promise<Response>((r) => { resolveFetch = r; }),
    ) as unknown as typeof globalThis.fetch;

    const { syncToCloud, flushPendingCloudSync, pendingCloudSyncCount } = await import('../sync.js');

    // Build a minimal-but-valid pipeline result.
    const result = {
      allowed: true,
      auditId: 1,
      trust: { score: 0.9, factors: {}, level: 'high' as const },
      sensitivity: { level: 'PUBLIC' as const, detectedPatterns: [] },
      firewall: {
        result: 'ALLOW' as const,
        anomalyScore: 0,
        threatIndicators: [],
        blockedPatterns: [],
        reason: 'unit test',
      },
      fragmentation: null,
      credentialScan: undefined,
    };
    syncToCloud(result as never, { type: 'cli', identifier: 'flush-test' }, 5);

    expect(pendingCloudSyncCount()).toBe(1);

    // Resolve fetch with a successful response; flush should then settle.
    resolveFetch(new Response(JSON.stringify({ ingested: 1 }), { status: 200 }));
    await flushPendingCloudSync(2000);
    expect(pendingCloudSyncCount()).toBe(0);
  });

  it('respects maxWaitMs when the network is hung', async () => {
    // fetch never resolves — flush must time out.
    globalThis.fetch = jest.fn().mockImplementation(
      () => new Promise<Response>(() => { /* never resolves */ }),
    ) as unknown as typeof globalThis.fetch;

    const { syncToCloud, flushPendingCloudSync, pendingCloudSyncCount } = await import('../sync.js');
    const result = {
      allowed: true,
      auditId: 1,
      trust: { score: 0.9, factors: {}, level: 'high' as const },
      sensitivity: { level: 'PUBLIC' as const, detectedPatterns: [] },
      firewall: {
        result: 'ALLOW' as const,
        anomalyScore: 0,
        threatIndicators: [],
        blockedPatterns: [],
        reason: 'unit test',
      },
      fragmentation: null,
      credentialScan: undefined,
    };
    syncToCloud(result as never, { type: 'cli', identifier: 'flush-timeout' }, 5);
    expect(pendingCloudSyncCount()).toBe(1);

    const t0 = Date.now();
    await flushPendingCloudSync(60);
    const elapsed = Date.now() - t0;
    // Bounded above by maxWaitMs + a generous CI margin; well below 8s default.
    expect(elapsed).toBeGreaterThanOrEqual(55);
    expect(elapsed).toBeLessThan(500);
    // The in-flight promise is still pending — flush didn't cancel it,
    // just returned. (The fetch's own 10s AbortController will end it.)
    expect(pendingCloudSyncCount()).toBe(1);
  });
});
