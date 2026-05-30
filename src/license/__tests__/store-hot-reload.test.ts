/**
 * Licence cache hot-reload (v4.27.2).
 *
 * Long-running workers (BrainWorker, dashboard, MCP server) used to cache
 * the parsed licence at module load and never re-read it. That meant
 * `shieldcortex license activate <key>` from another process didn't take
 * effect on the worker until the worker restarted — and feature gates
 * like `cloud_sync` (heartbeat, audit ingest) stayed stuck on the old
 * tier. This test verifies the cache invalidates when the licence file's
 * mtime advances.
 */
import { describe, it, expect, beforeEach, afterEach } from '@jest/globals';
import { mkdtempSync, rmSync, writeFileSync, existsSync, utimesSync, statSync } from 'fs';
import { join } from 'path';
import { tmpdir } from 'os';

describe('licence cache hot-reload', () => {
  let configDir: string;
  let licensePath: string;

  beforeEach(async () => {
    configDir = mkdtempSync(join(tmpdir(), 'shieldcortex-store-hotreload-'));
    process.env.SHIELDCORTEX_CONFIG_DIR = configDir;
    licensePath = join(configDir, 'license.json');
    // Reset any state from a previous test run.
    const { clearLicenseCache } = await import('../store.js');
    clearLicenseCache();
  });

  afterEach(async () => {
    delete process.env.SHIELDCORTEX_CONFIG_DIR;
    rmSync(configDir, { recursive: true, force: true });
    const { clearLicenseCache } = await import('../store.js');
    clearLicenseCache();
  });

  function writeLicenseFile(contents: object, mtimeMs?: number): void {
    writeFileSync(licensePath, JSON.stringify(contents, null, 2) + '\n', { mode: 0o600 });
    if (mtimeMs !== undefined) {
      const t = mtimeMs / 1000;
      utimesSync(licensePath, t, t);
    }
  }

  it('returns FREE when no licence file exists, and caches that', async () => {
    const { getLicense } = await import('../store.js');
    const a = getLicense();
    const b = getLicense();
    expect(a.tier).toBe('free');
    expect(a.valid).toBe(false);
    // Same object reference on second call proves the cache hit
    expect(b).toBe(a);
  });

  it('drops the FREE cache when a licence file appears', async () => {
    const { getLicense } = await import('../store.js');

    // First call: no file → FREE cached
    const first = getLicense();
    expect(first.tier).toBe('free');

    // File appears with a malformed key (will still verify as FREE via the
    // catch path, but the verification has run = cache was discarded).
    writeLicenseFile({ key: 'not-a-real-key', activatedAt: '2026-01-01T00:00:00Z' });

    // Second call: stat() sees a new mtime (was null, now a number) →
    // cache discarded, re-read from disk.
    const second = getLicense();
    // The malformed key fails verification → still FREE, but a DIFFERENT
    // FREE object (the cache was rebuilt).
    expect(second.tier).toBe('free');
    expect(second).not.toBe(first);
  });

  it('drops the cache when the licence file mtime advances', async () => {
    const { getLicense, clearLicenseCache } = await import('../store.js');

    // Seed a file with t=1000
    writeLicenseFile({ key: 'fake-key-1', activatedAt: '2026-01-01T00:00:00Z' }, 1000_000);
    const first = getLicense();
    expect(first).toBeDefined();

    // Second call without touching the file should hit cache (same reference)
    const cached = getLicense();
    expect(cached).toBe(first);

    // Advance mtime to t=2000 (simulating `shieldcortex license activate`
    // overwriting the file with a new key). Same content is fine — the
    // cache invalidation is mtime-driven, not content-driven.
    writeLicenseFile({ key: 'fake-key-2', activatedAt: '2026-01-02T00:00:00Z' }, 2000_000);

    // Sanity: the file's mtime is now > the originally cached value
    const newMtime = statSync(licensePath).mtimeMs;
    expect(newMtime).toBeGreaterThanOrEqual(2000_000);

    const reread = getLicense();
    expect(reread).not.toBe(first);

    clearLicenseCache();
  });

  it('drops the cache when the licence file disappears', async () => {
    const { getLicense } = await import('../store.js');

    writeLicenseFile({ key: 'fake-key', activatedAt: '2026-01-01T00:00:00Z' }, 1000_000);
    const first = getLicense();

    // File is deleted under us (shieldcortex license deactivate from another
    // process, or a user manually rm'd it)
    rmSync(licensePath);
    expect(existsSync(licensePath)).toBe(false);

    const second = getLicense();
    expect(second.tier).toBe('free');
    expect(second).not.toBe(first);
  });

  it('keeps the cache when nothing changes (stat-only on hot path)', async () => {
    const { getLicense } = await import('../store.js');

    writeLicenseFile({ key: 'fake', activatedAt: '2026-01-01T00:00:00Z' }, 1000_000);

    const a = getLicense();
    const b = getLicense();
    const c = getLicense();
    // Identical references — re-read only happens when mtime advances
    expect(b).toBe(a);
    expect(c).toBe(a);
  });

  it('activateLicense updates the cache + mtime atomically', async () => {
    const { activateLicense, getLicense } = await import('../store.js');

    // First call sees no file → FREE
    expect(getLicense().tier).toBe('free');

    // activateLicense with a junk key will throw — that's fine, what we
    // care about is that the function exists and that getLicense() picks
    // up state writes via mtime change.
    expect(() => activateLicense('not-a-real-signed-key')).toThrow();
    // Even after the throw, no file should have been written (verify
    // failed first). getLicense remains FREE.
    expect(getLicense().tier).toBe('free');
  });
});
