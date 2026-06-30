import fs from 'fs';
import os from 'os';
import path from 'path';
import { afterEach, beforeEach, describe, expect, it } from '@jest/globals';

import { checkDiskUsage } from '../doctor.js';

/**
 * v4.45.1: the Disk check's remedy used to always say "memories prune / dedupe"
 * even when the space was stale migration backups or session-capture rows —
 * neither of which prune/dedupe can reach. EDITH hit exactly this: a stack of
 * pre-backfill backups pushed her over 100 MB and the suggested fix did nothing.
 * The check now breaks the data down (live DB / backups / logs) and points at the
 * remedy that matches the actual consumer. A `limitBytes` arg keeps it testable
 * without writing ~100 MB of fixture data.
 */
describe('doctor checkDiskUsage names the real disk consumer (4.45.1)', () => {
  let tmpDir: string;
  const KB = 1024;

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'sc-disk-breakdown-'));
  });

  afterEach(() => {
    try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch { /* ignore */ }
  });

  function writeBytes(rel: string, bytes: number): void {
    const fullPath = path.join(tmpDir, rel);
    fs.mkdirSync(path.dirname(fullPath), { recursive: true });
    fs.writeFileSync(fullPath, Buffer.alloc(bytes, 0));
  }

  it('points at clearing backups when stale migration snapshots dominate', async () => {
    writeBytes('memories.db', 4 * KB);
    writeBytes('memories.db.pre-backfill-1700000000000', 40 * KB);
    writeBytes('memories.db.empty-live.1700000000001', 20 * KB);
    const result = await checkDiskUsage(tmpDir, 32 * KB);
    expect(result.status).toBe('fail');
    expect(result.fix).toMatch(/stale DB backups/);
    expect(result.fix).toMatch(/rm ~\/\.shieldcortex\/memories\.db/);
    // The whole point: NOT the old blanket "Run memories prune/dedupe" advice.
    expect(result.fix).not.toMatch(/^Run `shieldcortex memories prune/);
  });

  it('includes a DB / backups / logs breakdown in the message', async () => {
    writeBytes('memories.db', 40 * KB);
    writeBytes('memories.db.pre-backfill-1700000000000', 4 * KB);
    const result = await checkDiskUsage(tmpDir, 32 * KB);
    expect(result.status).toBe('fail');
    expect(result.message).toMatch(/DB .* · backups .* · logs/);
  });

  it('points at VACUUM when the live DB itself is the bulk', async () => {
    writeBytes('memories.db', 60 * KB);
    const result = await checkDiskUsage(tmpDir, 32 * KB);
    expect(result.status).toBe('fail');
    expect(result.fix).toMatch(/VACUUM/);
  });

  it('flags audit/log files when those dominate', async () => {
    writeBytes('memories.db', 2 * KB);
    writeBytes('audit/realtime.jsonl', 40 * KB);
    const result = await checkDiskUsage(tmpDir, 32 * KB);
    expect(result.status).toBe('fail');
    expect(result.fix).toMatch(/audit\/log files/);
  });

  it('honours a custom limit (the plumbing behind the breakdown remedy)', async () => {
    writeBytes('memories.db', 10 * KB);
    const small = await checkDiskUsage(tmpDir, 8 * KB);
    expect(small.status).toBe('fail');
    const large = await checkDiskUsage(tmpDir, 100 * 1024 * 1024);
    expect(large.status).toBe('pass');
  });
});
