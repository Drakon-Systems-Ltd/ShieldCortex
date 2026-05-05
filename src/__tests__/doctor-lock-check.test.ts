import fs from 'fs';
import os from 'os';
import path from 'path';
import { afterEach, beforeEach, describe, expect, it } from '@jest/globals';
import { checkLockFile } from '../cli/doctor.js';

/**
 * Doctor's lock check used to flag any lock older than 1 hour as stale, which
 * caused false positives for long-running daemons (e.g. `shieldcortex
 * dashboard` started at boot can hold the lock for days). The check now
 * matches `acquireStartupLock` semantics: a lock is stale only when its
 * recorded PID is no longer running.
 */
describe('doctor — lock file staleness', () => {
  let tmp: string;

  beforeEach(() => {
    tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'shieldcortex-doctor-lock-'));
  });

  afterEach(() => {
    fs.rmSync(tmp, { recursive: true, force: true });
  });

  function writeLock(name: string, payload: object): void {
    fs.writeFileSync(path.join(tmp, name), JSON.stringify(payload), 'utf-8');
  }

  it('reports `clean` when no lock files are present', async () => {
    const result = await checkLockFile(tmp);
    expect(result.status).toBe('pass');
    expect(result.message).toMatch(/clean/);
  });

  it('treats a lock owned by a live PID as active even when the file is days old', async () => {
    writeLock('memories.db.lock', {
      pid: process.pid,
      startedAt: '2026-04-01T00:00:00.000Z',
      entryPath: '/some/old/path.js',
    });
    // Backdate mtime to 5 days ago — the old check would have flagged this stale.
    const fiveDaysAgo = (Date.now() - 5 * 24 * 60 * 60 * 1000) / 1000;
    fs.utimesSync(path.join(tmp, 'memories.db.lock'), fiveDaysAgo, fiveDaysAgo);

    const result = await checkLockFile(tmp);
    expect(result.status).toBe('pass');
    expect(result.message).toMatch(/active lock/);
  });

  it('reports stale when the recorded PID is no longer running', async () => {
    // PID 999999 is well above any realistic live PID and reliably ESRCH on test hosts.
    writeLock('memories.db.lock', {
      pid: 999999,
      startedAt: new Date().toISOString(),
      entryPath: '/tmp/ghost.js',
    });

    const result = await checkLockFile(tmp);
    expect(result.status).toBe('warn');
    expect(result.message).toMatch(/stale lock file found.*memories\.db\.lock/);
    expect(result.fix).toMatch(/memories\.db\.lock/);
  });

  it('falls back to mtime when the lock file is unparseable', async () => {
    fs.writeFileSync(path.join(tmp, 'memories.db.lock'), 'not json', 'utf-8');
    const twoDaysAgo = (Date.now() - 2 * 24 * 60 * 60 * 1000) / 1000;
    fs.utimesSync(path.join(tmp, 'memories.db.lock'), twoDaysAgo, twoDaysAgo);

    const result = await checkLockFile(tmp);
    expect(result.status).toBe('warn');
    expect(result.message).toMatch(/stale/);
  });

  it('does not flag a recent unparseable lock as stale', async () => {
    fs.writeFileSync(path.join(tmp, 'memories.db.lock'), 'not json', 'utf-8');
    const result = await checkLockFile(tmp);
    expect(result.status).toBe('pass');
  });
});
