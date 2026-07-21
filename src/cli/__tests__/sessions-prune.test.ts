/**
 * `shieldcortex sessions prune` CLI tests (issue #110).
 *
 * Mirrors the memories-prune conventions (src/cli/migrate-legacy.ts runPrune):
 * dry-run by default, `--execute` to delete, `--days N` to override the
 * retention window. Dry-run prints matched count + payload MB and must not
 * delete anything; --execute deletes and reminds about `shieldcortex vacuum`
 * (deleted rows leave free pages in the file — only VACUUM shrinks it).
 */

import { describe, it, expect, beforeEach, afterEach, jest } from '@jest/globals';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { closeDatabase, getDatabase } from '../../database/init.js';
import { recordEvent } from '../../sessions/capture.js';
import { runSessionsPrune } from '../sessions.js';

function daysAgo(days: number): string {
  return new Date(Date.now() - days * 24 * 60 * 60 * 1000).toISOString();
}

describe('shieldcortex sessions prune (#110)', () => {
  let tmpDir: string;
  let dbPath: string;
  let logSpy: jest.SpiedFunction<typeof console.log>;
  let logged: () => string;

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'sc-sessions-prune-'));
    dbPath = path.join(tmpDir, 'memories.db');
    logSpy = jest.spyOn(console, 'log').mockImplementation(() => {});
    logged = () => logSpy.mock.calls.map((c) => c.map(String).join(' ')).join('\n');
  });

  afterEach(() => {
    logSpy.mockRestore();
    closeDatabase();
    try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch { /* ignore */ }
  });

  async function seed(): Promise<void> {
    // runSessionsPrune inits the DB itself; seed through a first invocation
    // is not possible, so init here via the override path used by the CLI.
    const { initDatabase } = await import('../../database/init.js');
    initDatabase(dbPath);
    recordEvent({ session_id: 's1', ts: daysAgo(45), kind: 'prompt', payload: 'x'.repeat(2048) });
    recordEvent({ session_id: 's1', ts: daysAgo(40), kind: 'response', payload: 'y'.repeat(2048) });
    recordEvent({ session_id: 's2', ts: daysAgo(3), kind: 'prompt', payload: 'z'.repeat(2048) });
  }

  it('dry-run by default: prints matched count + payload MB and deletes NOTHING', async () => {
    await seed();

    await runSessionsPrune([], dbPath);

    const out = logged();
    expect(out).toMatch(/DRY RUN/);
    expect(out).toMatch(/Matched: 2/);
    expect(out).toMatch(/MB/);
    expect(out).toMatch(/--execute/);

    const db = getDatabase();
    const count = (db.prepare('SELECT COUNT(*) AS c FROM session_events').get() as { c: number }).c;
    expect(count).toBe(3); // untouched
  });

  it('--execute deletes matched rows, prints deleted count, and reminds about vacuum', async () => {
    await seed();

    await runSessionsPrune(['--execute'], dbPath);

    const out = logged();
    expect(out).not.toMatch(/DRY RUN/);
    expect(out).toMatch(/Deleted: 2/);
    expect(out).toMatch(/shieldcortex vacuum/);

    const db = getDatabase();
    const count = (db.prepare('SELECT COUNT(*) AS c FROM session_events').get() as { c: number }).c;
    expect(count).toBe(1);
  });

  it('honours --days N', async () => {
    await seed();

    await runSessionsPrune(['--days', '2', '--execute'], dbPath);

    const db = getDatabase();
    const count = (db.prepare('SELECT COUNT(*) AS c FROM session_events').get() as { c: number }).c;
    expect(count).toBe(0); // everything is older than 2 days
    expect(logged()).toMatch(/Deleted: 3/);
  });

  it('rejects a non-numeric --days value', async () => {
    await seed();
    await expect(runSessionsPrune(['--days', 'soon', '--execute'], dbPath)).rejects.toThrow(/--days/);
    const db = getDatabase();
    const count = (db.prepare('SELECT COUNT(*) AS c FROM session_events').get() as { c: number }).c;
    expect(count).toBe(3); // nothing deleted on bad input
  });
});
