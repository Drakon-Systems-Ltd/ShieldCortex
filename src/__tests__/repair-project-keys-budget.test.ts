/**
 * WIRING test for #148 — proves `repair-project-keys` actually consults the
 * backup budget, not merely that a budget helper exists.
 *
 * Written after auditing my own fix for the pattern this week kept producing:
 * a helper with good unit tests, a confident claim in user-facing text, and
 * nothing anywhere proving the caller uses it. `backup-budget.test.ts` covers
 * planBackup/pruneOldBackups in isolation; delete the call site in
 * migrate-legacy.ts and every one of those tests still passes while the bug is
 * fully restored. These tests fail in that case, which is the point.
 *
 * Same shape as the two defects fixed today (#146, #148): the mechanism was
 * guarded and the wiring was not.
 */
import fs from 'fs';
import os from 'os';
import path from 'path';
import crypto from 'crypto';
import { afterEach, beforeEach, describe, expect, it, jest } from '@jest/globals';
import Database from 'better-sqlite3';

import { repairProjectKeys } from '../cli/migrate-legacy.js';
import { DIRECTORY_BUDGET_BYTES } from '../limits.js';

describe('#148 wiring — repair-project-keys respects the disk budget', () => {
  let tempHome: string;
  let scDir: string;
  let dbPath: string;
  const originalHome = process.env.HOME;

  function seed(): void {
    const db = new Database(dbPath);
    db.exec(`
      CREATE TABLE memories (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        uuid TEXT, type TEXT, category TEXT, title TEXT,
        content TEXT, project TEXT, salience REAL
      );
    `);
    const insert = db.prepare(
      `INSERT INTO memories (uuid, type, category, title, content, project, salience)
       VALUES (?, 'long_term', 'note', ?, ?, ?, 0.5)`,
    );
    insert.run(crypto.randomUUID(), 'a', 'a', 'myrepo');
    insert.run(crypto.randomUUID(), 'b', 'b', 'acme-myrepo');
    db.close();
  }

  /** Occupy the budget with an inert file, the way a real host's data does. */
  function fill(name: string, bytes: number): string {
    const p = path.join(scDir, name);
    fs.writeFileSync(p, Buffer.alloc(bytes));
    return p;
  }

  function backupsOnDisk(): string[] {
    return fs.readdirSync(scDir).filter(f => f.includes('memories.db.bak.'));
  }

  beforeEach(() => {
    tempHome = fs.mkdtempSync(path.join(os.tmpdir(), 'sc-repair-budget-'));
    process.env.HOME = tempHome;
    process.env.USERPROFILE = tempHome;
    scDir = path.join(tempHome, '.shieldcortex');
    fs.mkdirSync(scDir, { recursive: true });
    dbPath = path.join(scDir, 'memories.db');
    seed();
    jest.spyOn(console, 'log').mockImplementation(() => {});
    jest.spyOn(console, 'error').mockImplementation(() => {});
  });

  afterEach(() => {
    fs.rmSync(tempHome, { recursive: true, force: true });
    process.env.HOME = originalHome;
    jest.restoreAllMocks();
  });

  it('REFUSES the repair rather than overfilling the budget, and leaves the data untouched', async () => {
    // Leave less headroom than the database needs for its own copy.
    fill('bulk.dat', DIRECTORY_BUDGET_BYTES - 1024);

    const report = await repairProjectKeys({
      dbPath,
      map: { myrepo: 'acme-myrepo' },
      noConfirm: true,
      execute: true,
    } as Parameters<typeof repairProjectKeys>[0]);

    expect(report.aborted).toBeTruthy();
    expect(report.applied).toBe(0);
    expect(backupsOnDisk()).toHaveLength(0);

    // The rewrite must NOT have happened — refusing to back up must refuse the
    // destructive half too, or we would have traded a disk problem for data
    // written with no rollback point.
    const db = new Database(dbPath, { readonly: true });
    const n = (db.prepare("SELECT COUNT(*) AS n FROM memories WHERE project = 'myrepo'").get() as { n: number }).n;
    db.close();
    expect(n).toBe(1);
  });

  it('the refusal explains itself in terms the operator can act on', async () => {
    fill('bulk.dat', DIRECTORY_BUDGET_BYTES - 1024);
    const report = await repairProjectKeys({
      dbPath,
      map: { myrepo: 'acme-myrepo' },
      noConfirm: true,
      execute: true,
    } as Parameters<typeof repairProjectKeys>[0]);

    expect(report.aborted).toMatch(/budget|limit|headroom/i);
    expect(report.aborted!.length).toBeGreaterThan(20);
  });

  it('proceeds normally when there is headroom, and writes exactly one backup', async () => {
    const report = await repairProjectKeys({
      dbPath,
      map: { myrepo: 'acme-myrepo' },
      noConfirm: true,
      execute: true,
    } as Parameters<typeof repairProjectKeys>[0]);

    expect(report.aborted).toBeFalsy();
    expect(report.applied).toBe(1);
    expect(backupsOnDisk()).toHaveLength(1);
  });

  it('does not accumulate backups across repeated repairs, even with plenty of headroom', async () => {
    // The first version of this test was vacuous: after the first run there was
    // nothing left to rewrite, so later runs returned before ever taking a
    // backup — and it passed with the wiring removed entirely. It now forces a
    // real rewrite each time by alternating the project key back and forth.
    //
    // This is the case that matters most, and the one the first cut of the fix
    // got wrong: pruning ONLY when short of room still lets copies pile up on a
    // healthy host until it fills — the live failure, merely deferred.
    const rounds: Array<Record<string, string>> = [
      { myrepo: 'acme-myrepo' },
      { 'acme-myrepo': 'myrepo' },
      { myrepo: 'acme-myrepo' },
      { 'acme-myrepo': 'myrepo' },
    ];
    for (const map of rounds) {
      const r = await repairProjectKeys({
        dbPath, map, noConfirm: true, execute: true,
      } as Parameters<typeof repairProjectKeys>[0]);
      expect(r.applied).toBeGreaterThan(0); // prove a real backup was taken
      expect(backupsOnDisk().length).toBeLessThanOrEqual(1);
    }
    expect(backupsOnDisk()).toHaveLength(1);
  });
});
