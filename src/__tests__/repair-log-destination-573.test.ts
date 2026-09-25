/**
 * #573 — where `repair-project-keys` puts its per-rewrite JSON log.
 *
 * ROOT CAUSE of "3,508 files, up to 357 in a day": the log path was
 * `os.homedir()/.shieldcortex/logs/` regardless of which database had been
 * repaired, while the safety backup written moments earlier correctly followed
 * the DB (`<dbPath>.bak.<ts>`). So every run against a throwaway database — a
 * test, a probe, an explicit `--db <tmp>`, doctor's own repair against a
 * scratch copy — permanently littered the operator's REAL home with a record
 * of a database that no longer existed. Measured on the incident host: 3,508
 * repair logs, 3,508 of them describing a DB outside `~/.shieldcortex`, and
 * not one describing the live one. They were never a record of real repairs.
 *
 * The log now follows the database it describes. For the default DB at
 * `~/.shieldcortex/memories.db` that resolves to exactly the documented
 * `~/.shieldcortex/logs/`, so nothing moves for the real install.
 */

import { afterEach, beforeEach, describe, expect, it, jest } from '@jest/globals';
import fs from 'fs';
import os from 'os';
import path from 'path';
import crypto from 'crypto';
import Database from 'better-sqlite3';

import { repairProjectKeys } from '../cli/migrate-legacy.js';

let fakeHome: string;
let dbHome: string;
let dbPath: string;

const MEMORIES_DDL = `
  CREATE TABLE memories (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    uuid TEXT NOT NULL,
    type TEXT NOT NULL,
    category TEXT NOT NULL,
    title TEXT NOT NULL,
    content TEXT NOT NULL,
    project TEXT,
    salience REAL
  )
`;

function seedDb(target: string): void {
  fs.mkdirSync(path.dirname(target), { recursive: true });
  const db = new Database(target);
  db.prepare(MEMORIES_DDL).run();
  const ins = db.prepare(
    `INSERT INTO memories (uuid, type, category, title, content, project, salience)
     VALUES (?, 'long_term', 'note', 't', 'c', ?, 0.5)`,
  );
  for (let i = 0; i < 3; i++) ins.run(crypto.randomUUID(), 'myrepo');
  ins.run(crypto.randomUUID(), 'acme-myrepo');
  db.close();
}

/** Every `project-key-repair-*.json` anywhere under `root`. */
function repairLogsUnder(root: string): string[] {
  const out: string[] = [];
  const walk = (dir: string): void => {
    let entries: fs.Dirent[];
    try { entries = fs.readdirSync(dir, { withFileTypes: true }); } catch { return; }
    for (const e of entries) {
      const full = path.join(dir, e.name);
      if (e.isDirectory()) walk(full);
      else if (e.isFile() && /^project-key-repair-.+\.json$/.test(e.name)) out.push(full);
    }
  };
  walk(root);
  return out.sort();
}

beforeEach(() => {
  fakeHome = fs.mkdtempSync(path.join(os.tmpdir(), 'sc-573-fakehome-'));
  dbHome = fs.mkdtempSync(path.join(os.tmpdir(), 'sc-573-scratchdb-'));
  dbPath = path.join(dbHome, '.shieldcortex', 'memories.db');
  seedDb(dbPath);
  // The defect is about os.homedir(), so point it at a home we own: a
  // regression then writes HERE, where this test can see it, instead of into
  // the developer's real ~/.shieldcortex.
  jest.spyOn(os, 'homedir').mockReturnValue(fakeHome);
  fs.mkdirSync(path.join(fakeHome, '.shieldcortex', 'logs'), { recursive: true });
  jest.spyOn(console, 'log').mockImplementation(() => {});
});

afterEach(() => {
  jest.restoreAllMocks();
  for (const dir of [fakeHome, dbHome]) {
    try { fs.rmSync(dir, { recursive: true, force: true }); } catch { /* ignore */ }
  }
});

describe('#573 the repair log follows the database it describes', () => {
  it('writes beside the repaired DB and NOT into the home directory', async () => {
    // Guard first: if this spy ever stopped taking effect, a regression would
    // write into the real home instead of being caught here. Fail loudly
    // rather than quietly littering someone's machine.
    expect(os.homedir()).toBe(fakeHome);

    const report = await repairProjectKeys({
      dbPath, map: { myrepo: 'acme-myrepo' }, execute: true, noConfirm: true,
    });

    expect(report.applied).toBe(3);
    expect(report.logPath).toBeDefined();
    expect(path.dirname(report.logPath as string))
      .toBe(path.join(dbHome, '.shieldcortex', 'logs'));
    expect(fs.existsSync(report.logPath as string)).toBe(true);
    // The whole point: the home directory is untouched.
    expect(repairLogsUnder(fakeHome)).toEqual([]);
  });

  it('still logs to ~/.shieldcortex/logs for the real default database', async () => {
    // The documented location must not move for the DB that actually lives
    // there — <db-dir>/logs resolves to exactly the old path.
    const realDb = path.join(fakeHome, '.shieldcortex', 'memories.db');
    seedDb(realDb);

    const report = await repairProjectKeys({
      dbPath: realDb, map: { myrepo: 'acme-myrepo' }, execute: true, noConfirm: true,
    });

    expect(report.applied).toBe(3);
    expect(path.dirname(report.logPath as string))
      .toBe(path.join(fakeHome, '.shieldcortex', 'logs'));
  });

  it('records the database it describes in the log body', async () => {
    const report = await repairProjectKeys({
      dbPath, map: { myrepo: 'acme-myrepo' }, execute: true, noConfirm: true,
    });

    const body = JSON.parse(fs.readFileSync(report.logPath as string, 'utf-8'));
    expect(body.dbPath).toBe(dbPath);
    expect(body.totalRowsAffected).toBe(3);
  });
});
