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
import { repairLogName } from '../logs/retention.js';

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

// ── Round-2 blockers 4 and 5 ──────────────────────────────────────────────

/** The project keys currently stored, so "did it commit?" is a fact. */
function projectsIn(target: string): string[] {
  const db = new Database(target, { readonly: true });
  try {
    return (db.prepare('SELECT DISTINCT project FROM memories ORDER BY project').all() as
      Array<{ project: string }>).map((r) => r.project);
  } finally {
    db.close();
  }
}

describe('#573 blocker 5 — the destination is settled before the database is', () => {
  it('refuses, and commits nothing, when a regular file sits at <db-dir>/logs', async () => {
    // The reviewer's reproduction: mkdir threw EEXIST with the rewrite already
    // applied, so the project had changed, no log existed, and the exception
    // never said the repair had committed.
    const blocker = path.join(dbHome, '.shieldcortex', 'logs');
    fs.writeFileSync(blocker, 'not a directory');

    await expect(repairProjectKeys({
      dbPath, map: { myrepo: 'acme-myrepo' }, execute: true, noConfirm: true,
    })).rejects.toThrow(/refusing to repair/i);

    expect(projectsIn(dbPath)).toEqual(['acme-myrepo', 'myrepo']);
    expect(fs.readFileSync(blocker, 'utf-8')).toBe('not a directory');
    // No backup either: the repair did not start.
    expect(fs.readdirSync(path.join(dbHome, '.shieldcortex')).filter((n) => n.includes('.bak.')))
      .toEqual([]);
  });

  it('refuses, and commits nothing, when <db-dir>/logs is a symlink', async () => {
    const elsewhere = fs.mkdtempSync(path.join(os.tmpdir(), 'sc-573-elsewhere-'));
    fs.symlinkSync(elsewhere, path.join(dbHome, '.shieldcortex', 'logs'));
    try {
      await expect(repairProjectKeys({
        dbPath, map: { myrepo: 'acme-myrepo' }, execute: true, noConfirm: true,
      })).rejects.toThrow(/symlink/i);

      expect(projectsIn(dbPath)).toEqual(['acme-myrepo', 'myrepo']);
      expect(fs.readdirSync(elsewhere)).toEqual([]);
    } finally {
      fs.rmSync(elsewhere, { recursive: true, force: true });
    }
  });

  it('refuses when the destination is not writable', async () => {
    const logs = path.join(dbHome, '.shieldcortex', 'logs');
    fs.mkdirSync(logs, { recursive: true });
    fs.chmodSync(logs, 0o500);
    try {
      await expect(repairProjectKeys({
        dbPath, map: { myrepo: 'acme-myrepo' }, execute: true, noConfirm: true,
      })).rejects.toThrow(/not writable/i);
      expect(projectsIn(dbPath)).toEqual(['acme-myrepo', 'myrepo']);
    } finally {
      fs.chmodSync(logs, 0o700);
    }
  });

  it('names both the commit and the rollback point when only the log write fails', async () => {
    // Disk-full shape: the destination passed every pre-check, then the create
    // itself failed. The rewrite stands, so the error must say so.
    const realOpen = fs.openSync.bind(fs);
    jest.spyOn(fs, 'openSync').mockImplementation(((p: fs.PathLike, flags: string, mode?: number) => {
      if (typeof p === 'string' && /project-key-repair-/.test(p)) {
        const err = new Error('ENOSPC: no space left on device') as NodeJS.ErrnoException;
        err.code = 'ENOSPC';
        throw err;
      }
      return realOpen(p, flags as never, mode as never);
    }) as typeof fs.openSync);

    const failure = await repairProjectKeys({
      dbPath, map: { myrepo: 'acme-myrepo' }, execute: true, noConfirm: true,
    }).then(() => null, (err: Error) => err);

    expect(failure).toBeInstanceOf(Error);
    expect(failure!.message).toMatch(/Repair COMMITTED/);
    expect(failure!.message).toMatch(/3 row\(s\)/);
    expect(failure!.message).toMatch(/\.bak\./);       // names the rollback point
    expect(failure!.message).toMatch(/ENOSPC/);
    // And it is telling the truth: the rewrite really is committed.
    expect(projectsIn(dbPath)).toEqual(['acme-myrepo']);
  });
});

describe('#573 blocker 4 — the record is created exclusively', () => {
  it('never follows a preplanted symlink carrying the record\'s own name', async () => {
    // The reviewer's reproduction: with a fixed clock, preplant the expected
    // filename as a symlink to a realtime audit JSONL. The repair overwrote
    // the security evidence with repair JSON and the symlink survived.
    const evidence = path.join(fakeHome, '.shieldcortex', 'audit', 'realtime-2026-09-25.jsonl');
    fs.mkdirSync(path.dirname(evidence), { recursive: true });
    fs.writeFileSync(evidence, '{"event":"blocked","id":1}\n');
    const before = fs.readFileSync(evidence);

    const logs = path.join(dbHome, '.shieldcortex', 'logs');
    fs.mkdirSync(logs, { recursive: true });
    const fixed = new Date('2026-09-25T05:43:44.000Z');
    jest.useFakeTimers().setSystemTime(fixed);
    try {
      const planted = path.join(logs, repairLogName(dbPath, fixed));
      fs.symlinkSync(evidence, planted);

      const report = await repairProjectKeys({
        dbPath, map: { myrepo: 'acme-myrepo' }, execute: true, noConfirm: true,
      });

      // The evidence is byte-identical and the link still points at it.
      expect(fs.readFileSync(evidence)).toEqual(before);
      expect(fs.lstatSync(planted).isSymbolicLink()).toBe(true);
      // The record went somewhere else, and is a real file.
      expect(report.logPath).not.toBe(planted);
      expect(fs.lstatSync(report.logPath as string).isFile()).toBe(true);
      expect(JSON.parse(fs.readFileSync(report.logPath as string, 'utf-8')).dbPath).toBe(dbPath);
    } finally {
      jest.useRealTimers();
    }
  });

  it('refuses a database whose own directory is a link into the audit plane', async () => {
    // Round-3 blocker 1, the reviewer's layout: the database lives INSIDE
    // .shieldcortex/audit and is reached through HOME/db-link. The supplied
    // path contains no `.shieldcortex` component at all, so a boundary chosen
    // by basename never looked above `logs` — and the repair committed a row
    // and wrote its record into the realtime audit directory. `realpath` of
    // the database's own directory answers every one of these layouts at once.
    const audit = path.join(fakeHome, '.shieldcortex', 'audit');
    fs.mkdirSync(audit, { recursive: true });
    fs.writeFileSync(path.join(audit, 'realtime-2026-09-25.jsonl'), '{"event":"blocked"}\n');
    const auditDb = path.join(audit, 'memories.db');
    seedDb(auditDb);
    const manifest = fs.readdirSync(audit).sort();
    fs.symlinkSync(audit, path.join(dbHome, 'db-link'));
    const previous = process.env.SHIELDCORTEX_AUDIT_DIR;
    process.env.SHIELDCORTEX_AUDIT_DIR = audit;

    try {
      await expect(repairProjectKeys({
        dbPath: path.join(dbHome, 'db-link', 'memories.db'),
        map: { myrepo: 'acme-myrepo' }, execute: true, noConfirm: true,
      })).rejects.toThrow(/audit/i);

      // Nothing was written into the plane, and nothing was committed.
      expect(fs.readdirSync(audit).sort()).toEqual(manifest);
      expect(projectsIn(auditDb)).toEqual(['acme-myrepo', 'myrepo']);
    } finally {
      if (previous === undefined) delete process.env.SHIELDCORTEX_AUDIT_DIR;
      else process.env.SHIELDCORTEX_AUDIT_DIR = previous;
    }
  });

  it('refuses a <db-dir>/logs pointed at the realtime audit plane, leaving it untouched', async () => {
    const audit = path.join(fakeHome, '.shieldcortex', 'audit');
    fs.mkdirSync(audit, { recursive: true });
    fs.writeFileSync(path.join(audit, 'realtime-2026-09-25.jsonl'), '{"event":"blocked"}\n');
    const manifest = fs.readdirSync(audit).map((n) => [n, fs.readFileSync(path.join(audit, n), 'utf-8')]);
    fs.symlinkSync(audit, path.join(dbHome, '.shieldcortex', 'logs'));

    await expect(repairProjectKeys({
      dbPath, map: { myrepo: 'acme-myrepo' }, execute: true, noConfirm: true,
    })).rejects.toThrow(/symlink/i);

    expect(fs.readdirSync(audit).map((n) => [n, fs.readFileSync(path.join(audit, n), 'utf-8')]))
      .toEqual(manifest);
    expect(projectsIn(dbPath)).toEqual(['acme-myrepo', 'myrepo']);
  });
});
