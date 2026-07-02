import fs from 'fs';
import os from 'os';
import path from 'path';
import crypto from 'crypto';
import { afterEach, beforeEach, describe, expect, it, jest } from '@jest/globals';
import Database from 'better-sqlite3';

import { handleMemoriesCommand, repairProjectKeys } from '../cli/migrate-legacy.js';

/**
 * #42 data recovery — verify the repair-project-keys CLI rewrites legacy
 * basename rows to their canonical owner-repo form, leaves others alone,
 * is dry-run by default, and is idempotent on a second run.
 *
 * The test uses a hand-built minimal `memories` table rather than initDatabase
 * so it stays free of the singleton/lock-file machinery that init.ts uses for
 * production runtimes.
 */
describe('shieldcortex memories repair-project-keys (#42 migration)', () => {
  let tempHome: string;
  let dbPath: string;
  const originalHome = process.env.HOME;

  function seed() {
    const db = new Database(dbPath);
    // Hand-rolled minimal schema — enough for the repair tool's UPDATE.
    db.exec(`
      CREATE TABLE memories (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        uuid TEXT,
        type TEXT,
        category TEXT,
        title TEXT,
        content TEXT,
        project TEXT,
        salience REAL
      );
    `);
    const insert = db.prepare(
      `INSERT INTO memories (uuid, type, category, title, content, project, salience)
       VALUES (?, ?, 'note', ?, ?, ?, 0.5)`
    );
    insert.run(crypto.randomUUID(), 'long_term', 'a', 'a', 'myrepo');
    insert.run(crypto.randomUUID(), 'long_term', 'b', 'b', 'myrepo');
    insert.run(crypto.randomUUID(), 'long_term', 'c', 'c', 'myrepo');
    insert.run(crypto.randomUUID(), 'long_term', 'd', 'd', 'acme-myrepo');
    insert.run(crypto.randomUUID(), 'long_term', 'e', 'e', 'acme-myrepo');
    insert.run(crypto.randomUUID(), 'short_term', 'f', 'f', 'acme-myrepo');
    insert.run(crypto.randomUUID(), 'long_term', 'g', 'g', 'other');
    db.close();
  }

  beforeEach(() => {
    tempHome = fs.mkdtempSync(path.join(os.tmpdir(), 'shieldcortex-repair-'));
    process.env.HOME = tempHome;
    process.env.USERPROFILE = tempHome;
    fs.mkdirSync(path.join(tempHome, '.shieldcortex'), { recursive: true });
    dbPath = path.join(tempHome, '.shieldcortex', 'memories.db');
    seed();
    // Quiet the dry-run output so the jest reporter stays readable.
    jest.spyOn(console, 'log').mockImplementation(() => {});
  });

  afterEach(() => {
    fs.rmSync(tempHome, { recursive: true, force: true });
    process.env.HOME = originalHome;
    jest.restoreAllMocks();
  });

  function projectCounts(): Record<string, number> {
    const db = new Database(dbPath, { readonly: true });
    const rows = db
      .prepare('SELECT project, COUNT(*) AS n FROM memories GROUP BY project')
      .all() as Array<{ project: string; n: number }>;
    db.close();
    return Object.fromEntries(rows.map((r) => [r.project, r.n]));
  }

  it('default dry-run does not modify the DB', async () => {
    const report = await repairProjectKeys({
      dbPath,
      map: { myrepo: 'acme-myrepo' },
      noConfirm: true,
    });
    expect(report.dryRun).toBe(true);
    expect(report.applied).toBe(0);
    expect(report.proposals).toHaveLength(1);
    expect(report.proposals[0]).toMatchObject({ legacy: 'myrepo', canonical: 'acme-myrepo', count: 3 });
    expect(projectCounts()).toEqual({ myrepo: 3, 'acme-myrepo': 3, other: 1 });
  });

  it('--execute rewrites legacy rows under the canonical key (LTM only by default)', async () => {
    const report = await repairProjectKeys({
      dbPath,
      map: { myrepo: 'acme-myrepo' },
      execute: true,
      noConfirm: true,
    });
    expect(report.dryRun).toBe(false);
    expect(report.applied).toBe(3);
    expect(report.backupPath).toBeDefined();
    expect(report.logPath).toBeDefined();
    expect(fs.existsSync(report.backupPath as string)).toBe(true);
    expect(fs.existsSync(report.logPath as string)).toBe(true);

    const counts = projectCounts();
    expect(counts.myrepo).toBeUndefined();
    expect(counts['acme-myrepo']).toBe(6); // 3 rewritten + 3 originals (incl. short-term)
    expect(counts.other).toBe(1);
  });

  it('--include-stm rewrites short-term rows too', async () => {
    // Seed an extra short-term row under the legacy key so we can see the flag.
    const db = new Database(dbPath);
    db.prepare(
      `INSERT INTO memories (uuid, type, category, title, content, project, salience)
       VALUES (?, 'short_term', 'note', 'h', 'h', 'myrepo', 0.5)`
    ).run(crypto.randomUUID());
    db.close();

    const report = await repairProjectKeys({
      dbPath,
      map: { myrepo: 'acme-myrepo' },
      includeStm: true,
      execute: true,
      noConfirm: true,
    });
    expect(report.applied).toBe(4);
    expect(projectCounts().myrepo).toBeUndefined();
  });

  it('is idempotent — second run is a no-op', async () => {
    await repairProjectKeys({
      dbPath,
      map: { myrepo: 'acme-myrepo' },
      execute: true,
      noConfirm: true,
    });
    const second = await repairProjectKeys({
      dbPath,
      map: { myrepo: 'acme-myrepo' },
      execute: true,
      noConfirm: true,
    });
    expect(second.proposals).toHaveLength(0);
    expect(second.applied).toBe(0);
  });

  it('limits rewrites to --project when supplied', async () => {
    const report = await repairProjectKeys({
      dbPath,
      map: { myrepo: 'acme-myrepo', other: 'unused' },
      onlyProject: 'myrepo',
      execute: true,
      noConfirm: true,
    });
    expect(report.applied).toBe(3);
    expect(projectCounts().other).toBe(1);
  });

  async function withNonTtyStdin(fn: () => Promise<void>): Promise<void> {
    const original = Object.getOwnPropertyDescriptor(process.stdin, 'isTTY');
    Object.defineProperty(process.stdin, 'isTTY', { value: undefined, configurable: true });
    try {
      await fn();
    } finally {
      if (original) Object.defineProperty(process.stdin, 'isTTY', original);
      else Reflect.deleteProperty(process.stdin, 'isTTY');
    }
  }

  it('non-interactive --execute applies without prompting (headless no-op regression)', async () => {
    // Regression: from v4.14.0 the confirm gate returned false whenever stdin
    // was not a TTY, so `--execute` printed "Aborted — no changes written."
    // in every agent/cron/SSH-exec context — the tool's primary audience —
    // while exiting 0. `--execute` is itself the consent; a non-TTY session
    // must proceed (dry-run stays the default, backup still written first).
    await withNonTtyStdin(async () => {
      const report = await repairProjectKeys({
        dbPath,
        map: { myrepo: 'acme-myrepo' },
        execute: true,
        // noConfirm deliberately absent — this is the production path.
      });
      expect(report.dryRun).toBe(false);
      expect(report.applied).toBe(3);
      expect(fs.existsSync(report.backupPath as string)).toBe(true);
    });
    expect(projectCounts().myrepo).toBeUndefined();
  });

  it('CLI arg path honours --db/--map/--include-stm/--execute together (Edith incident shape)', async () => {
    const db = new Database(dbPath);
    db.prepare(
      `INSERT INTO memories (uuid, type, category, title, content, project, salience)
       VALUES (?, 'short_term', 'note', 'stm-legacy', 'stm-legacy', 'myrepo', 0.5)`
    ).run(crypto.randomUUID());
    db.close();

    await withNonTtyStdin(async () => {
      await handleMemoriesCommand([
        'repair-project-keys',
        '--db',
        dbPath,
        '--map',
        'myrepo=acme-myrepo',
        '--include-stm',
        '--execute',
      ]);
    });

    const counts = projectCounts();
    expect(counts.myrepo).toBeUndefined();
    expect(counts['acme-myrepo']).toBe(7); // 4 rewritten (3 LTM + 1 STM) + 3 originals
  });
});
