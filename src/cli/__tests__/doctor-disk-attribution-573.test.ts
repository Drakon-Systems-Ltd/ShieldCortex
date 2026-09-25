/**
 * #573 — the DISK check REPORTS what it measured, and prescribes only what a
 * measurement supports.
 *
 * THE INCIDENT. A host read `DB 54.2 MB · logs 41.4 MB`, and every remedy on
 * offer pointed into the database — because "logs" was one undifferentiated
 * lump and the only budget-freeing commands doctor knew were `memories prune`
 * and `memories dedupe`. The operator's only way to clear a failure caused by
 * log growth was to delete deliberately-retained memories.
 *
 * THE RULE, after two rounds of getting the clever version wrong. Rounds 1 and
 * 2 tried to decide WHICH ROWS were the bulk — `dbstat` page sums over the
 * `memories` table, its indexes and an FTS5 index's shadow tables, with the
 * index found by reading the `content=` option out of the schema. Each attempt
 * produced a new confidently-wrong recommendation to delete memories: a
 * threat-graph database, a database that was 95% free pages, an ordinary table
 * called `memories_backup` behind that `content=` option. So the ambition is
 * gone. The row reports the sizes it measured, and names a command in exactly
 * two cases, each backed by the number it already has:
 *
 *   1. repair logs are at least half the measured footprint → `logs prune`;
 *   2. at least 20% of the database is free pages → `vacuum`.
 *
 * Audit-dominated says so and names #579 (no command, nothing here deletes
 * evidence). Anything else reports the sizes and asks the operator to look.
 * NOTHING in this row ever recommends deleting a row — not memories, not
 * session events, not audit rows.
 */

import fs from 'fs';
import os from 'os';
import path from 'path';
import Database from 'better-sqlite3';
import { afterEach, beforeEach, describe, expect, it } from '@jest/globals';

import { checkDiskUsage } from '../doctor.js';

const KB = 1024;
let scDir: string;

/** Any row-deleting recommendation, in any of the forms doctor has ever used. */
const DELETION_ADVICE = /memories prune|memories dedupe|memories clear|sessions prune/;

beforeEach(() => {
  scDir = fs.mkdtempSync(path.join(os.tmpdir(), 'sc-573-disk-'));
});

afterEach(() => {
  try { fs.rmSync(scDir, { recursive: true, force: true }); } catch { /* ignore */ }
});

function writeBytes(rel: string, bytes: number): void {
  const full = path.join(scDir, rel);
  fs.mkdirSync(path.dirname(full), { recursive: true });
  fs.writeFileSync(full, Buffer.alloc(bytes, 0x61));
}

function repairLogs(count: number, bytesEach: number): void {
  for (let i = 0; i < count; i++) {
    writeBytes(
      path.join('logs', `project-key-repair-2026-01-01T00-00-${String(i).padStart(2, '0')}-000Z.json`),
      bytesEach,
    );
  }
}

const MEMORIES_DDL = 'CREATE TABLE memories (id INTEGER PRIMARY KEY AUTOINCREMENT, content TEXT NOT NULL)';
const THREAT_DDL = 'CREATE TABLE threat_nodes (id INTEGER PRIMARY KEY AUTOINCREMENT, blob TEXT NOT NULL)';

interface DbShape {
  memoryBytes: number;
  memoryRows?: number;
  threatBytes?: number;
  /** Bytes of threat_nodes written and then deleted — free pages, not data. */
  freedThreatBytes?: number;
  /**
   * An EXTERNAL-CONTENT FTS5 index over a table called `memories_backup`. The
   * round-2 attribution read its `content=memories_backup` option with
   * `/content\s*=\s*'?memories'?/` and charged its pages to `memories`.
   */
  ftsOverBackupBytes?: number;
}

function buildDb(shape: DbShape): void {
  const db = new Database(path.join(scDir, 'memories.db'));
  // One transaction for the whole fixture: a few hundred autocommitted inserts
  // is a few hundred fsyncs, and these suites build several of them.
  db.prepare('BEGIN').run();
  db.prepare(MEMORIES_DDL).run();
  db.prepare(THREAT_DDL).run();

  const rows = shape.memoryRows ?? 1;
  const per = Math.max(1, Math.floor(shape.memoryBytes / rows));
  const insMem = db.prepare('INSERT INTO memories (content) VALUES (?)');
  for (let i = 0; i < rows; i++) insMem.run('m'.repeat(per));

  const insThreat = db.prepare('INSERT INTO threat_nodes (blob) VALUES (?)');
  const chunk = 2048;
  for (let written = 0; written < (shape.threatBytes ?? 0); written += chunk) {
    insThreat.run('t'.repeat(chunk));
  }
  if (shape.freedThreatBytes) {
    const before = db.prepare('SELECT MAX(id) AS m FROM threat_nodes').get() as { m: number | null };
    for (let written = 0; written < shape.freedThreatBytes; written += chunk) {
      insThreat.run('f'.repeat(chunk));
    }
    db.prepare('DELETE FROM threat_nodes WHERE id > ?').run(before.m ?? 0);
  }
  if (shape.ftsOverBackupBytes) {
    db.prepare('CREATE TABLE memories_backup (id INTEGER PRIMARY KEY, content TEXT)').run();
    const ins = db.prepare('INSERT INTO memories_backup (content) VALUES (?)');
    let word = 0;
    for (let written = 0; written < shape.ftsOverBackupBytes; written += chunk) {
      const words: string[] = [];
      for (let j = 0; j < chunk / 6; j++) words.push(`w${(word++).toString(36)}`);
      ins.run(words.join(' '));
    }
    db.prepare(
      "CREATE VIRTUAL TABLE backup_search USING fts5(content, content=memories_backup, content_rowid=id)",
    ).run();
    db.prepare("INSERT INTO backup_search(backup_search) VALUES('rebuild')").run();
  }
  db.prepare('COMMIT').run();
  db.close();
}

describe('#573 the DISK breakdown reports the sizes it measured', () => {
  it('splits the logs term into audit, repair and other', async () => {
    writeBytes('memories.db', 4 * KB);
    writeBytes('audit/realtime-2026-01-01.jsonl', 20 * KB);
    repairLogs(6, 2 * KB);
    writeBytes('logs/some-other.log', 3 * KB);

    const result = await checkDiskUsage(scDir, 32 * KB);

    expect(result.status).toBe('fail');
    expect(result.message).toMatch(/audit 20\.0 KB/);
    expect(result.message).toMatch(/repair 12\.0 KB/);
    expect(result.message).toMatch(/other 3\.0 KB/);
  });

  it('reports the DB free pages, so vacuum advice is checkable', async () => {
    buildDb({ memoryBytes: 1, threatBytes: 200 * KB, freedThreatBytes: 300 * KB });

    const result = await checkDiskUsage(scDir, 128 * KB);

    expect(result.message).toMatch(/DB .*\(\d+\.\d KB free\)/);
  });

  it('counts a repair log by the grammar `logs prune` acts on, not by prefix', async () => {
    // The number shown has to be the set the recommended command would
    // consider. `project-key-repair-config.json` is an operator's file: prune
    // leaves it alone (round-3 blocker 4), so this must not count it either.
    writeBytes('memories.db', 1 * KB);
    repairLogs(4, 2 * KB);
    writeBytes(path.join('logs', 'project-key-repair-config.json'), 40 * KB);

    const result = await checkDiskUsage(scDir, 32 * KB);

    expect(result.message).toMatch(/repair 8\.0 KB/);
    expect(result.fix).not.toMatch(/logs prune/);
  });
});

describe('#573 the remedy follows the measurement, or names no command', () => {
  it('recommends `logs prune --execute` when repair logs are most of the footprint', async () => {
    writeBytes('memories.db', 4 * KB);
    repairLogs(30, 2 * KB);

    const result = await checkDiskUsage(scDir, 32 * KB);

    expect(result.status).toBe('fail');
    expect(result.fix).toMatch(/shieldcortex logs prune --execute/);
    expect(result.fix).toMatch(/project-key-repair/);
    expect(result.fix).not.toMatch(DELETION_ADVICE);
  });

  it('names the audit plane and the follow-up issue, with no command', async () => {
    writeBytes('memories.db', 4 * KB);
    writeBytes('audit/realtime-2026-01-01.jsonl', 60 * KB);
    repairLogs(1, 1 * KB);

    const result = await checkDiskUsage(scDir, 32 * KB);

    expect(result.status).toBe('fail');
    expect(result.fix).toMatch(/audit/);
    // The honest answer is "no retention for this plane yet, here is where
    // that is tracked" — not a command that would not touch it.
    expect(result.fix).toContain('#579');
    expect(result.fix).not.toMatch(/logs prune --execute/);
    expect(result.fix).not.toMatch(DELETION_ADVICE);
  });

  it('reports the sizes and names nothing when no term holds half of them', async () => {
    writeBytes('memories.db', 20 * KB);
    writeBytes('audit/realtime-2026-01-01.jsonl', 20 * KB);
    writeBytes('state/worker.json', 20 * KB);

    const result = await checkDiskUsage(scDir, 32 * KB);

    expect(result.status).toBe('fail');
    expect(result.fix).toMatch(/No single measured consumer/);
    expect(result.fix).toMatch(/inspect before removing anything/);
    expect(result.fix).not.toMatch(DELETION_ADVICE);
    expect(result.fix).not.toMatch(/shieldcortex vacuum|logs prune/);
  });

  it('recommends no vacuum, and no blanket clearing, for a state file and no database', async () => {
    // The round-2 reviewer's fixture: a large state file, no DB at all. It was
    // told to vacuum, and handed a list of five directories as "safe to rotate
    // or clear" — including state/ (worker freshness, locks) and quarantine/
    // (items awaiting review).
    writeBytes('state/worker.json', 40 * KB);

    const result = await checkDiskUsage(scDir, 32 * KB);

    expect(result.status).toBe('fail');
    expect(result.fix).not.toMatch(/shieldcortex vacuum/);
    expect(result.fix).not.toMatch(/safe to rotate or clear/);
    expect(result.fix).toMatch(/No single measured consumer/);
  });
});

// ── Round-3 blockers 2 and 3: the reviewer's three fixtures ───────────────

describe('#573 blocker 3 — deletion advice is gone, and vacuum needs free pages', () => {
  it('sends a 95%-free-pages database to vacuum, and to nothing else', async () => {
    // The reviewer's fixture: 25 pages of memories, then a large row inserted
    // and deleted — 488 of 515 pages free, reclaimable without deleting one
    // memory. Doctor called memories "the bulk" (93% of the REMAINING used
    // pages) and prescribed prune/dedupe before vacuum.
    buildDb({ memoryBytes: 100 * KB, memoryRows: 50, freedThreatBytes: 800 * KB });

    const result = await checkDiskUsage(scDir, 256 * KB);

    expect(result.status).toBe('fail');
    expect(result.fix).toMatch(/shieldcortex vacuum/);
    expect(result.fix).toMatch(/free/);
    expect(result.fix).not.toMatch(DELETION_ADVICE);
  });

  it('withholds vacuum below the 20% free-page floor, and gives it above', async () => {
    // A database with essentially no free pages must not be sent to a full
    // file rewrite that would reclaim nothing — the round-2 defect was that
    // the memory and session branches named `vacuum` without consulting this
    // threshold at all.
    buildDb({ memoryBytes: 1, threatBytes: 500 * KB });
    const tight = await checkDiskUsage(scDir, 256 * KB);
    expect(tight.fix).not.toMatch(/shieldcortex vacuum/);
    expect(tight.fix).not.toMatch(DELETION_ADVICE);

    fs.rmSync(path.join(scDir, 'memories.db'));
    buildDb({ memoryBytes: 1, threatBytes: 100 * KB, freedThreatBytes: 400 * KB });
    const loose = await checkDiskUsage(scDir, 256 * KB);
    expect(loose.fix).toMatch(/shieldcortex vacuum/);
  });

  it('gives a mixed footprint with no free pages no command at all', async () => {
    // The reviewer's second fixture: DB ~104 KB, audit ~98 KB, another 90 KB
    // file, zero free pages. Memories were ~35% of the measured total and
    // still drew `memories prune`/`dedupe`, followed by a `vacuum` with
    // nothing to reclaim.
    buildDb({ memoryBytes: 90 * KB, memoryRows: 90 });
    writeBytes('audit/realtime-2026-01-01.jsonl', 98 * KB);
    writeBytes('state/worker.json', 90 * KB);

    const result = await checkDiskUsage(scDir, 128 * KB);

    expect(result.status).toBe('fail');
    expect(result.fix).not.toMatch(DELETION_ADVICE);
    expect(result.fix).not.toMatch(/shieldcortex vacuum/);
    expect(result.fix).toMatch(/No single measured consumer/);
  });

  it('never recommends deletion for a database filled by the threat graph', async () => {
    // 1 byte of memories, 500 KB of threat_nodes: a file-size heuristic calls
    // this "the DB is the bulk, prune your memories".
    buildDb({ memoryBytes: 1, threatBytes: 500 * KB });

    const result = await checkDiskUsage(scDir, 256 * KB);

    expect(result.status).toBe('fail');
    expect(result.fix).not.toMatch(DELETION_ADVICE);
  });

  it('never recommends deletion even when the database really is all memories', async () => {
    // The case the old code was built to serve. It is STILL not advice this
    // row gives: doctor cannot tell a deliberately-retained corpus from a
    // runaway one, and the DISK row is not where that call gets made.
    buildDb({ memoryBytes: 500 * KB, memoryRows: 250 });

    const result = await checkDiskUsage(scDir, 256 * KB);

    expect(result.status).toBe('fail');
    expect(result.fix).not.toMatch(DELETION_ADVICE);
  });
});

describe('#573 blocker 2 — no schema text is read as ownership by the memory system', () => {
  it('gives no deletion advice for an FTS5 index over `memories_backup`', async () => {
    // The reviewer's fixture: one byte of memories, a separate memories_backup
    // table, and `CREATE VIRTUAL TABLE backup_search USING fts5(content,
    // content=memories_backup, content_rowid=id)`. The regex
    // /content\s*=\s*'?memories'?/ matched `content=memories_backup`, so one
    // real memories page out of 372 was reported as 50% and drew prune/dedupe.
    buildDb({ memoryBytes: 1, ftsOverBackupBytes: 400 * KB });

    const result = await checkDiskUsage(scDir, 256 * KB);

    expect(result.status).toBe('fail');
    expect(result.fix).not.toMatch(DELETION_ADVICE);
    // And no share of any table is claimed at all — there is no attribution
    // left to be right or wrong about.
    expect(result.fix).not.toMatch(/used pages|% of the/);
  });
});
