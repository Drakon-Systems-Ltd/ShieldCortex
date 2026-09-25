/**
 * #573 — the DISK check names the real consumer, and never recommends deleting
 * memories without positive page-level evidence.
 *
 * THE INCIDENT. A host read `DB 54.2 MB · logs 41.4 MB`, and every remedy on
 * offer pointed into the database — because "logs" was one undifferentiated
 * lump and the only budget-freeing commands doctor knew were `memories prune`
 * and `memories dedupe`. The operator's only way to clear a failure caused by
 * log growth was to delete deliberately-retained memories.
 *
 * THE RULE. Memory-deletion advice requires POSITIVE ATTRIBUTION: the pages of
 * the `memories` table plus its indexes and FTS shadow tables, read from the
 * `dbstat` virtual table, must be at least half the database's used pages, and
 * the database must be the largest disk term. The FILE's size is never the
 * evidence — free pages, session capture, defence-audit rows and the threat
 * graph all inflate it and none of them are reachable by prune or dedupe. When
 * attribution is unavailable (no dbstat, unreadable DB) the answer is
 * inspection, not a guess that happens to be destructive.
 */

import fs from 'fs';
import os from 'os';
import path from 'path';
import Database from 'better-sqlite3';
import { afterEach, beforeEach, describe, expect, it } from '@jest/globals';

import { checkDiskUsage } from '../doctor.js';

const KB = 1024;
let scDir: string;

/** Any memory-deleting recommendation, in any of the forms doctor uses. */
const DELETION_ADVICE = /memories prune|memories dedupe|memories clear/;

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
const MEMORIES_FTS_DDL = "CREATE VIRTUAL TABLE memories_fts USING fts5(content, content='memories', content_rowid='id')";
const THREAT_DDL = 'CREATE TABLE threat_nodes (id INTEGER PRIMARY KEY AUTOINCREMENT, blob TEXT NOT NULL)';
const SESSION_DDL = `CREATE TABLE session_events (
  id INTEGER PRIMARY KEY AUTOINCREMENT, session_id TEXT NOT NULL, ts TIMESTAMP NOT NULL,
  kind TEXT NOT NULL, payload TEXT NOT NULL)`;
const AUDIT_DDL = `CREATE TABLE defence_audit (
  id INTEGER PRIMARY KEY AUTOINCREMENT, reason TEXT, threat_indicators TEXT DEFAULT '[]',
  blocked_patterns TEXT DEFAULT '[]', source_type TEXT NOT NULL DEFAULT 'test',
  source_identifier TEXT NOT NULL DEFAULT 'test')`;

interface DbShape {
  memoryBytes: number;
  memoryRows?: number;
  threatBytes?: number;
  /** Bytes of threat_nodes written and then deleted — free pages, not data. */
  freedThreatBytes?: number;
  withFts?: boolean;
  /**
   * Fill memories with distinct tokens rather than one repeated character, so
   * the FTS5 index is a realistic share of the pages. Repetitive content
   * compresses to a single term and makes the shadow tables negligible, which
   * hides whether they are counted at all.
   */
  varied?: boolean;
  /** Shadow the dbstat vtab with a view, so attribution is genuinely absent. */
  breakDbstat?: boolean;
  /** Bytes in `defence_audit`, spread over `auditRows` rows (default 1). */
  auditBytes?: number;
  auditRows?: number;
  /**
   * Bytes in an ORDINARY table called `memories_fts_backup` — not an FTS index,
   * just a name a LIKE pattern used to claim (#573 round 2, blocker 7).
   */
  ftsBackupBytes?: number;
}

function buildDb(shape: DbShape): void {
  const db = new Database(path.join(scDir, 'memories.db'));
  // One transaction for the whole fixture: a few hundred autocommitted inserts
  // is a few hundred fsyncs, and these suites build ten of them.
  db.prepare('BEGIN').run();
  db.prepare(MEMORIES_DDL).run();
  db.prepare(SESSION_DDL).run();
  db.prepare(AUDIT_DDL).run();
  db.prepare(THREAT_DDL).run();
  if (shape.withFts) db.prepare(MEMORIES_FTS_DDL).run();

  const rows = shape.memoryRows ?? 1;
  const per = Math.max(1, Math.floor(shape.memoryBytes / rows));
  const insMem = db.prepare('INSERT INTO memories (content) VALUES (?)');
  for (let i = 0; i < rows; i++) {
    if (shape.varied) {
      // GLOBALLY distinct tokens. Tokens that repeat across rows collapse into
      // shared posting lists and shrink the FTS index below the table it
      // indexes, which is the one shape that would make this fixture unable to
      // tell "shadow tables counted" from "shadow tables ignored".
      const wordsPerRow = Math.max(1, Math.floor(per / 6));
      const words: string[] = [];
      for (let j = 0; j < wordsPerRow; j++) words.push(`w${(i * wordsPerRow + j).toString(36)}`);
      insMem.run(words.join(' '));
    } else {
      insMem.run('m'.repeat(per));
    }
  }
  if (shape.withFts) {
    db.prepare("INSERT INTO memories_fts(memories_fts) VALUES('rebuild')").run();
  }

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
  if (shape.auditBytes) {
    const auditRows = shape.auditRows ?? 1;
    const perAudit = Math.max(1, Math.floor(shape.auditBytes / auditRows));
    const insAudit = db.prepare('INSERT INTO defence_audit (reason) VALUES (?)');
    for (let i = 0; i < auditRows; i++) insAudit.run('a'.repeat(perAudit));
  }
  if (shape.ftsBackupBytes) {
    db.prepare('CREATE TABLE memories_fts_backup (id INTEGER PRIMARY KEY, content TEXT)').run();
    const insBackup = db.prepare('INSERT INTO memories_fts_backup (content) VALUES (?)');
    for (let written = 0; written < shape.ftsBackupBytes; written += chunk) {
      insBackup.run('b'.repeat(chunk));
    }
  }
  if (shape.breakDbstat) db.prepare('CREATE VIEW dbstat AS SELECT 1 AS irrelevant').run();
  db.prepare('COMMIT').run();
  db.close();
}

describe('#573 the DISK breakdown names which logs, and the free pages inside the DB', () => {
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
});

describe('#573 the remedy points at the term that is actually over budget', () => {
  it('recommends `logs prune --execute` when repair logs are the largest term', async () => {
    writeBytes('memories.db', 4 * KB);
    repairLogs(30, 2 * KB);

    const result = await checkDiskUsage(scDir, 32 * KB);

    expect(result.status).toBe('fail');
    expect(result.fix).toMatch(/shieldcortex logs prune --execute/);
    expect(result.fix).toMatch(/project-key-repair/);
    expect(result.fix).not.toMatch(DELETION_ADVICE);
  });

  it('names the audit plane and the follow-up issue when audit is the largest term, with no command', async () => {
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
});

describe('#573 memory deletion needs positive page-level attribution', () => {
  it('does not recommend deletion for a DB filled by the threat graph (reviewer fixture)', async () => {
    // 1 byte of memories, 500 KB of threat_nodes. A file-size heuristic calls
    // this "the DB is the bulk, prune your memories"; the pages say the
    // memories table is a rounding error.
    buildDb({ memoryBytes: 1, threatBytes: 500 * KB });

    const result = await checkDiskUsage(scDir, 256 * KB);

    expect(result.status).toBe('fail');
    expect(result.fix).not.toMatch(DELETION_ADVICE);
    expect(result.fix).toMatch(/shieldcortex stats/);
  });

  it('recommends vacuum, not deletion, when the DB is mostly free pages', async () => {
    buildDb({ memoryBytes: 1, threatBytes: 100 * KB, freedThreatBytes: 400 * KB });

    const result = await checkDiskUsage(scDir, 256 * KB);

    expect(result.status).toBe('fail');
    expect(result.fix).not.toMatch(DELETION_ADVICE);
    expect(result.fix).toMatch(/shieldcortex vacuum/);
    expect(result.fix).toMatch(/free pages/);
  });

  it('DOES recommend prune when the memories table really is the bulk', async () => {
    buildDb({ memoryBytes: 500 * KB, memoryRows: 250, withFts: true });

    const result = await checkDiskUsage(scDir, 256 * KB);

    expect(result.status).toBe('fail');
    expect(result.fix).toMatch(/shieldcortex memories prune --execute/);
    // Prune alone leaves the freed pages in the file.
    expect(result.fix).toMatch(/shieldcortex vacuum/);
  });

  it('refuses to recommend deletion when dbstat is unavailable, even on the same fixture', async () => {
    // Identical to the case above apart from dbstat being unreachable. Absence
    // of evidence is not evidence: the advice must fall back to inspection.
    buildDb({ memoryBytes: 500 * KB, memoryRows: 250, withFts: true, breakDbstat: true });

    const result = await checkDiskUsage(scDir, 256 * KB);

    expect(result.status).toBe('fail');
    expect(result.fix).not.toMatch(DELETION_ADVICE);
    expect(result.fix).toMatch(/shieldcortex stats/);
    // And it must say WHY it cannot advise, rather than reporting an
    // unmeasured share as a measured one. Treating "no dbstat" as "0% of the
    // pages" reaches the same non-destructive conclusion by asserting
    // something false about the operator's database.
    expect(result.fix).toMatch(/dbstat/);
    expect(result.fix).not.toMatch(/holds only 0%/);
  });

  it('counts the FTS shadow tables and indexes as part of the memories table', async () => {
    // Real text: the external-content FTS5 index ends up LARGER than the table
    // it indexes (measured on this fixture: 166 pages of shadow tables against
    // 111 of `memories`). Counting only the table puts the memory system at 39%
    // of the used pages and silently withdraws prune advice from a database
    // that genuinely is nothing but memories.
    buildDb({ memoryBytes: 400 * KB, memoryRows: 400, withFts: true, varied: true });

    const result = await checkDiskUsage(scDir, 512 * KB);

    expect(result.status).toBe('fail');
    expect(result.fix).toMatch(/shieldcortex memories prune --execute/);
  });

  it('gives no deletion advice when the DB is not the largest term at all', async () => {
    // Even a genuinely memories-dominated DB must not be the answer when
    // something else is what filled the directory.
    buildDb({ memoryBytes: 20 * KB, memoryRows: 20, withFts: true });
    repairLogs(60, 2 * KB);

    const result = await checkDiskUsage(scDir, 64 * KB);

    expect(result.status).toBe('fail');
    expect(result.fix).toMatch(/shieldcortex logs prune --execute/);
    expect(result.fix).not.toMatch(DELETION_ADVICE);
  });
});

// ── Round-2 blockers 6 and 7 ──────────────────────────────────────────────

describe('#573 blocker 6 — a consumer is only "the bulk" when it is measured to be', () => {
  it('does not blame one byte of defence_audit for a threat-graph database', async () => {
    // The reviewer's fixture exactly: 1 B of memories, 500 KB of threat_nodes,
    // 1 B in defence_audit, no free pages. The old condition compared audit
    // bytes ONLY against session bytes (1 > 0), so doctor announced "the bulk
    // is defence-audit rows … ~1 B" and recommended a vacuum with nothing to
    // reclaim.
    buildDb({ memoryBytes: 1, threatBytes: 500 * KB, auditBytes: 1 });

    const result = await checkDiskUsage(scDir, 256 * KB);

    expect(result.status).toBe('fail');
    expect(result.fix).not.toMatch(/bulk is defence-audit/);
    expect(result.fix).not.toMatch(DELETION_ADVICE);
    expect(result.fix).not.toMatch(/shieldcortex vacuum/);
    expect(result.fix).toMatch(/shieldcortex stats/);
  });

  it('DOES blame defence_audit when it genuinely holds the file', async () => {
    // The other side of the same rule: the branch must still fire when the
    // measurement supports it, or the fix above is just a mute button.
    buildDb({ memoryBytes: 1, auditBytes: 400 * KB, auditRows: 400 });

    const result = await checkDiskUsage(scDir, 256 * KB);

    expect(result.status).toBe('fail');
    expect(result.fix).toMatch(/bulk is defence-audit rows/);
    expect(result.fix).toMatch(/400 rows/);
    expect(result.fix).not.toMatch(DELETION_ADVICE);
  });

  it('recommends no vacuum, and no blanket clearing, for a state file and no database', async () => {
    // The reviewer's second fixture: a large state file, no DB at all. It was
    // told to vacuum, and handed a list of five directories as "safe to rotate
    // or clear" — including state/ (worker freshness, locks) and quarantine/
    // (items awaiting review).
    writeBytes('state/worker.json', 40 * KB);

    const result = await checkDiskUsage(scDir, 32 * KB);

    expect(result.status).toBe('fail');
    expect(result.fix).not.toMatch(/shieldcortex vacuum/);
    expect(result.fix).not.toMatch(/safe to rotate or clear/);
    expect(result.fix).toMatch(/No single measured consumer/);
    expect(result.fix).toMatch(/Inspect before removing anything/);
  });

  it('withholds vacuum advice below the 20% free-page floor, and gives it above', async () => {
    buildDb({ memoryBytes: 1, threatBytes: 500 * KB });
    const tight = await checkDiskUsage(scDir, 256 * KB);
    expect(tight.fix).not.toMatch(/shieldcortex vacuum/);

    fs.rmSync(path.join(scDir, 'memories.db'));
    buildDb({ memoryBytes: 1, threatBytes: 100 * KB, freedThreatBytes: 400 * KB });
    const loose = await checkDiskUsage(scDir, 256 * KB);
    expect(loose.fix).toMatch(/shieldcortex vacuum/);
    expect(loose.fix).toMatch(/free pages/);
  });
});

describe('#573 blocker 7 — a name prefix is not ownership by the search index', () => {
  it('does not claim the pages of an ordinary table called memories_fts_backup', async () => {
    // The reviewer's fixture: 1 B of memories and 500 KB in an ORDINARY table
    // named `memories_fts_backup`. Under `tbl_name LIKE 'memories_fts%'` doctor
    // reported memories owning 99% of the used pages and recommended
    // `memories prune`/`dedupe`, neither of which can reclaim another table.
    buildDb({ memoryBytes: 1, withFts: true, ftsBackupBytes: 500 * KB });

    const result = await checkDiskUsage(scDir, 256 * KB);

    expect(result.status).toBe('fail');
    expect(result.fix).not.toMatch(DELETION_ADVICE);
    expect(result.fix).toMatch(/holds only \d+% of its used pages/);
    expect(result.fix).toMatch(/shieldcortex stats/);
  });

  it('still counts the real FTS5 index, so the rule is precision and not silence', async () => {
    // Same shape as the fixture above minus the impostor table: the genuine
    // external-content FTS5 index and its shadow tables must still be counted
    // as the memory system's, or blocker 7's fix would simply withdraw all
    // prune advice.
    buildDb({ memoryBytes: 400 * KB, memoryRows: 400, withFts: true, varied: true });

    const result = await checkDiskUsage(scDir, 512 * KB);

    expect(result.fix).toMatch(/shieldcortex memories prune --execute/);
  });
});
