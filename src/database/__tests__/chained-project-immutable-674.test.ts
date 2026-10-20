import fs from 'fs';
import os from 'os';
import path from 'path';
import { fileURLToPath } from 'url';
import { randomUUID } from 'crypto';
import { afterEach, beforeEach, describe, expect, it, jest } from '@jest/globals';
import Database from 'better-sqlite3';
import { logIfUnexpectedDdlError, runMigrations } from '../migrations.js';
import { getInlineSchema } from '../inline-schema.js';

/**
 * #674: builds up to v5.2.1 run the defence_audit project backfill on every
 * start with no `seq IS NULL` guard. Against a database a 5.3+ build has
 * chained, that rewrote `project` (part of the content digest) and broke
 * `ledger verify`. The refusal lives in the database as
 * trg_defence_audit_chained_project_immutable, so it holds whichever build
 * issues the UPDATE.
 */

const TRIGGER = 'trg_defence_audit_chained_project_immutable';

const thisFile = fileURLToPath(import.meta.url);
const schemaPath = path.join(path.dirname(thisFile), '..', 'schema.sql');

// The v5.2.1 backfill, verbatim apart from formatting: the same two UPDATEs
// the current build runs, without the `AND seq IS NULL` guard.
function legacyBackfill(db: Database.Database): void {
  db.exec(`UPDATE defence_audit SET project = (
    SELECT m.project FROM memories m WHERE m.id = defence_audit.memory_id
  ) WHERE memory_id IS NOT NULL AND project IS NULL`);
  db.exec(`UPDATE defence_audit SET project = (
    SELECT project FROM memories WHERE project IS NOT NULL GROUP BY project ORDER BY COUNT(*) DESC LIMIT 1
  ) WHERE project IS NULL`);
}

function insertMemory(db: Database.Database, project: string): number {
  return Number(
    db
      .prepare(
        `INSERT INTO memories (uuid, type, category, title, content, project)
         VALUES (?, 'long_term', 'note', 't', 'c', ?)`,
      )
      .run(randomUUID(), project).lastInsertRowid,
  );
}

function insertAudit(
  db: Database.Database,
  opts: { memoryId?: number | null; project?: string | null; seq?: number | null },
): number {
  return Number(
    db
      .prepare(
        `INSERT INTO defence_audit
           (memory_id, project, source_type, source_identifier, trust_score, firewall_result, epoch, seq)
         VALUES (?, ?, 'hook', 'test', 0.9, 'ALLOW', ?, ?)`,
      )
      .run(
        opts.memoryId ?? null,
        opts.project ?? null,
        opts.seq == null ? null : 0,
        opts.seq ?? null,
      ).lastInsertRowid,
  );
}

function projectOf(db: Database.Database, id: number): string | null {
  return (db.prepare('SELECT project FROM defence_audit WHERE id = ?').get(id) as { project: string | null })
    .project;
}

function hasTrigger(db: Database.Database): boolean {
  return !!db.prepare("SELECT 1 FROM sqlite_master WHERE type = 'trigger' AND name = ?").get(TRIGGER);
}

describe('#674 chained defence_audit project is immutable', () => {
  let tempDir: string;
  let db: Database.Database;

  beforeEach(() => {
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'shieldcortex-674-'));
    db = new Database(path.join(tempDir, 'memories.db'));
    db.exec(fs.readFileSync(schemaPath, 'utf-8'));
  });

  afterEach(() => {
    db.close();
    fs.rmSync(tempDir, { recursive: true, force: true });
  });

  it('schema.sql and the inline schema both create the trigger', () => {
    expect(hasTrigger(db)).toBe(true);
    const inline = new Database(':memory:');
    try {
      inline.exec(getInlineSchema());
      expect(hasTrigger(inline)).toBe(true);
    } finally {
      inline.close();
    }
  });

  it('refuses the v5.2.1 backfill and leaves chained and unchained rows as they were', () => {
    const mem = insertMemory(db, 'alpha');
    const chainedLinked = insertAudit(db, { memoryId: mem, seq: 0 });
    const chainedBare = insertAudit(db, { seq: 1 });
    const unchained = insertAudit(db, { memoryId: mem });

    expect(() => legacyBackfill(db)).toThrow(/ShieldCortex #674: project of a chained defence_audit row is immutable/);

    // The refused statement rolls back as a whole, unchained rows included.
    expect(projectOf(db, chainedLinked)).toBeNull();
    expect(projectOf(db, chainedBare)).toBeNull();
    expect(projectOf(db, unchained)).toBeNull();
  });

  it('a current start still backfills unchained rows and skips chained ones', () => {
    const mem = insertMemory(db, 'alpha');
    const chained = insertAudit(db, { memoryId: mem, seq: 0 });
    const unchainedLinked = insertAudit(db, { memoryId: mem });
    const unchainedBare = insertAudit(db, {});

    const errSpy = jest.spyOn(console, 'error').mockImplementation(() => {});
    try {
      runMigrations(db);
      const triggerErrors = errSpy.mock.calls.filter((c) => String(c[0]).includes('#674'));
      expect(triggerErrors).toEqual([]);
    } finally {
      errSpy.mockRestore();
    }

    expect(projectOf(db, chained)).toBeNull();
    expect(projectOf(db, unchainedLinked)).toBe('alpha');
    expect(projectOf(db, unchainedBare)).toBe('alpha');
  });

  it('lets no-op project updates, other columns, unchained rows and deletes through', () => {
    const chainedNull = insertAudit(db, { seq: 0 });
    const chainedSet = insertAudit(db, { project: 'alpha', seq: 1 });
    const unchained = insertAudit(db, {});

    db.prepare('UPDATE defence_audit SET project = NULL WHERE id = ?').run(chainedNull);
    db.prepare("UPDATE defence_audit SET project = 'alpha' WHERE id = ?").run(chainedSet);
    db.prepare("UPDATE defence_audit SET content_digest = 'd', row_hash = 'h' WHERE id = ?").run(chainedNull);
    db.prepare('UPDATE defence_audit SET memory_id = NULL WHERE id = ?').run(chainedSet);
    db.prepare("UPDATE defence_audit SET project = 'beta' WHERE id = ?").run(unchained);
    expect(projectOf(db, unchained)).toBe('beta');

    expect(() =>
      db.prepare("UPDATE defence_audit SET project = 'beta' WHERE id = ?").run(chainedSet),
    ).toThrow(/#674/);
    expect(() =>
      db.prepare('UPDATE defence_audit SET project = NULL WHERE id = ?').run(chainedSet),
    ).toThrow(/#674/);
    expect(projectOf(db, chainedSet)).toBe('alpha');

    db.prepare('DELETE FROM defence_audit WHERE id = ?').run(chainedSet);
    expect(db.prepare('SELECT COUNT(*) AS n FROM defence_audit WHERE id = ?').get(chainedSet)).toEqual({ n: 0 });
  });

  it('runMigrations adds the trigger to an existing chained database that lacks it', () => {
    db.exec(`DROP TRIGGER ${TRIGGER}`);
    expect(hasTrigger(db)).toBe(false);
    runMigrations(db);
    expect(hasTrigger(db)).toBe(true);
    const chained = insertAudit(db, { seq: 0 });
    expect(() =>
      db.prepare("UPDATE defence_audit SET project = 'x' WHERE id = ?").run(chained),
    ).toThrow(/#674/);
  });

  it('the DDL error filter prints the refusal instead of swallowing it', () => {
    const errSpy = jest.spyOn(console, 'error').mockImplementation(() => {});
    try {
      insertAudit(db, { seq: 0 });
      insertMemory(db, 'alpha');
      try {
        legacyBackfill(db);
      } catch (err) {
        logIfUnexpectedDdlError(err, 'defence_audit/quarantine project backfill (data migration)');
      }
      expect(errSpy).toHaveBeenCalledTimes(1);
      // Under jest's module realms SqliteError can fail `instanceof Error`, so
      // the filter falls back to String(err) and gains a "SqliteError: " prefix.
      expect(String(errSpy.mock.calls[0][0])).toMatch(
        /^\[database\] unexpected migration error in defence_audit\/quarantine project backfill \(data migration\): (SqliteError: )?ShieldCortex #674: /,
      );
    } finally {
      errSpy.mockRestore();
    }
  });
});
