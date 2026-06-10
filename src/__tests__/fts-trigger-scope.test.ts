/**
 * Phase 10 — scope the FTS reindex trigger (`memories_au`) to UPDATE OF the
 * indexed columns only (title, content, tags).
 *
 * THE BUG: `memories_au` shipped as `AFTER UPDATE ON memories` with no `OF`
 * column list, so it fired a full FTS5 external-content delete+reinsert on ANY
 * column update. The hottest write path — `accessMemory()` bumping
 * access_count / last_accessed / salience on EVERY recalled memory, plus the
 * 5-minute decay-score persistence — never touches indexed text, yet was
 * re-tokenising and rewriting the FTS index on every read. Pure write
 * amplification + extra surface for FTS drift.
 *
 * THE FIX: recreate the trigger as `AFTER UPDATE OF title, content, tags`.
 * The delete+insert body is unchanged, so real text edits still reindex.
 *
 * These tests assert three things:
 *   1. The shipped trigger DEFINITION is scoped (UPDATE OF title/content/tags),
 *      and an access-count-only bump does NOT corrupt/clear the index.
 *   2. A real title change STILL reindexes (new title matches, old does not).
 *   3. runMigrations() drops+recreates an OLD unscoped trigger so existing DBs
 *      get the scoped version (CREATE IF NOT EXISTS alone can't replace it).
 */
import fs from 'fs';
import os from 'os';
import path from 'path';
import { fileURLToPath } from 'url';
import { afterEach, beforeEach, describe, expect, it } from '@jest/globals';
import Database from 'better-sqlite3';
import { runMigrations } from '../database/migrations.js';

const thisFile = fileURLToPath(import.meta.url);
const repoRoot = path.resolve(path.dirname(thisFile), '..', '..');
const schemaPath = path.join(repoRoot, 'src', 'database', 'schema.sql');

/** Insert a memory via raw SQL (bypasses the defence pipeline; we only care
 * about the trigger here). Returns the new row id. */
function insertMemory(
  db: Database.Database,
  fields: { title: string; content: string; tags: string },
): number {
  const res = db
    .prepare(
      `INSERT INTO memories (uuid, title, content, tags, type, category, project)
       VALUES (?, ?, ?, ?, 'long_term', 'note', 'fts-scope-test')`,
    )
    .run(
      `uuid-${Math.random().toString(36).slice(2)}`,
      fields.title,
      fields.content,
      fields.tags,
    );
  return Number(res.lastInsertRowid);
}

/** Full-text search returning matching memory ids. */
function ftsSearch(db: Database.Database, term: string): number[] {
  const rows = db
    .prepare(
      `SELECT m.id AS id
       FROM memories m
       JOIN memories_fts fts ON m.id = fts.rowid
       WHERE memories_fts MATCH ?`,
    )
    .all(term) as { id: number }[];
  return rows.map((r) => r.id);
}

function triggerSql(db: Database.Database): string {
  const row = db
    .prepare(
      "SELECT sql FROM sqlite_master WHERE type='trigger' AND name='memories_au'",
    )
    .get() as { sql: string } | undefined;
  return row?.sql ?? '';
}

describe('memories_au FTS trigger is scoped to UPDATE OF title/content/tags', () => {
  let tempDir: string;
  let db: Database.Database;

  beforeEach(() => {
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'sc-fts-scope-'));
    db = new Database(':memory:');
    db.exec(fs.readFileSync(schemaPath, 'utf-8'));
  });

  afterEach(() => {
    db.close();
    fs.rmSync(tempDir, { recursive: true, force: true });
  });

  it('1. an access/salience bump does not reindex, and the trigger definition is scoped', () => {
    const id = insertMemory(db, {
      title: 'distinctivetitle architecture',
      content: 'some indexed body text',
      tags: 'database,postgres',
    });

    // The trigger definition itself must be scoped to the indexed columns.
    const sql = triggerSql(db);
    expect(sql).toMatch(/UPDATE\s+OF/i);
    expect(sql).toContain('title');
    expect(sql).toContain('content');
    expect(sql).toContain('tags');

    // Bump only the hot non-indexed columns (the accessMemory() write path).
    db.prepare(
      `UPDATE memories
       SET access_count = access_count + 1,
           last_accessed = CURRENT_TIMESTAMP,
           salience = 0.42
       WHERE id = ?`,
    ).run(id);

    // The FTS index must be intact: a search for the title still matches the row.
    expect(ftsSearch(db, 'distinctivetitle')).toContain(id);
    expect(ftsSearch(db, 'architecture')).toContain(id);
  });

  it('2. a real title change still reindexes (new title matches, old does not)', () => {
    const id = insertMemory(db, {
      title: 'oldtitleword reference',
      content: 'body content unchanged',
      tags: 'tagone',
    });

    expect(ftsSearch(db, 'oldtitleword')).toContain(id);

    db.prepare('UPDATE memories SET title = ? WHERE id = ?').run(
      'newtitleword replacement',
      id,
    );

    // Index updated for the real text change.
    expect(ftsSearch(db, 'newtitleword')).toContain(id);
    expect(ftsSearch(db, 'oldtitleword')).not.toContain(id);
  });

  it('3. runMigrations drops+recreates an OLD unscoped trigger on an existing DB', () => {
    // Simulate an old database: replace the scoped trigger with the legacy
    // unscoped `AFTER UPDATE ON memories` form that shipped before Phase 10.
    db.exec('DROP TRIGGER IF EXISTS memories_au');
    db.exec(`
      CREATE TRIGGER memories_au AFTER UPDATE ON memories BEGIN
        INSERT INTO memories_fts(memories_fts, rowid, title, content, tags)
        VALUES('delete', old.id, old.title, old.content, old.tags);
        INSERT INTO memories_fts(rowid, title, content, tags)
        VALUES (new.id, new.title, new.content, new.tags);
      END;
    `);

    // Sanity: the seeded trigger is the unscoped legacy form.
    expect(triggerSql(db)).not.toMatch(/UPDATE\s+OF/i);

    runMigrations(db);

    // The migration must have dropped + recreated it as the scoped form.
    const sql = triggerSql(db);
    expect(sql).toMatch(/UPDATE\s+OF/i);
    expect(sql).toContain('title');
    expect(sql).toContain('content');
    expect(sql).toContain('tags');

    // And the recreated trigger still maintains the index correctly.
    const id = insertMemory(db, {
      title: 'migratedword entry',
      content: 'post migration body',
      tags: 'migr',
    });
    db.prepare(
      'UPDATE memories SET access_count = access_count + 1 WHERE id = ?',
    ).run(id);
    expect(ftsSearch(db, 'migratedword')).toContain(id);
  });
});
