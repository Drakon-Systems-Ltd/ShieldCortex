import fs from 'fs';
import os from 'os';
import path from 'path';
import { afterEach, beforeEach, describe, expect, it } from '@jest/globals';
import Database from 'better-sqlite3';
import { runMigrations } from '../migrations.js';

/**
 * P1/WS3 (issue #60) — the defence_verdict provenance migration on an EXISTING
 * (pre-invariant) database: the column is added, and every row that predates
 * the invariant is backfilled to 'legacy' (never left null or mislabelled
 * 'unverified', which is reserved for post-migration funnel bypasses). The
 * backfill is run-once, guarded by the sentinel table.
 */
describe('runMigrations — defence_verdict provenance backfill', () => {
  let tempDir: string;
  let db: Database.Database;

  beforeEach(() => {
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'shieldcortex-verdict-mig-'));
    db = new Database(path.join(tempDir, 'memories.db'));
    // An OLD-schema memories table: no defence_verdict column.
    db.exec(`CREATE TABLE memories (
      id INTEGER PRIMARY KEY AUTOINCREMENT, uuid TEXT NOT NULL UNIQUE,
      type TEXT NOT NULL, title TEXT NOT NULL, content TEXT NOT NULL,
      source TEXT DEFAULT 'user:direct', trust_score REAL DEFAULT 1.0
    )`);
    db.prepare("INSERT INTO memories (uuid, type, title, content) VALUES ('a','short_term','t','legacy row A')").run();
    db.prepare("INSERT INTO memories (uuid, type, title, content) VALUES ('b','short_term','t','legacy row B')").run();
  });

  afterEach(() => {
    db.close();
    fs.rmSync(tempDir, { recursive: true, force: true });
  });

  it('adds the column and backfills every pre-existing row to legacy', () => {
    expect(db.prepare("PRAGMA table_info(memories)").all().some((c: any) => c.name === 'defence_verdict')).toBe(false);
    runMigrations(db);
    const cols = db.prepare("PRAGMA table_info(memories)").all() as { name: string }[];
    expect(cols.some((c) => c.name === 'defence_verdict')).toBe(true);
    const rows = db.prepare('SELECT defence_verdict FROM memories ORDER BY id').all() as { defence_verdict: string }[];
    expect(rows.map((r) => r.defence_verdict)).toEqual(['legacy', 'legacy']);
    // sentinel created → run-once
    expect(db.prepare("SELECT name FROM sqlite_master WHERE name='memories_provenance_backfilled'").get()).toBeDefined();
  });

  it('is idempotent and does not re-label post-migration rows', () => {
    runMigrations(db);
    // a NEW row written after the migration, honestly 'unverified' (funnel bypass)
    db.prepare("INSERT INTO memories (uuid, type, title, content, defence_verdict) VALUES ('c','short_term','t','new','unverified')").run();
    runMigrations(db); // second run must not touch the new row
    const c = db.prepare("SELECT defence_verdict FROM memories WHERE uuid='c'").get() as { defence_verdict: string };
    expect(c.defence_verdict).toBe('unverified');
    const legacy = db.prepare("SELECT COUNT(*) n FROM memories WHERE defence_verdict='legacy'").get() as { n: number };
    expect(legacy.n).toBe(2);
  });
});
