import fs from 'fs';
import os from 'os';
import path from 'path';
import { fileURLToPath } from 'url';
import { randomUUID } from 'crypto';
import { afterEach, beforeEach, describe, expect, it } from '@jest/globals';
import Database from 'better-sqlite3';
import { runMigrations } from '../database/migrations.js';
import { revertBackfill } from '../cli/memory.js';

/**
 * v4.29.0 salience-wall backfill REVERT (Task 5).
 *
 * The backfill clamps stale machine-generated salience>0.6 rows down to 0.6,
 * stashing the pre-clamp salience in `memories_backfill_backup` (id, salience,
 * backed_up_at). `revertBackfill` is the operator undo: it restores salience
 * from that backup table and — crucially — KEEPS the table so the migration's
 * run-once guard stays satisfied and never re-clamps over the revert.
 *
 * Setup mirrors src/database/__tests__/migration-backfill.test.ts: apply the
 * canonical schema to a temp DB, then seed stale rows AFTER the schema is in.
 */
describe('revertBackfill — undo of the v4.29.0 salience-wall clamp', () => {
  const thisFile = fileURLToPath(import.meta.url);
  const repoRoot = path.resolve(path.dirname(thisFile), '..', '..');
  const schemaPath = path.join(repoRoot, 'src', 'database', 'schema.sql');

  let tempDir: string;
  let dbPath: string;
  let db: Database.Database;

  beforeEach(() => {
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'shieldcortex-revert-'));
    dbPath = path.join(tempDir, 'memories.db');
    db = new Database(dbPath);
    const schema = fs.readFileSync(schemaPath, 'utf-8');
    db.exec(schema);
  });

  afterEach(() => {
    db.close();
    fs.rmSync(tempDir, { recursive: true, force: true });
  });

  function insertStale(
    database: Database.Database,
    overrides: Partial<{
      title: string;
      content: string;
      category: string;
      salience: number;
      capture_method: string;
      source_kind: string;
      pinned: number;
      status: string;
    }> = {},
  ): number {
    const row = {
      title: 'Some machine-extracted memory',
      content: 'auto-extracted body text',
      category: 'note',
      salience: 1.0,
      capture_method: 'auto',
      source_kind: 'hook',
      pinned: 0,
      status: 'active',
      ...overrides,
    };
    const info = database
      .prepare(
        `INSERT INTO memories (uuid, type, category, title, content, salience, capture_method, source_kind, pinned, status)
         VALUES (?, 'long_term', ?, ?, ?, ?, ?, ?, ?, ?)`,
      )
      .run(
        randomUUID(),
        row.category,
        row.title,
        row.content,
        row.salience,
        row.capture_method,
        row.source_kind,
        row.pinned,
        row.status,
      );
    return Number(info.lastInsertRowid);
  }

  const salienceOf = (id: number): number =>
    (db.prepare('SELECT salience FROM memories WHERE id = ?').get(id) as { salience: number }).salience;

  const backupTableExists = (): boolean =>
    !!db
      .prepare("SELECT 1 FROM sqlite_master WHERE type='table' AND name='memories_backfill_backup'")
      .get();

  it('round-trips: restores each clamped row to its ORIGINAL salience', () => {
    const auto = insertStale(db, { capture_method: 'auto', salience: 1.0 });
    const legacy = insertStale(db, { capture_method: 'legacy-migrate', salience: 0.95 });

    // Clamp (creates the backup table).
    runMigrations(db);
    expect(salienceOf(auto)).toBeCloseTo(0.6, 9);
    expect(salienceOf(legacy)).toBeCloseTo(0.6, 9);

    // Undo.
    const result = revertBackfill(db);

    expect(result.hadBackup).toBe(true);
    expect(result.reverted).toBe(2);
    expect(salienceOf(auto)).toBeCloseTo(1.0, 9);
    expect(salienceOf(legacy)).toBeCloseTo(0.95, 9);
  });

  it('is a graceful no-op when no backfill was ever run', () => {
    insertStale(db, { capture_method: 'auto', salience: 1.0 });
    expect(backupTableExists()).toBe(false);

    let result: ReturnType<typeof revertBackfill> | undefined;
    expect(() => {
      result = revertBackfill(db);
    }).not.toThrow();

    expect(result).toEqual({ hadBackup: false, reverted: 0 });
  });

  it('handles an empty backup table: hadBackup:true, reverted:0, salience untouched', () => {
    // The migration creates memories_backfill_backup even when nothing matched
    // the clamp, so the table can EXIST with ZERO rows. That must read as a
    // present-but-empty backup (hadBackup:true, reverted:0), distinct from a
    // never-backfilled DB (hadBackup:false). Simulate the empty-guard state
    // directly with the same 3-column shape the migration uses.
    const untouched = insertStale(db, { capture_method: 'manual', salience: 0.8 });
    db.exec(
      `CREATE TABLE memories_backfill_backup (
         id INTEGER PRIMARY KEY,
         salience REAL NOT NULL,
         backed_up_at TEXT NOT NULL DEFAULT (datetime('now'))
       )`,
    );
    expect(backupTableExists()).toBe(true);

    let result: ReturnType<typeof revertBackfill> | undefined;
    expect(() => {
      result = revertBackfill(db);
    }).not.toThrow();

    expect(result).toEqual({ hadBackup: true, reverted: 0 });
    // No backed-up rows -> the UPDATE touches nothing -> salience is unchanged.
    expect(salienceOf(untouched)).toBeCloseTo(0.8, 9);
  });

  it('is sticky: keeps the guard table so a re-run of runMigrations does NOT re-clamp', () => {
    const auto = insertStale(db, { capture_method: 'auto', salience: 1.0 });

    runMigrations(db);
    expect(salienceOf(auto)).toBeCloseTo(0.6, 9);

    revertBackfill(db);
    expect(salienceOf(auto)).toBeCloseTo(1.0, 9);

    // Guard table retained -> the migration's run-once guard stays satisfied.
    expect(backupTableExists()).toBe(true);

    // A subsequent startup must NOT undo the revert.
    runMigrations(db);
    expect(salienceOf(auto)).toBeCloseTo(1.0, 9);
    expect(backupTableExists()).toBe(true);
  });
});
