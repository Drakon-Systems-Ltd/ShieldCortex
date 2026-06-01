import fs from 'fs';
import os from 'os';
import path from 'path';
import { fileURLToPath } from 'url';
import { randomUUID } from 'crypto';
import { afterEach, beforeEach, describe, expect, it } from '@jest/globals';
import Database from 'better-sqlite3';
import { runMigrations } from '../migrations.js';

/**
 * v4.29.0 salience-wall backfill (Task 3).
 *
 * 80% of stored memories historically landed at salience=1.0 (the "wall"),
 * so salience could no longer rank anything. This one-time, self-healing
 * auto-migration clamps stale MACHINE-generated 1.0 rows down to 0.6 while
 * leaving manual/user, pinned and canonical rows untouched. It is guarded by
 * the existence of the `memories_backfill_backup` table so it runs exactly
 * once per box.
 *
 * These tests seed stale rows AFTER applying the schema — the backfill must be
 * data-conditional, so a schema-conditional guard would wrongly no-op here.
 */
describe('runMigrations — v4.29.0 salience-wall backfill', () => {
  const thisFile = fileURLToPath(import.meta.url);
  const repoRoot = path.resolve(path.dirname(thisFile), '..', '..', '..');
  const schemaPath = path.join(repoRoot, 'src', 'database', 'schema.sql');

  let tempDir: string;
  let dbPath: string;
  let db: Database.Database;

  beforeEach(() => {
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'shieldcortex-backfill-'));
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

  // Count the v4.29.0 backfill telemetry markers written into defence_audit.
  // The SUCCESS marker must only appear when the run actually clamped rows.
  const markerCount = (): number =>
    (db
      .prepare(
        "SELECT COUNT(*) as c FROM defence_audit WHERE source_identifier = 'backfill-v4.29.0'",
      )
      .get() as { c: number }).c;

  it('clamps machine salience > 0.6 down to 0.6 (auto / legacy-migrate / plugin)', () => {
    const auto = insertStale(db, { capture_method: 'auto', salience: 1.0 });
    const legacy = insertStale(db, { capture_method: 'legacy-migrate', salience: 1.0 });
    const plugin = insertStale(db, { capture_method: 'plugin', salience: 1.0 });

    runMigrations(db);

    expect(salienceOf(auto)).toBeLessThanOrEqual(0.6);
    expect(salienceOf(legacy)).toBeLessThanOrEqual(0.6);
    expect(salienceOf(plugin)).toBeLessThanOrEqual(0.6);
    expect(salienceOf(auto)).toBeCloseTo(0.6, 9);

    // A run that DID clamp rows writes exactly one success telemetry marker.
    expect(markerCount()).toBe(1);
  });

  it('writes NO defence_audit success marker when zero rows are clamped (fresh / no-stale DB)', () => {
    // No clamp-eligible rows at all — only a manual row, which the predicate
    // skips. The run-once guard table is still created, but a migration that
    // healed nothing must not emit a "healed" telemetry row. This is the exact
    // regression that made defence-pipeline-bypass see 2 audit rows instead of 1.
    insertStale(db, { capture_method: 'manual', salience: 1.0 });

    runMigrations(db);

    // Guard table created unconditionally (run-once persistence on a 0-clamp box).
    const guard = db
      .prepare("SELECT name FROM sqlite_master WHERE type='table' AND name='memories_backfill_backup'")
      .get();
    expect(guard).toBeDefined();

    // ...but ZERO success markers, because nothing was clamped.
    expect(markerCount()).toBe(0);
  });

  it('writes NO success marker on a completely empty DB (no memories at all)', () => {
    runMigrations(db);

    const guard = db
      .prepare("SELECT name FROM sqlite_master WHERE type='table' AND name='memories_backfill_backup'")
      .get();
    expect(guard).toBeDefined();
    expect(markerCount()).toBe(0);
  });

  it('does NOT clamp manual / user rows', () => {
    const manual = insertStale(db, { capture_method: 'manual', salience: 1.0 });
    const user = insertStale(db, { capture_method: 'user', salience: 1.0 });

    runMigrations(db);

    expect(salienceOf(manual)).toBeCloseTo(1.0, 9);
    expect(salienceOf(user)).toBeCloseTo(1.0, 9);
  });

  it('does NOT clamp pinned or canonical rows even when machine-captured', () => {
    const pinned = insertStale(db, { capture_method: 'auto', salience: 1.0, pinned: 1 });
    const canonical = insertStale(db, { capture_method: 'auto', salience: 1.0, status: 'canonical' });

    runMigrations(db);

    expect(salienceOf(pinned)).toBeCloseTo(1.0, 9);
    expect(salienceOf(canonical)).toBeCloseTo(1.0, 9);
  });

  it('is idempotent on re-run (a 0.6 row stays 0.6, not 0.36)', () => {
    insertStale(db, { capture_method: 'auto', salience: 1.0 });
    insertStale(db, { capture_method: 'plugin', salience: 0.9 });

    runMigrations(db);
    const after1 = db
      .prepare('SELECT id, salience FROM memories ORDER BY id')
      .all() as { id: number; salience: number }[];

    runMigrations(db);
    const after2 = db
      .prepare('SELECT id, salience FROM memories ORDER BY id')
      .all() as { id: number; salience: number }[];

    expect(after2).toEqual(after1);
    for (const r of after2) {
      expect(r.salience).toBeCloseTo(0.6, 9);
    }
  });

  it('survives a drifted / corrupt FTS index and still clamps', () => {
    const target = insertStale(db, { capture_method: 'auto', salience: 1.0 });

    // Simulate the recurrent FTS drift seen on live boxes: empty the FTS index
    // while the base rows remain. The next UPDATE's memories_au trigger then
    // throws "database disk image is malformed" unless the index is rebuilt
    // first — which is exactly what the backfill must do before clamping.
    db.exec("INSERT INTO memories_fts(memories_fts) VALUES('delete-all')");

    expect(() => runMigrations(db)).not.toThrow();
    expect(salienceOf(target)).toBeCloseTo(0.6, 9);
  });

  it('never leaves a row with an invalid category (defensive — clamp-only)', () => {
    insertStale(db, { capture_method: 'auto', category: 'architecture', salience: 1.0 });
    insertStale(db, { capture_method: 'manual', category: 'learning', salience: 1.0 });

    runMigrations(db);

    const valid = new Set([
      'architecture', 'pattern', 'preference', 'error',
      'context', 'learning', 'todo', 'note', 'relationship', 'custom',
    ]);
    const cats = db.prepare('SELECT category FROM memories').all() as { category: string }[];
    expect(cats.length).toBeGreaterThan(0);
    for (const c of cats) {
      expect(valid.has(c.category)).toBe(true);
    }
  });

  it('creates the run-once guard table; a NEW 1.0 row seeded after the first run is NOT clamped', () => {
    insertStale(db, { capture_method: 'auto', salience: 1.0 });

    runMigrations(db);

    const guard = db
      .prepare("SELECT name FROM sqlite_master WHERE type='table' AND name='memories_backfill_backup'")
      .get();
    expect(guard).toBeDefined();

    // Seed a fresh stale row AFTER the one-shot has fired.
    const late = insertStale(db, { capture_method: 'auto', salience: 1.0 });
    runMigrations(db);

    // The guard table exists, so the second run is a no-op: the late row stays 1.0.
    expect(salienceOf(late)).toBeCloseTo(1.0, 9);
  });
});
