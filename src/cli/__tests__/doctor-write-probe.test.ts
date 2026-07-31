import fs from 'fs';
import os from 'os';
import path from 'path';
import Database from 'better-sqlite3';
import { afterEach, beforeEach, describe, expect, it } from '@jest/globals';
import { runWritePathProbe } from '../doctor.js';
import { closeDatabase, getCanonicalSchema, initDatabase } from '../../database/init.js';

/**
 * The doctor's write-path probe is the smoking-gun check for stale
 * schema or migration drift. It has to:
 *   - Pass on a healthy database (round-trip succeeds, leaves no rows).
 *   - Skip cleanly when the database file doesn't exist (don't crash).
 *   - Fail with the actual error when the schema is broken.
 *
 * v4.12.4 (path encoding) and v4.12.5 (NOT NULL UUID) both shipped
 * doctor PASSES while real writes were silently failing in production.
 * These tests pin the inverted contract: a green doctor must mean
 * memory writes actually work.
 */
describe('doctor write-path probe', () => {
  let tmpDir: string;
  let dbPath: string;

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'sc-doctor-probe-'));
    dbPath = path.join(tmpDir, 'memories.db');
  });

  afterEach(() => {
    try { closeDatabase(); } catch { /* ignore */ }
    try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch { /* ignore */ }
  });

  // Skipped, not warned: "no database yet" is the normal state of a fresh
  // install (the DB is created lazily on first use), so this is reported as
  // info and collapsed out of doctor's printed report (#129).
  it('skips cleanly, without crashing or warning, when the database file does not exist', () => {
    const result = runWritePathProbe(dbPath);
    expect(result.status).toBe('info');
    expect(result.skipped).toBe('db-uninitialised');
    expect(result.message).toMatch(/database not created yet/i);
  });

  it('passes the round-trip on a freshly initialised database and leaves no probe rows behind', () => {
    initDatabase(dbPath);
    closeDatabase();

    const result = runWritePathProbe(dbPath);
    expect(result.status).toBe('pass');
    expect(result.message).toMatch(/round-trip/i);

    // Re-open and verify no probe rows leaked through (cleanup is part of the contract)
    const db = new Database(dbPath, { readonly: true });
    try {
      const orphans = db.prepare(`
        SELECT COUNT(*) AS c FROM memories WHERE source = 'cli:doctor'
      `).get() as { c: number };
      expect(orphans.c).toBe(0);
    } finally {
      db.close();
    }
  });

  it('returns "fail" with the actual sqlite error when the database file is corrupt / unopenable', () => {
    // A genuinely broken DB (not just a stale schema) must still fail loudly.
    // Migrations can heal a missing column; they cannot open a non-SQLite file.
    fs.writeFileSync(dbPath, 'this is not a sqlite database at all');

    const result = runWritePathProbe(dbPath);
    expect(result.status).toBe('fail');
    expect(result.message).toMatch(/round-trip failed/i);
    // The fix hint should explicitly call out the schema/migration root cause
    expect(result.fix).toMatch(/schema|migration|install|repair/i);
  });

  // ── #116 regression: the probe must migrate before it writes ──────────────
  //
  // The probe used to open the DB raw and INSERT against whatever schema was on
  // disk. After a column-adding upgrade (e.g. 4.47.13's defence_verdict) a
  // perfectly healthy pre-restart DB is simply missing that one column — the
  // running init/migration path adds it on the next open. Opening raw meant the
  // probe INSERT hit "no such column: defence_verdict" and doctor screamed
  // "❌ Write path: round-trip failed — the smoking gun for migration drift" on
  // an install that was one `shieldcortex` command away from healthy. The fix:
  // run the same migrations initDatabase() runs before the probe INSERT.
  it('passes on a healthy DB that is merely missing a recently-added migration column (#116)', () => {
    // Build the real, current schema, then rewind it to a pre-upgrade state by
    // removing defence_verdict (and the provenance trigger that references it) —
    // exactly what a DB looks like after upgrading the package but before the
    // migration path has re-opened it.
    const db = new Database(dbPath);
    try {
      db.exec(getCanonicalSchema());
      db.exec('DROP TRIGGER IF EXISTS trg_memories_provenance');
      db.exec('ALTER TABLE memories DROP COLUMN defence_verdict');
      const cols = (db.prepare('PRAGMA table_info(memories)').all() as Array<{ name: string }>)
        .map((c) => c.name);
      expect(cols).not.toContain('defence_verdict'); // fixture sanity
    } finally {
      db.close();
    }

    const result = runWritePathProbe(dbPath);
    expect(result.status).toBe('pass');
    expect(result.message).toMatch(/round-trip/i);

    // And the migration must have actually run (column now present, no leak).
    const verify = new Database(dbPath, { readonly: true });
    try {
      const cols = (verify.prepare('PRAGMA table_info(memories)').all() as Array<{ name: string }>)
        .map((c) => c.name);
      expect(cols).toContain('defence_verdict');
      const orphans = verify.prepare(
        "SELECT COUNT(*) AS c FROM memories WHERE source = 'cli:doctor'",
      ).get() as { c: number };
      expect(orphans.c).toBe(0);
    } finally {
      verify.close();
    }
  });
});
