import fs from 'fs';
import os from 'os';
import path from 'path';
import Database from 'better-sqlite3';
import { afterEach, beforeEach, describe, expect, it } from '@jest/globals';
import { runWritePathProbe } from '../doctor.js';
import { closeDatabase, initDatabase } from '../../database/init.js';

/**
 * The doctor's write-path probe is the smoking-gun check for stale
 * schema or migration drift. It has to:
 *   - Pass on a healthy database (round-trip succeeds, leaves no rows).
 *   - Warn cleanly when the database file doesn't exist (don't crash).
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

  it('returns "warn / skipped" when the database file does not exist', () => {
    const result = runWritePathProbe(dbPath);
    expect(result.status).toBe('warn');
    expect(result.message).toMatch(/no database/i);
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

  it('returns "fail" with the actual sqlite error when the schema is broken', () => {
    // Create a database with a memories table but missing the uuid column
    // — the exact failure mode that v4.12.5 had silently in production.
    const db = new Database(dbPath);
    try {
      db.exec(`
        CREATE TABLE memories (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          type TEXT NOT NULL,
          category TEXT NOT NULL,
          title TEXT NOT NULL,
          content TEXT NOT NULL
        );
      `);
    } finally {
      db.close();
    }

    const result = runWritePathProbe(dbPath);
    expect(result.status).toBe('fail');
    expect(result.message).toMatch(/round-trip failed/i);
    // The fix hint should explicitly call out the schema/migration root cause
    expect(result.fix).toMatch(/schema|migration|install/i);
  });
});
