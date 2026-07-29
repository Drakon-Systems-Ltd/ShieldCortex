import fs from 'fs';
import os from 'os';
import path from 'path';
import Database from 'better-sqlite3';
import { afterEach, beforeEach, describe, expect, it } from '@jest/globals';
import { runSchemaDriftCheck } from '../doctor.js';
import { closeDatabase, initDatabase } from '../../database/init.js';

/**
 * v4.47.13 field incident (21 Jul 2026): doctor reported "Schema: up to
 * date" while the memories table was missing defence_verdict — the write
 * probe caught it, the schema check didn't. Root cause: the check compared
 * against a hand-maintained three-column list frozen at ~v4.0, so every
 * migration since was invisible to it.
 *
 * These tests pin the replacement contract: the expected column set is
 * derived from the canonical schema itself (getCanonicalSchema() applied to
 * a throwaway in-memory DB), so a migration can never be forgotten again.
 */
describe('doctor schema drift check', () => {
  let tmpDir: string;
  let dbPath: string;

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'sc-doctor-schema-'));
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
    const result = runSchemaDriftCheck(dbPath);
    expect(result.status).toBe('info');
    expect(result.skipped).toBe('db-uninitialised');
    expect(result.message).toMatch(/database not created yet/i);
  });

  it('passes on a freshly initialised (fully migrated) database', () => {
    initDatabase(dbPath);
    closeDatabase();

    const result = runSchemaDriftCheck(dbPath);
    expect(result.status).toBe('pass');
  });

  it('warns and names the missing column on a pre-migration database (the 4.47.13 incident shape)', () => {
    initDatabase(dbPath);
    closeDatabase();

    // Simulate an un-migrated upgrade: rebuild memories without defence_verdict.
    const db = new Database(dbPath);
    try {
      db.exec(`
        DROP TRIGGER IF EXISTS trg_memories_provenance;
        ALTER TABLE memories DROP COLUMN defence_verdict;
      `);
    } finally {
      db.close();
    }

    const result = runSchemaDriftCheck(dbPath);
    expect(result.status).toBe('warn');
    expect(result.message).toContain('defence_verdict');
    expect(result.fix).toMatch(/migrate/i);
  });

  it('does not warn about extra live columns the canonical schema lacks', () => {
    initDatabase(dbPath);
    closeDatabase();

    const db = new Database(dbPath);
    try {
      db.exec('ALTER TABLE memories ADD COLUMN legacy_leftover TEXT');
    } finally {
      db.close();
    }

    const result = runSchemaDriftCheck(dbPath);
    expect(result.status).toBe('pass');
  });
});
