import os from 'os';
import path from 'path';
import fs from 'fs';
import { afterEach, describe, expect, it } from '@jest/globals';
import { initDatabase, closeDatabase, getDatabase } from '../database/init.js';

/**
 * Phase 17 B1: built-in firewall rules the README advertises as "seeded on
 * first run" were never seeded on a FRESH database. `seedDefaultFirewallRules()`
 * was only invoked inside `runMigrations()`, which returns early when the
 * `memories` table is absent (i.e. exactly the fresh-DB case). So a brand-new
 * install came up with an empty `firewall_rules` table.
 *
 * These tests drive the full `initDatabase()` path against a fresh in-memory
 * database and assert the built-in rules are present, enabled, marked
 * built_in=1, and not duplicated on a second init.
 */
describe('B1: built-in firewall rules seeded on fresh DB init', () => {
  afterEach(() => {
    closeDatabase();
  });

  it('seeds built-in firewall rules on a fresh :memory: DB via initDatabase', () => {
    initDatabase(':memory:');
    const db = getDatabase();

    const builtIns = db
      .prepare('SELECT name, enabled, built_in FROM firewall_rules WHERE built_in = 1')
      .all() as Array<{ name: string; enabled: number; built_in: number }>;

    expect(builtIns.length).toBeGreaterThan(0);
    for (const r of builtIns) {
      expect(r.built_in).toBe(1);
      expect(r.enabled).toBe(1);
    }
  });

  it('does not duplicate built-in rules across a re-init of the same file', () => {
    // Use a temp file (not :memory:, which is per-connection) so the second
    // init reopens the SAME database and exercises the idempotency guard.
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sc-seed-init-'));
    const dbPath = path.join(dir, 'memories.db');

    try {
      initDatabase(dbPath);
      const firstCount = (
        getDatabase()
          .prepare('SELECT COUNT(*) AS c FROM firewall_rules WHERE built_in = 1')
          .get() as { c: number }
      ).c;
      expect(firstCount).toBeGreaterThan(0);
      closeDatabase();

      initDatabase(dbPath);
      const secondCount = (
        getDatabase()
          .prepare('SELECT COUNT(*) AS c FROM firewall_rules WHERE built_in = 1')
          .get() as { c: number }
      ).c;

      expect(secondCount).toBe(firstCount);
    } finally {
      closeDatabase();
      fs.rmSync(dir, { recursive: true, force: true });
    }
  });
});
