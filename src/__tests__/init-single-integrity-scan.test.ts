/**
 * Phase 17 B4: the startup path integrity-checked the live DB TWICE (once
 * directly, once inside an `inspectDatabaseFile()` re-open used only to read the
 * row count for the empty-live heuristic) and eagerly opened+scanned EVERY
 * `.corrupt.*` backup on every startup.
 *
 * Fix: one live-DB integrity scan; the empty-live count comes from the open
 * connection; backups are inspected lazily (only when recovery is invoked).
 *
 * The recovery semantics (binding-error guard, FTS rebuild, dump recovery,
 * empty-live restore) are covered by database-integrity.test.ts and must stay
 * green. This test pins the "single scan / no eager backup inspection" property
 * on a healthy existing DB.
 */
import { afterEach, describe, expect, it, jest } from '@jest/globals';
import { mkdtempSync, rmSync, copyFileSync, statSync, utimesSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import Database from 'better-sqlite3';
import { initDatabase, closeDatabase } from '../database/init.js';
import { addMemory } from '../memory/store.js';

describe('B4: single startup integrity scan, lazy backup inspection', () => {
  afterEach(() => {
    closeDatabase();
    jest.restoreAllMocks();
  });

  it('runs the integrity_check pragma at most once and opens no backup read-only on a healthy startup', () => {
    const tempDir = mkdtempSync(join(tmpdir(), 'shieldcortex-b4-'));
    const dbPath = join(tempDir, 'memories.db');

    try {
      // Seed a healthy, NON-empty DB and a sibling .corrupt.* backup so the old
      // code would have eagerly inspected the backup on the next startup.
      initDatabase(dbPath);
      addMemory({ title: 'Healthy row', content: 'B4 single-scan test row', project: 'B4-Project' });
      closeDatabase();

      const backupPath = `${dbPath}.corrupt.2026-03-20T09-15-00-000Z`;
      copyFileSync(dbPath, backupPath);
      // Make the backup look recent so it would be a restore candidate if reached.
      const recent = new Date(Date.now() - 60 * 60 * 1000);
      utimesSync(backupPath, recent, recent);

      // Count integrity_check pragmas issued during init by spying on the
      // prototype. runIntegrityCheck() issues `integrity_check(1)` then
      // `integrity_check` per scan — count the calls that mention integrity_check.
      const pragmaSpy = jest.spyOn(Database.prototype, 'pragma');

      const opened = initDatabase(dbPath);

      const integrityScans = pragmaSpy.mock.calls.filter((c) =>
        typeof c[0] === 'string' && (c[0] as string).includes('integrity_check'),
      );

      // A single scan issues at most two integrity_check pragmas (quick + full).
      // The OLD double-scan path issued at least four (live ×2). Assert we are at
      // or below the single-scan budget.
      expect(integrityScans.length).toBeLessThanOrEqual(2);

      // DB opened cleanly and the healthy row survived (no destructive recovery).
      const count = (opened.prepare('SELECT COUNT(*) AS c FROM memories').get() as { c: number }).c;
      expect(count).toBe(1);

      // The backup file is untouched (not consumed/renamed by an eager path).
      expect(() => statSync(backupPath)).not.toThrow();
    } finally {
      closeDatabase();
      rmSync(tempDir, { recursive: true, force: true });
    }
  });
});
