import { jest } from '@jest/globals';
import Database from 'better-sqlite3';
import { mkdtempSync, rmSync } from 'fs';
import { join } from 'path';
import { homedir, tmpdir } from 'os';
import { __databaseTestUtils } from '../database/init.js';

describe('database integrity recovery', () => {
  describe('isLikelyFtsIntegrityIssue', () => {
    it('matches malformed memories_fts errors', () => {
      expect(
        __databaseTestUtils.isLikelyFtsIntegrityIssue(
          'malformed inverted index for FTS5 table main.memories_fts'
        )
      ).toBe(true);
    });

    it('does not match unrelated integrity failures', () => {
      expect(
        __databaseTestUtils.isLikelyFtsIntegrityIssue('row 12 missing from index idx_memories_uuid')
      ).toBe(false);
    });
  });

  describe('attemptFtsRecovery', () => {
    it('rebuilds memories_fts and preserves the database when integrity returns to ok', () => {
      const exec = jest.fn();
      const pragma = jest
        .fn()
        .mockReturnValueOnce([{ integrity_check: 'ok' }])
        .mockReturnValueOnce([{ integrity_check: 'ok' }]);

      const prepare = jest.fn((sql: string) => {
        if (sql.includes("sqlite_master")) {
          return { get: () => ({ name: 'memories_fts' }) };
        }
        if (sql.includes('SELECT id FROM memories')) {
          return { all: () => [{ id: 1 }] };
        }
        throw new Error(`Unexpected SQL in test: ${sql}`);
      });

      const recovered = __databaseTestUtils.attemptFtsRecovery({
        exec,
        pragma,
        prepare,
      } as never);

      expect(recovered).toBe(true);
      expect(exec).toHaveBeenCalledWith(`INSERT INTO memories_fts(memories_fts) VALUES('rebuild')`);
    });

    it('returns false when the rebuilt index still fails integrity', () => {
      const exec = jest.fn();
      const pragma = jest
        .fn()
        .mockReturnValueOnce([{ integrity_check: 'malformed inverted index for FTS5 table main.memories_fts' }]);

      const prepare = jest.fn((sql: string) => {
        if (sql.includes("sqlite_master")) {
          return { get: () => ({ name: 'memories_fts' }) };
        }
        if (sql.includes('SELECT id FROM memories')) {
          return { all: () => [{ id: 1 }] };
        }
        throw new Error(`Unexpected SQL in test: ${sql}`);
      });

      const recovered = __databaseTestUtils.attemptFtsRecovery({
        exec,
        pragma,
        prepare,
      } as never);

      expect(recovered).toBe(false);
      expect(exec).toHaveBeenCalledWith(`INSERT INTO memories_fts(memories_fts) VALUES('rebuild')`);
    });
  });

  describe('verifyOnDiskIntegrity', () => {
    it('returns ok for a healthy on-disk database', () => {
      const tempDir = mkdtempSync(join(tmpdir(), 'shieldcortex-db-'));
      const dbPath = join(tempDir, 'memories.db');
      const db = new Database(dbPath);

      db.exec(`
        CREATE TABLE memories (
          id INTEGER PRIMARY KEY,
          uuid TEXT NOT NULL UNIQUE,
          title TEXT NOT NULL,
          content TEXT NOT NULL
        );
        INSERT INTO memories (uuid, title, content) VALUES ('u1', 'Test', 'Healthy');
      `);
      db.close();

      expect(__databaseTestUtils.verifyOnDiskIntegrity(dbPath)).toBe('ok');

      rmSync(tempDir, { recursive: true, force: true });
    });
  });

  describe('backup inspection', () => {
    it('finds healthy rotated backups with row counts', () => {
      const tempDir = mkdtempSync(join(tmpdir(), 'shieldcortex-db-'));
      const dbPath = join(tempDir, 'memories.db');
      const backupPath = `${dbPath}.corrupt.2026-03-17T13-37-02-151Z`;
      const db = new Database(backupPath);

      db.exec(`
        CREATE TABLE memories (
          id INTEGER PRIMARY KEY,
          uuid TEXT NOT NULL UNIQUE,
          title TEXT NOT NULL,
          content TEXT NOT NULL
        );
        INSERT INTO memories (uuid, title, content) VALUES ('u1', 'Recovered', 'Healthy backup');
      `);
      db.close();

      const backups = __databaseTestUtils.listHealthyBackups(dbPath);

      expect(backups).toHaveLength(1);
      expect(backups[0]?.path).toBe(backupPath);
      expect(backups[0]?.count).toBe(1);

      rmSync(tempDir, { recursive: true, force: true });
    });
  });

  describe('runtime safety guard', () => {
    it('blocks project-checkout runtimes from using the default managed database path', () => {
      const originalArgv = [...process.argv];

      process.argv = ['/usr/bin/node', '/Users/michael/Development/ShieldCortex-Project/ShieldCortex/dist/index.js'];

      expect(() => {
        __databaseTestUtils.enforceSafeRuntimePath(join(homedir(), '.shieldcortex', 'memories.db'), false);
      }).toThrow(/Refusing to open/);

      process.argv = originalArgv;
    });

    it('allows explicit database paths even from a project checkout', () => {
      const originalArgv = [...process.argv];

      process.argv = ['/usr/bin/node', '/Users/michael/Development/ShieldCortex-Project/ShieldCortex/dist/index.js'];

      expect(() => {
        __databaseTestUtils.enforceSafeRuntimePath('/tmp/shieldcortex-test.db', true);
      }).not.toThrow();

      process.argv = originalArgv;
    });
  });
});
