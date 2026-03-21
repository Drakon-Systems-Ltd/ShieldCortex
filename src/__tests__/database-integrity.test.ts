import { jest } from '@jest/globals';
import Database from 'better-sqlite3';
import { copyFileSync, mkdtempSync, rmSync } from 'fs';
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

  describe('startup recovery', () => {
    beforeEach(() => {
      jest.resetModules();
      jest.unstable_mockModule('../cloud/memory-sync.js', () => ({
        syncMemoryUpsertToCloud: jest.fn(),
        syncMemoryDeleteToCloud: jest.fn(),
        syncAllMemoriesToCloud: jest.fn(),
      }));
      jest.unstable_mockModule('../cloud/graph-sync.js', () => ({
        syncGraphForMemoryToCloud: jest.fn(),
        syncGraphDeleteForMemoryToCloud: jest.fn(),
        syncAllGraphToCloud: jest.fn(),
      }));
      jest.unstable_mockModule('../cloud/quarantine-sync.js', () => ({
        syncQuarantineToCloud: jest.fn(),
      }));
    });

    afterEach(async () => {
      const { closeDatabase } = await import('../database/init.js');
      closeDatabase();
    });

    it('restores a recent healthy backup when the live database is empty', async () => {
      const tempDir = mkdtempSync(join(tmpdir(), 'shieldcortex-db-'));
      const dbPath = join(tempDir, 'memories.db');
      const backupPath = `${dbPath}.corrupt.2026-03-20T09-15-00-000Z`;

      const { initDatabase, closeDatabase } = await import('../database/init.js');
      const { addMemory } = await import('../memory/store.js');

      initDatabase(dbPath);
      closeDatabase();
      copyFileSync(dbPath, backupPath);

      const backupDb = new Database(backupPath);
      backupDb.prepare('DELETE FROM memories').run();
      backupDb.close();

      initDatabase(backupPath);
      for (let i = 0; i < 120; i += 1) {
        addMemory({
          title: `Recovered ${i}`,
          content: `Healthy backup row ${i}`,
          project: 'ShieldCortex-Project',
        });
      }
      closeDatabase();

      const liveDb = new Database(dbPath);
      liveDb.prepare('DELETE FROM memories').run();
      liveDb.close();

      const now = Date.now();
      const recent = new Date(now - (60 * 60 * 1000));
      // Match mtimes so startup sees the backup as recent enough to restore.
      const { utimesSync } = await import('fs');
      utimesSync(dbPath, recent, recent);
      utimesSync(backupPath, recent, recent);

      const recovered = initDatabase(dbPath);
      const count = (recovered.prepare('SELECT COUNT(*) AS count FROM memories').get() as { count: number }).count;

      expect(count).toBe(120);

      closeDatabase();
      rmSync(tempDir, { recursive: true, force: true });
    });

    it('ignores a stale startup lock file and reclaims the database safely', async () => {
      const tempDir = mkdtempSync(join(tmpdir(), 'shieldcortex-db-'));
      const dbPath = join(tempDir, 'memories.db');
      const { initDatabase, closeDatabase } = await import('../database/init.js');
      const { addMemory } = await import('../memory/store.js');

      initDatabase(dbPath);
      addMemory({
        title: 'Healthy',
        content: 'Lock test',
        project: 'ShieldCortex-Project',
      });
      closeDatabase();

      const lockPath = `${dbPath}.lock`;
      const { writeFileSync, existsSync } = await import('fs');
      writeFileSync(lockPath, JSON.stringify({ pid: 999999, entryPath: '/tmp/old-runner.js' }), 'utf-8');

      const opened = initDatabase(dbPath);
      const count = (opened.prepare('SELECT COUNT(*) AS count FROM memories').get() as { count: number }).count;

      expect(count).toBe(1);
      expect(existsSync(lockPath)).toBe(true);

      closeDatabase();
      rmSync(tempDir, { recursive: true, force: true });
    });

    it('treats a live startup lock as advisory so concurrent sessions can continue', async () => {
      const tempDir = mkdtempSync(join(tmpdir(), 'shieldcortex-db-'));
      const dbPath = join(tempDir, 'memories.db');
      const lockPath = `${dbPath}.lock`;
      const errorSpy = jest.spyOn(console, 'error').mockImplementation(() => {});
      const { writeFileSync, existsSync } = await import('fs');
      const { closeDatabase } = await import('../database/init.js');

      const db = new Database(dbPath);
      db.exec(`
        CREATE TABLE memories (
          id INTEGER PRIMARY KEY,
          uuid TEXT NOT NULL UNIQUE,
          title TEXT NOT NULL,
          content TEXT NOT NULL
        );
      `);
      db.close();

      writeFileSync(
        lockPath,
        JSON.stringify({ pid: process.pid, entryPath: '/tmp/other-shieldcortex.js' }),
        'utf-8',
      );

      expect(() => {
        __databaseTestUtils.acquireStartupLock(dbPath);
      }).not.toThrow();

      expect(errorSpy).toHaveBeenCalledWith(
        expect.stringContaining('continuing anyway (SQLite WAL handles concurrency)'),
      );

      closeDatabase();
      expect(existsSync(lockPath)).toBe(true);

      errorSpy.mockRestore();
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
