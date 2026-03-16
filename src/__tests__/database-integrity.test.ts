import { jest } from '@jest/globals';
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
});
