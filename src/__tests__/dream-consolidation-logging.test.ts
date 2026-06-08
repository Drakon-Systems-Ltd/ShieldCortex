import { describe, it, expect, jest } from '@jest/globals';

/**
 * Jarvis P3 (2026-06-08): the nightly deep "dream" produced a 2-line near-empty
 * report on an active day, with no signal as to whether it under-extracted,
 * errored, or legitimately had nothing to do. consolidateMemories() returned
 * structured counts but emitted no completion log. This pins the summary log,
 * including the explicit "nothing to consolidate" wording on a quiet pass.
 *
 * DB-backed integration test against in-memory SQLite (the established
 * initDatabase(':memory:') pattern).
 */
describe('consolidateMemories — dream-mode completion logging (Jarvis P3)', () => {
  it('logs an explicit "nothing to consolidate" summary on an empty pass', async () => {
    const { initDatabase, closeDatabase } = await import('../database/init.js');
    const { consolidateMemories } = await import('../memory/consolidate.js');

    closeDatabase();
    initDatabase(':memory:');
    const spy = jest.spyOn(console, 'error').mockImplementation(() => {});
    try {
      const result = consolidateMemories();
      expect(result.totalProcessed).toBe(0);
      const logged = spy.mock.calls.map((c) => String(c[0])).join('\n');
      expect(logged).toMatch(/\[dream\][^\n]*nothing to consolidate/i);
    } finally {
      spy.mockRestore();
      closeDatabase();
    }
  });
});
