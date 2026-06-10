/**
 * Phase 17 B2: spurious O(n²) co-access links on recall.
 *
 * `searchMemoriesInternal`'s side-effect block linked EVERY pair of the top-K
 * results to each other as `related` (strength 0.2), running one
 * `SELECT existing` + one INSERT/UPDATE per pair — C(K,2) ≈ K² queries and K²
 * graph edges between memories whose only relationship is co-appearing in one
 * search. The audit flagged these links as spurious graph pollution.
 *
 * Fix: drop the automatic all-pairs co-access linking entirely. Per-result
 * reinforcement (`reinforceFromSearch`) and contradiction enrichment stay.
 *
 * Harness mirrors recall-batching.test.ts: in-memory DB + addMemory, with
 * SHIELDCORTEX_SKIP_EMBEDDINGS=1 so the recall path stays on FTS (hermetic).
 */
import { afterEach, beforeEach, describe, expect, it } from '@jest/globals';
import { initDatabase, closeDatabase, getDatabase } from '../database/init.js';
import { addMemory } from '../memory/store.js';
import { searchMemories } from '../memory/search-recall.js';
import { DEFAULT_CONFIG } from '../memory/types.js';

const PROJECT = 'recall-coaccess-test';

/** Count prepared SQL strings matching a predicate, by wrapping db.prepare. */
function spyOnPrepare(predicate: (sql: string) => boolean): { count: () => number; restore: () => void } {
  const db = getDatabase() as unknown as { prepare: (sql: string) => unknown };
  const original = db.prepare.bind(db);
  let hits = 0;
  db.prepare = (sql: string) => {
    if (predicate(sql)) hits++;
    return original(sql);
  };
  return { count: () => hits, restore: () => { db.prepare = original; } };
}

describe('B2: recall does not create O(n²) co-access links', () => {
  beforeEach(() => {
    process.env.SHIELDCORTEX_SKIP_EMBEDDINGS = '1';
    closeDatabase();
    initDatabase(':memory:');
  });

  afterEach(() => {
    closeDatabase();
    delete process.env.SHIELDCORTEX_SKIP_EMBEDDINGS;
  });

  it('a multi-result recall creates zero `related` co-access links and runs no per-pair existence query', async () => {
    // Five memories that all match the same query → all land in the top results.
    const ids: number[] = [];
    for (let i = 0; i < 5; i++) {
      const m = addMemory({
        title: `Database tuning note ${i}`,
        content: `Database tuning note ${i}: indexing strategy for query performance and cache sizing.`,
        category: 'architecture',
        tags: ['database', 'tuning'],
        project: PROJECT,
        type: 'long_term',
      });
      ids.push(m.id);
    }

    // addMemory may auto-detect `related` links between similar new memories.
    // Clear ALL links so we measure only what the recall side-effect path adds.
    getDatabase().prepare('DELETE FROM memory_links').run();
    const before = (
      getDatabase().prepare('SELECT COUNT(*) AS c FROM memory_links').get() as { c: number }
    ).c;
    expect(before).toBe(0);

    // Spy on the per-pair co-access existence probe that the old double loop ran.
    const pairProbe = spyOnPrepare(
      (sql) =>
        /select\s+strength\s+from\s+memory_links\s+where\s+\(source_id\s*=\s*\?\s+and\s+target_id\s*=\s*\?\)/i.test(sql),
    );
    const coAccessInsert = spyOnPrepare(
      (sql) => /insert\s+into\s+memory_links\b[\s\S]*'?related'?/i.test(sql) ||
        /insert\s+into\s+memory_links\s*\(source_id,\s*target_id,\s*relationship,\s*strength\)/i.test(sql),
    );

    const results = await searchMemories(
      { query: 'database tuning indexing', project: PROJECT, limit: 10 },
      DEFAULT_CONFIG,
    );

    pairProbe.restore();
    coAccessInsert.restore();

    // Results themselves are unaffected.
    expect(results.length).toBeGreaterThanOrEqual(2);

    // No per-pair existence probe (the N² query storm is gone).
    expect(pairProbe.count()).toBe(0);
    expect(coAccessInsert.count()).toBe(0);

    // No spurious `related` co-access edges created between co-returned results.
    const relatedLinks = (
      getDatabase()
        .prepare("SELECT COUNT(*) AS c FROM memory_links WHERE relationship = 'related'")
        .get() as { c: number }
    ).c;
    expect(relatedLinks).toBe(0);
  });
});
