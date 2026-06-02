/**
 * No-Frankenmerge Consolidation Tests (B11 / Task 9)
 *
 * The auto-consolidation merge USED to resolve near-duplicate clusters by
 * appending every loser's body into the kept memory's `content`
 * ("Consolidated context:" / "Merged from duplicate:") and then deleting the
 * losers. Over time this produced ever-growing "frankenmemories" — 45% of the
 * live DB carried these appended artefacts.
 *
 * The new generator (mergeSimilarMemories):
 *   - KEEPS the single highest-EFFECTIVE-salience cluster member, content
 *     untouched (no concatenation, no growth).
 *   - DOWNVOTES moderate near-dups (0.25 ≤ combined < 0.85) — reversible.
 *   - DELETES near-identical losers (combined ≥ 0.85) — keeps the store bounded
 *     because NO reaping path reads downvote_count.
 *
 * These are DB-backed integration tests against an in-memory SQLite instance,
 * following the established initDatabase(':memory:') pattern in store.test.ts.
 */

import { describe, it, expect } from '@jest/globals';
import { jaccardSimilarity } from '../memory/similarity.js';

const NEAR_IDENTICAL_DELETE_THRESHOLD = 0.85;

function combinedSim(a: { title: string; content: string }, b: { title: string; content: string }): number {
  const contentSim = jaccardSimilarity(a.content, b.content);
  const titleSim = jaccardSimilarity(a.title, b.title);
  return contentSim * 0.6 + titleSim * 0.4;
}

describe('mergeSimilarMemories — no frankenmerge (B11)', () => {
  it('keeps the highest-effective-salience memory, leaves its content verbatim, and downvotes the moderate near-dup', async () => {
    const { initDatabase, closeDatabase, getDatabase } = await import('../database/init.js');
    const { addMemory, getMemoryById } = await import('../memory/store.js');
    const { mergeSimilarMemories } = await import('../memory/consolidate.js');

    closeDatabase();
    initDatabase(':memory:');
    const db = getDatabase();

    try {
      // Two MODERATE near-dups: enough shared vocabulary to cluster (combined
      // ≥ 0.25) but each carries distinct content, so combined < 0.85.
      const a = {
        title: 'JWT authentication token setup',
        content: 'Configured JWT authentication token signing with the RS256 algorithm inside the auth service login module',
      };
      const b = {
        title: 'JWT authentication token rotation',
        content: 'Configured JWT authentication token rotation with refresh windows inside the billing service renewal module',
      };

      // Guard the fixture: the pair must land in the downvote band.
      const sim = combinedSim(a, b);
      expect(sim).toBeGreaterThanOrEqual(0.25);
      expect(sim).toBeLessThan(NEAR_IDENTICAL_DELETE_THRESHOLD);

      // Higher salience on `a` so it is unambiguously the kept memory.
      const memA = addMemory({
        ...a, category: 'architecture', project: 'frankenmerge-test', type: 'short_term', salience: 0.8,
      });
      const memB = addMemory({
        ...b, category: 'architecture', project: 'frankenmerge-test', type: 'short_term', salience: 0.4,
      });

      const contentABefore = memA.content;

      const deleted = await mergeSimilarMemories('frankenmerge-test', 0.25);

      // Moderate near-dup → downvote, NOT delete.
      expect(deleted).toBe(0);

      // Kept memory (highest effective salience) survives with content verbatim.
      const keptAfter = getMemoryById(memA.id);
      expect(keptAfter).not.toBeNull();
      expect(keptAfter!.content).toBe(contentABefore);
      expect(keptAfter!.content).not.toContain('Consolidated context:');
      expect(keptAfter!.content).not.toContain('Merged from duplicate:');
      expect(keptAfter!.content.length).toBe(contentABefore.length);

      // Loser survives (non-lossy) but is downvoted.
      const loserAfter = getMemoryById(memB.id);
      expect(loserAfter).not.toBeNull();
      const loserRow = db
        .prepare('SELECT COALESCE(downvote_count, 0) AS dv, last_downvoted_at FROM memories WHERE id = ?')
        .get(memB.id) as { dv: number; last_downvoted_at: string | null };
      expect(loserRow.dv).toBe(1);
      expect(loserRow.last_downvoted_at).not.toBeNull();

      // The kept row was promoted to long_term and its raw salience NOT boosted.
      const keptRow = db.prepare('SELECT type, salience FROM memories WHERE id = ?').get(memA.id) as {
        type: string;
        salience: number;
      };
      expect(keptRow.type).toBe('long_term');
      expect(keptRow.salience).toBeCloseTo(0.8, 5);

      // Generator produced NO frankenmerge artefacts anywhere in the store.
      const artefacts = db
        .prepare(
          "SELECT COUNT(*) AS n FROM memories WHERE content LIKE '%Consolidated context:%' OR content LIKE '%Merged from duplicate:%'",
        )
        .get() as { n: number };
      expect(artefacts.n).toBe(0);
    } finally {
      closeDatabase();
    }
  });

  it('downvote is reversible and demotes effective salience (threshold reconciliation: combined ~0.3 < Task 8 write-skip 0.5)', async () => {
    const { initDatabase, closeDatabase, getDatabase } = await import('../database/init.js');
    const { addMemory } = await import('../memory/store.js');
    const { mergeSimilarMemories } = await import('../memory/consolidate.js');
    const { computeEffectiveSalience } = await import('../../scripts/lib/salience.mjs');

    closeDatabase();
    initDatabase(':memory:');
    const db = getDatabase();

    try {
      const a = {
        title: 'Postgres connection pool tuning notes',
        content: 'Tuned the Postgres connection pool size and idle timeout settings for the nightly reporting batch worker process that aggregates invoices',
      };
      const b = {
        title: 'Postgres connection pool limit changes',
        content: 'Raised the Postgres connection pool maximum alongside a longer statement timeout for the realtime analytics dashboard streaming service',
      };

      const sim = combinedSim(a, b);
      // Lives in the band that survives Task 8's irreversible 0.5 write-skip
      // but is handled by consolidate's reversible 0.25 downvote.
      expect(sim).toBeGreaterThanOrEqual(0.25);
      expect(sim).toBeLessThan(0.5);

      const memA = addMemory({ ...a, category: 'note', project: 'reconcile-test', type: 'short_term', salience: 0.7 });
      const memB = addMemory({ ...b, category: 'note', project: 'reconcile-test', type: 'short_term', salience: 0.5 });

      const before = db
        .prepare('SELECT salience, last_accessed, access_count, pinned, COALESCE(downvote_count,0) AS downvote_count FROM memories WHERE id = ?')
        .get(memB.id) as Record<string, unknown>;
      const effBefore = computeEffectiveSalience(before);

      await mergeSimilarMemories('reconcile-test', 0.25);

      const after = db
        .prepare('SELECT salience, last_accessed, access_count, pinned, COALESCE(downvote_count,0) AS downvote_count FROM memories WHERE id = ?')
        .get(memB.id) as Record<string, unknown>;
      const effAfter = computeEffectiveSalience(after);

      // Downvote (reversible) sank the loser's effective salience.
      expect(after.downvote_count).toBe(1);
      expect(effAfter).toBeLessThan(effBefore);

      // Reversibility: clearing the downvote restores the prior ranking.
      db.prepare('UPDATE memories SET downvote_count = 0, last_downvoted_at = NULL WHERE id = ?').run(memB.id);
      const restored = db
        .prepare('SELECT salience, last_accessed, access_count, pinned, COALESCE(downvote_count,0) AS downvote_count FROM memories WHERE id = ?')
        .get(memB.id) as Record<string, unknown>;
      expect(computeEffectiveSalience(restored)).toBeCloseTo(effBefore, 5);

      void memA;
    } finally {
      closeDatabase();
    }
  });

  it('DELETES near-identical losers (combined ≥ 0.85) to keep the store bounded, with no frankenmerge', async () => {
    const { initDatabase, closeDatabase, getDatabase } = await import('../database/init.js');
    const { addMemory, getMemoryById } = await import('../memory/store.js');
    const { mergeSimilarMemories } = await import('../memory/consolidate.js');

    closeDatabase();
    initDatabase(':memory:');
    const db = getDatabase();

    try {
      // Near-IDENTICAL pair — same title, essentially the same body.
      const a = {
        title: 'Redis cache eviction policy',
        content: 'Set the Redis cache eviction policy to allkeys-lru with a two gigabyte maximum memory limit',
      };
      const b = {
        title: 'Redis cache eviction policy',
        content: 'Set the Redis cache eviction policy to allkeys-lru with a two gigabyte maximum memory limit',
      };

      expect(combinedSim(a, b)).toBeGreaterThanOrEqual(NEAR_IDENTICAL_DELETE_THRESHOLD);

      const memA = addMemory({ ...a, category: 'pattern', project: 'identical-test', type: 'short_term', salience: 0.9 });
      const memB = addMemory({ ...b, category: 'pattern', project: 'identical-test', type: 'short_term', salience: 0.3 });

      const contentABefore = memA.content;

      const deleted = await mergeSimilarMemories('identical-test', 0.25);

      // Near-identical loser deleted (bounded store), no information lost.
      expect(deleted).toBe(1);
      expect(getMemoryById(memA.id)).not.toBeNull();
      expect(getMemoryById(memB.id)).toBeNull();

      // Kept content untouched — not a frankenmerge.
      const keptAfter = getMemoryById(memA.id);
      expect(keptAfter!.content).toBe(contentABefore);
      expect(keptAfter!.content).not.toContain('Consolidated context:');

      const artefacts = db
        .prepare(
          "SELECT COUNT(*) AS n FROM memories WHERE content LIKE '%Consolidated context:%' OR content LIKE '%Merged from duplicate:%'",
        )
        .get() as { n: number };
      expect(artefacts.n).toBe(0);
    } finally {
      closeDatabase();
    }
  });

  it('keeps the highest-effective-salience member even when it is not the highest raw salience', async () => {
    const { initDatabase, closeDatabase, getDatabase } = await import('../database/init.js');
    const { addMemory, getMemoryById } = await import('../memory/store.js');
    const { mergeSimilarMemories } = await import('../memory/consolidate.js');

    closeDatabase();
    initDatabase(':memory:');
    const db = getDatabase();

    try {
      const a = {
        title: 'Webhook retry backoff strategy',
        content: 'Implemented webhook retry with exponential backoff and jitter for the delivery queue dispatcher',
      };
      const b = {
        title: 'Webhook retry backoff tuning',
        content: 'Tuned webhook retry exponential backoff ceiling and jitter for the delivery queue dispatcher worker',
      };

      const sim = combinedSim(a, b);
      expect(sim).toBeGreaterThanOrEqual(0.25);
      expect(sim).toBeLessThan(NEAR_IDENTICAL_DELETE_THRESHOLD);

      // `a` has slightly LOWER raw salience but is freshly accessed AND pinned,
      // so its EFFECTIVE salience is higher → it must be the kept memory.
      const memLowRawHighEff = addMemory({
        ...a, category: 'learning', project: 'eff-test', type: 'short_term', salience: 0.55, pinned: true,
      });
      const memHighRaw = addMemory({
        ...b, category: 'learning', project: 'eff-test', type: 'short_term', salience: 0.6,
      });

      // Age the high-raw memory's last_accessed so recency drags its effective
      // salience below the pinned one's.
      const old = new Date(Date.now() - 60 * 86_400_000).toISOString();
      db.prepare('UPDATE memories SET last_accessed = ? WHERE id = ?').run(old, memHighRaw.id);

      await mergeSimilarMemories('eff-test', 0.25);

      // The pinned/fresh memory is kept and promoted; the other is downvoted.
      const keptRow = db.prepare('SELECT type FROM memories WHERE id = ?').get(memLowRawHighEff.id) as { type: string };
      expect(keptRow.type).toBe('long_term');

      const otherRow = db
        .prepare('SELECT COALESCE(downvote_count,0) AS dv FROM memories WHERE id = ?')
        .get(memHighRaw.id) as { dv: number };
      expect(otherRow.dv).toBe(1);

      // Kept content verbatim.
      const kept = getMemoryById(memLowRawHighEff.id);
      expect(kept!.content).toBe(a.content);
    } finally {
      closeDatabase();
    }
  });
});
