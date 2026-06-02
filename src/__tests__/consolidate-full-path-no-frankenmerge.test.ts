/**
 * Full auto-run-path no-frankenmerge regression test (B11 / Task 9).
 *
 * THE GAP THIS COVERS: the original Task 9 fix only touched mergeSimilarMemories
 * and its dedicated tests called that function DIRECTLY. The OTHER lossy-append
 * site, deduplicateMemories ("Merged from duplicate:"), runs every ~4h on the
 * REAL auto path — server.ts setInterval → fullCleanup() → consolidate() →
 * deduplicateMemories() — and was never exercised, so it kept producing
 * frankenmemories while the direct-call tests stayed green.
 *
 * These tests drive the ACTUAL fullCleanup()/consolidate() entry points (NOT
 * mergeSimilarMemories/deduplicateMemories directly), seeding BOTH:
 *   - long_term duplicate PAIRS (consumed by deduplicateMemories inside
 *     consolidate())
 *   - short_term near-dup clusters (consumed by mergeSimilarMemories inside
 *     fullCleanup())
 * and then assert the no-frankenmerge contract holds across the whole pass.
 *
 * DB-backed integration against in-memory SQLite, following the established
 * initDatabase(':memory:') pattern in the sibling no-frankenmerge test.
 */

import { describe, it, expect } from '@jest/globals';
import { jaccardSimilarity } from '../memory/similarity.js';

const NEAR_IDENTICAL_DELETE_THRESHOLD = 0.85;

function combinedSim(
  a: { title: string; content: string },
  b: { title: string; content: string }
): number {
  return jaccardSimilarity(a.content, b.content) * 0.6 + jaccardSimilarity(a.title, b.title) * 0.4;
}

function frankenmergeCount(db: import('better-sqlite3').Database): number {
  return (
    db
      .prepare(
        "SELECT COUNT(*) AS n FROM memories WHERE content LIKE '%Merged from duplicate:%' OR content LIKE '%Consolidated context:%'"
      )
      .get() as { n: number }
  ).n;
}

describe('full auto-run path (fullCleanup → consolidate → both dedup sites) — no frankenmerge (B11/Task 9)', () => {
  it('produces NO "Merged from duplicate:" / "Consolidated context:" rows, keeps the best member, disposes losers per policy', async () => {
    const { initDatabase, closeDatabase, getDatabase } = await import('../database/init.js');
    const { addMemory, getMemoryById } = await import('../memory/store.js');
    const { fullCleanup } = await import('../memory/consolidate.js');

    closeDatabase();
    initDatabase(':memory:');
    const db = getDatabase();

    try {
      // ── LONG-TERM duplicate pair, MODERATE (combined < 0.85 → downvote). ──
      // Asymmetric: the kept row carries extra distinct trailing content, so it
      // passes findDuplicateMemoryPairs' gate (identical title + content overlap
      // measured vs the SMALLER set > 0.5) yet combined Jaccard over the union
      // lands in the downvote band. This is exactly the shape the OLD
      // deduplicateMemories would have concatenated.
      const ltKept = {
        title: 'Postgres connection pool tuning for the batch worker',
        content:
          'Tuned the Postgres connection pool size and idle timeout for the nightly batch worker, plus extra notes about the dedicated read replica failover, the connection retry budget, and the monitoring dashboards we wired up',
      };
      const ltLoser = {
        title: 'Postgres connection pool tuning for the batch worker',
        content: 'Tuned the Postgres connection pool size and idle timeout for the nightly batch worker',
      };
      const ltSim = combinedSim(ltKept, ltLoser);
      expect(ltSim).toBeGreaterThan(0.5); // passes the pair gate
      expect(ltSim).toBeLessThan(NEAR_IDENTICAL_DELETE_THRESHOLD); // → downvote

      // ── LONG-TERM duplicate pair, NEAR-IDENTICAL (combined ≥ 0.85 → delete). ──
      const ltDup = {
        title: 'Redis cache eviction policy allkeys-lru',
        content:
          'Set the Redis cache eviction policy to allkeys-lru with a two gigabyte maximum memory limit configured',
      };
      expect(combinedSim(ltDup, ltDup)).toBeGreaterThanOrEqual(NEAR_IDENTICAL_DELETE_THRESHOLD);

      // ── SHORT-TERM near-dup cluster (combined < 0.85 → downvote in merge). ──
      const stA = {
        title: 'JWT authentication token setup',
        content:
          'Configured JWT authentication token signing with the RS256 algorithm inside the auth service login module',
      };
      const stB = {
        title: 'JWT authentication token rotation',
        content:
          'Configured JWT authentication token rotation with refresh windows inside the billing service renewal module',
      };
      const stSim = combinedSim(stA, stB);
      expect(stSim).toBeGreaterThanOrEqual(0.25); // clusters
      expect(stSim).toBeLessThan(NEAR_IDENTICAL_DELETE_THRESHOLD); // → downvote

      // Seed long_term pairs. Salience high enough to survive consolidate()'s
      // decay (decayedScore ≈ salience for fresh rows, well above any deletion
      // threshold). The kept LT-moderate row has the HIGHER salience so it is
      // the effective-salience winner and keeps its (longer) content verbatim.
      const ltKeptMem = addMemory({
        ...ltKept, category: 'architecture', project: 'fullpath-test', type: 'long_term', salience: 0.8,
      });
      const ltLoserMem = addMemory({
        ...ltLoser, category: 'architecture', project: 'fullpath-test', type: 'long_term', salience: 0.4,
      });
      const ltDupKeep = addMemory({
        ...ltDup, category: 'pattern', project: 'fullpath-test', type: 'long_term', salience: 0.9,
      });
      const ltDupDel = addMemory({
        ...ltDup, category: 'pattern', project: 'fullpath-test', type: 'long_term', salience: 0.3,
      });

      // Seed short_term cluster. Fresh + accessCount 0 → NOT promoted by
      // processDecay (needs access ≥ 3, or age ≥ 4h with salience ≥ 0.7), so the
      // rows survive to mergeSimilarMemories inside fullCleanup().
      const stKept = addMemory({
        ...stA, category: 'note', project: 'fullpath-test', type: 'short_term', salience: 0.7,
      });
      const stLoser = addMemory({
        ...stB, category: 'note', project: 'fullpath-test', type: 'short_term', salience: 0.4,
      });

      const ltKeptContentBefore = ltKeptMem.content;
      const ltDupKeepContentBefore = ltDupKeep.content;
      const stKeptContentBefore = stKept.content;

      // ── Drive the REAL auto-run path. ──
      const result = fullCleanup();
      expect(result.consolidation).toBeDefined();

      // (1) THE regression assertion: no frankenmerge artefacts ANYWHERE after a
      //     full pass through BOTH dedup sites. RED against the old
      //     deduplicateMemories (which wrote "Merged from duplicate:").
      expect(frankenmergeCount(db)).toBe(0);

      // (2) LONG-TERM moderate pair: higher-effective-salience row kept with its
      //     content VERBATIM (no append, no growth); loser survives + downvoted.
      const ltKeptAfter = getMemoryById(ltKeptMem.id);
      expect(ltKeptAfter).not.toBeNull();
      expect(ltKeptAfter!.content).toBe(ltKeptContentBefore);
      expect(ltKeptAfter!.content.length).toBe(ltKeptContentBefore.length);

      const ltLoserAfter = getMemoryById(ltLoserMem.id);
      expect(ltLoserAfter).not.toBeNull(); // moderate → NOT deleted
      const ltLoserRow = db
        .prepare('SELECT COALESCE(downvote_count,0) AS dv, last_downvoted_at FROM memories WHERE id = ?')
        .get(ltLoserMem.id) as { dv: number; last_downvoted_at: string | null };
      expect(ltLoserRow.dv).toBe(1);
      expect(ltLoserRow.last_downvoted_at).not.toBeNull();

      // (3) LONG-TERM near-identical pair: higher-salience row kept verbatim;
      //     loser DELETED (bounded store), no information lost.
      const ltDupKeepAfter = getMemoryById(ltDupKeep.id);
      expect(ltDupKeepAfter).not.toBeNull();
      expect(ltDupKeepAfter!.content).toBe(ltDupKeepContentBefore);
      expect(getMemoryById(ltDupDel.id)).toBeNull();

      // (4) SHORT-TERM cluster: best member kept (promoted to long_term) with
      //     content verbatim; loser downvoted (moderate), content intact.
      const stKeptAfter = getMemoryById(stKept.id);
      expect(stKeptAfter).not.toBeNull();
      expect(stKeptAfter!.content).toBe(stKeptContentBefore);
      const stKeptRow = db.prepare('SELECT type FROM memories WHERE id = ?').get(stKept.id) as { type: string };
      expect(stKeptRow.type).toBe('long_term');

      const stLoserAfter = getMemoryById(stLoser.id);
      expect(stLoserAfter).not.toBeNull();
      const stLoserRow = db
        .prepare('SELECT COALESCE(downvote_count,0) AS dv FROM memories WHERE id = ?')
        .get(stLoser.id) as { dv: number };
      expect(stLoserRow.dv).toBe(1);
    } finally {
      closeDatabase();
    }
  });

  it('consolidate() alone (the deduplicateMemories site) never writes "Merged from duplicate:"', async () => {
    const { initDatabase, closeDatabase, getDatabase } = await import('../database/init.js');
    const { addMemory, getMemoryById } = await import('../memory/store.js');
    const { consolidate } = await import('../memory/consolidate.js');

    closeDatabase();
    initDatabase(':memory:');
    const db = getDatabase();

    try {
      // A single long_term duplicate pair that the OLD deduplicateMemories would
      // have concatenated: distinct sentences in the loser would have been
      // appended into the kept row under a "Merged from duplicate:" header.
      const kept = {
        title: 'Stripe webhook signature verification approach',
        content:
          'Verified Stripe webhook signatures with the raw request body and the endpoint signing secret before parsing the event payload',
      };
      const loser = {
        title: 'Stripe webhook signature verification approach',
        content:
          'Verified Stripe webhook signatures with the raw request body and the endpoint signing secret before parsing the event payload. Also rejected events older than five minutes to block replay attacks.',
      };

      const keptMem = addMemory({
        ...kept, category: 'architecture', project: 'dedup-only-test', type: 'long_term', salience: 0.85,
      });
      const loserMem = addMemory({
        ...loser, category: 'architecture', project: 'dedup-only-test', type: 'long_term', salience: 0.5,
      });

      const keptContentBefore = keptMem.content;

      // Drive consolidate() — this is the site that calls deduplicateMemories().
      consolidate();

      // No "Merged from duplicate:" artefact written into the kept row.
      const keptAfter = getMemoryById(keptMem.id);
      expect(keptAfter).not.toBeNull();
      expect(keptAfter!.content).not.toContain('Merged from duplicate:');
      expect(keptAfter!.content).toBe(keptContentBefore);

      expect(frankenmergeCount(db)).toBe(0);

      // The loser was disposed (downvoted or deleted), not used to grow the
      // kept row. Whichever it is, the kept content stayed verbatim above.
      const loserAfter = getMemoryById(loserMem.id);
      if (loserAfter) {
        const dv = (
          db
            .prepare('SELECT COALESCE(downvote_count,0) AS dv FROM memories WHERE id = ?')
            .get(loserMem.id) as { dv: number }
        ).dv;
        expect(dv).toBeGreaterThanOrEqual(1);
      }
    } finally {
      closeDatabase();
    }
  });
});
