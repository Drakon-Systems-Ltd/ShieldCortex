/**
 * Recall-path N+1 batching regression (Phase 9b).
 *
 * The recall pipeline in `search-recall.ts` issued several per-id query loops:
 *   - `recallWithEmbeddings` hydrated each embedding hit with its own
 *     `SELECT * FROM memories WHERE id = ?`.
 *   - the RRF candidate path ran one `SELECT * WHERE id = ?` per vector/graph id.
 *   - contradiction enrichment looked up each counterpart title with its own
 *     `SELECT title FROM memories WHERE id = ?` (an N+1 within an N+1).
 *   - the ACL filter ran `SELECT source, sensitivity_level WHERE id = ?` per row.
 *
 * Phase 9b replaces each loop with a single `WHERE id IN (<placeholders>)`
 * resolved through an id→row map, and switches the two candidate prefilters from
 * raw `salience` to the persisted `decayed_score` (COALESCE back to salience for
 * rows not yet scored). These tests pin two things:
 *   1. CORRECTNESS — recall result sets, order, hydration and contradiction
 *      titles are unchanged by the batching.
 *   2. NO N+1 — the per-id `WHERE id = ?` loops are gone (asserted by spying on
 *      `db.prepare` SQL strings).
 *
 * Harness mirrors search-recall-engine.test.ts: in-memory DB + addMemory, with
 * SHIELDCORTEX_SKIP_EMBEDDINGS=1 so the recall path stays on FTS (hermetic).
 */
import { afterEach, beforeEach, describe, expect, it } from '@jest/globals';
import { initDatabase, closeDatabase, getDatabase } from '../database/init.js';
import { addMemory } from '../memory/store.js';
import { createMemoryLink } from '../memory/links.js';
import { searchMemories, searchMemoriesExplained, recallWithEmbeddings } from '../memory/search-recall.js';
import { DEFAULT_CONFIG } from '../memory/types.js';

const PROJECT = 'recall-batching-test';

/** Count prepared SQL strings matching a predicate, by wrapping db.prepare. */
function spyOnPrepare(predicate: (sql: string) => boolean): { count: () => number; restore: () => void } {
  const db = getDatabase() as unknown as { prepare: (sql: string) => unknown };
  const original = db.prepare.bind(db);
  let hits = 0;
  db.prepare = (sql: string) => {
    if (predicate(sql)) hits++;
    return original(sql);
  };
  return {
    count: () => hits,
    restore: () => {
      db.prepare = original;
    },
  };
}

describe('recall-path N+1 batching (Phase 9b)', () => {
  beforeEach(() => {
    process.env.SHIELDCORTEX_SKIP_EMBEDDINGS = '1';
    closeDatabase();
    initDatabase(':memory:');
  });

  afterEach(() => {
    closeDatabase();
    delete process.env.SHIELDCORTEX_SKIP_EMBEDDINGS;
  });

  it('searchMemories returns the matching memory and is stable across repeat calls', async () => {
    const m = addMemory({
      title: 'PostgreSQL decision',
      content: 'Decided to use PostgreSQL for JSONB support and strong transactional guarantees.',
      category: 'architecture',
      tags: ['postgresql', 'jsonb'],
      project: PROJECT,
      type: 'long_term',
    });

    const opts = { query: 'postgresql jsonb', project: PROJECT, limit: 5 } as const;
    const first = await searchMemories(opts, DEFAULT_CONFIG);
    const second = await searchMemories(opts, DEFAULT_CONFIG);

    expect(first[0]?.memory.id).toBe(m.id);
    // Result set + order are deterministic for identical input (no batching drift).
    expect(first.map((r) => r.memory.id)).toEqual(second.map((r) => r.memory.id));
  });

  it('contradiction titles resolve correctly with a single batched IN query (no per-id title N+1)', async () => {
    const subject = addMemory({
      title: 'Use SQLite for the local store',
      content: 'The local memory store should use SQLite with FTS5 for full-text recall.',
      category: 'architecture',
      tags: ['sqlite'],
      project: PROJECT,
      type: 'long_term',
    });
    const rivalA = addMemory({
      title: 'Switch local store to LMDB',
      content: 'Proposal to replace SQLite with LMDB for the local store.',
      category: 'architecture',
      tags: ['lmdb'],
      project: PROJECT,
      type: 'long_term',
    });
    const rivalB = addMemory({
      title: 'Use Postgres for the local store',
      content: 'Alternative proposal to use Postgres locally instead of SQLite.',
      category: 'architecture',
      tags: ['postgres'],
      project: PROJECT,
      type: 'long_term',
    });

    // addMemory auto-detects `related` links between similar new memories; clear
    // them so the contradiction links below are the only links and can't collide
    // with an auto-link on the same (source_id, target_id) UNIQUE pair.
    getDatabase().prepare('DELETE FROM memory_links').run();

    // Two contradiction links on the subject — exercises the N+1-within-N+1.
    createMemoryLink(subject.id, rivalA.id, 'contradicts', 0.8);
    createMemoryLink(rivalB.id, subject.id, 'contradicts', 0.6); // reversed direction

    // Spy AFTER seeding so only the recall path's prepares are counted.
    const titleSpy = spyOnPrepare(
      (sql) => /select\s+title\s+from\s+memories\s+where\s+id\s*=\s*\?/i.test(sql),
    );
    const inTitleSpy = spyOnPrepare(
      (sql) => /select\s+id,\s*title\s+from\s+memories\s+where\s+id\s+in\s*\(/i.test(sql),
    );

    const results = await searchMemoriesExplained(
      { query: 'sqlite local store', project: PROJECT, limit: 10 },
      DEFAULT_CONFIG,
    );

    titleSpy.restore();
    inTitleSpy.restore();

    const subjectResult = results.find((r) => r.memory.id === subject.id);
    expect(subjectResult).toBeDefined();
    expect(subjectResult!.contradictions).toBeDefined();

    const byId = new Map(subjectResult!.contradictions!.map((c) => [c.memoryId, c]));
    expect(byId.get(rivalA.id)?.title).toBe('Switch local store to LMDB');
    expect(byId.get(rivalA.id)?.score).toBe(0.8);
    expect(byId.get(rivalB.id)?.title).toBe('Use Postgres for the local store');
    expect(byId.get(rivalB.id)?.score).toBe(0.6);

    // The per-id title N+1 must be gone; titles come from ONE batched IN query.
    expect(titleSpy.count()).toBe(0);
    expect(inTitleSpy.count()).toBeGreaterThanOrEqual(1);
  });

  it('recallWithEmbeddings returns FTS memories and hydrates without a per-id SELECT * loop', async () => {
    // Seed > 3 matches so the FTS branch is taken (>=3 short-circuits before the
    // embedding fallback) — the deterministic, hermetic path.
    const ids: number[] = [];
    for (let i = 0; i < 5; i++) {
      ids.push(
        addMemory({
          title: `Drizzle migration note ${i}`,
          content: `Drizzle migration ${i}: hand-write the schema SQL and a journal rollback entry.`,
          category: 'learning',
          tags: ['drizzle', 'migration'],
          project: PROJECT,
          type: 'long_term',
        }).id,
      );
    }

    const singleIdSpy = spyOnPrepare(
      (sql) => /select\s+\*\s+from\s+memories\s+where\s+id\s*=\s*\?/i.test(sql),
    );

    const recalled = await recallWithEmbeddings('drizzle migration', { project: PROJECT, limit: 15 });

    singleIdSpy.restore();

    // Every recalled memory is one we seeded, fully hydrated (uuid present).
    expect(recalled.length).toBeGreaterThanOrEqual(3);
    for (const mem of recalled) {
      expect(ids).toContain(mem.id);
      expect(typeof mem.uuid).toBe('string');
      expect(mem.uuid.length).toBeGreaterThan(0);
    }

    // No single-id `SELECT * WHERE id = ?` loop in the recall path.
    expect(singleIdSpy.count()).toBe(0);
  });

  it('prefilters on the persisted decayed_score, not raw salience: a high-decayed row survives a LIMIT that raw salience would exclude it from', async () => {
    // Three equally FTS-matching memories, LIMIT 2 prefilter:
    //   winner — modest salience (0.4, survives the salience threshold) but the
    //            HIGHEST persisted decayed_score (0.95).
    //   filler1/filler2 — HIGHER raw salience (0.9) but LOW decayed_score (0.1).
    // Under the old `ORDER BY salience DESC LIMIT 2`, the two fillers fill both
    // slots and `winner` never enters scoring. Under `decayed_score DESC`, winner
    // is in the top 2 — so it must appear in the results.
    const winner = addMemory({
      title: 'Decayed prefilter winner alpha',
      content: 'alpha beta gamma delta epsilon — high persisted decay winner.',
      category: 'note',
      project: PROJECT,
      type: 'long_term',
    });
    const filler1 = addMemory({
      title: 'Raw salience filler one alpha',
      content: 'alpha beta gamma delta epsilon — high raw salience filler one.',
      category: 'note',
      project: PROJECT,
      type: 'long_term',
    });
    const filler2 = addMemory({
      title: 'Raw salience filler two alpha',
      content: 'alpha beta gamma delta epsilon — high raw salience filler two.',
      category: 'note',
      project: PROJECT,
      type: 'long_term',
    });

    const db = getDatabase();
    db.prepare('UPDATE memories SET salience = ?, decayed_score = ? WHERE id = ?').run(0.4, 0.95, winner.id);
    db.prepare('UPDATE memories SET salience = ?, decayed_score = ? WHERE id = ?').run(0.9, 0.1, filler1.id);
    db.prepare('UPDATE memories SET salience = ?, decayed_score = ? WHERE id = ?').run(0.9, 0.1, filler2.id);

    const results = await searchMemoriesExplained(
      { query: 'alpha beta gamma', project: PROJECT, limit: 2 },
      DEFAULT_CONFIG,
    );

    // decayed_score prefilter put `winner` in the top-2 candidate set; under the
    // old raw-salience prefilter it would have been excluded by the two fillers.
    expect(results.map((r) => r.memory.id)).toContain(winner.id);
  });

  it('decayed_score prefilter falls back to raw salience for rows with NULL decayed_score (fresh writes not buried)', async () => {
    // addMemory leaves decayed_score NULL. Under a naive `decayed_score DESC`,
    // NULL sorts LAST and a fresh high-salience memory would be buried out of a
    // LIMIT-1 prefilter. COALESCE(decayed_score, salience) must keep it on top.
    const freshHigh = addMemory({
      title: 'Fresh high salience zeta',
      content: 'zeta eta theta iota kappa — fresh write, no persisted decay yet.',
      category: 'note',
      project: PROJECT,
      type: 'long_term',
    });
    const oldLow = addMemory({
      title: 'Old low salience zeta',
      content: 'zeta eta theta iota kappa — older, persisted low decay.',
      category: 'note',
      project: PROJECT,
      type: 'long_term',
    });

    const db = getDatabase();
    db.prepare('UPDATE memories SET salience = ? WHERE id = ?').run(0.9, freshHigh.id); // decayed_score stays NULL
    db.prepare('UPDATE memories SET salience = ?, decayed_score = ? WHERE id = ?').run(0.3, 0.2, oldLow.id);

    const results = await searchMemoriesExplained(
      { query: 'zeta eta theta', project: PROJECT, limit: 1 },
      DEFAULT_CONFIG,
    );

    // NULL decayed_score → COALESCE to salience 0.9, which beats oldLow's 0.2.
    expect(results[0]?.memory.id).toBe(freshHigh.id);
  });
});
