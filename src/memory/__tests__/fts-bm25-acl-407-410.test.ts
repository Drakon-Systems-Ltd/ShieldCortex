/**
 * #407 — FTS BM25 ordering before LIMIT
 * #410 — ACL filter before top-k slice (with candidate over-fetch)
 */
import { afterEach, beforeEach, describe, expect, it } from '@jest/globals';
import type { MemoryConfig } from '../types.js';
import { DEFAULT_CONFIG, DEFAULT_RANKER_CONFIG } from '../types.js';

const PROJECT = 'fts-407-410';

function cfg(over: Partial<MemoryConfig> = {}): MemoryConfig {
  return {
    ...DEFAULT_CONFIG,
    // Pin legacy scorer so FTS rank dominates the sort input set.
    ranker: { engine: 'legacy' } as MemoryConfig['ranker'],
    ...over,
  };
}

describe('#407 FTS BM25 before LIMIT', () => {
  beforeEach(async () => {
    process.env.SHIELDCORTEX_SKIP_EMBEDDINGS = '1';
    const { closeDatabase, initDatabase } = await import('../../database/init.js');
    closeDatabase();
    initDatabase(':memory:');
  });

  afterEach(async () => {
    const { closeDatabase } = await import('../../database/init.js');
    closeDatabase();
    delete process.env.SHIELDCORTEX_SKIP_EMBEDDINGS;
  });

  it('returns the highest-BM25 match even when it has low salience and sits outside a salience pre-limit', async () => {
    const { addMemory, getMemoryById } = await import('../store.js');
    const { getDatabase } = await import('../../database/init.js');
    const { searchMemories } = await import('../search-recall.js');
    const db = getDatabase();

    // Noise: high salience, weak lexical match (token present once).
    for (let i = 0; i < 25; i++) {
      const m = addMemory({
        title: `ops note ${i}`,
        content: `Routine checklist item ${i}. Mentions deploy once among unrelated filler text about weather and lunch.`,
        type: 'long_term',
        salience: 0.95,
        project: PROJECT,
      });
      db.prepare('UPDATE memories SET salience = 0.95, decayed_score = 0.95 WHERE id = ?').run(m.id);
    }

    // Perfect lexical hit, intentionally lower salience (would lose a salience ORDER BY LIMIT 5).
    // Stay above default salienceThreshold (0.2) so scoring does not drop the row.
    const perfect = addMemory({
      title: 'deploy staging pipeline runbook',
      content:
        'deploy staging pipeline deploy staging pipeline deploy staging pipeline — the canonical runbook for staging deploys.',
      type: 'long_term',
      salience: 0.45,
      project: PROJECT,
    });
    db.prepare('UPDATE memories SET salience = 0.45, decayed_score = 0.45 WHERE id = ?').run(perfect.id);

    const results = await searchMemories(
      { query: 'deploy staging pipeline', project: PROJECT, limit: 5 },
      cfg(),
    );

    expect(results.length).toBeGreaterThan(0);
    expect(results[0]?.memory.id).toBe(perfect.id);
    expect(getMemoryById(perfect.id)?.title).toContain('deploy staging pipeline');
  });

  it('is stable under insertion-order changes for the same corpus', async () => {
    const { addMemory } = await import('../store.js');
    const { searchMemories } = await import('../search-recall.js');

    const a = addMemory({
      title: 'alpha bravo unique407',
      content: 'alpha bravo unique407 document',
      type: 'long_term',
      salience: 0.5,
      project: PROJECT,
    });
    const b = addMemory({
      title: 'unrelated noise',
      content: 'something else entirely',
      type: 'long_term',
      salience: 0.9,
      project: PROJECT,
    });
    void b;

    const first = await searchMemories({ query: 'unique407', project: PROJECT, limit: 3 }, cfg());
    const second = await searchMemories({ query: 'unique407', project: PROJECT, limit: 3 }, cfg());
    expect(first.map((r) => r.memory.id)).toEqual(second.map((r) => r.memory.id));
    expect(first[0]?.memory.id).toBe(a.id);
  });
});

describe('#410 ACL before LIMIT with over-fetch', () => {
  beforeEach(async () => {
    process.env.SHIELDCORTEX_SKIP_EMBEDDINGS = '1';
    const { closeDatabase, initDatabase } = await import('../../database/init.js');
    closeDatabase();
    initDatabase(':memory:');
  });

  afterEach(async () => {
    const { closeDatabase } = await import('../../database/init.js');
    closeDatabase();
    delete process.env.SHIELDCORTEX_SKIP_EMBEDDINGS;
  });

  it('unauthorized high-rank RESTRICTED rows do not prevent authorized fill of top-k', async () => {
    const { addMemory } = await import('../store.js');
    const { getDatabase } = await import('../../database/init.js');
    const { searchMemories } = await import('../search-recall.js');
    const db = getDatabase();

    for (let i = 0; i < 15; i++) {
      const m = addMemory({
        title: `secret credential vault ${i}`,
        content: `credential vault secret material ${i} credential vault`,
        type: 'long_term',
        salience: 0.99,
        project: PROJECT,
        sensitivityLevel: 'RESTRICTED',
      });
      db.prepare(
        `UPDATE memories SET salience = 0.99, decayed_score = 0.99, sensitivity_level = 'RESTRICTED', source = 'cli:other-agent' WHERE id = ?`,
      ).run(m.id);
    }

    const ownerSource = 'agent:user-spawned>task-410';
    const allowed = addMemory({
      title: 'credential vault runbook public notes',
      content: 'credential vault operational notes for the owner agent',
      type: 'long_term',
      salience: 0.4,
      project: PROJECT,
      sensitivityLevel: 'INTERNAL',
    });
    db.prepare(
      `UPDATE memories SET salience = 0.4, decayed_score = 0.4, sensitivity_level = 'INTERNAL', source = ? WHERE id = ?`,
    ).run(ownerSource, allowed.id);

    const source = { type: 'agent' as const, identifier: 'user-spawned>task-410' };

    const results = await searchMemories(
      { query: 'credential vault', project: PROJECT, limit: 3 },
      cfg(),
      source,
    );

    expect(results.some((r) => r.memory.id === allowed.id)).toBe(true);
    for (const r of results) {
      expect(r.memory.sensitivityLevel).not.toBe('RESTRICTED');
    }
    expect(results[0]?.memory.id).toBe(allowed.id);
  });

  it('RRF default path also ACL-filters before user top-k (Grok #410 hole)', async () => {
    const { addMemory } = await import('../store.js');
    const { getDatabase } = await import('../../database/init.js');
    const { searchMemories } = await import('../search-recall.js');
    const db = getDatabase();

    for (let i = 0; i < 12; i++) {
      const m = addMemory({
        title: `secret credential vault rrf ${i}`,
        content: `credential vault secret material rrf ${i} credential vault`,
        type: 'long_term',
        salience: 0.99,
        project: PROJECT,
        sensitivityLevel: 'RESTRICTED',
      });
      db.prepare(
        `UPDATE memories SET salience = 0.99, decayed_score = 0.99, sensitivity_level = 'RESTRICTED', source = 'cli:other-agent' WHERE id = ?`,
      ).run(m.id);
    }

    const ownerSource = 'agent:user-spawned>task-410-rrf';
    const allowed = addMemory({
      title: 'credential vault runbook public notes rrf',
      content: 'credential vault operational notes for the owner agent rrf',
      type: 'long_term',
      salience: 0.4,
      project: PROJECT,
      sensitivityLevel: 'INTERNAL',
    });
    db.prepare(
      `UPDATE memories SET salience = 0.4, decayed_score = 0.4, sensitivity_level = 'INTERNAL', source = ? WHERE id = ?`,
    ).run(ownerSource, allowed.id);

    const source = { type: 'agent' as const, identifier: 'user-spawned>task-410-rrf' };
    const results = await searchMemories(
      { query: 'credential vault', project: PROJECT, limit: 3 },
      cfg({ ranker: { ...DEFAULT_RANKER_CONFIG, engine: 'rrf' } }),
      source,
    );

    expect(results.some((r) => r.memory.id === allowed.id)).toBe(true);
    for (const r of results) {
      expect(r.memory.sensitivityLevel).not.toBe('RESTRICTED');
    }
  });
});
