/**
 * Integration check that `searchMemoriesInternal` honours the
 * `config.ranker.engine` selector — i.e. A.4's wiring actually flips the
 * scoring backend.
 *
 * Both engines should retrieve a query-matching memory, but the resulting
 * `relevanceScore` numbers must differ because RRF's score scale is
 * rank-based (≪ 1) while legacy's weighted sum can exceed 1. That score
 * gap is the cleanest observable proof that the branch took different
 * paths through `searchMemoriesInternal`. We don't assert on absolute
 * numbers — only that the engines produce different scores for the same
 * input, and that both still return the right memory at rank 0.
 *
 * `SHIELDCORTEX_SKIP_EMBEDDINGS=1` prevents the embedding model loading,
 * keeping the test hermetic and fast.
 */
import { afterEach, beforeEach, describe, expect, it, jest } from '@jest/globals';
import { mkdtempSync, rmSync, mkdirSync } from 'fs';
import { join } from 'path';
import { tmpdir } from 'os';

const originalConfigDir = process.env.SHIELDCORTEX_CONFIG_DIR;
const originalSkipEmbeds = process.env.SHIELDCORTEX_SKIP_EMBEDDINGS;
const originalRanker = process.env.SHIELDCORTEX_RANKER;

describe('searchMemoriesInternal honours ranker engine selection', () => {
  let tempDir: string;

  beforeEach(() => {
    jest.resetModules();
    tempDir = mkdtempSync(join(tmpdir(), 'sc-engine-int-'));
    mkdirSync(join(tempDir, '.shieldcortex'), { recursive: true });
    process.env.SHIELDCORTEX_CONFIG_DIR = join(tempDir, '.shieldcortex');
    process.env.SHIELDCORTEX_SKIP_EMBEDDINGS = '1';
    delete process.env.SHIELDCORTEX_RANKER;
  });

  afterEach(() => {
    rmSync(tempDir, { recursive: true, force: true });
    if (originalConfigDir === undefined) delete process.env.SHIELDCORTEX_CONFIG_DIR;
    else process.env.SHIELDCORTEX_CONFIG_DIR = originalConfigDir;
    if (originalSkipEmbeds === undefined) delete process.env.SHIELDCORTEX_SKIP_EMBEDDINGS;
    else process.env.SHIELDCORTEX_SKIP_EMBEDDINGS = originalSkipEmbeds;
    if (originalRanker === undefined) delete process.env.SHIELDCORTEX_RANKER;
    else process.env.SHIELDCORTEX_RANKER = originalRanker;
  });

  it('rrf and legacy engines return same top memory but with different relevance scores', async () => {
    const { initDatabase, closeDatabase } = await import('../database/init.js');
    const { addMemory, deleteMemory } = await import('../memory/store.js');
    const { searchMemoriesExplained } = await import('../memory/search-recall.js');
    const { DEFAULT_CONFIG } = await import('../memory/types.js');

    closeDatabase();
    initDatabase(':memory:');

    let memoryId: number | undefined;
    try {
      const memory = addMemory({
        title: 'PostgreSQL architecture decision',
        content: 'Decided to use PostgreSQL for JSONB support and strong transactional guarantees.',
        category: 'architecture',
        tags: ['database', 'postgresql', 'jsonb'],
        project: 'engine-test',
        type: 'long_term',
      });
      memoryId = memory.id;

      const query = 'postgresql jsonb';
      const baseOpts = { query, project: 'engine-test', limit: 5 } as const;

      const rrfResults = await searchMemoriesExplained(baseOpts, {
        ...DEFAULT_CONFIG,
        ranker: { engine: 'rrf', rrfK: 60, weights: { fts: 0.4, vector: 0.6, graph: 0.3 } },
      });
      const legacyResults = await searchMemoriesExplained(baseOpts, {
        ...DEFAULT_CONFIG,
        ranker: { engine: 'legacy', rrfK: 60, weights: { fts: 0.4, vector: 0.6, graph: 0.3 } },
      });

      // Both engines must surface the matching memory.
      expect(rrfResults[0]?.memory.id).toBe(memoryId);
      expect(legacyResults[0]?.memory.id).toBe(memoryId);

      // RRF score is rank-based (small, ~1/(60+1)). Legacy is a weighted sum
      // that combines fts*0.25 + decay*0.2 + boosts and is much larger.
      // The gap is the observable proof that the engine branch took effect.
      expect(rrfResults[0].relevanceScore).not.toBe(legacyResults[0].relevanceScore);
      expect(rrfResults[0].relevanceScore).toBeLessThan(legacyResults[0].relevanceScore);
    } finally {
      if (memoryId) {
        try { deleteMemory(memoryId); } catch { /* ignore */ }
      }
      closeDatabase();
    }
  });

  it('omitting config.ranker falls back to the env/file resolver (default rrf)', async () => {
    const { initDatabase, closeDatabase } = await import('../database/init.js');
    const { addMemory, deleteMemory } = await import('../memory/store.js');
    const { searchMemoriesExplained } = await import('../memory/search-recall.js');
    const { DEFAULT_CONFIG } = await import('../memory/types.js');

    closeDatabase();
    initDatabase(':memory:');

    let memoryId: number | undefined;
    try {
      const memory = addMemory({
        title: 'Resolver fallback target',
        content: 'JSONB support and strong PostgreSQL transactional guarantees.',
        category: 'architecture',
        tags: ['postgresql'],
        project: 'engine-test',
        type: 'long_term',
      });
      memoryId = memory.id;

      // Build a config without `ranker` to force the fallback path. We
      // strip the field by destructuring rather than passing undefined so
      // that `??` correctly observes the absence.
      const { ranker: _ignored, ...configWithoutRanker } = DEFAULT_CONFIG;
      void _ignored;

      const results = await searchMemoriesExplained(
        { query: 'postgresql jsonb', project: 'engine-test', limit: 5 },
        configWithoutRanker as typeof DEFAULT_CONFIG,
      );

      expect(results[0]?.memory.id).toBe(memoryId);
      // Default resolved engine is rrf; rrf scores are rank-based ≪ 1.
      expect(results[0].relevanceScore).toBeLessThan(0.5);
    } finally {
      if (memoryId) {
        try { deleteMemory(memoryId); } catch { /* ignore */ }
      }
      closeDatabase();
    }
  });
});
