/**
 * Embedding reuse on the recall path (Phase 17 batch E).
 *
 * Before this fix the recall fallback (`findSimilarMemories`) ignored the
 * embedding ALREADY persisted in `memories.embedding` (written by addMemory) and
 * instead routed every candidate through `getOrComputeEmbedding`, which read a
 * SEPARATE, perpetually-cold `memory_embeddings` cache table and — on the miss —
 * RE-EMBEDDED the candidate's text through the worker. Up to 200 sequential
 * worker round-trips per cold recall, all redundant.
 *
 * The fix makes the persisted `memories.embedding` column the canonical per-memory
 * embedding store. `findSimilarMemories` now reads candidate embeddings in ONE
 * batched `SELECT id, embedding ... WHERE id IN (...) AND embedding IS NOT NULL`,
 * decodes the BLOBs (same Float32Array view as vectorSearch), and scores them with
 * cosineSimilarity — no per-candidate compute for candidates that have a persisted
 * embedding.
 *
 * These tests pin:
 *   1. REUSE — candidates with a persisted embedding are scored from the column,
 *      and the per-memory compute path (`generateEmbedding`) is NOT called.
 *   2. EQUIVALENCE — the ranking from the reuse path matches a brute-force cosine
 *      reference over the same persisted vectors (same vectors → same order).
 *   3. STALENESS — updateMemory refreshes (or clears) the persisted embedding when
 *      content changes, so recall never matches on an outdated vector.
 *
 * Harness: the real `../embeddings/index.js` is replaced via unstable_mockModule so
 * `generateEmbedding` is a tracked jest.fn (the COMPUTE path) while cosineSimilarity
 * stays the real pure-math implementation. Embeddings are seeded directly as BLOBs,
 * exactly as vector-search-hydration.test.ts does.
 */
import { afterEach, beforeEach, describe, expect, it, jest } from '@jest/globals';

// Real cosine (pure math) — used both by the seam mock below and by the test's
// own brute-force reference.
function realCosine(a: Float32Array, b: Float32Array): number {
  if (a.length !== b.length) return 0;
  let dot = 0, na = 0, nb = 0;
  for (let i = 0; i < a.length; i++) {
    dot += a[i] * b[i];
    na += a[i] * a[i];
    nb += b[i] * b[i];
  }
  const mag = Math.sqrt(na) * Math.sqrt(nb);
  return mag === 0 ? 0 : dot / mag;
}

// COMPUTE spy: the per-memory re-embed path. Reuse must never call this for a
// candidate that already has a persisted embedding.
const generateEmbedding = jest.fn(async (_text: string): Promise<Float32Array> => {
  throw new Error('Embeddings disabled via SHIELDCORTEX_SKIP_EMBEDDINGS=1');
});

jest.unstable_mockModule('../embeddings/index.js', () => ({
  generateEmbedding,
  cosineSimilarity: realCosine,
  isModelLoaded: () => false,
  preloadModel: async () => {},
  disposeModel: async () => {},
}));

const { initDatabase, closeDatabase, getDatabase } = await import('../database/init.js');

const PROJECT = 'embedding-reuse-test';

function embeddingBuffer(vec: number[]): Buffer {
  return Buffer.from(new Float32Array(vec).buffer);
}

interface Seed {
  uuid: string;
  title: string;
  content: string;
  vec: number[] | null; // null => no persisted embedding
}

/** Insert a memory row directly with (or without) a persisted embedding BLOB. */
function insertMemory(seed: Seed): number {
  const db = getDatabase();
  const r = db.prepare(`
    INSERT INTO memories (uuid, type, category, title, content, project, scope, salience, embedding)
    VALUES (@uuid, 'long_term', 'note', @title, @content, @project, 'project', 0.6, @embedding)
  `).run({
    uuid: seed.uuid,
    title: seed.title,
    content: seed.content,
    project: PROJECT,
    embedding: seed.vec === null ? null : embeddingBuffer(seed.vec),
  });
  return Number(r.lastInsertRowid);
}

describe('embedding reuse on recall (Phase 17 batch E)', () => {
  beforeEach(() => {
    process.env.SHIELDCORTEX_SKIP_EMBEDDINGS = '1';
    closeDatabase();
    initDatabase(':memory:');
    generateEmbedding.mockClear();
  });

  afterEach(() => {
    closeDatabase();
    delete process.env.SHIELDCORTEX_SKIP_EMBEDDINGS;
  });

  it('reads candidate embeddings from memories.embedding — no per-candidate re-embed', async () => {
    const seeds: Seed[] = [
      { uuid: 'r-aligned', title: 'aligned', content: 'aligned body', vec: [1, 0, 0, 0, 0, 0, 0, 0] },
      { uuid: 'r-close', title: 'close', content: 'close body', vec: [0.9, 0.1, 0, 0, 0, 0, 0, 0] },
      { uuid: 'r-mid', title: 'mid', content: 'mid body', vec: [0.6, 0.6, 0, 0, 0, 0, 0, 0] },
    ];
    const idByUuid = new Map<string, number>();
    for (const s of seeds) idByUuid.set(s.uuid, insertMemory(s));

    const { findSimilarMemories } = await import('../memory/embedding.js');
    const queryEmbedding = new Float32Array([1, 0, 0, 0, 0, 0, 0, 0]);
    const candidates = seeds.map((s) => ({
      id: idByUuid.get(s.uuid)!,
      title: s.title,
      content: s.content,
    }));

    const scored = await findSimilarMemories('aligned', candidates, 10, queryEmbedding);

    // All three candidates scored from the column.
    expect(scored.map((s) => s.id).sort((a, b) => a - b)).toEqual(
      candidates.map((c) => c.id).sort((a, b) => a - b),
    );
    // Zero re-embeds for candidates with a persisted embedding.
    expect(generateEmbedding).not.toHaveBeenCalled();
  });

  it('ranking from the reuse path matches a brute-force cosine reference over the persisted vectors', async () => {
    const query = [1, 0, 0, 0, 0, 0, 0, 0];
    const seeds: Seed[] = [
      { uuid: 'q-top', title: 'top', content: 'top', vec: [1, 0, 0, 0, 0, 0, 0, 0] },        // sim 1.0
      { uuid: 'q-2nd', title: 'second', content: 'second', vec: [0.95, 0.05, 0, 0, 0, 0, 0, 0] },
      { uuid: 'q-3rd', title: 'third', content: 'third', vec: [0.7, 0.3, 0, 0, 0, 0, 0, 0] },
      { uuid: 'q-low', title: 'low', content: 'low', vec: [0.2, 0.9, 0, 0, 0, 0, 0, 0] },
    ];
    const idByUuid = new Map<string, number>();
    for (const s of seeds) idByUuid.set(s.uuid, insertMemory(s));

    const q = new Float32Array(query);
    const expected = seeds
      .map((s) => ({ id: idByUuid.get(s.uuid)!, similarity: realCosine(q, new Float32Array(s.vec!)) }))
      .sort((a, b) => b.similarity - a.similarity);

    const { findSimilarMemories } = await import('../memory/embedding.js');
    const candidates = seeds.map((s) => ({
      id: idByUuid.get(s.uuid)!,
      title: s.title,
      content: s.content,
    }));

    const scored = await findSimilarMemories('top', candidates, 10, q);

    // Same vectors → same cosine → same order.
    expect(scored.map((s) => s.id)).toEqual(expected.map((e) => e.id));
    for (let i = 0; i < scored.length; i++) {
      expect(scored[i].score).toBeCloseTo(expected[i].similarity, 5);
    }
  });

  it('a candidate that genuinely lacks a persisted embedding is skipped (not re-embedded) under SKIP_EMBEDDINGS', async () => {
    const withEmb = insertMemory({ uuid: 'has', title: 'has', content: 'has', vec: [1, 0, 0, 0, 0, 0, 0, 0] });
    const noEmb = insertMemory({ uuid: 'none', title: 'none', content: 'none', vec: null });

    const { findSimilarMemories } = await import('../memory/embedding.js');
    const queryEmbedding = new Float32Array([1, 0, 0, 0, 0, 0, 0, 0]);
    const candidates = [
      { id: withEmb, title: 'has', content: 'has' },
      { id: noEmb, title: 'none', content: 'none' },
    ];

    const scored = await findSimilarMemories('has', candidates, 10, queryEmbedding);

    // Only the candidate with a persisted embedding is scored; the missing one is
    // skipped (the model is disabled, so a re-embed would only fail anyway).
    expect(scored.map((s) => s.id)).toEqual([withEmb]);
  });

  it('updateMemory refreshes the persisted embedding when content changes (no stale vector)', async () => {
    const { addMemory, updateMemory, getMemoryById } = await import('../memory/store.js');

    const created = addMemory({
      title: 'Original title',
      content: 'Original content about postgres jsonb.',
      category: 'architecture',
      project: PROJECT,
      type: 'long_term',
    });

    // addMemory's embedding write is async + skipped under SKIP_EMBEDDINGS, so seed
    // a deterministic "old content" embedding directly to simulate the persisted
    // vector for the original content.
    const db = getDatabase();
    const oldVec = embeddingBuffer([1, 0, 0, 0, 0, 0, 0, 0]);
    db.prepare('UPDATE memories SET embedding = ? WHERE id = ?').run(oldVec, created.id);

    const before = (db.prepare('SELECT embedding FROM memories WHERE id = ?').get(created.id) as { embedding: Buffer }).embedding;
    expect(before).not.toBeNull();

    // Change the content (the Phase-17-A dedupe-update path). The persisted
    // embedding must no longer reflect the OLD content — it is refreshed or cleared.
    updateMemory(created.id, { content: 'Completely different content about kubernetes networking.' });

    const after = (db.prepare('SELECT embedding FROM memories WHERE id = ?').get(created.id) as { embedding: Buffer | null }).embedding;

    // Either cleared (recomputed lazily/asynchronously) or replaced — but NOT the
    // stale old-content vector.
    if (after !== null) {
      expect(Buffer.compare(after, before)).not.toBe(0);
    }
    // Sanity: the memory itself still exists with the new content.
    expect(getMemoryById(created.id)?.content).toContain('kubernetes');
  });

  it('updateMemory leaves the persisted embedding untouched when content is unchanged', async () => {
    const { addMemory, updateMemory } = await import('../memory/store.js');

    const created = addMemory({
      title: 'Stable title',
      content: 'Stable content that will not change.',
      category: 'note',
      project: PROJECT,
      type: 'long_term',
    });

    const db = getDatabase();
    const vec = embeddingBuffer([0, 1, 0, 0, 0, 0, 0, 0]);
    db.prepare('UPDATE memories SET embedding = ? WHERE id = ?').run(vec, created.id);

    // Update a non-content field — the embedding must be preserved.
    updateMemory(created.id, { salience: 0.95 });

    const after = (db.prepare('SELECT embedding FROM memories WHERE id = ?').get(created.id) as { embedding: Buffer | null }).embedding;
    expect(after).not.toBeNull();
    expect(Buffer.compare(after!, vec)).toBe(0);
  });
});
