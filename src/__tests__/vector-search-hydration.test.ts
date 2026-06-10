/**
 * vectorSearch deferred-hydration test (Phase 9a).
 *
 * vectorSearch used to `SELECT *` and run rowToMemory() (2 JSON parses + several
 * `new Date()`) on EVERY embedded row just to keep the top `limit`, even though
 * its only caller consumes nothing but `{id, similarity}`. The fix scores over a
 * lean `SELECT id, embedding` projection and returns `Array<{id, similarity}>` —
 * no per-row Memory hydration. These tests pin the returned shape, the >0.3
 * threshold, the limit/sort order, and project/global scoping, comparing against
 * a brute-force cosine reference.
 *
 * Harness: a fresh in-memory DB with hand-built normalised embeddings (no model
 * needed — cosineSimilarity is pure math).
 */

import { afterEach, beforeEach, describe, expect, it } from '@jest/globals';
import { initDatabase, closeDatabase, getDatabase } from '../database/init.js';
import { vectorSearch } from '../memory/search.js';
import { cosineSimilarity } from '../embeddings/index.js';

const DIM = 8;

function embeddingBuffer(vec: number[]): Buffer {
  return Buffer.from(new Float32Array(vec).buffer);
}

interface VecSeed {
  uuid: string;
  vec: number[];
  project?: string;
  scope?: string;
  withEmbedding?: boolean;
}

function insertMemory(seed: VecSeed): number {
  const db = getDatabase();
  const r = db.prepare(`
    INSERT INTO memories (uuid, type, category, title, content, project, scope, embedding)
    VALUES (@uuid, 'long_term', 'note', @title, @content, @project, @scope, @embedding)
  `).run({
    uuid: seed.uuid,
    title: `mem ${seed.uuid}`,
    content: `content ${seed.uuid}`,
    project: seed.project ?? 'test',
    scope: seed.scope ?? 'project',
    embedding: seed.withEmbedding === false ? null : embeddingBuffer(seed.vec),
  });
  return Number(r.lastInsertRowid);
}

/** Brute-force reference: cosine over every seed, filtered >0.3, sorted desc. */
function bruteForce(
  query: number[],
  seeds: Array<{ id: number; vec: number[] }>,
  limit: number,
): Array<{ id: number; similarity: number }> {
  const q = new Float32Array(query);
  return seeds
    .map((s) => ({ id: s.id, similarity: cosineSimilarity(q, new Float32Array(s.vec)) }))
    .filter((r) => r.similarity > 0.3)
    .sort((a, b) => b.similarity - a.similarity)
    .slice(0, limit);
}

describe('vectorSearch deferred hydration (Phase 9a)', () => {
  beforeEach(() => {
    initDatabase(':memory:');
  });

  afterEach(() => {
    closeDatabase();
  });

  it('returns {id, similarity} pairs — no hydrated Memory objects', () => {
    insertMemory({ uuid: 'a', vec: [1, 0, 0, 0, 0, 0, 0, 0] });

    const hits = vectorSearch(getDatabase(), new Float32Array([1, 0, 0, 0, 0, 0, 0, 0]), 10);

    expect(hits.length).toBe(1);
    expect(Object.keys(hits[0]).sort()).toEqual(['id', 'similarity']);
    expect(hits[0]).not.toHaveProperty('memory');
    expect(typeof hits[0].id).toBe('number');
    expect(typeof hits[0].similarity).toBe('number');
  });

  it('returns the correct top-k ids in the same order as a brute-force reference', () => {
    const query = [1, 0, 0, 0, 0, 0, 0, 0];
    const seeds = [
      { uuid: 's-aligned', vec: [1, 0, 0, 0, 0, 0, 0, 0] },          // sim 1.0
      { uuid: 's-close', vec: [0.9, 0.1, 0, 0, 0, 0, 0, 0] },        // high
      { uuid: 's-mid', vec: [0.6, 0.6, 0, 0, 0, 0, 0, 0] },         // ~0.7
      { uuid: 's-orthogonal', vec: [0, 1, 0, 0, 0, 0, 0, 0] },      // sim 0 → filtered
    ];
    const idByUuid = new Map<string, number>();
    for (const s of seeds) idByUuid.set(s.uuid, insertMemory(s));

    const refSeeds = seeds.map((s) => ({ id: idByUuid.get(s.uuid)!, vec: s.vec }));
    const expected = bruteForce(query, refSeeds, 10);

    const hits = vectorSearch(getDatabase(), new Float32Array(query), 10);

    expect(hits.map((h) => h.id)).toEqual(expected.map((r) => r.id));
    // Orthogonal vector (similarity 0) is below the 0.3 threshold → excluded.
    expect(hits.map((h) => h.id)).not.toContain(idByUuid.get('s-orthogonal'));
    // Similarities match the brute-force values.
    for (let i = 0; i < hits.length; i++) {
      expect(hits[i].similarity).toBeCloseTo(expected[i].similarity, 5);
    }
  });

  it('honours the limit (slices to the top-k by similarity)', () => {
    const query = [1, 0, 0, 0, 0, 0, 0, 0];
    insertMemory({ uuid: 'top', vec: [1, 0, 0, 0, 0, 0, 0, 0] });
    insertMemory({ uuid: 'second', vec: [0.95, 0.05, 0, 0, 0, 0, 0, 0] });
    insertMemory({ uuid: 'third', vec: [0.8, 0.2, 0, 0, 0, 0, 0, 0] });

    const hits = vectorSearch(getDatabase(), new Float32Array(query), 2);

    expect(hits.length).toBe(2);
    // Sorted descending by similarity.
    expect(hits[0].similarity).toBeGreaterThanOrEqual(hits[1].similarity);
  });

  it('ignores rows without an embedding', () => {
    insertMemory({ uuid: 'has-emb', vec: [1, 0, 0, 0, 0, 0, 0, 0] });
    insertMemory({ uuid: 'no-emb', vec: [], withEmbedding: false });

    const hits = vectorSearch(getDatabase(), new Float32Array([1, 0, 0, 0, 0, 0, 0, 0]), 10);

    expect(hits.length).toBe(1);
  });

  it('applies project + global scoping', () => {
    const inProject = insertMemory({ uuid: 'p1', vec: [1, 0, 0, 0, 0, 0, 0, 0], project: 'alpha' });
    const globalMem = insertMemory({ uuid: 'g1', vec: [1, 0, 0, 0, 0, 0, 0, 0], project: 'other', scope: 'global' });
    const otherProject = insertMemory({ uuid: 'o1', vec: [1, 0, 0, 0, 0, 0, 0, 0], project: 'beta', scope: 'project' });

    // includeGlobal=true: project rows + global rows, excluding other projects.
    const withGlobal = vectorSearch(getDatabase(), new Float32Array([1, 0, 0, 0, 0, 0, 0, 0]), 10, 'alpha', true);
    const idsWithGlobal = withGlobal.map((h) => h.id).sort();
    expect(idsWithGlobal).toEqual([inProject, globalMem].sort((a, b) => a - b));
    expect(withGlobal.map((h) => h.id)).not.toContain(otherProject);

    // includeGlobal=false: only the project's own rows.
    const noGlobal = vectorSearch(getDatabase(), new Float32Array([1, 0, 0, 0, 0, 0, 0, 0]), 10, 'alpha', false);
    expect(noGlobal.map((h) => h.id)).toEqual([inProject]);
  });
});
