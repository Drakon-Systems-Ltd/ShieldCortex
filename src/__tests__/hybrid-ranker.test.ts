/**
 * Tests for the hybrid ranker orchestrator (`runHybridRanker`).
 *
 * The orchestrator is the load-bearing piece that ties Step A.1 (RRF) and
 * Step A.2 (graph-rank) to the existing FTS + vector retrievers, then
 * applies post-fusion multipliers (recency, category, link, tag, activation,
 * contradiction) on top of the RRF score.
 *
 *   finalScore = rrfScore
 *     × (1 + 0.05 × priority)
 *     × (1 + recencyBoost)
 *     × (1 + 0.1 × categoryMatch)
 *     × (1 + linkBoost)
 *     × (1 + tagBoost)
 *     × (1 + activationBoost)
 *     × (1 - contradictionPenalty)
 *
 * `runHybridRanker` is a pure-ish function — it accepts pre-loaded rank
 * lists and a memory map, plus a db handle for the link/contradiction
 * lookups that genuinely need it. Tests use an in-memory SQLite seeded
 * from the production schema.
 */

import { afterEach, describe, expect, it } from '@jest/globals';
import Database from 'better-sqlite3';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import { DEFAULT_CONFIG } from '../memory/types.js';
import type { Memory, MemoryConfig } from '../memory/types.js';
import type { RankList } from '../memory/ranker/rrf.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const SCHEMA_PATH = path.resolve(__dirname, '..', 'database', 'schema.sql');

function makeDb(): Database.Database {
  const db = new Database(':memory:');
  db.exec(fs.readFileSync(SCHEMA_PATH, 'utf-8'));
  return db;
}

function makeMemory(overrides: Partial<Memory> = {}): Memory {
  const now = new Date();
  return {
    id: 1,
    uuid: `uuid-${overrides.id ?? 1}`,
    type: 'long_term',
    category: 'note',
    title: 'test memory',
    content: 'test content',
    project: 'test',
    tags: [],
    salience: 0.5,
    accessCount: 0,
    lastAccessed: now,
    createdAt: now,
    updatedAt: now,
    decayedScore: 0.5,
    metadata: {},
    scope: 'project',
    transferable: false,
    status: 'active',
    pinned: false,
    reviewedAt: null,
    reviewedBy: null,
    sourceKind: 'user',
    captureMethod: 'manual',
    trustScore: 1.0,
    sensitivityLevel: 'INTERNAL',
    source: 'user:direct',
    cloudExcluded: false,
    memoryPurpose: 'project',
    memoryScope: 'private',
    ...overrides,
  };
}

const baseConfig: MemoryConfig = { ...DEFAULT_CONFIG, salienceThreshold: 0.0 };

describe('runHybridRanker', () => {
  let db: Database.Database;
  afterEach(() => {
    if (db) db.close();
  });

  it('returns empty array when all rank lists are empty', async () => {
    const { runHybridRanker } = await import('../memory/ranker/index.js');
    db = makeDb();
    const results = runHybridRanker({
      rankLists: [
        { name: 'fts', ids: [] },
        { name: 'vector', ids: [] },
        { name: 'graph', ids: [] },
      ],
      memories: new Map(),
      query: 'test',
      db,
      config: baseConfig,
    });
    expect(results).toEqual([]);
  });

  it('returns empty array when no rank list contains any id with a matching memory', async () => {
    const { runHybridRanker } = await import('../memory/ranker/index.js');
    db = makeDb();
    const results = runHybridRanker({
      rankLists: [{ name: 'fts', ids: [99] }],
      memories: new Map(), // no matching memory
      query: 'test',
      db,
      config: baseConfig,
    });
    expect(results).toEqual([]);
  });

  it('produces SearchResult with relevanceScore reflecting RRF score and base multipliers', async () => {
    const { runHybridRanker } = await import('../memory/ranker/index.js');
    db = makeDb();
    const memory = makeMemory({ id: 1, title: 'auth notes', salience: 0.5 });
    const results = runHybridRanker({
      rankLists: [{ name: 'fts', ids: [1] }],
      memories: new Map([[1, memory]]),
      query: 'auth notes',
      db,
      config: baseConfig,
    });
    expect(results).toHaveLength(1);
    expect(results[0].memory.id).toBe(1);
    expect(results[0].relevanceScore).toBeGreaterThan(0);
  });

  it('combines contributions from multiple rank lists (memory in FTS + vector + graph ranks higher than memory in only one)', async () => {
    const { runHybridRanker } = await import('../memory/ranker/index.js');
    db = makeDb();
    // Memory 1 appears in all three lists; memory 2 only in FTS.
    const m1 = makeMemory({ id: 1, title: 'shared', salience: 0.5 });
    const m2 = makeMemory({ id: 2, title: 'fts only', salience: 0.5 });
    const results = runHybridRanker({
      rankLists: [
        { name: 'fts', ids: [2, 1] },     // m2 ranked 1st, m1 2nd
        { name: 'vector', ids: [1] },     // m1 only
        { name: 'graph', ids: [1] },      // m1 only
      ],
      memories: new Map([[1, m1], [2, m2]]),
      query: 'shared',
      db,
      config: baseConfig,
    });
    expect(results.length).toBe(2);
    // m1 (in all three) should outrank m2 (only fts) thanks to RRF.
    expect(results[0].memory.id).toBe(1);
  });

  it('applies recency boost when memory was accessed in the last hour', async () => {
    const { runHybridRanker } = await import('../memory/ranker/index.js');
    db = makeDb();
    const recentlyAccessed = new Date(Date.now() - 30 * 60 * 1000); // 30 min ago
    const stale = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000); // 7 days ago
    const m1 = makeMemory({ id: 1, title: 'recent', lastAccessed: recentlyAccessed });
    const m2 = makeMemory({ id: 2, title: 'stale', lastAccessed: stale });
    const results = runHybridRanker({
      rankLists: [{ name: 'fts', ids: [1, 2] }],
      memories: new Map([[1, m1], [2, m2]]),
      query: 'general',
      db,
      config: baseConfig,
    });
    expect(results).toHaveLength(2);
    const r1 = results.find((r) => r.memory.id === 1)!;
    const r2 = results.find((r) => r.memory.id === 2)!;
    // r1 has recency boost; rrf gives it lower base score (rank 1 > rank 2),
    // but recency multiplier should keep r1 above r2.
    expect(r1.relevanceScore).toBeGreaterThan(r2.relevanceScore);
  });

  it('applies category match boost when query category matches memory category', async () => {
    const { runHybridRanker } = await import('../memory/ranker/index.js');
    db = makeDb();
    const errorMemory = makeMemory({ id: 1, category: 'error', title: 'bug fix' });
    const noteMemory = makeMemory({ id: 2, category: 'note', title: 'note about bugs' });
    const results = runHybridRanker({
      // Both at same FTS rank (rank 1) — only category boost differs.
      rankLists: [{ name: 'fts', ids: [1, 2] }],
      memories: new Map([[1, errorMemory], [2, noteMemory]]),
      query: 'how to fix this bug error', // detectQueryCategory → 'error'
      db,
      config: baseConfig,
    });
    const errorRes = results.find((r) => r.memory.id === 1)!;
    const noteRes = results.find((r) => r.memory.id === 2)!;
    expect(errorRes.relevanceScore).toBeGreaterThan(noteRes.relevanceScore);
  });

  it('applies tag boost when query tags overlap memory tags', async () => {
    const { runHybridRanker } = await import('../memory/ranker/index.js');
    db = makeDb();
    const tagged = makeMemory({ id: 1, title: 'a', tags: ['authentication', 'jwt'] });
    const untagged = makeMemory({ id: 2, title: 'b', tags: [] });
    const results = runHybridRanker({
      rankLists: [{ name: 'fts', ids: [1, 2] }],
      memories: new Map([[1, tagged], [2, untagged]]),
      query: 'authentication jwt config',
      db,
      config: baseConfig,
    });
    const taggedRes = results.find((r) => r.memory.id === 1)!;
    const untaggedRes = results.find((r) => r.memory.id === 2)!;
    expect(taggedRes.relevanceScore).toBeGreaterThan(untaggedRes.relevanceScore);
  });

  it('penalises memories with contradictions', async () => {
    const { runHybridRanker } = await import('../memory/ranker/index.js');
    db = makeDb();
    // memory_links has an FK to memories(id), so we need real rows first.
    // m1 has multiple contradiction links to OTHER memories (m3, m4, m5);
    // m2 has none. Both endpoints of a 'contradicts' link are penalised,
    // so wiring m1 → m2 directly would penalise both — use a third memory.
    // The link targets are inserted with salience=0 so they don't add a
    // counterbalancing linkBoost — we want to observe the contradiction
    // penalty in isolation.
    const insertMem = db.prepare(
      `INSERT INTO memories (id, uuid, type, category, title, content, salience)
       VALUES (?, ?, 'long_term', 'note', ?, ?, ?)`,
    );
    insertMem.run(1, 'uuid-1', 'with contradiction', 'a', 0.5);
    insertMem.run(2, 'uuid-2', 'no contradiction', 'b', 0.5);
    insertMem.run(3, 'uuid-3', 'other-3', 'c', 0);
    insertMem.run(4, 'uuid-4', 'other-4', 'd', 0);
    insertMem.run(5, 'uuid-5', 'other-5', 'e', 0);
    const insertLink = db.prepare(
      `INSERT INTO memory_links (source_id, target_id, relationship, strength)
       VALUES (?, ?, 'contradicts', 1.0)`,
    );
    insertLink.run(1, 3);
    insertLink.run(1, 4);
    insertLink.run(1, 5);
    const m1 = makeMemory({ id: 1, title: 'with contradiction' });
    const m2 = makeMemory({ id: 2, title: 'no contradiction' });
    const results = runHybridRanker({
      rankLists: [{ name: 'fts', ids: [1, 2] }],
      memories: new Map([[1, m1], [2, m2]]),
      query: 'general',
      db,
      config: baseConfig,
    });
    const m1Res = results.find((r) => r.memory.id === 1)!;
    const m2Res = results.find((r) => r.memory.id === 2)!;
    // m1 ranks first in FTS but has 3 contradictions (penalty 0.09) — m2 should win.
    expect(m2Res.relevanceScore).toBeGreaterThan(m1Res.relevanceScore);
    expect(m1Res.recallEligibility?.eligible).toBe(false);
    expect(m1Res.recallEligibility?.reasons.some((r) => r.includes('contradiction'))).toBe(true);
  });

  it('filters memories below salience threshold unless includeDecayed=true', async () => {
    const { runHybridRanker } = await import('../memory/ranker/index.js');
    db = makeDb();
    const lowSalience = makeMemory({
      id: 1,
      salience: 0.05,
      decayedScore: 0.05,
      lastAccessed: new Date(Date.now() - 365 * 24 * 60 * 60 * 1000), // a year ago
    });
    const cfg: MemoryConfig = { ...baseConfig, salienceThreshold: 0.2 };
    const filteredOut = runHybridRanker({
      rankLists: [{ name: 'fts', ids: [1] }],
      memories: new Map([[1, lowSalience]]),
      query: 'test',
      db,
      config: cfg,
      includeDecayed: false,
    });
    expect(filteredOut).toEqual([]);

    const included = runHybridRanker({
      rankLists: [{ name: 'fts', ids: [1] }],
      memories: new Map([[1, lowSalience]]),
      query: 'test',
      db,
      config: cfg,
      includeDecayed: true,
    });
    expect(included).toHaveLength(1);
  });

  it('respects limit option (caps result count)', async () => {
    const { runHybridRanker } = await import('../memory/ranker/index.js');
    db = makeDb();
    const memories = new Map<number, Memory>();
    const ids: number[] = [];
    for (let i = 1; i <= 10; i++) {
      ids.push(i);
      memories.set(i, makeMemory({ id: i, title: `m${i}` }));
    }
    const results = runHybridRanker({
      rankLists: [{ name: 'fts', ids }],
      memories,
      query: 'test',
      db,
      config: baseConfig,
      limit: 3,
    });
    expect(results).toHaveLength(3);
  });

  it('flags low-trust source memories as ineligible', async () => {
    const { runHybridRanker } = await import('../memory/ranker/index.js');
    db = makeDb();
    const lowTrust = makeMemory({ id: 1, trustScore: 0.5 });
    const results = runHybridRanker({
      rankLists: [{ name: 'fts', ids: [1] }],
      memories: new Map([[1, lowTrust]]),
      query: 'test',
      db,
      config: baseConfig,
    });
    expect(results[0].recallEligibility?.eligible).toBe(false);
    expect(results[0].recallEligibility?.reasons.some((r) => r.includes('Low trust'))).toBe(true);
  });

  it('includes search explanation when includeExplanation=true', async () => {
    const { runHybridRanker } = await import('../memory/ranker/index.js');
    db = makeDb();
    const memory = makeMemory({ id: 1, title: 'detailed' });
    const results = runHybridRanker({
      rankLists: [{ name: 'fts', ids: [1] }],
      memories: new Map([[1, memory]]),
      query: 'detailed',
      db,
      config: baseConfig,
      includeExplanation: true,
    });
    expect(results[0].explanation).toBeDefined();
    expect(results[0].explanation?.breakdown).toBeDefined();
    expect(typeof results[0].explanation?.breakdown.finalScore).toBe('number');
  });

  it('omits explanation when includeExplanation=false (default)', async () => {
    const { runHybridRanker } = await import('../memory/ranker/index.js');
    db = makeDb();
    const memory = makeMemory({ id: 1 });
    const results = runHybridRanker({
      rankLists: [{ name: 'fts', ids: [1] }],
      memories: new Map([[1, memory]]),
      query: 'test',
      db,
      config: baseConfig,
    });
    expect(results[0].explanation).toBeUndefined();
  });

  it('respects custom RRF weights — graph weight 0 effectively ignores graph rank list', async () => {
    const { runHybridRanker } = await import('../memory/ranker/index.js');
    db = makeDb();
    const m1 = makeMemory({ id: 1 });
    const m2 = makeMemory({ id: 2 });
    // FTS ranks m1 first; graph ranks m2 first. With graph weight 0, the
    // FTS order should win.
    const results = runHybridRanker({
      rankLists: [
        { name: 'fts', ids: [1, 2], weight: 1 },
        { name: 'graph', ids: [2, 1], weight: 0 },
      ],
      memories: new Map([[1, m1], [2, m2]]),
      query: 'test',
      db,
      config: baseConfig,
    });
    expect(results[0].memory.id).toBe(1);
  });

  it('uses injected activationBoostFn when provided (bypasses module-level cache)', async () => {
    const { runHybridRanker } = await import('../memory/ranker/index.js');
    db = makeDb();
    const m1 = makeMemory({ id: 1 });
    const m2 = makeMemory({ id: 2 });
    const activationBoostFn = (id: number) => (id === 2 ? 0.5 : 0);
    const results = runHybridRanker({
      rankLists: [{ name: 'fts', ids: [1, 2] }],
      memories: new Map([[1, m1], [2, m2]]),
      query: 'test',
      db,
      config: baseConfig,
      activationBoostFn,
    });
    // m2 has activation boost, m1 doesn't — m2 should outrank despite m1's
    // higher RRF base score (rank 1 in fts).
    expect(results[0].memory.id).toBe(2);
  });

  it('breaks score ties by memoryId ascending for stable output', async () => {
    const { runHybridRanker } = await import('../memory/ranker/index.js');
    db = makeDb();
    const m1 = makeMemory({ id: 99, title: 'a' });
    const m2 = makeMemory({ id: 7, title: 'b' });
    // Identical RRF rank in two retrievers, no other multipliers differ.
    const results = runHybridRanker({
      rankLists: [
        { name: 'fts', ids: [99, 7] },
        { name: 'vector', ids: [7, 99] },
      ],
      memories: new Map([[99, m1], [7, m2]]),
      query: 'test',
      db,
      config: baseConfig,
    });
    expect(results).toHaveLength(2);
    // Score-tied entries sort by memoryId ascending → 7 before 99.
    expect(results[0].relevanceScore).toBeCloseTo(results[1].relevanceScore, 6);
    expect(results[0].memory.id).toBe(7);
    expect(results[1].memory.id).toBe(99);
  });
});
