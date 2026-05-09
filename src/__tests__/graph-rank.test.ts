/**
 * Tests for graphRankFromQuery — a side-effect-free retriever that turns
 * a free-text query into a ranked list of memories by traversing the
 * knowledge graph (entities + triples).
 *
 * Algorithm:
 *   1. Tokenize the query, drop stop-words and tokens < 3 chars.
 *   2. Resolve each surviving token to seed entities via exact (CI), alias,
 *      or Levenshtein (≤ 2 distance, tokens ≥ 6 chars).
 *   3. BFS over triples up to `maxHops`. Track shortest hop distance per
 *      entity reached.
 *   4. For every memory that mentions a reached entity (via memory_entities),
 *      accumulate score: Σ (triple.confidence) / (hop + 1).
 *   5. Optional project filter via JOIN with memories.project.
 *   6. Sort by score desc, dedupe by memoryId, cap at `limit`.
 *
 * Tests use a fresh in-memory better-sqlite3 DB with the production schema
 * loaded from src/database/schema.sql, then seed graph fixtures by hand.
 */

import { afterEach, beforeEach, describe, expect, it } from '@jest/globals';
import Database from 'better-sqlite3';
import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const SCHEMA_PATH = path.resolve(__dirname, '..', 'database', 'schema.sql');

interface SeedOptions {
  entities: Array<{ name: string; type: string; aliases?: string[] }>;
  triples: Array<{ subject: string; predicate: string; object: string; confidence?: number }>;
  memories: Array<{
    title: string;
    content: string;
    project?: string;
    type?: 'short_term' | 'long_term' | 'episodic';
    mentions: string[];
  }>;
}

function makeTestDb(seed: SeedOptions): Database.Database {
  const db = new Database(':memory:');
  db.exec(fs.readFileSync(SCHEMA_PATH, 'utf-8'));

  const entityIdByName = new Map<string, number>();
  const insertEntity = db.prepare('INSERT INTO entities (name, type, aliases) VALUES (?, ?, ?)');
  for (const e of seed.entities) {
    const r = insertEntity.run(e.name, e.type, JSON.stringify(e.aliases ?? []));
    entityIdByName.set(e.name, Number(r.lastInsertRowid));
  }

  const memoryIdByTitle = new Map<string, number>();
  const insertMemory = db.prepare(
    `INSERT INTO memories (uuid, type, category, title, content, project)
     VALUES (?, 'long_term', 'note', ?, ?, ?)`,
  );
  const insertMemEntity = db.prepare(
    'INSERT OR IGNORE INTO memory_entities (memory_id, entity_id, role) VALUES (?, ?, ?)',
  );
  let mid = 0;
  for (const m of seed.memories) {
    const r = insertMemory.run(`uuid-${++mid}`, m.title, m.content, m.project ?? 'test');
    const memoryId = Number(r.lastInsertRowid);
    memoryIdByTitle.set(m.title, memoryId);
    for (const mention of m.mentions) {
      const eid = entityIdByName.get(mention);
      if (eid === undefined) throw new Error(`unknown mention: ${mention}`);
      insertMemEntity.run(memoryId, eid, 'mention');
    }
  }

  const insertTriple = db.prepare(
    'INSERT INTO triples (subject_id, predicate, object_id, confidence) VALUES (?, ?, ?, ?)',
  );
  for (const t of seed.triples) {
    const sid = entityIdByName.get(t.subject);
    const oid = entityIdByName.get(t.object);
    if (sid === undefined || oid === undefined) {
      throw new Error(`unknown triple endpoint: ${t.subject} or ${t.object}`);
    }
    insertTriple.run(sid, t.predicate, oid, t.confidence ?? 0.8);
  }

  return db;
}

describe('graphRankFromQuery', () => {
  let db: Database.Database;
  afterEach(() => {
    if (db) db.close();
  });

  it('returns empty array when query has no resolvable seed entities', async () => {
    const { graphRankFromQuery } = await import('../memory/ranker/graph-rank.js');
    db = makeTestDb({
      entities: [{ name: 'auth', type: 'concept' }],
      triples: [],
      memories: [{ title: 'auth note', content: '...', mentions: ['auth'] }],
    });
    expect(graphRankFromQuery('xyz unknown garbage', db)).toEqual([]);
  });

  it('returns empty array when query is empty', async () => {
    const { graphRankFromQuery } = await import('../memory/ranker/graph-rank.js');
    db = makeTestDb({ entities: [], triples: [], memories: [] });
    expect(graphRankFromQuery('', db)).toEqual([]);
    expect(graphRankFromQuery('   ', db)).toEqual([]);
  });

  it('finds memories that mention the seed entity (hop 0)', async () => {
    const { graphRankFromQuery } = await import('../memory/ranker/graph-rank.js');
    db = makeTestDb({
      entities: [{ name: 'auth', type: 'concept' }],
      triples: [],
      memories: [
        { title: 'A', content: '...', mentions: ['auth'] },
        { title: 'B', content: '...', mentions: [] },
      ],
    });
    const results = graphRankFromQuery('auth', db);
    expect(results.length).toBe(1);
    expect(results[0].score).toBeGreaterThan(0);
  });

  it('expands to 1-hop neighbours via triples and finds memories that mention only the neighbour', async () => {
    const { graphRankFromQuery } = await import('../memory/ranker/graph-rank.js');
    db = makeTestDb({
      entities: [
        { name: 'auth', type: 'concept' },
        { name: 'jose', type: 'library' },
      ],
      triples: [{ subject: 'auth', predicate: 'uses', object: 'jose' }],
      memories: [
        { title: 'jose note', content: '...', mentions: ['jose'] },
        { title: 'unrelated', content: '...', mentions: [] },
      ],
    });
    const results = graphRankFromQuery('auth', db);
    const titles = results.map((r) => r.memoryId);
    expect(titles.length).toBe(1);
    // The memory mentioning jose (hop-1 neighbour of auth) is found
  });

  it('hop-0 mentions outscore hop-2 mentions when seed has both', async () => {
    const { graphRankFromQuery } = await import('../memory/ranker/graph-rank.js');
    db = makeTestDb({
      entities: [
        { name: 'auth', type: 'concept' },
        { name: 'jose', type: 'library' },
        { name: 'edge', type: 'concept' },
      ],
      triples: [
        { subject: 'auth', predicate: 'uses', object: 'jose', confidence: 0.9 },
        { subject: 'jose', predicate: 'targets', object: 'edge', confidence: 0.9 },
      ],
      memories: [
        { title: 'auth note', content: '...', mentions: ['auth'] }, // hop 0
        { title: 'edge note', content: '...', mentions: ['edge'] }, // hop 2
      ],
    });
    const results = graphRankFromQuery('auth', db, { maxHops: 2 });
    expect(results.length).toBe(2);
    expect(results[0].memoryId).toBe(results.find((r) => r.score === Math.max(...results.map((x) => x.score)))!.memoryId);
    // Top result is the hop-0 (auth note); hop-2 (edge note) ranks below
    const authMemoryScore = results.find((r) => r.memoryId === 1)!.score;
    const edgeMemoryScore = results.find((r) => r.memoryId === 2)!.score;
    expect(authMemoryScore).toBeGreaterThan(edgeMemoryScore);
  });

  it('does not expand past maxHops', async () => {
    const { graphRankFromQuery } = await import('../memory/ranker/graph-rank.js');
    db = makeTestDb({
      entities: [
        { name: 'auth', type: 'concept' },
        { name: 'jose', type: 'library' },
        { name: 'edge', type: 'concept' },
      ],
      triples: [
        { subject: 'auth', predicate: 'uses', object: 'jose' },
        { subject: 'jose', predicate: 'targets', object: 'edge' },
      ],
      memories: [{ title: 'edge only', content: '...', mentions: ['edge'] }],
    });
    // maxHops=1 should NOT reach edge (which is 2 hops from auth).
    const results = graphRankFromQuery('auth', db, { maxHops: 1 });
    expect(results).toEqual([]);
  });

  it('scales score by triple confidence', async () => {
    const { graphRankFromQuery } = await import('../memory/ranker/graph-rank.js');
    db = makeTestDb({
      entities: [
        { name: 'auth', type: 'concept' },
        { name: 'high-conf', type: 'concept' },
        { name: 'low-conf', type: 'concept' },
      ],
      triples: [
        { subject: 'auth', predicate: 'uses', object: 'high-conf', confidence: 0.95 },
        { subject: 'auth', predicate: 'uses', object: 'low-conf', confidence: 0.3 },
      ],
      memories: [
        { title: 'high', content: '...', mentions: ['high-conf'] },
        { title: 'low', content: '...', mentions: ['low-conf'] },
      ],
    });
    const results = graphRankFromQuery('auth', db, { maxHops: 1 });
    expect(results.length).toBe(2);
    const highScore = results.find((r) => r.memoryId === 1)!.score;
    const lowScore = results.find((r) => r.memoryId === 2)!.score;
    expect(highScore).toBeGreaterThan(lowScore);
  });

  it('matches entities case-insensitively', async () => {
    const { graphRankFromQuery } = await import('../memory/ranker/graph-rank.js');
    db = makeTestDb({
      entities: [{ name: 'JWT', type: 'concept' }],
      triples: [],
      memories: [{ title: 'jwt note', content: '...', mentions: ['JWT'] }],
    });
    expect(graphRankFromQuery('jwt', db)).toHaveLength(1);
    expect(graphRankFromQuery('JWT', db)).toHaveLength(1);
    expect(graphRankFromQuery('Jwt', db)).toHaveLength(1);
  });

  it('matches via alias', async () => {
    const { graphRankFromQuery } = await import('../memory/ranker/graph-rank.js');
    db = makeTestDb({
      entities: [{ name: 'jose', type: 'library', aliases: ['jose-jwt', 'jose lib'] }],
      triples: [],
      memories: [{ title: 'jose', content: '...', mentions: ['jose'] }],
    });
    expect(graphRankFromQuery('jose-jwt', db)).toHaveLength(1);
  });

  it('matches via Levenshtein fuzzy for tokens ≥ 6 chars', async () => {
    const { graphRankFromQuery } = await import('../memory/ranker/graph-rank.js');
    db = makeTestDb({
      entities: [{ name: 'authentication', type: 'concept' }],
      triples: [],
      memories: [{ title: 'auth', content: '...', mentions: ['authentication'] }],
    });
    // single-char typo — Levenshtein distance 1
    expect(graphRankFromQuery('autentication', db)).toHaveLength(1);
  });

  it('does NOT fuzzy-match short tokens (avoids false positives on 3–5 char words)', async () => {
    const { graphRankFromQuery } = await import('../memory/ranker/graph-rank.js');
    db = makeTestDb({
      entities: [{ name: 'auth', type: 'concept' }],
      triples: [],
      memories: [{ title: 'auth note', content: '...', mentions: ['auth'] }],
    });
    // "atth" is Lev=1 from "auth" but only 4 chars — should NOT match.
    expect(graphRankFromQuery('atth', db)).toEqual([]);
  });

  it('drops stop-words from query tokenization', async () => {
    const { graphRankFromQuery } = await import('../memory/ranker/graph-rank.js');
    db = makeTestDb({
      entities: [
        { name: 'the', type: 'concept' }, // would match "the" if not filtered
        { name: 'auth', type: 'concept' },
      ],
      triples: [],
      memories: [
        { title: 'the', content: '...', mentions: ['the'] },
        { title: 'auth', content: '...', mentions: ['auth'] },
      ],
    });
    const results = graphRankFromQuery('the auth', db);
    // Only the auth memory should come back; "the" is a stop-word.
    expect(results.length).toBe(1);
  });

  it('drops tokens shorter than 3 chars', async () => {
    const { graphRankFromQuery } = await import('../memory/ranker/graph-rank.js');
    db = makeTestDb({
      entities: [
        { name: 'go', type: 'language' },
        { name: 'rust', type: 'language' },
      ],
      triples: [],
      memories: [
        { title: 'go', content: '...', mentions: ['go'] },
        { title: 'rust', content: '...', mentions: ['rust'] },
      ],
    });
    const results = graphRankFromQuery('go rust', db);
    // "go" is 2 chars, dropped; only rust resolves.
    expect(results.length).toBe(1);
  });

  it('filters by project when specified', async () => {
    const { graphRankFromQuery } = await import('../memory/ranker/graph-rank.js');
    db = makeTestDb({
      entities: [{ name: 'auth', type: 'concept' }],
      triples: [],
      memories: [
        { title: 'a', content: '...', project: 'projA', mentions: ['auth'] },
        { title: 'b', content: '...', project: 'projB', mentions: ['auth'] },
      ],
    });
    const results = graphRankFromQuery('auth', db, { project: 'projA' });
    expect(results.length).toBe(1);
    expect(results[0].memoryId).toBe(1);
  });

  it('respects limit option', async () => {
    const { graphRankFromQuery } = await import('../memory/ranker/graph-rank.js');
    db = makeTestDb({
      entities: [{ name: 'auth', type: 'concept' }],
      triples: [],
      memories: Array.from({ length: 10 }, (_, i) => ({
        title: `m${i}`,
        content: '...',
        mentions: ['auth'],
      })),
    });
    const results = graphRankFromQuery('auth', db, { limit: 3 });
    expect(results.length).toBe(3);
  });

  it('dedupes by memoryId when multiple paths reach the same memory', async () => {
    const { graphRankFromQuery } = await import('../memory/ranker/graph-rank.js');
    db = makeTestDb({
      entities: [
        { name: 'auth', type: 'concept' },
        { name: 'jwt', type: 'concept' },
        { name: 'session', type: 'concept' },
      ],
      triples: [],
      memories: [
        // Same memory mentions two seeds — should appear once with combined score.
        { title: 'multi', content: '...', mentions: ['auth', 'jwt'] },
      ],
    });
    const results = graphRankFromQuery('auth jwt', db);
    expect(results.length).toBe(1);
    // Single entry, score reflects two hop-0 contributions (so > 1 contribution).
    expect(results[0].score).toBeGreaterThan(0.5);
  });
});
