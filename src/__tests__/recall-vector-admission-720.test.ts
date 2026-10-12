/**
 * #720 review (Tars) — the prompt-recall vector plane.
 *
 * Blocker 1 (lane isolation / merge order):
 *   (i)   default config → the vector plane is never consulted (the embedder
 *         module is not even imported);
 *   (ii)  opted in → vector candidates pass the SAME admission + lexical
 *         predicate as FTS candidates: a row FTS would exclude (a same-project
 *         private row with no term overlap, a suppressed row, a faded row, a
 *         foreign-project row) is excluded from vector results too;
 *   (iii) a semantic hit with no lexical overlap is still gated — not admitted
 *         by the vector plane, and not exempted by the relevance gate.
 *
 * Blocker 3 (mixed snapshots): a concurrent writer that edits, suppresses or
 * clears the embedding of a row between "pick by similarity" and "read its
 * content" must not produce new content carrying the old similarity — for a
 * vector-only hit and for a row that is both an FTS and a vector hit. The
 * writer is a second connection interposed after the first statement runs.
 */
import { describe, it, expect, beforeAll, afterEach } from '@jest/globals';
import Database from 'better-sqlite3';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..', '..');
const SCHEMA = readFileSync(join(repoRoot, 'src', 'database', 'schema.sql'), 'utf8');
const PROJECT = 'vec720';

type Row = Record<string, unknown> & { id: number; content?: string; _source?: string; _similarity?: number };
type Db = Database.Database;
let vec: any;
let admission: any;
let relevance: any;

beforeAll(async () => {
  vec = await import(pathToFileURL(join(repoRoot, 'scripts', 'lib', 'recall-vector.mjs')).href);
  admission = await import(pathToFileURL(join(repoRoot, 'scripts', 'lib', 'recall-admission.mjs')).href);
  relevance = await import(pathToFileURL(join(repoRoot, 'scripts', 'lib', 'recall-relevance.mjs')).href);
});

const tmpDirs: string[] = [];
const openDbs: Db[] = [];
afterEach(() => {
  for (const db of openDbs.splice(0)) { try { db.close(); } catch { /* closed */ } }
  for (const d of tmpDirs.splice(0)) { try { rmSync(d, { recursive: true, force: true }); } catch { /* best effort */ } }
});

function blob(v: number[]): Buffer {
  return Buffer.from(new Float32Array(v).buffer);
}

function freshDbPath(): string {
  const dir = mkdtempSync(join(tmpdir(), 'sc-720-'));
  tmpDirs.push(dir);
  const path = join(dir, 'm.db');
  const db = new Database(path);
  db.pragma('journal_mode = WAL'); // as src/database/init.ts sets it
  db.exec(SCHEMA);
  db.close();
  return path;
}

function open(path: string, readonly = false): Db {
  const db = new Database(path, { readonly });
  openDbs.push(db);
  return db;
}

interface RowSpec {
  title: string; content: string; embedding: number[] | null;
  project?: string; scope?: string; status?: string; salience?: number; memoryScope?: string;
}

function insert(db: Db, r: RowSpec): number {
  const info = db.prepare(
    `INSERT INTO memories (uuid, type, category, title, content, project, scope, memory_scope, salience,
                           trust_score, sensitivity_level, status, embedding)
     VALUES (lower(hex(randomblob(16))), 'long_term', 'note', ?, ?, ?, ?, ?, ?, 1.0, 'PUBLIC', ?, ?)`,
  ).run(r.title, r.content, r.project ?? PROJECT, r.scope ?? 'project', r.memoryScope ?? 'private',
    r.salience ?? 0.9, r.status ?? 'active', r.embedding ? blob(r.embedding) : null);
  return Number(info.lastInsertRowid);
}

const Q = new Float32Array([1, 0, 0, 0]);
const FTS_QUERY = '"weekend" OR "lake" OR "plans"';
const BASE = { limit: 10, minSalience: 0.2, minSimilarity: 0.35 };

/**
 * Wrap `db` so `mutate` runs once, right after the first statement's rows are
 * read — i.e. between a scan and anything that follows it.
 */
function interposeAfterFirstRead(db: Db, mutate: () => void): Db {
  let fired = false;
  const wrapStmt = (stmt: any) => new Proxy(stmt, {
    get(target, prop) {
      const value = target[prop];
      if (typeof value !== 'function') return value;
      if (prop === 'all' || prop === 'get') {
        return (...args: unknown[]) => {
          const out = value.apply(target, args);
          if (!fired) { fired = true; mutate(); }
          return out;
        };
      }
      return value.bind(target);
    },
  });
  return new Proxy(db, {
    get(target, prop) {
      if (prop === 'prepare') return (sql: string) => wrapStmt(target.prepare(sql));
      const value = (target as any)[prop];
      return typeof value === 'function' ? value.bind(target) : value;
    },
  }) as Db;
}

// ── Blocker 1 ────────────────────────────────────────────────────────────

describe('vector plane is default-off (#720 blocker 1-i)', () => {
  it('isRecallVectorEnabled: off unless config or env opts in; an explicit env off wins', () => {
    expect(vec.isRecallVectorEnabled({}, {})).toBe(false);
    expect(vec.isRecallVectorEnabled({ proactiveRecall: true }, {})).toBe(false);
    expect(vec.isRecallVectorEnabled({ recallVector: 'yes' }, {})).toBe(false);
    expect(vec.isRecallVectorEnabled({ recallVector: true }, {})).toBe(true);
    expect(vec.isRecallVectorEnabled({}, { SHIELDCORTEX_RECALL_VECTOR: '1' })).toBe(true);
    expect(vec.isRecallVectorEnabled({ recallVector: true }, { SHIELDCORTEX_RECALL_VECTOR: '0' })).toBe(false);
  });

  it('loadQueryEmbedder with default config never imports the embedder', async () => {
    const dist = mkdtempSync(join(tmpdir(), 'sc-720-dist-'));
    tmpDirs.push(dist);
    mkdirSync(join(dist, 'embeddings'), { recursive: true });
    const probe = join(dist, 'probe');
    writeFileSync(join(dist, 'embeddings', 'model-cache.js'),
      `import { writeFileSync } from 'node:fs';\nwriteFileSync(${JSON.stringify(probe)}, 'imported');\n`
      + 'export async function inspectEmbeddingHookReady() { return { ready: true }; }\n');
    writeFileSync(join(dist, 'embeddings', 'index.js'), 'export async function generateEmbedding() { return new Float32Array([1]); }\n');

    const saved = process.env.SHIELDCORTEX_SKIP_EMBEDDINGS;
    delete process.env.SHIELDCORTEX_SKIP_EMBEDDINGS;
    try {
      const r = await vec.loadQueryEmbedder({ distRoot: dist, config: { proactiveRecall: true }, env: {} });
      expect(r).toEqual({ embed: null, reason: 'disabled:default-off' });
      expect(existsSync(probe)).toBe(false);
    } finally {
      if (saved !== undefined) process.env.SHIELDCORTEX_SKIP_EMBEDDINGS = saved;
    }
  });
});

describe('vector candidates obey the FTS admission predicate (#720 blocker 1-ii/iii)', () => {
  it('a row FTS excludes is excluded from vector results too (differential)', () => {
    const path = freshDbPath();
    const db = open(path);
    const near = [1, 0, 0, 0];
    const ids = {
      admitted: insert(db, { title: 'Weekend lake plans', content: 'weekend lake plans with the kayak club', embedding: near }),
      globalOther: insert(db, { title: 'Lake safety', content: 'lake plans need a life jacket', embedding: near, project: 'other', scope: 'global' }),
      privateNoOverlap: insert(db, { title: 'Anniversary', content: 'Private surprise booked for my partner', embedding: near, memoryScope: 'private' }),
      suppressed: insert(db, { title: 'Weekend lake plans (old)', content: 'weekend lake plans cancelled', embedding: near, status: 'suppressed' }),
      archived: insert(db, { title: 'Weekend lake plans 2025', content: 'weekend lake plans last year', embedding: near, status: 'archived' }),
      faded: insert(db, { title: 'Weekend lake notes', content: 'weekend lake plans scribble', embedding: near, salience: 0.05 }),
      foreignPrivate: insert(db, { title: 'Weekend lake plans', content: 'weekend lake plans for another project', embedding: near, project: 'other' }),
    };

    const ftsIds = new Set(admission.selectFtsCandidates(db, { project: PROJECT, ftsQuery: FTS_QUERY, limit: 50, minSalience: 0.2 })
      .map((r: Row) => r.id));
    const vecIds = new Set(vec.vectorCandidates(db, PROJECT, Q, { ...BASE, limit: 50, ftsQuery: FTS_QUERY })
      .map((r: Row) => r.id));

    for (const [label, id] of Object.entries(ids)) {
      expect({ label, vector: vecIds.has(id) }).toEqual({ label, vector: ftsIds.has(id) });
    }
    expect([...vecIds].sort()).toEqual([ids.admitted, ids.globalOther].sort());
    // The private same-project row is a perfect semantic neighbour (cosine 1)
    // that FTS excludes for want of any query term: so does the vector plane.
    expect(vecIds.has(ids.privateNoOverlap)).toBe(false);
  });

  it('with no lexical query the vector plane admits nothing', () => {
    const db = open(freshDbPath());
    insert(db, { title: 'Weekend lake plans', content: 'weekend lake plans', embedding: [1, 0, 0, 0] });
    expect(vec.vectorCandidates(db, PROJECT, Q, { ...BASE, ftsQuery: '' })).toEqual([]);
    expect(vec.vectorCandidates(db, PROJECT, Q, BASE)).toEqual([]);
  });

  it('the relevance gate no longer exempts a semantic hit with zero term overlap', () => {
    const row: Row = { id: 1, title: 'Kayak hire booked', content: 'Paddling outing reserved', _similarity: 0.99, _source: 'vector' };
    const opts = { queryTerms: ['weekend', 'plans', 'lake'], minTermMatches: 2, relFactor: 0.35 };
    for (const extra of [{}, { minSemanticSimilarity: 0.35 }]) {
      const { kept, dropped } = relevance.filterByRelevance([row], { ...opts, ...extra });
      expect(kept).toHaveLength(0);
      expect(dropped.map((d: { reason: string }) => d.reason)).toEqual(['below_term_coverage']);
    }
  });

  it('a ranked semantic hit is still subject to the BM25 floor', () => {
    const best: Row = { id: 1, title: 'weekend lake plans', content: 'weekend lake plans', rank: -10 };
    const weak: Row = { id: 2, title: 'weekend lake', content: 'weekend lake', rank: -1, _similarity: 0.99 };
    const { dropped } = relevance.filterByRelevance([best, weak], {
      queryTerms: ['weekend', 'lake', 'plans'], minTermMatches: 2, relFactor: 0.35, minSemanticSimilarity: 0.35,
    });
    expect(dropped.map((d: { row: Row; reason: string }) => [d.row.id, d.reason])).toEqual([[2, 'below_relevance_floor']]);
  });
});

// ── Blocker 3 ────────────────────────────────────────────────────────────

const V1 = { title: 'Weekend lake plans', content: 'weekend lake plans: kayak club, Saturday 9am' };

const MUTATIONS: Array<[string, (w: Db, id: number) => void]> = [
  // Still a vector hit after the edit (cosine 0.6), so a mixed read would pair
  // one version's content with the other's similarity.
  ['edited and re-embedded nearby', (w, id) => w.prepare(
    `UPDATE memories SET content = 'weekend lake plans: CANCELLED, flat for sale', embedding = ? WHERE id = ?`,
  ).run(blob([0.6, 0.8, 0, 0]), id)],
  ['edited and embedding cleared', (w, id) => w.prepare(
    `UPDATE memories SET content = 'weekend lake plans: CANCELLED, flat for sale', embedding = NULL WHERE id = ?`,
  ).run(id)],
  ['suppressed, redacted and embedding cleared', (w, id) => w.prepare(
    `UPDATE memories SET status = 'suppressed', content = '[REDACTED]', embedding = NULL WHERE id = ?`,
  ).run(id)],
];

describe('vector candidates come from one coherent snapshot (#720 blocker 3)', () => {
  it.each(MUTATIONS)('vector-only hit %s between scan and read: never new content with the old similarity', (_label, mutate) => {
    const path = freshDbPath();
    const writer = open(path);
    const id = insert(writer, { ...V1, embedding: [1, 0, 0, 0] });
    const reader = interposeAfterFirstRead(open(path, true), () => mutate(writer, id));

    const rows: Row[] = vec.vectorCandidates(reader, PROJECT, Q, { ...BASE, ftsQuery: FTS_QUERY });
    for (const row of rows) {
      // Whatever is returned must be the content the similarity was computed on.
      expect({ id: row.id, content: row.content }).toEqual({ id, content: V1.content });
      expect(row._similarity).toBeCloseTo(1, 5);
    }
  });

  it.each(MUTATIONS)('row that is both an FTS and a vector hit, %s between the planes: content and similarity agree', (_label, mutate) => {
    const path = freshDbPath();
    const writer = open(path);
    const id = insert(writer, { ...V1, embedding: [1, 0, 0, 0] });
    const reader = interposeAfterFirstRead(open(path, true), () => mutate(writer, id));

    const { ftsRows, vectorRows } = vec.readRecallSnapshot(reader, {
      project: PROJECT, ftsQuery: FTS_QUERY, queryVector: Q, ...BASE,
    });
    const fused: Row[] = vec.fuseRecallCandidates(ftsRows, vectorRows);
    const row = fused.find((r) => r.id === id);
    expect(row).toBeDefined();
    expect(row!.content).toBe(V1.content);
    // One snapshot: the FTS read and the vector read saw the same version.
    expect(row!._source).toBe('both');
    expect(row!._similarity).toBeCloseTo(1, 5);
  });

  it('fusion never attaches a similarity computed on different content', () => {
    const fts: Row[] = [{ id: 7, title: 'T', content: 'version one', rank: -3, _source: 'fts' }];
    const vecRows: Row[] = [{ id: 7, title: 'T', content: 'version two', _similarity: 0.6 }];
    const [row] = vec.fuseRecallCandidates(fts, vecRows);
    expect(row.content).toBe('version one');
    expect(row._source).toBe('fts');
    expect(row._similarity).toBeUndefined();
  });
});
