/**
 * #717 — the prompt-recall hook's vector plane.
 *
 * Before #717 the hook was FTS-only, so a memory that shares no literal terms
 * with the prompt could never be a candidate however close its embedding was.
 * #720 (Tars review) narrowed the plane: it is default-off, and opted in it
 * only re-ranks / tops up rows the FTS expression also matches. These tests
 * prove:
 *   1. vectorCandidates + fuseRecallCandidates tag a lexical row found only by
 *      the vector scan `source: 'vector'` and a row in both lists `'both'`,
 *      while a row with no term overlap is never a vector candidate;
 *   2. the relevance gate judges every row on wording — no semantic exemption;
 *   3. end to end, the REAL hook (run as its own process inside a temp package
 *      whose dist/embeddings is a deterministic fake) never touches the
 *      embedder on default config, and opted in records `vectorPlane:
 *      'active:N'` without admitting a zero-overlap memory;
 *   4. fail soft: with no embedder the hook behaves as before and records
 *      `vectorPlane: 'unavailable:<reason>'`.
 */
import { describe, it, expect, beforeAll, afterEach } from '@jest/globals';
import { execFileSync } from 'node:child_process';
import Database from 'better-sqlite3';
import {
  cpSync, existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..', '..');
const SCHEMA = readFileSync(join(repoRoot, 'src', 'database', 'schema.sql'), 'utf8');
const PROJECT = 'vec717';
const CWD = `/tmp/${PROJECT}`;

type Row = Record<string, unknown> & { id: number; _source?: string; _similarity?: number };
let vec: {
  vectorCandidates: (db: unknown, project: string, q: Float32Array, o: Record<string, unknown>) => Row[];
  fuseRecallCandidates: (a: Row[], b: Row[], t?: (a: Row, b: Row) => number) => Row[];
};
let relevance: {
  filterByRelevance: (rows: Row[], o: Record<string, unknown>) => { kept: Row[]; dropped: Array<{ row: Row; reason: string }> };
};

beforeAll(async () => {
  vec = await import(pathToFileURL(join(repoRoot, 'scripts', 'lib', 'recall-vector.mjs')).href);
  relevance = await import(pathToFileURL(join(repoRoot, 'scripts', 'lib', 'recall-relevance.mjs')).href);
});

const tmpDirs: string[] = [];
afterEach(() => {
  for (const d of tmpDirs.splice(0)) {
    try { rmSync(d, { recursive: true, force: true }); } catch { /* best effort */ }
  }
});

function blob(v: number[]): Buffer {
  return Buffer.from(new Float32Array(v).buffer);
}

function makeDb(path: string): Database.Database {
  const db = new Database(path);
  db.exec(SCHEMA);
  return db;
}

function insert(db: Database.Database, title: string, content: string, embedding: number[] | null, salience = 0.9): number {
  const info = db.prepare(
    `INSERT INTO memories (uuid, type, category, title, content, project, salience, trust_score, sensitivity_level, status, embedding)
     VALUES (lower(hex(randomblob(16))), 'long_term', 'note', ?, ?, ?, ?, 1.0, 'PUBLIC', 'active', ?)`,
  ).run(title, content, PROJECT, salience, embedding ? blob(embedding) : null);
  return Number(info.lastInsertRowid);
}

describe('vector plane helpers (#717)', () => {
  it('re-ranks lexical candidates and tags fusion sources; no vector-only door (#720)', () => {
    const dir = mkdtempSync(join(tmpdir(), 'sc-717-unit-'));
    tmpDirs.push(dir);
    const db = makeDb(join(dir, 'm.db'));
    // Shares no word with the query below; close to it in vector space. #720:
    // FTS cannot surface it, so neither may the vector plane.
    const noOverlap = insert(db, 'Kayak hire booked', 'Paddling outing reserved for Saturday morning', [1, 0, 0, 0]);
    // Shares words AND is close: should fuse to 'both'.
    const both = insert(db, 'Weekend plans', 'weekend plans: lake trip', [0.9, 0.1, 0, 0]);
    // Shares words, close, but outside the FTS list given below: 'vector'.
    const vectorTopUp = insert(db, 'Lake weekend', 'lake weekend checklist', [1, 0, 0, 0]);
    // Shares words but far away in vector space: not a vector candidate.
    insert(db, 'Weekend compiler', 'weekend compiler flags for the ARM build', [0, 0, 1, 0]);
    // Below the salience floor: excluded like the FTS path excludes it.
    insert(db, 'Faded', 'weekend paddling notes', [1, 0, 0, 0], 0.05);

    const q = new Float32Array([1, 0, 0, 0]);
    const ftsQuery = '"weekend" OR "plans" OR "lake"';
    const vecRows = vec.vectorCandidates(db, PROJECT, q, { limit: 10, minSalience: 0.2, minSimilarity: 0.35, ftsQuery });
    expect(vecRows.map((r) => r.id)).toEqual([vectorTopUp, both]);
    expect(vecRows.map((r) => r.id)).not.toContain(noOverlap);

    const ftsRows: Row[] = [{ id: both, rank: -2, title: 'Weekend plans', content: 'weekend plans: lake trip', _source: 'fts' }];
    const fused = vec.fuseRecallCandidates(ftsRows, vecRows);
    const byId = new Map(fused.map((r) => [r.id, r]));
    expect(byId.get(both)?._source).toBe('both');
    expect(byId.get(vectorTopUp)?._source).toBe('vector');
    // Both-lists row outranks a single-list row under RRF.
    expect(fused[0].id).toBe(both);
    db.close();
  });

  it('relevance gate drops a semantic match with zero term overlap, opted in or not (#720)', () => {
    const row: Row = { id: 1, title: 'Kayak hire booked', content: 'Paddling outing reserved', _similarity: 0.8, _source: 'vector' };
    const opts = { queryTerms: ['weekend', 'plans', 'lake'], minTermMatches: 2, relFactor: 0.35 };
    expect(relevance.filterByRelevance([row], opts).dropped.map((d) => d.reason)).toEqual(['below_term_coverage']);
    expect(relevance.filterByRelevance([row], { ...opts, minSemanticSimilarity: 0.35 }).kept).toHaveLength(0);
  });

  it('a zero-length or mismatched-dimension blob never matches', () => {
    const dir = mkdtempSync(join(tmpdir(), 'sc-717-dim-'));
    tmpDirs.push(dir);
    const db = makeDb(join(dir, 'm.db'));
    insert(db, 'Old model row', 'vector from a different model', [1, 0, 0, 0, 0, 0]);
    const rows = vec.vectorCandidates(db, PROJECT, new Float32Array([1, 0, 0, 0]), { limit: 5, minSalience: 0.2, ftsQuery: '"model"' });
    expect(rows).toEqual([]);
    db.close();
  });
});

// ── End to end: the real hook in a package with a fake embedder ──────────

// Both fakes append to $SC_717_PROBE when loaded/called, so a test can prove
// the vector plane was never consulted.
const PROBE_PREAMBLE = `import { appendFileSync } from 'node:fs';
const probe = (what) => { if (process.env.SC_717_PROBE) appendFileSync(process.env.SC_717_PROBE, what + '\\n'); };
`;
const FAKE_MODEL_CACHE = `${PROBE_PREAMBLE}probe('model-cache-imported');
export async function inspectEmbeddingHookReady() { return { ready: true, reason: 'ok', missing: [] }; }\n`;
// Deterministic: anything mentioning "weekend" points along axis 0.
const FAKE_EMBEDDER = `${PROBE_PREAMBLE}export async function generateEmbedding(text) {
  probe('embed-called');
  return /weekend/i.test(text) ? new Float32Array([1, 0, 0, 0]) : new Float32Array([0, 0, 0, 1]);
}\n`;

function buildPackage(withEmbedder: boolean): string {
  const pkg = mkdtempSync(join(tmpdir(), 'sc-717-pkg-'));
  tmpDirs.push(pkg);
  writeFileSync(join(pkg, 'package.json'), JSON.stringify({ type: 'module' }));
  symlinkSync(join(repoRoot, 'node_modules'), join(pkg, 'node_modules'), 'dir');
  cpSync(join(repoRoot, 'scripts'), join(pkg, 'scripts'), { recursive: true });
  if (withEmbedder) {
    mkdirSync(join(pkg, 'dist', 'embeddings'), { recursive: true });
    writeFileSync(join(pkg, 'dist', 'embeddings', 'model-cache.js'), FAKE_MODEL_CACHE);
    writeFileSync(join(pkg, 'dist', 'embeddings', 'index.js'), FAKE_EMBEDDER);
  }
  return pkg;
}

// #720: the vector plane is opt-in; `vector: true` writes `recallVector: true`.
function makeHome({ vector = false }: { vector?: boolean } = {}): { home: string; db: Database.Database } {
  const home = mkdtempSync(join(tmpdir(), 'sc-717-home-'));
  tmpDirs.push(home);
  mkdirSync(join(home, '.shieldcortex'), { recursive: true });
  writeFileSync(
    join(home, '.shieldcortex', 'config.json'),
    JSON.stringify({ proactiveRecall: true, captureEvents: false, ...(vector ? { recallVector: true } : {}) }),
  );
  return { home, db: makeDb(join(home, '.shieldcortex', 'memories.db')) };
}

function runHook(pkg: string, home: string, prompt: string, envExtra: Record<string, string> = {}): string {
  const env: Record<string, string | undefined> = { ...process.env, HOME: home, USERPROFILE: home };
  for (const key of Object.keys(env)) {
    if (key.startsWith('SHIELDCORTEX_')) delete env[key];
  }
  Object.assign(env, envExtra);
  try {
    return execFileSync('node', [join(pkg, 'scripts', 'prompt-recall-hook.mjs')], {
      input: JSON.stringify({ prompt, cwd: CWD, session_id: null }),
      env: env as NodeJS.ProcessEnv,
      timeout: 30_000,
      encoding: 'utf8',
      stdio: ['pipe', 'pipe', 'pipe'],
    });
  } catch (e) {
    return String((e as { stdout?: string }).stdout ?? '');
  }
}

function lastRecallLog(home: string): Record<string, any> {
  return JSON.parse(readFileSync(join(home, '.shieldcortex', 'recall-log', '0.json'), 'utf8'));
}

describe('prompt-recall hook vector plane, end to end (#717)', () => {
  it('#720: default config never consults the vector plane, even with an embedder present', () => {
    const pkg = buildPackage(true);
    const { home, db } = makeHome();
    const id = insert(db, 'Weekend lake plans', 'weekend lake plans with the kayak club', [1, 0, 0, 0]);
    db.close();
    const probe = join(home, 'vector-probe.log');

    const out = runHook(pkg, home, 'remind me about the weekend lake plans', { SC_717_PROBE: probe });
    const log = lastRecallLog(home);
    expect(log.vectorPlane).toBe('disabled:default-off');
    expect(existsSync(probe)).toBe(false); // embedder neither imported nor called
    const cand = log.candidates.find((c: { id: number }) => c.id === id);
    expect(cand.source).toBe('fts');
    expect(cand.vectorSimilarity).toBeNull();
    expect(JSON.parse(out).hookSpecificOutput.additionalContext).toContain('Weekend lake plans');
  });

  it('#720: opted in, a memory with no FTS term overlap is not a candidate, however similar', () => {
    const pkg = buildPackage(true);
    const { home, db } = makeHome({ vector: true });
    const id = insert(db, 'Kayak hire booked', 'Paddling outing reserved for Saturday morning', [1, 0, 0, 0]);
    const lexical = insert(db, 'Weekend rota', 'weekend rota for the support desk', [0, 0, 0, 1]);
    db.close();
    const probe = join(home, 'vector-probe.log');

    const out = runHook(pkg, home, 'what is the weekend rota this week?', { SC_717_PROBE: probe });
    const log = lastRecallLog(home);
    expect(readFileSync(probe, 'utf8')).toContain('embed-called'); // the plane did run
    expect(log.vectorPlane).toMatch(/^active:/);
    expect(log.candidates.map((c: { id: number }) => c.id)).not.toContain(id);
    expect(log.candidates.map((c: { id: number }) => c.id)).toContain(lexical);
    expect(JSON.parse(out).hookSpecificOutput.additionalContext).not.toContain('Kayak hire booked');
  });

  it('a row matched by both planes is logged as source "both"', () => {
    const pkg = buildPackage(true);
    const { home, db } = makeHome({ vector: true });
    const id = insert(db, 'Weekend lake plans', 'weekend lake plans with the kayak club', [1, 0, 0, 0]);
    db.close();

    runHook(pkg, home, 'remind me about the weekend lake plans');
    const cand = lastRecallLog(home).candidates.find((c: { id: number }) => c.id === id);
    expect(cand.source).toBe('both');
    expect(typeof cand.ftsRank).toBe('number');
  });

  it('fails soft with no embedder: FTS-only, vectorPlane records why', () => {
    const pkg = buildPackage(false);
    const { home, db } = makeHome({ vector: true });
    insert(db, 'Kayak hire booked', 'Paddling outing reserved for Saturday morning', [1, 0, 0, 0]);
    const ftsId = insert(db, 'Deploy checklist', 'deploy checklist for the production gateway service', null);
    db.close();

    const out = runHook(pkg, home, 'show the deploy checklist for production gateway');
    const log = lastRecallLog(home);
    expect(log.vectorPlane).toBe('unavailable:no-dist-build');
    expect(log.candidates.map((c: { id: number }) => c.id)).toContain(ftsId);
    expect(log.candidates.every((c: { source: string; vectorSimilarity: number | null }) =>
      c.source === 'fts' && c.vectorSimilarity === null)).toBe(true);
    expect(JSON.parse(out).hookSpecificOutput.additionalContext).toContain('Deploy checklist');
  });

  it('SHIELDCORTEX_SKIP_EMBEDDINGS=1 disables the plane even with an embedder present', () => {
    const pkg = buildPackage(true);
    const { home, db } = makeHome({ vector: true });
    insert(db, 'Weekend lake plans', 'weekend lake plans with the kayak club', [1, 0, 0, 0]);
    db.close();

    runHook(pkg, home, 'remind me about the weekend lake plans', { SHIELDCORTEX_SKIP_EMBEDDINGS: '1' });
    const log = lastRecallLog(home);
    expect(log.vectorPlane).toBe('unavailable:skip-embeddings');
    expect(log.candidates.every((c: { source: string }) => c.source === 'fts')).toBe(true);
  });
});
