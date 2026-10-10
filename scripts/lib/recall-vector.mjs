/**
 * Vector plane for the prompt-recall hook (#717).
 *
 * The hook used to be FTS-only: on a host with ~950 embedded memories, none of
 * those vectors ever influenced what was injected, so a prompt that shared no
 * literal terms with the right memory recalled nothing (or boilerplate). This
 * module adds a cosine-similarity candidate list over the project's persisted
 * `memories.embedding` blobs and fuses it with the FTS list via weighted RRF —
 * the same fusion and weights the MCP-side ranker uses
 * (src/memory/ranker: fts 0.4, vector 0.6, k 60).
 *
 * FAIL SOFT, always. A missing dist build, an incomplete model cache,
 * SHIELDCORTEX_SKIP_EMBEDDINGS=1, a slow worker or any throw leaves the hook
 * on its exact pre-#717 FTS path; the reason is recorded as
 * `vectorPlane: 'unavailable:<reason>'` in the recall log.
 *
 * The query embedder is the one the writer side (save-memory.mjs) persists
 * row vectors with — `dist/embeddings/index.js` resolved by package layout —
 * behind the same cache-health gate, so a hook can never trigger a model
 * download. Pure helpers (`vectorCandidates`, `fuseRecallCandidates`) take a
 * query vector directly so they test without ONNX.
 */

import { dirname, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

// Weights/k mirror src/memory/ranker/index.ts DEFAULT_WEIGHTS / DEFAULT_RRF_K.
// Duplicated rather than imported: the hook must not need dist/ to rank FTS.
export const RRF_K = 60;
export const RRF_WEIGHTS = Object.freeze({ fts: 0.4, vector: 0.6 });

function pickNumber(envName, fallback) {
  const raw = process.env[envName];
  if (raw === undefined || raw === '') return fallback;
  const n = Number(raw);
  return Number.isFinite(n) ? n : fallback;
}

// Minimum cosine similarity for a row to enter the vector list. Higher than
// vectorSearch's 0.3: here a vector-only hit can be injected into the prompt
// unprompted, so a weak semantic neighbour is worse than no candidate.
export const DEFAULT_MIN_SIMILARITY = 0.35;
// Upper bound on rows scanned per prompt. ~950 rows x 384 floats is ~1ms; the
// cap only exists so a pathological store cannot stall the user's turn.
export const DEFAULT_SCAN_CAP = 20_000;
// Cold first embed measured at ~0.5s on clawdbot1 (worker spawn + ONNX load),
// ~7ms warm. Past this the turn proceeds on FTS alone.
const DEFAULT_EMBED_TIMEOUT_MS = 2_000;

function distRootFor(override) {
  if (override) return override;
  const here = dirname(fileURLToPath(import.meta.url));
  return resolve(here, '..', '..', 'dist');
}

/**
 * Resolve the query embedder, or say why there is none.
 *
 * @param {{ distRoot?: string, config?: object }} [opts]
 * @returns {Promise<{ embed: ((text: string) => Promise<Float32Array>) | null, reason: string }>}
 */
export async function loadQueryEmbedder(opts = {}) {
  if (opts.config && opts.config.recallVector === false) {
    return { embed: null, reason: 'disabled:config' };
  }
  if (process.env.SHIELDCORTEX_SKIP_EMBEDDINGS === '1') {
    return { embed: null, reason: 'unavailable:skip-embeddings' };
  }
  const distRoot = distRootFor(opts.distRoot);
  // Same gate as save-memory.mjs embedStoredRow: never let a hook reach a
  // model download, and never enter the worker on a truncated weight.
  try {
    const cacheMod = await import(pathToFileURL(resolve(distRoot, 'embeddings', 'model-cache.js')).href);
    if (typeof cacheMod.inspectEmbeddingHookReady !== 'function') {
      return { embed: null, reason: 'unavailable:no-cache-inspector' };
    }
    const ready = await cacheMod.inspectEmbeddingHookReady();
    if (!ready || ready.ready !== true) {
      return { embed: null, reason: `unavailable:model-cache-${ready?.reason ?? 'not-ready'}` };
    }
  } catch {
    return { embed: null, reason: 'unavailable:no-dist-build' };
  }
  try {
    const mod = await import(pathToFileURL(resolve(distRoot, 'embeddings', 'index.js')).href);
    if (typeof mod.generateEmbedding !== 'function') {
      return { embed: null, reason: 'unavailable:no-embedder' };
    }
    return { embed: mod.generateEmbedding, reason: 'ok' };
  } catch {
    return { embed: null, reason: 'unavailable:no-dist-build' };
  }
}

/**
 * Embed the query under a deadline. Never throws.
 *
 * @returns {Promise<{ vector: Float32Array | null, reason: string }>}
 */
export async function embedQuery(embed, text, timeoutMs = pickNumber('SHIELDCORTEX_RECALL_EMBED_TIMEOUT_MS', DEFAULT_EMBED_TIMEOUT_MS)) {
  let timer;
  try {
    const vector = await Promise.race([
      Promise.resolve().then(() => embed(text)),
      new Promise((_, reject) => {
        timer = setTimeout(() => reject(new Error('timeout')), Math.max(1, timeoutMs));
      }),
    ]);
    if (!vector || typeof vector.length !== 'number' || vector.length === 0) {
      return { vector: null, reason: 'unavailable:empty-vector' };
    }
    return { vector, reason: 'ok' };
  } catch (err) {
    return { vector: null, reason: err?.message === 'timeout' ? 'unavailable:timeout' : 'unavailable:embed-failed' };
  } finally {
    if (timer) clearTimeout(timer);
  }
}

function decodeBlob(buf) {
  // Copy into an aligned buffer: a Buffer slice's byteOffset need not be a
  // multiple of 4, which Float32Array over the shared buffer would reject.
  const copy = new Uint8Array(buf.length);
  copy.set(buf);
  return new Float32Array(copy.buffer, 0, Math.floor(buf.length / 4));
}

function cosine(a, b) {
  if (a.length !== b.length || a.length === 0) return 0;
  let dot = 0;
  let na = 0;
  let nb = 0;
  for (let i = 0; i < a.length; i++) {
    dot += a[i] * b[i];
    na += a[i] * a[i];
    nb += b[i] * b[i];
  }
  if (na === 0 || nb === 0) return 0;
  return dot / (Math.sqrt(na) * Math.sqrt(nb));
}

/**
 * Bounded in-process cosine scan over the project's embedded rows. Applies
 * the same scope/status/salience filters as the hook's FTS SELECT, and
 * projects the same columns, so a vector-only row is indistinguishable
 * downstream (ranking, relevance gate, defence, log) from an FTS row.
 *
 * @param {import('better-sqlite3').Database} db
 * @param {string} project
 * @param {Float32Array} queryVector
 * @param {{ limit: number, minSalience: number, minSimilarity?: number, scanCap?: number }} opts
 * @returns {Array<object>} rows best-first, each with `_similarity`
 */
export function vectorCandidates(db, project, queryVector, opts) {
  const minSimilarity = opts.minSimilarity ?? pickNumber('SHIELDCORTEX_RECALL_VECTOR_MIN_SIM', DEFAULT_MIN_SIMILARITY);
  const scanCap = opts.scanCap ?? DEFAULT_SCAN_CAP;
  const scanned = db.prepare(`
    SELECT id, embedding FROM memories
    WHERE embedding IS NOT NULL
      AND (project = ? OR scope = 'global')
      AND COALESCE(status, 'active') = 'active'
      AND salience >= ?
    ORDER BY id DESC
    LIMIT ?
  `).all(project, opts.minSalience, scanCap);

  const scored = [];
  for (const row of scanned) {
    if (!row.embedding || row.embedding.length < 4) continue;
    const similarity = cosine(queryVector, decodeBlob(row.embedding));
    if (similarity >= minSimilarity) scored.push({ id: row.id, similarity });
  }
  scored.sort((a, b) => b.similarity - a.similarity);
  const top = scored.slice(0, opts.limit);
  if (top.length === 0) return [];

  const placeholders = top.map(() => '?').join(',');
  const hydrated = db.prepare(`
    SELECT
      id, title, content, category, salience,
      pinned, access_count, last_accessed,
      trust_score, sensitivity_level, metadata, reviewed_at,
      COALESCE(downvote_count, 0) AS downvote_count
    FROM memories WHERE id IN (${placeholders})
  `).all(...top.map((t) => t.id));
  const byId = new Map(hydrated.map((r) => [r.id, r]));
  const out = [];
  for (const t of top) {
    const row = byId.get(t.id);
    if (!row) continue;
    row._similarity = t.similarity;
    out.push(row);
  }
  return out;
}

/**
 * Weighted RRF over the FTS list (already in BM25 order) and the vector list
 * (similarity order). Each returned row carries `_source` ('fts' | 'vector' |
 * 'both') and `_rrf`. A row in both lists keeps its FTS `rank` (so the BM25
 * relevance floor still sees it) and gains `_similarity`.
 *
 * @param {Array<object>} ftsRows
 * @param {Array<object>} vectorRows
 * @param {(a: object, b: object) => number} tiebreak  e.g. compareRecallResults
 */
export function fuseRecallCandidates(ftsRows, vectorRows, tiebreak) {
  const byId = new Map();
  ftsRows.forEach((row, idx) => {
    if (byId.has(row.id)) return;
    byId.set(row.id, { row, rrf: RRF_WEIGHTS.fts / (RRF_K + idx + 1), fts: true, vector: false });
  });
  vectorRows.forEach((row, idx) => {
    const add = RRF_WEIGHTS.vector / (RRF_K + idx + 1);
    const hit = byId.get(row.id);
    if (hit) {
      if (hit.vector) return;
      hit.rrf += add;
      hit.vector = true;
      hit.row._similarity = row._similarity;
    } else {
      byId.set(row.id, { row, rrf: add, fts: false, vector: true });
    }
  });
  const fused = [...byId.values()].map((h) => {
    h.row._source = h.fts && h.vector ? 'both' : h.fts ? 'fts' : 'vector';
    h.row._rrf = h.rrf;
    return h.row;
  });
  fused.sort((a, b) => (b._rrf - a._rrf) || (tiebreak ? tiebreak(a, b) : 0));
  return fused;
}
