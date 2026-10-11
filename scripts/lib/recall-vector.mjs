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
import { recallAdmissionClause, recallRowColumns, selectFtsCandidates } from './recall-admission.mjs';

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

/**
 * Is the vector plane switched on? Off unless `config.recallVector === true`
 * or SHIELDCORTEX_RECALL_VECTOR is truthy; a falsy env value
 * ("0"/"false"/"no"/"off") turns it off whatever the config says.
 *
 * @param {object} [config]
 * @param {Record<string, string | undefined>} [env]
 */
export function isRecallVectorEnabled(config = {}, env = process.env) {
  const raw = (env?.SHIELDCORTEX_RECALL_VECTOR ?? '').trim().toLowerCase();
  if (raw === '1' || raw === 'true' || raw === 'yes' || raw === 'on') return true;
  if (raw === '0' || raw === 'false' || raw === 'no' || raw === 'off') return false;
  return config?.recallVector === true;
}

function distRootFor(override) {
  if (override) return override;
  const here = dirname(fileURLToPath(import.meta.url));
  return resolve(here, '..', '..', 'dist');
}

/**
 * Resolve the query embedder, or say why there is none.
 *
 * @param {{ distRoot?: string, config?: object, env?: Record<string, string | undefined> }} [opts]
 * @returns {Promise<{ embed: ((text: string) => Promise<Float32Array>) | null, reason: string }>}
 */
export async function loadQueryEmbedder(opts = {}) {
  const env = opts.env ?? process.env;
  // Checked before anything is imported: default config never loads dist.
  if (!isRecallVectorEnabled(opts.config, env)) {
    return { embed: null, reason: opts.config?.recallVector === false ? 'disabled:config' : 'disabled:default-off' };
  }
  if (env.SHIELDCORTEX_SKIP_EMBEDDINGS === '1') {
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
 * Bounded in-process cosine scan over the project's embedded rows.
 *
 * Admission (#720 blocker 1): the SAME clause and the SAME FTS MATCH
 * expression as the FTS plane, so a row FTS would exclude — another project's
 * private row, a suppressed or faded row, or a same-project row sharing no
 * term with the prompt — is never a vector candidate. No `ftsQuery`, no
 * candidates.
 *
 * Snapshot (#720 blocker 3): one statement returns each row's content WITH
 * the embedding its similarity is computed from. There is no second
 * "hydrate by id" read for a concurrent writer to slip between, so new
 * content can never carry an old similarity.
 *
 * @param {import('better-sqlite3').Database} db
 * @param {string} project
 * @param {Float32Array} queryVector
 * @param {{ limit: number, minSalience: number, ftsQuery?: string, minSimilarity?: number, scanCap?: number }} opts
 * @returns {Array<object>} rows best-first, each with `_similarity`
 */
export function vectorCandidates(db, project, queryVector, opts) {
  if (!opts.ftsQuery || !opts.ftsQuery.trim()) return [];
  const minSimilarity = opts.minSimilarity ?? pickNumber('SHIELDCORTEX_RECALL_VECTOR_MIN_SIM', DEFAULT_MIN_SIMILARITY);
  const scanCap = opts.scanCap ?? DEFAULT_SCAN_CAP;
  const scanned = db.prepare(`
    SELECT ${recallRowColumns()}, embedding
    FROM memories
    WHERE embedding IS NOT NULL
      AND ${recallAdmissionClause()}
      AND id IN (SELECT rowid FROM memories_fts WHERE memories_fts MATCH ?)
    ORDER BY id DESC
    LIMIT ?
  `).all(project, opts.minSalience, opts.ftsQuery, scanCap);

  const scored = [];
  for (const { embedding, ...row } of scanned) {
    if (!embedding || embedding.length < 4) continue;
    const similarity = cosine(queryVector, decodeBlob(embedding));
    if (similarity >= minSimilarity) {
      row._similarity = similarity;
      scored.push(row);
    }
  }
  scored.sort((a, b) => b._similarity - a._similarity);
  return scored.slice(0, opts.limit);
}

/**
 * Read the FTS and vector candidate lists inside ONE read transaction, so a
 * row that is a hit on both planes is read at the same version by both (#720
 * blocker 3). Each plane fails independently, as before: an FTS error leaves
 * an empty FTS list, a vector error is reported in `vectorError`.
 *
 * @param {import('better-sqlite3').Database} db
 * @param {{ project: string, ftsQuery: string, queryVector: Float32Array | null,
 *           limit: number, minSalience: number, minSimilarity?: number }} opts
 * @returns {{ ftsRows: object[], vectorRows: object[], vectorError: string | null }}
 */
export function readRecallSnapshot(db, opts) {
  const { project, ftsQuery, queryVector, limit, minSalience, minSimilarity } = opts;
  return db.transaction(() => {
    let ftsRows = [];
    try {
      ftsRows = selectFtsCandidates(db, { project, ftsQuery, limit, minSalience });
    } catch {
      // FTS query failed — the caller continues with its fallbacks.
    }
    let vectorRows = [];
    let vectorError = null;
    if (queryVector) {
      try {
        vectorRows = vectorCandidates(db, project, queryVector, { limit, minSalience, minSimilarity, ftsQuery });
      } catch (e) {
        vectorError = e?.message ?? 'unknown';
      }
    }
    return { ftsRows, vectorRows, vectorError };
  })();
}

/**
 * Weighted RRF over the FTS list (already in BM25 order) and the vector list
 * (similarity order). Each returned row carries `_source` ('fts' | 'vector' |
 * 'both') and `_rrf`. A row in both lists keeps its FTS `rank` (so the BM25
 * relevance floor still sees it) and gains `_similarity` — but only when both
 * planes read the same title and content. A mismatch means the two lists saw
 * different versions of the row; the similarity belongs to the other version,
 * so the row stays a plain FTS hit (#720 blocker 3).
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
      if (hit.row.content !== row.content || hit.row.title !== row.title) return;
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
