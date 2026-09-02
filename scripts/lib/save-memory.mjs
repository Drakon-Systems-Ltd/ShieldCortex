import { randomUUID } from 'crypto';
import { dirname, resolve } from 'path';
import { fileURLToPath, pathToFileURL } from 'url';
import { isNearDuplicate } from './dedup.mjs';
import { readFileSync, existsSync } from 'fs';
import { join } from 'path';
import { homedir } from 'os';
import { readInjectConfig } from './inject-pack.mjs';

// Env-tunable dedup thresholds (pickNumber/env pattern — mirrors
// scripts/prompt-recall-hook.mjs). A typo'd or empty env var falls back to the
// documented default rather than silently zeroing the gate.
function pickNumber(envName, fallback) {
  const fromEnv = Number(process.env[envName]);
  if (Number.isFinite(fromEnv) && process.env[envName] !== undefined && process.env[envName] !== '') {
    return fromEnv;
  }
  return fallback;
}

// Title-Jaccard PRE-GATE: only pairs whose titles already overlap this much get
// a content comparison (bounds cost + avoids merging unrelated notes).
const DEDUP_TITLE_JACCARD = pickNumber('SHIELDCORTEX_DEDUP_TITLE_JACCARD', 0.6);
// Combined (content*0.6 + title*0.4) score at/above which the incoming write is
// dropped as a near-duplicate.
//
// DELIBERATE: this write-skip threshold (0.5) is STRICTER than
// consolidate.ts's merge threshold (0.25). Skipping silently DISCARDS the new
// write, so a false positive here is data loss — we demand high confidence. A
// consolidate false-merge only concatenates two existing rows (recoverable),
// so it can afford to be more aggressive. Do not lower this to match consolidate.
const DEDUP_COMBINED = pickNumber('SHIELDCORTEX_DEDUP_COMBINED', 0.5);
const DEDUP_CANDIDATE_LIMIT = 200; // bound the candidate scan per write

// Hook identities shipped IN THIS PACKAGE — string literals at the three hook
// call sites (session-end/pre-compact/stop) plus the JSDoc'd default. These are
// attested by construction: no transcript content or hook stdin can reach the
// field. The clamp exists because this module is importable by any same-user
// process — a free opts.source must NOT mint attested rows under an arbitrary
// name. Out-of-allowlist sources still scan and store, but land UNDEFINED →
// source_attested NULL (never `false`→0: an explicit 0 under a real key is the
// mute lever risk.ts's latest-non-null attestation resolution hands out).
const KNOWN_HOOK_SOURCES = new Set(['session-end-hook', 'pre-compact-hook', 'stop-hook', 'hook']);

function loadScConfig() {
  try {
    const p = join(homedir(), '.shieldcortex', 'config.json');
    if (!existsSync(p)) return {};
    return JSON.parse(readFileSync(p, 'utf-8'));
  } catch { return {}; }
}

function resolveScopeIds() {
  const cfg = readInjectConfig(loadScConfig());
  const hostId = cfg.hostId || process.env.SHIELDCORTEX_HOST_ID || process.env.HOSTNAME || 'local';
  const agentId = cfg.agentId || process.env.SHIELDCORTEX_AGENT_ID || 'default';
  return { hostId: String(hostId).slice(0, 128), agentId: String(agentId).slice(0, 128) };
}


/**
 * Insert an auto-extracted memory into the SC database, routed through the
 * full defence pipeline.
 *
 * Single source of truth for hook-side memory writes (session-end,
 * pre-compact, and stop hooks all converge here). Every byte that lands in
 * `memories` must have passed `runDefencePipeline()` first — that guarantees:
 *   - a defence_audit row exists for every capture (good or bad)
 *   - injection-shaped content lands in `quarantine`, not in `memories`
 *   - a hard BLOCK is dropped with an audit trail (no silent loss)
 *
 * If the pipeline cannot be loaded (no dist build, e.g. dev workspace before
 * `npm run build`) the call is fail-closed: nothing is written to memories
 * and a stderr warning is printed. A fallback defence_audit row is logged.
 *
 * Async: the pipeline lives in dist/ as ESM and is loaded via dynamic import.
 *
 * @param {import('better-sqlite3').Database} db
 * @param {{ title: string, content: string, category: string, salience: number, tags: string[], memoryPurpose?: string }} memory
 * @param {string|null} [project]
 * @param {{ source?: string }} [opts] — `source` identifies the calling hook
 *   ('session-end-hook' | 'pre-compact-hook' | 'stop-hook' | 'hook').
 */
export async function saveAutoExtractedMemory(db, memory, project, opts = {}) {
  const sourceIdentifier = opts.source ?? 'hook';
  const source = { type: 'hook', identifier: sourceIdentifier };

  const defence = await loadDefenceModules(db);

  if (!defence) {
    writeFallbackAudit(db, memory, project, sourceIdentifier, 'defence_pipeline_unavailable: dist build missing');
    process.stderr.write(`[shieldcortex save-memory] dropped (defence pipeline unavailable): ${memory.title}\n`);
    return;
  }

  let result;
  try {
    result = defence.runDefencePipeline(memory.content, memory.title, source, undefined, project ?? undefined, {
      sourceAttested: KNOWN_HOOK_SOURCES.has(sourceIdentifier) ? true : undefined,
    });
  } catch (err) {
    const msg = err && typeof err === 'object' && 'message' in err ? String(err.message) : String(err);
    writeFallbackAudit(db, memory, project, sourceIdentifier, `pipeline_error: ${msg}`);
    process.stderr.write(`[shieldcortex save-memory] dropped (pipeline error): ${memory.title} — ${msg}\n`);
    return;
  }

  // P1/WS4: route through the ONE shared verdict→disposition mapping so this
  // hook path can't drift from store.ts:addMemory. This is what gives the hook
  // the sub-agent trust-band hold (0.5–0.7) it previously lacked, and makes a
  // BLOCK be HELD in quarantine (forensically preserved, auto-rejected at
  // review) rather than silently dropped.
  const disposition = defence.resolveDisposition({
    allowed: result.allowed,
    firewallResult: result.firewall.result,
    trustScore: result.trust?.score ?? 0,
    reason: result.firewall.reason,
  });

  if (disposition.action === 'store') {
    // Persist the COMPUTED trust + sensitivity from the scan — not the schema
    // DEFAULT (trust 1.0 / INTERNAL). The INSERT used to omit these columns, so
    // every hook-captured memory was over-trusted at 1.0, undercutting the
    // recall shim's trust filter.
    // #402: stamp content_form via the SAME compiled classifier store.ts uses
    // (loaded from dist alongside the pipeline) so hook-captured facts are
    // injectable while hook-captured directives land inert (fail-closed to
    // NULL if the classifier isn't available → not injectable unless pinned).
    const contentForm = typeof defence.classifyContentForm === 'function'
      ? defence.classifyContentForm(memory.content)
      : null;
    const memoryId = insertMemoryRow(db, memory, project, sourceIdentifier, result.trust?.score, result.sensitivity?.level, contentForm);
    // #458: embed HERE, awaited, not scheduled. See embedStoredRow().
    if (memoryId !== null) {
      await embedStoredRow(db, memoryId, `${memory.title} ${memory.content}`);
    }
    return;
  }

  // action === 'quarantine' — reflect the resolved verdict onto the result the
  // quarantine INSERT records, then hold. Route through the singleton's
  // connection so the audit_id FK resolves against the connection pipeline.ts
  // wrote the audit row on.
  result.firewall.result = disposition.firewallResult;
  result.firewall.reason = disposition.reason;
  const quarantineDb = (typeof _getDatabase === 'function' && defence.isDatabaseInitialized && defence.isDatabaseInitialized())
    ? _getDatabase()
    : db;
  insertQuarantineRow(quarantineDb, memory, project, source, result);
  process.stderr.write(`[shieldcortex save-memory] ${disposition.firewallResult.toLowerCase()} (held): ${memory.title} — ${disposition.reason}\n`);
}

// ==================== Internal: writes ====================

/**
 * @returns {number|null} the new `memories.id`, or null when the write was
 *   skipped as a duplicate. The caller needs the id to attach an embedding
 *   (#458), and a skip must not be mistaken for a stored row.
 */
function insertMemoryRow(db, memory, project, sourceIdentifier, trustScore, sensitivityLevel, contentForm) {
  const timestamp = new Date().toISOString();

  // Cross-call, CROSS-PATH exact-title dedup: the hook fires repeatedly (per
  // turn, or per salience bypass) over overlapping transcript windows, so the
  // same regex match tends to surface multiple times across calls. The
  // within-batch dedup in processSegments doesn't cover that. We match on
  // (title, project) WITHOUT a source_kind filter — incoming writes here are
  // always hook, so dropping the filter just means a hook re-extraction of
  // something the user ALREADY saved manually is caught too (the old
  // source_kind='hook' filter let those through).
  const existing = db.prepare(
    `SELECT 1 FROM memories
       WHERE title = ?
         AND (project IS ? OR (project IS NULL AND ? IS NULL))
       LIMIT 1`,
  ).get(memory.title, project || null, project || null);
  if (existing) {
    process.stderr.write(`[shieldcortex save-memory] skipped duplicate: ${memory.title}\n`);
    return null;
  }

  // Near-duplicate dedup: exact-title only catches verbatim re-saves. Reworded
  // captures of the same fact ("Fix: X" vs "X fix") have different titles but
  // near-identical content. Scan same-project, same-category, ACTIVE rows
  // (most-recent first, bounded) and skip the write if any is a near-dup. This
  // is also cross-path — a prior manual row can block a hook re-extraction.
  const candidates = db.prepare(
    `SELECT title, content FROM memories
       WHERE (project IS ? OR (project IS NULL AND ? IS NULL))
         AND category IS ?
         AND COALESCE(status, 'active') = 'active'
       ORDER BY created_at DESC
       LIMIT ?`,
  ).all(project || null, project || null, memory.category ?? null, DEDUP_CANDIDATE_LIMIT);

  for (const candidate of candidates) {
    const { duplicate, combined } = isNearDuplicate(
      { title: memory.title, content: memory.content },
      { title: candidate.title, content: candidate.content },
      { titleJaccard: DEDUP_TITLE_JACCARD, combinedThreshold: DEDUP_COMBINED },
    );
    if (duplicate) {
      process.stderr.write(
        `[shieldcortex save-memory] skipped near-duplicate (combined=${combined.toFixed(2)}): ${memory.title}\n`,
      );
      return null;
    }
  }

  const scope = resolveScopeIds();
  const captureLayer = memory.capture_layer || memory.captureLayer || 'L0';
  // host_id/agent_id may be missing on pre-migration DBs — try/catch insert with fallback.
  try {
    const info = db.prepare(`
      INSERT INTO memories (
        uuid, title, content, type, category, salience, tags, project,
        memory_purpose, source, source_kind, capture_method,
        trust_score, sensitivity_level,
        host_id, agent_id, capture_layer, content_form,
        created_at, last_accessed
      )
      VALUES (?, ?, ?, 'short_term', ?, ?, ?, ?, ?, ?, 'hook', 'auto', ?, ?, ?, ?, ?, ?, ?, ?)
    `).run(
      randomUUID(),
      memory.title,
      memory.content,
      memory.category,
      memory.salience,
      JSON.stringify(memory.tags),
      project || null,
      memory.memoryPurpose ?? 'project',
      `hook:${sourceIdentifier}`,
      typeof trustScore === 'number' ? trustScore : 1.0,
      sensitivityLevel ?? 'INTERNAL',
      scope.hostId,
      scope.agentId,
      captureLayer,
      contentForm ?? null,
      timestamp,
      timestamp,
    );
    return Number(info.lastInsertRowid);
  } catch (err) {
    const msg = err && err.message ? err.message : String(err);
    if (!/no such column/i.test(msg)) throw err;
    const info = db.prepare(`
      INSERT INTO memories (
        uuid, title, content, type, category, salience, tags, project,
        memory_purpose, source, source_kind, capture_method,
        trust_score, sensitivity_level,
        created_at, last_accessed
      )
      VALUES (?, ?, ?, 'short_term', ?, ?, ?, ?, ?, ?, 'hook', 'auto', ?, ?, ?, ?)
    `).run(
      randomUUID(),
      memory.title,
      memory.content,
      memory.category,
      memory.salience,
      JSON.stringify(memory.tags),
      project || null,
      memory.memoryPurpose ?? 'project',
      `hook:${sourceIdentifier}`,
      typeof trustScore === 'number' ? trustScore : 1.0,
      sensitivityLevel ?? 'INTERNAL',
      timestamp,
      timestamp,
    );
    return Number(info.lastInsertRowid);
  }
}

function insertQuarantineRow(db, memory, project, source, result) {
  // Mirrors the canonical SQL used by src/memory/store.ts:quarantineMemory
  // so QUARANTINE decisions from any path produce schema-identical rows.
  const firewallResult = result.firewall.result === 'ALLOW' ? 'BLOCK' : result.firewall.result;
  db.prepare(`
    INSERT INTO quarantine (
      original_title, original_content, project,
      source_type, source_identifier, reason,
      threat_indicators, anomaly_score, firewall_result, audit_id, status
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 'pending')
  `).run(
    memory.title,
    memory.content,
    project || null,
    source.type,
    source.identifier,
    result.firewall.reason,
    JSON.stringify(result.firewall.threatIndicators),
    result.firewall.anomalyScore,
    firewallResult,
    result.auditId ?? null,
  );
}

function writeFallbackAudit(db, memory, project, sourceIdentifier, reason) {
  // Synthetic audit row for cases where the pipeline could not run.
  //
  // source_attested is DELIBERATELY absent (schema default NULL): both call
  // sites are self-inflicted states (dist build missing / pipeline threw), and
  // an attested BLOCK here would accrue full-weight risk against the hook's
  // own identity for a packaging problem, not an attack. Leave NULL — do not
  // "fix" this into an accruing row.
  try {
    db.prepare(`
      INSERT INTO defence_audit (
        memory_id, project, timestamp,
        source_type, source_identifier,
        trust_score, sensitivity_level, firewall_result,
        anomaly_score, threat_indicators, blocked_patterns,
        reason, fragmentation_score, pipeline_duration_ms
      ) VALUES (?, ?, ?, ?, ?, ?, ?, 'BLOCK', ?, ?, ?, ?, ?, ?)
    `).run(
      null,
      project || null,
      new Date().toISOString(),
      'hook',
      sourceIdentifier,
      0,
      'INTERNAL',
      0,
      '[]',
      '[]',
      reason,
      null,
      0,
    );
  } catch {
    // Schema may be older than the audit columns. Better silent here than
    // raising into the hook — the stderr line above carries the signal.
  }
}

// ==================== Internal: embeddings (#458) ====================

// A hook is a short-lived process. `addMemory()` can afford to schedule an
// embedding and let the long-lived gateway finish it; a hook that did the same
// would exit at `process.exit(0)` with the promise still pending and leave the
// column NULL for ever — which is exactly the state #458 measured (267 auto
// rows, 0 embedded, all-time). So this path AWAITS the embed inline.
//
// Cost, measured on clawdbot1 with the model already on disk: 508ms for the
// first embed in a process (worker spawn + 90MB ONNX load) and 7ms warm. That
// is affordable once per hook invocation; an unbounded wait is not, because a
// wedged model load would stall the turn the hook is ending. Hence the timeout.
//
// Best-effort by construction: any failure leaves the row stored with a NULL
// embedding and is reported on stderr. `shieldcortex memories embed-backfill`
// is the guaranteed-coverage path, and the doctor MEMEMB check is what makes a
// host with a growing NULL population visible instead of silently keyword-only.
const EMBED_TIMEOUT_MS = pickNumber('SHIELDCORTEX_HOOK_EMBED_TIMEOUT_MS', 10_000);

let _embedCache = null;
let _embedCacheKey = null;
let _warnedEmbedUnavailable = false;

async function loadEmbedder() {
  const here = dirname(fileURLToPath(import.meta.url));
  const distRoot = resolve(here, '..', '..', 'dist');
  if (_embedCache !== null && _embedCacheKey === distRoot) return _embedCache;

  try {
    const mod = await import(pathToFileURL(resolve(distRoot, 'embeddings', 'index.js')).href);
    _embedCache = typeof mod.generateEmbedding === 'function' ? mod.generateEmbedding : null;
  } catch {
    // No dist build (dev workspace before `npm run build`) — same fail-soft
    // posture the defence loader takes, except a missing embedder degrades
    // recall rather than admitting unscanned content, so it is not fail-CLOSED.
    _embedCache = null;
  }
  _embedCacheKey = distRoot;
  return _embedCache;
}

/**
 * Generate and persist the embedding for a just-stored row.
 *
 * Never throws: the memory is already committed, and losing the row because the
 * ONNX worker is unavailable would be a strictly worse outcome than losing the
 * vector.
 *
 * @param {import('better-sqlite3').Database} db
 * @param {number} memoryId
 * @param {string} text
 */
async function embedStoredRow(db, memoryId, text) {
  if (process.env.SHIELDCORTEX_SKIP_EMBEDDINGS === '1') return;

  const generateEmbedding = await loadEmbedder();
  if (!generateEmbedding) {
    if (!_warnedEmbedUnavailable) {
      _warnedEmbedUnavailable = true;
      process.stderr.write('[shieldcortex save-memory] embeddings unavailable (no dist build) — row stored without a vector; run `shieldcortex memories embed-backfill` after building\n');
    }
    return;
  }

  let timer;
  try {
    const embedding = await Promise.race([
      generateEmbedding(text),
      new Promise((_, reject) => {
        timer = setTimeout(() => reject(new Error(`embedding timed out after ${EMBED_TIMEOUT_MS}ms`)), EMBED_TIMEOUT_MS);
      }),
    ]);
    if (!embedding || !embedding.buffer) {
      process.stderr.write(`[shieldcortex save-memory] embedding returned no vector for memory ${memoryId}\n`);
      return;
    }
    db.prepare('UPDATE memories SET embedding = ? WHERE id = ?').run(Buffer.from(embedding.buffer), memoryId);
  } catch (err) {
    const msg = err && err.message ? err.message : String(err);
    // Absent worker / explicitly disabled embeddings are configuration, not
    // failure — say it once and stay quiet, exactly as store.ts does.
    if (/Embedding worker unavailable|Embeddings disabled via/i.test(msg)) {
      if (!_warnedEmbedUnavailable) {
        _warnedEmbedUnavailable = true;
        process.stderr.write(`[shieldcortex save-memory] embeddings unavailable — rows stored without vectors (${msg})\n`);
      }
      return;
    }
    process.stderr.write(`[shieldcortex save-memory] embedding failed for memory ${memoryId}: ${msg}\n`);
  } finally {
    if (timer) clearTimeout(timer);
  }
}

// ==================== Internal: lazy dist loader ====================

let _defenceCache = null;
let _defenceCacheKey = null;
let _getDatabase = null;

async function loadDefenceModules(db) {
  // Resolve the dist build relative to this file's location. save-memory.mjs
  // lives at scripts/lib/, so dist is two directories up.
  const here = dirname(fileURLToPath(import.meta.url));
  const distRoot = resolve(here, '..', '..', 'dist');

  if (_defenceCache && _defenceCacheKey === distRoot) {
    ensureDatabaseSingleton(db, _defenceCache);
    return _defenceCache;
  }

  try {
    const pipelineUrl = pathToFileURL(resolve(distRoot, 'defence', 'pipeline.js')).href;
    const initUrl = pathToFileURL(resolve(distRoot, 'database', 'init.js')).href;
    const dispositionUrl = pathToFileURL(resolve(distRoot, 'defence', 'disposition.js')).href;
    const formUrl = pathToFileURL(resolve(distRoot, 'defence', 'form-classifier.js')).href;

    const [pipelineMod, initMod, dispositionMod, formMod] = await Promise.all([
      import(pipelineUrl),
      import(initUrl),
      import(dispositionUrl),
      // #402 classifier; tolerate its absence on an older dist (falls back to
      // NULL content_form → fail-closed non-injectable, never a hard failure).
      import(formUrl).catch(() => ({})),
    ]);

    if (typeof pipelineMod.runDefencePipeline !== 'function') return null;
    if (typeof initMod.initDatabase !== 'function') return null;
    if (typeof dispositionMod.resolveDisposition !== 'function') return null;

    _defenceCache = {
      runDefencePipeline: pipelineMod.runDefencePipeline,
      resolveDisposition: dispositionMod.resolveDisposition,
      classifyContentForm: typeof formMod.classifyContentForm === 'function' ? formMod.classifyContentForm : null,
      initDatabase: initMod.initDatabase,
      isDatabaseInitialized: initMod.isDatabaseInitialized,
      getDatabase: initMod.getDatabase,
      closeDatabase: initMod.closeDatabase,
    };
    _defenceCacheKey = distRoot;
    _getDatabase = initMod.getDatabase;

    ensureDatabaseSingleton(db, _defenceCache);
    return _defenceCache;
  } catch {
    return null;
  }
}

function ensureDatabaseSingleton(db, defence) {
  // The pipeline's audit + custom-rules layers use getDatabase() (singleton).
  // Initialise it against the same path the hook is writing to so audit
  // rows are visible across connections (and to the dashboard).
  const targetPath = db && db.name ? db.name : null;
  if (!targetPath || targetPath === ':memory:') return;

  if (defence.isDatabaseInitialized && defence.isDatabaseInitialized()) {
    try {
      const current = defence.getDatabase();
      if (current && current.name === targetPath) return; // already pointed here
      // Path mismatch (typical in tests using per-case temp DBs) — re-init.
      if (defence.closeDatabase) defence.closeDatabase();
    } catch {
      // If anything throws, fall through and try to (re-)init.
    }
  }

  try {
    defence.initDatabase(targetPath);
  } catch {
    // Recoverable: pipeline.ts skips audit + custom-rules gracefully when
    // the singleton isn't initialised.
  }
}
