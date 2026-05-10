import { randomUUID } from 'crypto';
import { dirname, resolve } from 'path';
import { fileURLToPath, pathToFileURL } from 'url';

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
 * @param {{ title: string, content: string, category: string, salience: number, tags: string[] }} memory
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
    result = defence.runDefencePipeline(memory.content, memory.title, source, undefined, project ?? undefined);
  } catch (err) {
    const msg = err && typeof err === 'object' && 'message' in err ? String(err.message) : String(err);
    writeFallbackAudit(db, memory, project, sourceIdentifier, `pipeline_error: ${msg}`);
    process.stderr.write(`[shieldcortex save-memory] dropped (pipeline error): ${memory.title} — ${msg}\n`);
    return;
  }

  const decision = result.firewall.result;

  if (decision === 'ALLOW') {
    insertMemoryRow(db, memory, project);
    return;
  }

  if (decision === 'QUARANTINE') {
    // Route quarantine writes through the singleton's connection so the
    // audit_id FK reference resolves against the same connection that
    // wrote the audit row a few lines up in pipeline.ts.
    const quarantineDb = (typeof _getDatabase === 'function' && defence.isDatabaseInitialized && defence.isDatabaseInitialized())
      ? _getDatabase()
      : db;
    insertQuarantineRow(quarantineDb, memory, project, source, result);
    process.stderr.write(`[shieldcortex save-memory] quarantined: ${memory.title} — ${result.firewall.reason}\n`);
    return;
  }

  // BLOCK — defence_audit row already written by the pipeline. Drop with
  // a single stderr line for operator visibility.
  process.stderr.write(`[shieldcortex save-memory] blocked: ${memory.title} — ${result.firewall.reason}\n`);
}

// ==================== Internal: writes ====================

function insertMemoryRow(db, memory, project) {
  const timestamp = new Date().toISOString();
  db.prepare(`
    INSERT INTO memories (uuid, title, content, type, category, salience, tags, project, created_at, last_accessed)
    VALUES (?, ?, ?, 'short_term', ?, ?, ?, ?, ?, ?)
  `).run(
    randomUUID(),
    memory.title,
    memory.content,
    memory.category,
    memory.salience,
    JSON.stringify(memory.tags),
    project || null,
    timestamp,
    timestamp,
  );
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

    const [pipelineMod, initMod] = await Promise.all([
      import(pipelineUrl),
      import(initUrl),
    ]);

    if (typeof pipelineMod.runDefencePipeline !== 'function') return null;
    if (typeof initMod.initDatabase !== 'function') return null;

    _defenceCache = {
      runDefencePipeline: pipelineMod.runDefencePipeline,
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
