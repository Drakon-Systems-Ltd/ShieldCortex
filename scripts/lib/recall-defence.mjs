/**
 * Recall-boundary defence shim (Feature #1).
 *
 * The read hooks (prompt-recall, session-start) used to inject recalled memory
 * VERBATIM into the model prompt with no defence. This module sits between the
 * SQL SELECT and the formatter: it filters rows by trust/sensitivity (via the
 * dead-no-more filterByTrust) and re-scans surviving content for injection /
 * credentials / encoded payloads, withholding (not deleting) anything bad so a
 * poisoned or RESTRICTED row never reaches the model.
 *
 * `defendRecallRows` is PURE + dependency-injected so it unit-tests with no dist
 * build and no DB. `loadRecallDefence` / `emitRecallAudit` (below) wire the real
 * dist modules for the hooks and are exercised by the integration test.
 */

import { dirname, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const RESTRICTED_MARKER = '[REDACTED - RESTRICTED]';

let _recallDefenceCache = null;
let _recallDefenceCacheKey = null;

/**
 * Lazy-load the built dist defence modules the read hooks need. Returns null if
 * the dist build is missing/incomplete → the caller MUST fail OPEN (leave recall
 * unchanged), because blanking recall in an un-built dev workspace would break
 * the product. Imports only LEAF detector modules (never dist/defence/pipeline.js)
 * to stay inside the hook's <500ms budget; caches across invocations.
 *
 * @param {string} [distRootOverride] test seam — point at an empty dir to assert fail-open.
 */
export async function loadRecallDefence(distRootOverride) {
  const here = dirname(fileURLToPath(import.meta.url));
  const distRoot = distRootOverride ?? resolve(here, '..', '..', 'dist');
  if (_recallDefenceCache && _recallDefenceCacheKey === distRoot) return _recallDefenceCache;

  try {
    const [trustMod, firewallMod, credMod, auditMod, initMod, sanitiseMod] = await Promise.all([
      import(pathToFileURL(resolve(distRoot, 'defence', 'trust', 'recall-filter.js')).href),
      import(pathToFileURL(resolve(distRoot, 'defence', 'firewall', 'index.js')).href),
      import(pathToFileURL(resolve(distRoot, 'defence', 'credential-leak', 'index.js')).href),
      import(pathToFileURL(resolve(distRoot, 'defence', 'audit', 'logger.js')).href),
      import(pathToFileURL(resolve(distRoot, 'database', 'init.js')).href),
      import(pathToFileURL(resolve(distRoot, 'defence', 'input-sanitisation', 'index.js')).href).catch(() => ({})),
    ]);

    if (
      typeof trustMod.filterByTrust !== 'function' ||
      typeof firewallMod.detectInstructions !== 'function' ||
      typeof firewallMod.detectEncoding !== 'function' ||
      typeof credMod.scanForCredentials !== 'function' ||
      typeof auditMod.logAudit !== 'function' ||
      typeof initMod.initDatabase !== 'function'
    ) {
      return null;
    }

    _recallDefenceCache = {
      filterByTrust: trustMod.filterByTrust,
      // Optional — strips zero-width/RTL/control bytes before scanning so a
      // hidden injection can't dodge the regex detectors; defendRecallRows guards.
      sanitiseInput: sanitiseMod.sanitiseInput,
      detectInstructions: firewallMod.detectInstructions,
      detectEncoding: firewallMod.detectEncoding,
      // Optional — older dist builds may not export it; defendRecallRows guards.
      detectMarkdownImageExfil: firewallMod.detectMarkdownImageExfil,
      scanForCredentials: credMod.scanForCredentials,
      logAudit: auditMod.logAudit,
      initDatabase: initMod.initDatabase,
      isDatabaseInitialized: initMod.isDatabaseInitialized,
      getDatabase: initMod.getDatabase,
      closeDatabase: initMod.closeDatabase,
    };
    _recallDefenceCacheKey = distRoot;
    return _recallDefenceCache;
  } catch {
    return null;
  }
}

/**
 * Point the dist DB singleton (used by logAudit) at the hook's DB so withhold
 * audit rows are visible across connections. Only needed when ≥1 row is withheld
 * — keep it out of the common all-clear path. Best-effort.
 */
export function ensureRecallAuditDb(defence, dbPath) {
  if (!defence || !dbPath || dbPath === ':memory:') return;
  try {
    if (defence.isDatabaseInitialized && defence.isDatabaseInitialized()) {
      const current = defence.getDatabase();
      if (current && current.name === dbPath) return;
      if (defence.closeDatabase) defence.closeDatabase();
    }
    defence.initDatabase(dbPath);
  } catch {
    // logAudit no-ops gracefully if the singleton isn't initialised.
  }
}

/**
 * Write a defence_audit row recording a withheld/redacted recall. Best-effort —
 * never throws into the hook (a recall must not fail because audit failed).
 */
export function emitRecallAudit(logAudit, { memoryId, action, layer, reason, project } = {}) {
  try {
    logAudit({
      memory_id: typeof memoryId === 'number' ? memoryId : null,
      project: project ?? null,
      timestamp: new Date().toISOString(),
      source_type: 'hook',
      source_identifier: 'recall-defence',
      trust_score: 0,
      sensitivity_level: 'INTERNAL',
      // No 'READ' firewall result exists; encode the withhold as BLOCK (dropped)
      // / QUARANTINE (redacted) with the detail in `reason`.
      firewall_result: action === 'redacted' ? 'QUARANTINE' : 'BLOCK',
      anomaly_score: 0,
      threat_indicators: JSON.stringify([`recall:${layer ?? 'unknown'}`]),
      blocked_patterns: '[]',
      reason: `recall-withheld: ${reason ?? layer ?? 'policy'}`,
      fragmentation_score: null,
      pipeline_duration_ms: 0,
      // hook:recall-defence is a literal in this shipped file — attested by
      // construction, so withheld-recall BLOCKs can accrue to the channel.
      source_attested: 1,
    });
  } catch {
    // best-effort
  }
}

function parseMetadata(meta) {
  if (meta == null) return {};
  if (typeof meta === 'object') return meta;
  if (typeof meta === 'string') {
    try {
      return JSON.parse(meta);
    } catch {
      return {};
    }
  }
  return {};
}

/**
 * Filter recalled rows through the trust/sensitivity + content defence layers.
 *
 * @param {Array<object>} rows  raw recalled rows (better-sqlite3 rows — NOT mutated)
 * @param {{ minTrust?: number, project?: string, reviewedPinnedBypass?: boolean }} opts
 * @param {{ filterByTrust, detectInstructions, scanForCredentials, detectEncoding }} deps
 * @returns {{ kept: object[], actions: Array<{id:any, action:'allowed'|'dropped'|'redacted', layer:string|null, reason:string|null}> }}
 */
export function defendRecallRows(rows, opts = {}, deps) {
  const minTrust = typeof opts.minTrust === 'number' ? opts.minTrust : 0;
  const reviewedPinnedBypass = opts.reviewedPinnedBypass !== false; // default ON
  const actions = [];

  // Shallow copies — never mutate the better-sqlite3 rows (reused by the dedupe
  // ring + telemetry). Coalesce undefined trust → 1.0 (column DEFAULT 1.0) so a
  // legacy un-migrated row isn't dropped as trust 0 by filterByTrust.
  const copies = rows.map((r) => ({
    ...r,
    trust_score: r.trust_score ?? 1.0,
    metadata: parseMetadata(r.metadata),
  }));

  // Trust + sensitivity: drops quarantined/below-minTrust, redacts RESTRICTED.
  const trusted = deps.filterByTrust(copies, minTrust, opts.project);
  const trustedIds = new Set(trusted.map((r) => r.id));
  for (const c of copies) {
    if (!trustedIds.has(c.id)) {
      actions.push({ id: c.id, action: 'dropped', layer: 'trust', reason: `trust<${minTrust} or quarantined` });
    }
  }

  const kept = [];
  for (const row of trusted) {
    // Already redacted by the trust layer — keep the masked row, don't re-scan
    // the marker.
    if (row.content === RESTRICTED_MARKER) {
      actions.push({ id: row.id, action: 'redacted', layer: 'restricted', reason: 'RESTRICTED content redacted on recall' });
      kept.push(row);
      continue;
    }

    // Reviewed/pinned bypass: a human-reviewed or pinned memory skips the
    // content detectors (trust/RESTRICTED above still applied) so a legitimately
    // reviewed security note isn't re-suppressed at read time.
    if (reviewedPinnedBypass && (row.reviewed_at != null || row.pinned)) {
      actions.push({ id: row.id, action: 'allowed', layer: 'bypass', reason: 'reviewed/pinned — content scan skipped' });
      kept.push(row);
      continue;
    }

    const content = typeof row.content === 'string' ? row.content : '';
    // Sanitise (strip zero-width / RTL / control bytes) BEFORE scanning — the
    // write path does this, so an injection hidden behind zero-width chars
    // otherwise dodges the read-path regex detectors. Scan the sanitised form;
    // the original (benign zero-width is harmless) is what gets injected.
    const scanContent = deps.sanitiseInput ? (deps.sanitiseInput(content)?.sanitised ?? content) : content;

    const instr = deps.detectInstructions(scanContent);
    if (instr && instr.detected) {
      actions.push({ id: row.id, action: 'dropped', layer: 'instruction', reason: `instruction:${(instr.patterns ?? []).join(',')}` });
      continue;
    }

    // Mirror the WRITE path: drop only on a BLOCKING credential finding, not a
    // warned/logged one. A benign high-entropy hash / cache key is stored
    // (write blocks only on action==='blocked'), so recall must not be stricter
    // or it silently withholds legitimate notes.
    const cred = deps.scanForCredentials(scanContent);
    const credBlocked = !!cred && Array.isArray(cred.findings) && cred.findings.some((f) => f && f.action === 'blocked');
    if (credBlocked) {
      const blocked = cred.findings.filter((f) => f && f.action === 'blocked');
      actions.push({ id: row.id, action: 'dropped', layer: 'credential', reason: `credential:${blocked.length}` });
      continue;
    }

    // Decode-and-rescan: a bare encoding flag is NOT a drop (base64 hashes are
    // common) — only drop if a DECODED snippet itself trips a detector.
    const enc = deps.detectEncoding(scanContent);
    if (enc && enc.detected) {
      let malicious = false;
      for (const snippet of enc.decodedSnippets ?? []) {
        const di = deps.detectInstructions(snippet);
        const dc = deps.scanForCredentials(snippet);
        const dcBlocked = !!dc && Array.isArray(dc.findings) && dc.findings.some((f) => f && f.action === 'blocked');
        if ((di && di.detected) || dcBlocked) {
          malicious = true;
          break;
        }
      }
      if (malicious) {
        actions.push({ id: row.id, action: 'dropped', layer: 'encoding', reason: `encoding-payload:${(enc.encodingTypes ?? []).join(',')}` });
        continue;
      }
    }

    // Markdown-image exfil: a stored ![alt](url?d=<smuggled>) is a click-free
    // data-leak shape the write firewall catches but the read path didn't.
    // detectMarkdownImageExfil only flags data-bearing image URLs (low FP).
    if (deps.detectMarkdownImageExfil) {
      const mdImg = deps.detectMarkdownImageExfil(scanContent);
      if (mdImg && mdImg.detected) {
        actions.push({ id: row.id, action: 'dropped', layer: 'markdown-image-exfil', reason: `markdown-image-exfil:${(mdImg.urls ?? []).length}` });
        continue;
      }
    }

    actions.push({ id: row.id, action: 'allowed', layer: null, reason: null });
    kept.push(row);
  }

  return { kept, actions };
}
