#!/usr/bin/env node
/**
 * ShieldCortex — Proactive Recall Hook (UserPromptSubmit)
 *
 * Fires on every user message. Queries memory for relevant context
 * and injects it via additionalContext so the model always has
 * prior knowledge before responding.
 *
 * Performance budget: <500ms total.
 */

import Database from 'better-sqlite3';
import { mkdirSecure } from './lib/state-perms.mjs';
import { createHash } from 'crypto';
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'fs';
import { join } from 'path';
import { homedir } from 'os';
import { deriveProjectKey } from './lib/project-key.mjs';
import { sanitisePromptForRecall } from './lib/prompt-sanitiser.mjs';
import { recordSessionEvent } from './lib/session-capture.mjs';
import { captureForSessionEvent } from './lib/capture-prompt.mjs';
import { truncatePreservingWords } from './lib/truncate.mjs';
import { compareRecallResults } from './lib/recall-rank.mjs';
import { computeEffectiveSalience } from './lib/salience.mjs';
import { writeRecallLog } from './lib/recall-log.mjs';
import { recordHookInvocation } from './lib/telemetry.mjs';
import { filterByRelevance, extractQueryTerms } from './lib/recall-relevance.mjs';
import { defendRecallRows, loadRecallDefence, ensureRecallAuditDb, emitRecallAudit } from './lib/recall-defence.mjs';

// ==================== CONFIG ====================

const CONFIG_PATH = join(homedir(), '.shieldcortex', 'config.json');
const RECALL_DEDUP_PATH = join(homedir(), '.shieldcortex', '.recall-dedup.json');
const MAX_RESULTS = 5;
const MAX_CONTENT_LENGTH = 150;
const MIN_PROMPT_LENGTH = 8;
const MIN_SALIENCE = 0.2;
// v4.24.3: how many recent recall turns to remember for dedupe.
// Suppresses a recalled memory if its content hash appeared in any of the
// last DEDUP_RING_SIZE turns of THIS session. Per-session, not global.
const DEDUP_RING_SIZE = 5;
const DEDUP_TTL_MS = 60 * 60 * 1000; // forget session rings after 1h idle

// ── P4 recall relevance gate (B9) ────────────────────────────────────────
// Term-coverage is the PRIMARY gate; relative BM25 floor is secondary. SHADOW
// MODE is the default: we compute the gate and LOG what it would drop, but
// inject the original set unchanged until SHIELDCORTEX_RECALL_ENFORCE=1. This
// lets us tune thresholds from real fleet recall-logs before trading recall
// noise for amnesia. All thresholds are env-tunable (pickNumber pattern,
// mirrors scripts/lib/salience.mjs).

// Resolve a numeric tuning constant from a SHIELDCORTEX_* env var, falling back
// to the documented default. Returns the default for a NaN/empty env var so a
// typo can't silently zero out a threshold. (Same contract as salience.mjs's
// pickNumber, minus the explicit-override arg — the hook has no overrides.)
function pickNumber(envName, fallback) {
  const fromEnv = Number(process.env[envName]);
  if (Number.isFinite(fromEnv) && process.env[envName] !== undefined && process.env[envName] !== '') {
    return fromEnv;
  }
  return fallback;
}

// Truthy env flag: "1", "true", "yes", "on" (case-insensitive). Unset = false.
function pickBool(envName) {
  const v = (process.env[envName] || '').trim().toLowerCase();
  return v === '1' || v === 'true' || v === 'yes' || v === 'on';
}

const RECALL_ENFORCE = pickBool('SHIELDCORTEX_RECALL_ENFORCE');
const RECALL_MIN_TERMS = pickNumber('SHIELDCORTEX_RECALL_MIN_TERMS', 2);
const RECALL_REL_FACTOR = pickNumber('SHIELDCORTEX_RECALL_REL_FACTOR', 0.35);
// Absolute BM25 floor is OFF by default (null) — it has no safe default across
// corpus sizes: on a small/new FTS index real bm25 ranks are tiny (~-1e-6), so
// any fixed floor would drop even a perfect full-coverage match the moment an
// operator sets SHIELDCORTEX_RECALL_ENFORCE=1. The relative floor + term-
// coverage do the gating; tune the absolute floor from fleet recall-logs if a
// real corpus shows it's needed. Read the env only if present; absent → null.
const RECALL_MAX_BM25 =
  process.env.SHIELDCORTEX_RECALL_MAX_BM25 !== undefined &&
  process.env.SHIELDCORTEX_RECALL_MAX_BM25 !== ''
    ? pickNumber('SHIELDCORTEX_RECALL_MAX_BM25', null)
    : null;

function loadConfig() {
  try {
    if (existsSync(CONFIG_PATH)) {
      return JSON.parse(readFileSync(CONFIG_PATH, 'utf-8'));
    }
  } catch { /* default config */ }
  return {};
}

// ==================== DATABASE ====================

function getDbPath() {
  const newPath = join(homedir(), '.shieldcortex', 'memories.db');
  const legacyPath = join(homedir(), '.claude-cortex', 'memories.db');
  if (existsSync(newPath) || !existsSync(legacyPath)) return newPath;
  return legacyPath;
}

// ==================== PROJECT DETECTION ====================
// Uses the shared helper in scripts/lib/project-key.mjs so that the recall
// scope, the session-start banner, and the pre-compact writer all agree on
// which project key this cwd maps to.

// ==================== FTS5 QUERY ====================

// Build the FTS5 MATCH expression from the same distinct terms the relevance
// gate scores against. extractQueryTerms (recall-relevance.mjs) is the single
// source of truth for "which words count" — strip FTS5 operators, drop boolean
// keywords, keep words longer than two chars, cap at six. Keeping both in sync
// is load-bearing: the gate must score the SAME terms the FTS query OR-joined.
function escapeFts5(query) {
  return extractQueryTerms(query)
    .map((w) => `"${w}"`)
    .join(' OR ');
}

// ==================== RECALL ====================

function recallRelevant(db, project, prompt) {
  const results = [];
  const seen = new Set();
  let ftsHits = 0;

  // 1. FTS5 text search
  const ftsQuery = escapeFts5(prompt);
  if (ftsQuery.trim()) {
    try {
      // v4.25.0: project pinned/access_count/last_accessed/downvote_count
      // so compareRecallResults can compute effective salience without a
      // second query. COALESCE on downvote_count for DBs that pre-date the
      // 4.25 migration (the prompt-recall-hook runs against legacy DBs too).
      const ftsRows = db.prepare(`
        SELECT
          m.id, m.title, m.content, m.category, m.salience, fts.rank,
          m.pinned, m.access_count, m.last_accessed,
          m.trust_score, m.sensitivity_level, m.metadata, m.reviewed_at,
          COALESCE(m.downvote_count, 0) AS downvote_count
        FROM memories m
        JOIN memories_fts fts ON m.id = fts.rowid
        WHERE memories_fts MATCH ?
          AND (m.project = ? OR m.scope = 'global')
          AND COALESCE(m.status, 'active') = 'active'
          AND m.salience >= ?
        ORDER BY fts.rank
        LIMIT ?
      `).all(ftsQuery, project, MIN_SALIENCE, MAX_RESULTS * 2);

      for (const row of ftsRows) {
        if (!seen.has(row.id)) {
          seen.add(row.id);
          // v4.25.1: tag with source so the recall ring buffer can show
          // operators which path surfaced a given candidate. _-prefixed so
          // it doesn't collide with any future SELECT column.
          row._source = 'fts';
          results.push(row);
          ftsHits += 1;
        }
      }
    } catch {
      // FTS query failed — continue with fallback
    }
  }

  // 2. Category-based recall for certain prompt patterns
  const promptLower = prompt.toLowerCase();
  let categoryBoost = null;
  if (/\b(bug|fix|error|crash|fail|broken)\b/.test(promptLower)) categoryBoost = 'error';
  else if (/\b(deploy|release|publish|ship)\b/.test(promptLower)) categoryBoost = 'architecture';
  else if (/\b(prefer|style|convention|format)\b/.test(promptLower)) categoryBoost = 'preference';

  // P4 (B9 item 6): only fire the category-boost fallback when the FTS path
  // found at least one on-topic hit. The fallback has ZERO query relevance —
  // it matches purely on category + salience — so firing it whenever the
  // result set is short was a back-door for off-topic high-salience rows on a
  // prompt that didn't match ANY memory. Requiring an FTS hit means the prompt
  // is genuinely on-topic for this project before we top up from its category.
  if (categoryBoost && ftsHits > 0 && results.length < MAX_RESULTS) {
    try {
      // v4.25.0: project the salience-formula inputs (same as the FTS
      // SELECT above) so compareRecallResults can compute effective
      // salience for rows that came in via this fallback path.
      const catRows = db.prepare(`
        SELECT
          id, title, content, category, salience,
          pinned, access_count, last_accessed,
          trust_score, sensitivity_level, metadata, reviewed_at,
          COALESCE(downvote_count, 0) AS downvote_count
        FROM memories
        WHERE category = ?
          AND (project = ? OR scope = 'global')
          AND COALESCE(status, 'active') = 'active'
          AND salience >= ?
        ORDER BY salience DESC, last_accessed DESC
        LIMIT ?
      `).all(categoryBoost, project, MIN_SALIENCE, MAX_RESULTS - results.length);

      for (const row of catRows) {
        if (!seen.has(row.id)) {
          seen.add(row.id);
          row._source = 'category-boost';
          results.push(row);
        }
      }
    } catch { /* best-effort */ }
  }

  // v4.23.0: FTS rank primary, salience tiebreaker. The previous raw-salience
  // sort discarded the relevance signal from the FTS5 query above — high-
  // salience-but-off-topic memories bubbled to the top of the recall preamble.
  results.sort(compareRecallResults);
  // v4.25.1: return the full sorted set alongside the sliced top-N so the
  // recall ring buffer can log which candidates were considered but didn't
  // make the cut. The top-N is the existing public contract.
  //
  // P4: also surface the distinct query terms (the same set escapeFts5 OR-
  // joined) and the FTS hit count so the caller can run the relevance gate
  // and the dedupe step against a consistent term list.
  return {
    topN: results.slice(0, MAX_RESULTS),
    fullSet: results,
    queryTerms: extractQueryTerms(prompt),
    ftsHits,
  };
}

// ==================== DEDUPE STATE ====================
//
// Per-session ring of recently-injected content hashes, persisted to
// `~/.shieldcortex/.recall-dedup.json`. v4.24.3 — Jarvis flagged that
// near-identical recalls were being injected in adjacent turns. The cheap
// fix: hash content + suppress if seen in any of the last DEDUP_RING_SIZE
// turns of this session. Best-effort — failures don't block recall.

function loadDedupState() {
  try {
    if (!existsSync(RECALL_DEDUP_PATH)) return {};
    const raw = JSON.parse(readFileSync(RECALL_DEDUP_PATH, 'utf-8'));
    if (!raw || typeof raw !== 'object') return {};
    // Purge stale sessions to keep the file bounded.
    const now = Date.now();
    for (const sid of Object.keys(raw)) {
      const entry = raw[sid];
      if (!entry || typeof entry.touched !== 'number' || now - entry.touched > DEDUP_TTL_MS) {
        delete raw[sid];
      }
    }
    return raw;
  } catch {
    return {};
  }
}

function saveDedupState(state) {
  try {
    mkdirSecure(join(homedir(), '.shieldcortex'));
    writeFileSync(RECALL_DEDUP_PATH, JSON.stringify(state), { mode: 0o600 });
  } catch {
    // Best-effort.
  }
}

function hashContent(s) {
  return createHash('sha256').update(s).digest('hex').slice(0, 16);
}

// ==================== RECALL LOG (v4.25.1) ====================
//
// Per-run dump of "what prompt fired, which memories were considered, which
// were injected, which were dropped, and why" to ~/.shieldcortex/recall-log/.
// Operators read this via `shieldcortex inspect last-recall`. Best-effort —
// never throws into the caller. Designed to gather diagnostic data so we
// can scope v4.26.x recall-quality fixes from real fleet usage.

const RECALL_LOG_PROMPT_CAP = 200;

function buildLogCandidates({ fullSet, topN, injected, dedupHashes, relevanceDrops }) {
  const injectedIds = new Set(injected.map((m) => m.id));
  const topNIds = new Set(topN.map((m) => m.id));
  // P4: id → 'below_term_coverage' | 'below_relevance_floor'. Populated even
  // in shadow mode (where these rows ARE still injected) so the recall-log
  // surfaces "considered but below floor" to `shieldcortex inspect last-recall`
  // for threshold tuning before enforcement. Map is empty when the gate found
  // nothing to drop.
  const relDrops = relevanceDrops instanceof Map ? relevanceDrops : new Map();
  return fullSet.map((row) => {
    const wasInjected = injectedIds.has(row.id);
    let dropReason = null;
    // The relevance-gate reason takes precedence for a row it flagged: it's the
    // most specific "why this is noise" signal, and in shadow mode it's the
    // ONLY drop signal (the row is still injected, so the dedupe/top-N branches
    // below wouldn't fire). When enforcing, a gate-dropped row is also not
    // injected, so this is still the correct reason.
    if (relDrops.has(row.id)) {
      dropReason = relDrops.get(row.id);
    } else if (!wasInjected) {
      if (topNIds.has(row.id) && dedupHashes.has(hashContent(row.content))) {
        dropReason = 'dedupe';
      } else if (!topNIds.has(row.id)) {
        dropReason = 'outside_top_n';
      } else {
        // In top-N, not deduped, not injected — early exit on empty memories
        // before the dedupe filter ran. Mark as not-injected-no-reason so the
        // CLI can distinguish from an active drop.
        dropReason = 'not_injected';
      }
    }
    return {
      id: row.id ?? null,
      title: row.title ?? null,
      category: row.category ?? null,
      memoryPurpose: row.memory_purpose ?? null,
      salience: typeof row.salience === 'number' ? row.salience : null,
      ftsRank: typeof row.rank === 'number' ? row.rank : null,
      source: row._source ?? null,
      effectiveSalience: computeEffectiveSalience(row),
      injected: wasInjected,
      dropReason,
    };
  });
}

function logRecallRun({ prompt, sessionId, project, fullSet, topN, injected, dedupHashes, context, relevanceDrops }) {
  try {
    const promptCapped = prompt.length > RECALL_LOG_PROMPT_CAP
      ? prompt.slice(0, RECALL_LOG_PROMPT_CAP) + '…'
      : prompt;
    writeRecallLog({
      prompt: promptCapped,
      promptHash: hashContent(prompt),
      sessionId: sessionId ?? null,
      project: project ?? null,
      minSalience: MIN_SALIENCE,
      candidates: buildLogCandidates({ fullSet, topN, injected, dedupHashes, relevanceDrops }),
      injectedCount: injected.length,
      finalContextChars: context ? context.length : 0,
    });
  } catch {
    // Best-effort — recall must not block on log write failures.
  }
}

// ==================== FORMAT ====================

function formatRecallContext(memories) {
  if (memories.length === 0) return null;

  const lines = ['🧠 Recalled from memory:'];
  for (const m of memories) {
    const content = truncatePreservingWords(m.content, MAX_CONTENT_LENGTH);
    // v4.24.3: append a source ref so the operator can grep / inspect
    // the backing memory. Uses memory ID (always available); a future
    // schema change could store the source_file path for clickability.
    const source = m.id != null ? ` _[mem #${m.id}]_` : '';
    lines.push(`- **${m.title}**: ${content}${source}`);
  }
  return lines.join('\n');
}

// ==================== TELEMETRY (#253) ====================

/**
 * Record a prompt-recall invocation BEFORE any early exit.
 *
 * Issue #253: seven process.exit(0) paths sat above the only
 * recordHookInvocation call, so "fires but extracts nothing" was
 * indistinguishable from "never fires" — the exact ambiguity this
 * table was built to remove. Call this on every terminal path
 * (including zero-yield gates) with memoriesExtracted: 0 and a
 * short notes reason. Best-effort; never throws; never blocks exit.
 */
function recordPromptRecallTelemetry({
  startedAt,
  memoriesExtracted = 0,
  notes = null,
  dbPath = null,
} = {}) {
  const path = dbPath || getDbPath();
  if (!path || !existsSync(path)) return;
  let tdb = null;
  try {
    tdb = new Database(path, { timeout: 1000 });
    recordHookInvocation(tdb, {
      hookName: 'prompt-recall',
      exitCode: 0,
      durationMs: typeof startedAt === 'number' ? Date.now() - startedAt : null,
      memoriesExtracted,
      notes,
    });
  } catch {
    // Telemetry must never block the user prompt.
  } finally {
    try { if (tdb) tdb.close(); } catch { /* ignore */ }
  }
}

// ==================== MAIN ====================

let input = '';
process.stdin.setEncoding('utf8');
process.stdin.on('readable', () => {
  let chunk;
  while ((chunk = process.stdin.read()) !== null) input += chunk;
});

process.stdin.on('end', async () => {
  const startedAt = Date.now();
  try {
    const config = loadConfig();
    const hookData = JSON.parse(input || '{}');
    const rawPrompt = hookData.prompt || '';
    const cwd = hookData.cwd || process.cwd();
    const sessionId = hookData.session_id || hookData.sessionId || null;

    // ── Session capture (v4.17): record the user prompt regardless of
    //    proactiveRecall config so the dashboard replay timeline gets a
    //    complete event stream. Opt-out via captureEvents=false. Failures
    //    are swallowed — capture must never block the user prompt.
    //
    // Fix #10 (v4.28): redact credentials + classify sensitivity BEFORE the
    // INSERT. Pasting a `.env` into Claude Code used to land verbatim in
    // session_events; now it's routed through the defence pipeline first
    // and the resulting sensitivity_level lets the dashboard mask/strip
    // RESTRICTED rows from replay timelines.
    if (config.captureEvents !== false && sessionId && rawPrompt) {
      try {
        const project = deriveProjectKey(cwd);
        const dbPath = getDbPath();
        if (existsSync(dbPath)) {
          const { redactedText, sensitivity } = await captureForSessionEvent(rawPrompt);
          const captureDb = new Database(dbPath, { timeout: 1000 });
          recordSessionEvent(captureDb, {
            session_id: sessionId,
            ts: new Date().toISOString(),
            kind: 'prompt',
            payload: { text: redactedText },
            project: project || null,
            actor: 'user',
            sensitivity_level: sensitivity,
          });
          captureDb.close();
        }
      } catch {
        // Capture is best-effort.
      }
    }

    if (config.proactiveRecall !== true) {
      // #253: fired, gated off — not "never ran".
      recordPromptRecallTelemetry({ startedAt, notes: 'gated:proactiveRecall-disabled' });
      process.exit(0);
    }

    // Strip OpenClaw / framework metadata wrappers (e.g. Telegram channel
    // headers) before any prompt-based decisions. Without this, the FTS5
    // query is built from "Conversation info untrusted metadata json" tokens
    // instead of the user's actual words and recall returns 0 relevant rows.
    const prompt = sanitisePromptForRecall(rawPrompt);

    if (prompt.length < MIN_PROMPT_LENGTH) {
      recordPromptRecallTelemetry({ startedAt, notes: 'gated:prompt-too-short' });
      process.exit(0);
    }

    if (/^(yes|no|ok|sure|do it|go|send it|y|n|yep|nope)\s*[.!?]?\s*$/i.test(prompt.trim())) {
      recordPromptRecallTelemetry({ startedAt, notes: 'gated:trivial-prompt' });
      process.exit(0);
    }

    const project = deriveProjectKey(cwd);
    if (!project) {
      recordPromptRecallTelemetry({ startedAt, notes: 'gated:no-project-key' });
      process.exit(0);
    }

    const dbPath = getDbPath();
    if (!existsSync(dbPath)) {
      // No DB file → cannot write telemetry either; still not a silent
      // "never fired" once a DB exists on later runs. notes unused here.
      process.exit(0);
    }

    const db = new Database(dbPath, { readonly: true, timeout: 2000 });
    const { topN, fullSet, queryTerms } = recallRelevant(db, project, prompt);
    db.close();

    // ── P4 recall relevance gate (B9) ───────────────────────────────────
    // Run the term-coverage + relative-BM25 gate over the would-be-injected
    // top-N. SHADOW MODE (default): record the would-drops in the recall log
    // but inject the ORIGINAL top-N unchanged. ENFORCE mode
    // (SHIELDCORTEX_RECALL_ENFORCE=1): inject only the survivors. Either way
    // the dropped rows STAY in fullSet so `inspect last-recall` shows them as
    // "considered but below floor".
    const { kept, dropped } = filterByRelevance(topN, {
      queryTerms,
      minTermMatches: RECALL_MIN_TERMS,
      relFactor: RECALL_REL_FACTOR,
      maxBm25: RECALL_MAX_BM25,
    });
    const relevanceDrops = new Map(dropped.map((d) => [d.row.id, d.reason]));
    if (dropped.length > 0) {
      // Visible in the hook's stderr diagnostics; the structured detail lands
      // in the recall log via relevanceDrops.
      console.error(
        `[shieldcortex] Recall relevance gate (${RECALL_ENFORCE ? 'ENFORCE' : 'SHADOW'}): ` +
          `${dropped.length}/${topN.length} would-drop ` +
          `(${dropped.map((d) => `#${d.row.id}:${d.reason}`).join(', ')})`,
      );
    }
    // SHADOW = inject original top-N; ENFORCE = inject only survivors.
    let memories = RECALL_ENFORCE ? kept : topN;

    if (memories.length === 0) {
      // v4.25.1: still log no-candidate runs ONLY when the FTS step actually
      // ran (fullSet has something filtered out before the slice). Pure
      // empties (no FTS match at all) skip the log — saves disk + signal.
      // P4: in ENFORCE mode the gate can empty the set (the "weather query →
      // inject nothing" case) even though fullSet has rows — those are logged
      // with their relevance dropReason. The empty-path logger still fires.
      if (fullSet.length > 0) {
        logRecallRun({
          prompt,
          sessionId,
          project,
          fullSet,
          topN: [],
          injected: [],
          dedupHashes: new Set(),
          context: null,
          relevanceDrops,
        });
      }
      // #253: zero-yield recall MUST leave a hook_invocations row.
      // This is the Veronica empty-store case — fires, injects nothing.
      recordPromptRecallTelemetry({
        startedAt,
        memoriesExtracted: 0,
        notes: fullSet.length > 0 ? 'zero-yield:filtered-empty' : 'zero-yield:no-candidates',
        dbPath,
      });
      process.exit(0);
    }

    // v4.24.3: suppress memories whose content hash appeared in any of
    // the last DEDUP_RING_SIZE turns of this session. Avoids the
    // "near-identical recall in adjacent turns" failure Jarvis flagged.
    let dedupState = null;
    let sessionRing = [];
    let dedupHashes = new Set();
    if (sessionId) {
      dedupState = loadDedupState();
      const entry = dedupState[sessionId] ?? { ring: [], touched: Date.now() };
      sessionRing = Array.isArray(entry.ring) ? entry.ring : [];
      dedupHashes = new Set(sessionRing);
      memories = memories.filter((m) => !dedupHashes.has(hashContent(m.content)));
      if (memories.length === 0) {
        // v4.25.1: log even when every top-N candidate was dedupe-suppressed.
        // This is the most interesting case for diagnosing recall noise.
        logRecallRun({
          prompt,
          sessionId,
          project,
          fullSet,
          topN,
          injected: [],
          dedupHashes,
          context: null,
          relevanceDrops,
        });
        recordPromptRecallTelemetry({
          startedAt,
          memoriesExtracted: 0,
          notes: 'zero-yield:dedup-suppressed',
          dbPath,
        });
        process.exit(0);
      }
    }

    // ── RECALL-BOUNDARY DEFENCE (Feature #1) ─────────────────────────────
    // Filter poisoned / RESTRICTED / credential-bearing rows OUT of the recalled
    // set before they're formatted into the prompt. Runs after dedupe (acts on
    // the final injected set) and before format + ring + telemetry (so those see
    // only safe rows). FAIL-OPEN: a missing dist build leaves recall unchanged.
    if (config.recallDefence !== false && memories.length > 0) {
      try {
        const defence = await loadRecallDefence();
        if (defence) {
          const minTrust = typeof config.recallDefenceMinTrust === 'number' ? config.recallDefenceMinTrust : 0;
          const { kept: safe, actions } = defendRecallRows(memories, { minTrust, project }, defence);
          const withheld = actions.filter((a) => a.action !== 'allowed');
          if (withheld.length > 0) {
            console.error(
              `[shieldcortex] recall-defence withheld ${withheld.length} memory row(s): ` +
                withheld.map((w) => `#${w.id}:${w.layer}`).join(', '),
            );
            // Only touch a writable audit connection when something was withheld.
            ensureRecallAuditDb(defence, dbPath);
            for (const a of withheld) {
              emitRecallAudit(defence.logAudit, { memoryId: a.id, action: a.action, layer: a.layer, reason: a.reason, project });
            }
          }
          memories = safe;
        }
      } catch (e) {
        console.error('[shieldcortex] recall-defence skipped:', e?.message ?? e);
      }
    }

    const context = formatRecallContext(memories);

    // Update the session ring with the hashes of what we just injected.
    if (sessionId && dedupState) {
      const newHashes = memories.map((m) => hashContent(m.content));
      const merged = [...newHashes, ...sessionRing].slice(0, DEDUP_RING_SIZE);
      dedupState[sessionId] = { ring: merged, touched: Date.now() };
      saveDedupState(dedupState);
    }

    // Reinforce access counts (fire-and-forget in a writable connection)
    try {
      const writeDb = new Database(dbPath, { timeout: 1000 });
      const ids = memories.map(m => m.id);
      if (ids.length > 0) {
        const placeholders = ids.map(() => '?').join(',');
        writeDb.prepare(`
          UPDATE memories SET access_count = access_count + 1, last_accessed = datetime('now')
          WHERE id IN (${placeholders})
        `).run(...ids);
      }
      // #253: record EVERY terminal path, including zero-yield after
      // recall-defence emptied the set. memories_extracted = injected count;
      // notes distinguish success from zero-yield so status is not a lie.
      recordHookInvocation(writeDb, {
        hookName: 'prompt-recall',
        exitCode: 0,
        durationMs: Date.now() - startedAt,
        memoriesExtracted: memories.length,
        notes: memories.length > 0 ? 'injected' : 'zero-yield:defence-empty',
      });
      writeDb.close();
    } catch {
      // Non-critical — don't block on access count update / telemetry
      recordPromptRecallTelemetry({
        startedAt,
        memoriesExtracted: memories.length,
        notes: memories.length > 0 ? 'injected' : 'zero-yield:defence-empty',
        dbPath,
      });
    }

    const output = {
      hookSpecificOutput: {
        hookEventName: 'UserPromptSubmit',
        additionalContext: context,
      },
    };

    // v4.25.1: log the recall run (best-effort, never blocks output)
    logRecallRun({
      prompt,
      sessionId,
      project,
      fullSet,
      topN,
      injected: memories,
      dedupHashes,
      context,
      relevanceDrops,
    });

    console.log(JSON.stringify(output));
    console.error(`[shieldcortex] Proactive recall: ${memories.length} memories for "${project}"`);

    process.exit(0);
  } catch (error) {
    console.error(`[shieldcortex] Proactive recall error: ${error.message}`);
    // #253: errors are still firings — record when a DB is available.
    recordPromptRecallTelemetry({
      startedAt,
      memoriesExtracted: 0,
      notes: `error:${error?.message ?? 'unknown'}`.slice(0, 200),
    });
    process.exit(0);
  }
});
