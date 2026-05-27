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
import { createHash } from 'crypto';
import { existsSync, mkdirSync, readFileSync, writeFileSync } from 'fs';
import { join } from 'path';
import { homedir } from 'os';
import { deriveProjectKey } from './lib/project-key.mjs';
import { sanitisePromptForRecall } from './lib/prompt-sanitiser.mjs';
import { recordSessionEvent } from './lib/session-capture.mjs';
import { truncatePreservingWords } from './lib/truncate.mjs';
import { compareRecallResults } from './lib/recall-rank.mjs';

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

function escapeFts5(query) {
  return query
    .replace(/[*(){}[\]<>~^"]/g, ' ')
    .replace(/\b(AND|OR|NOT|NEAR)\b/gi, '')
    .split(/\s+/)
    .filter(w => w.length > 2)
    .map(w => `"${w}"`)
    .slice(0, 6)
    .join(' OR ');
}

// ==================== RECALL ====================

function recallRelevant(db, project, prompt) {
  const results = [];
  const seen = new Set();

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
          COALESCE(m.downvote_count, 0) AS downvote_count
        FROM memories m
        JOIN memories_fts fts ON m.id = fts.rowid
        WHERE memories_fts MATCH ?
          AND (m.project = ? OR m.project IS NULL OR m.scope = 'global')
          AND COALESCE(m.status, 'active') = 'active'
          AND m.salience >= ?
        ORDER BY fts.rank
        LIMIT ?
      `).all(ftsQuery, project, MIN_SALIENCE, MAX_RESULTS * 2);

      for (const row of ftsRows) {
        if (!seen.has(row.id)) {
          seen.add(row.id);
          results.push(row);
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

  if (categoryBoost && results.length < MAX_RESULTS) {
    try {
      // v4.25.0: project the salience-formula inputs (same as the FTS
      // SELECT above) so compareRecallResults can compute effective
      // salience for rows that came in via this fallback path.
      const catRows = db.prepare(`
        SELECT
          id, title, content, category, salience,
          pinned, access_count, last_accessed,
          COALESCE(downvote_count, 0) AS downvote_count
        FROM memories
        WHERE category = ?
          AND (project = ? OR project IS NULL OR scope = 'global')
          AND COALESCE(status, 'active') = 'active'
          AND salience >= ?
        ORDER BY salience DESC, last_accessed DESC
        LIMIT ?
      `).all(categoryBoost, project, MIN_SALIENCE, MAX_RESULTS - results.length);

      for (const row of catRows) {
        if (!seen.has(row.id)) {
          seen.add(row.id);
          results.push(row);
        }
      }
    } catch { /* best-effort */ }
  }

  // v4.23.0: FTS rank primary, salience tiebreaker. The previous raw-salience
  // sort discarded the relevance signal from the FTS5 query above — high-
  // salience-but-off-topic memories bubbled to the top of the recall preamble.
  results.sort(compareRecallResults);
  return results.slice(0, MAX_RESULTS);
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
    mkdirSync(join(homedir(), '.shieldcortex'), { recursive: true });
    writeFileSync(RECALL_DEDUP_PATH, JSON.stringify(state), { mode: 0o600 });
  } catch {
    // Best-effort.
  }
}

function hashContent(s) {
  return createHash('sha256').update(s).digest('hex').slice(0, 16);
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

// ==================== MAIN ====================

let input = '';
process.stdin.setEncoding('utf8');
process.stdin.on('readable', () => {
  let chunk;
  while ((chunk = process.stdin.read()) !== null) input += chunk;
});

process.stdin.on('end', () => {
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
    if (config.captureEvents !== false && sessionId && rawPrompt) {
      try {
        const project = deriveProjectKey(cwd);
        const dbPath = getDbPath();
        if (existsSync(dbPath)) {
          const captureDb = new Database(dbPath, { timeout: 1000 });
          recordSessionEvent(captureDb, {
            session_id: sessionId,
            ts: new Date().toISOString(),
            kind: 'prompt',
            payload: { text: rawPrompt },
            project: project || null,
            actor: 'user',
          });
          captureDb.close();
        }
      } catch {
        // Capture is best-effort.
      }
    }

    if (config.proactiveRecall !== true) {
      process.exit(0);
    }

    // Strip OpenClaw / framework metadata wrappers (e.g. Telegram channel
    // headers) before any prompt-based decisions. Without this, the FTS5
    // query is built from "Conversation info untrusted metadata json" tokens
    // instead of the user's actual words and recall returns 0 relevant rows.
    const prompt = sanitisePromptForRecall(rawPrompt);

    if (prompt.length < MIN_PROMPT_LENGTH) {
      process.exit(0);
    }

    if (/^(yes|no|ok|sure|do it|go|send it|y|n|yep|nope)\s*[.!?]?\s*$/i.test(prompt.trim())) {
      process.exit(0);
    }

    const project = deriveProjectKey(cwd);
    if (!project) {
      process.exit(0);
    }

    const dbPath = getDbPath();
    if (!existsSync(dbPath)) {
      process.exit(0);
    }

    const db = new Database(dbPath, { readonly: true, timeout: 2000 });
    let memories = recallRelevant(db, project, prompt);
    db.close();

    if (memories.length === 0) {
      process.exit(0);
    }

    // v4.24.3: suppress memories whose content hash appeared in any of
    // the last DEDUP_RING_SIZE turns of this session. Avoids the
    // "near-identical recall in adjacent turns" failure Jarvis flagged.
    let dedupState = null;
    let sessionRing = [];
    if (sessionId) {
      dedupState = loadDedupState();
      const entry = dedupState[sessionId] ?? { ring: [], touched: Date.now() };
      sessionRing = Array.isArray(entry.ring) ? entry.ring : [];
      const recentHashes = new Set(sessionRing);
      memories = memories.filter((m) => !recentHashes.has(hashContent(m.content)));
      if (memories.length === 0) {
        process.exit(0);
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
      const placeholders = ids.map(() => '?').join(',');
      writeDb.prepare(`
        UPDATE memories SET access_count = access_count + 1, last_accessed = datetime('now')
        WHERE id IN (${placeholders})
      `).run(...ids);
      writeDb.close();
    } catch {
      // Non-critical — don't block on access count update
    }

    const output = {
      hookSpecificOutput: {
        hookEventName: 'UserPromptSubmit',
        additionalContext: context,
      },
    };

    console.log(JSON.stringify(output));
    console.error(`[shieldcortex] Proactive recall: ${memories.length} memories for "${project}"`);

    process.exit(0);
  } catch (error) {
    console.error(`[shieldcortex] Proactive recall error: ${error.message}`);
    process.exit(0);
  }
});
