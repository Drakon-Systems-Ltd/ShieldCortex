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
import { existsSync, readFileSync } from 'fs';
import { join } from 'path';
import { homedir } from 'os';
import { deriveProjectKey } from './lib/project-key.mjs';
import { sanitisePromptForRecall } from './lib/prompt-sanitiser.mjs';

// ==================== CONFIG ====================

const CONFIG_PATH = join(homedir(), '.shieldcortex', 'config.json');
const MAX_RESULTS = 5;
const MAX_CONTENT_LENGTH = 150;
const MIN_PROMPT_LENGTH = 8;
const MIN_SALIENCE = 0.2;

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
      const ftsRows = db.prepare(`
        SELECT m.id, m.title, m.content, m.category, m.salience, fts.rank
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
      const catRows = db.prepare(`
        SELECT id, title, content, category, salience
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

  results.sort((a, b) => (b.salience || 0) - (a.salience || 0));
  return results.slice(0, MAX_RESULTS);
}

// ==================== FORMAT ====================

function formatRecallContext(memories) {
  if (memories.length === 0) return null;

  const lines = ['🧠 Recalled from memory:'];
  for (const m of memories) {
    const content = m.content.length > MAX_CONTENT_LENGTH
      ? m.content.slice(0, MAX_CONTENT_LENGTH) + '...'
      : m.content;
    lines.push(`- **${m.title}**: ${content}`);
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

    if (config.proactiveRecall !== true) {
      process.exit(0);
    }

    const hookData = JSON.parse(input || '{}');
    const rawPrompt = hookData.prompt || '';
    const cwd = hookData.cwd || process.cwd();

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
    const memories = recallRelevant(db, project, prompt);
    db.close();

    if (memories.length === 0) {
      process.exit(0);
    }

    const context = formatRecallContext(memories);

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
