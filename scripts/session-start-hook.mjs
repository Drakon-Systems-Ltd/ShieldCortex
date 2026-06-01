#!/usr/bin/env node
/**
 * Session Start Hook for ShieldCortex - Auto-Recall Context
 *
 * Fires on Claude Code session boot. Emits project-scoped memory context so
 * the model starts with relevant knowledge.
 *
 * Behaviour (resolves issues #27 / #28 / #29):
 *   - Only emits output when `source === 'startup'`. On `resume`, `compact`,
 *     and `clear` the hook exits silently — those transitions should not
 *     re-paste the banner into context (that was the "amnesia every other
 *     message" bug in v4.10.4).
 *   - The proactive-memory nag block is now opt-in via config
 *     (`sessionStart.preamble`: 'full' | 'minimal' | 'off'). Default is
 *     'minimal' — one line instead of 13 — because CLAUDE.md already carries
 *     the long-form instructions and repeating them burns context.
 *   - Project key is derived via the shared helper (git origin → config alias
 *     → cwd basename) so sibling repos under one workspace resolve together.
 */

import Database from 'better-sqlite3';
import { existsSync, readFileSync } from 'fs';
import { join } from 'path';
import { homedir } from 'os';
import { deriveProjectKey } from './lib/project-key.mjs';
import { truncatePreservingWords } from './lib/truncate.mjs';
import { orderByEffectiveSalience } from './lib/session-context.mjs';

const NEW_DB_DIR = join(homedir(), '.shieldcortex');
const LEGACY_DB_DIR = join(homedir(), '.claude-cortex');
const CONFIG_PATH = join(homedir(), '.shieldcortex', 'config.json');

function getDbPath() {
  const newPath = join(NEW_DB_DIR, 'memories.db');
  const legacyPath = join(LEGACY_DB_DIR, 'memories.db');
  if (existsSync(newPath) || !existsSync(legacyPath)) {
    return { dir: NEW_DB_DIR, path: newPath };
  }
  return { dir: LEGACY_DB_DIR, path: legacyPath };
}

const { path: DB_PATH } = getDbPath();

// Reduced 15 → 5 in v4.11.0. Each memory is 100–400 tokens; 15 of them was
// 500–2000 tokens of boot-time context pollution. Five high-salience items
// is enough to jog a returning session without eating the window.
const MAX_CONTEXT_MEMORIES = 5;
const MIN_SALIENCE_THRESHOLD = 0.3;

// Sources Claude Code passes on SessionStart. Only 'startup' should trigger
// the full banner; the rest would re-paste it after every resume/compact.
const EMITTING_SOURCES = new Set(['startup']);

function loadConfig() {
  try {
    if (!existsSync(CONFIG_PATH)) return {};
    return JSON.parse(readFileSync(CONFIG_PATH, 'utf-8'));
  } catch {
    return {};
  }
}

function preambleFor(mode) {
  if (mode === 'off') return '';
  if (mode === 'full') {
    return `
## IMPORTANT: Proactive Memory Use

You have access to a persistent memory system. Use it proactively:

**ALWAYS use \`remember\` immediately when:**
- Making architecture/design decisions
- Fixing bugs (capture the root cause and solution)
- Learning something new about the codebase
- User states a preference
- Completing significant features

**Don't wait** - call \`remember\` right after the event, not at the end of the session.
`;
  }
  // Default: minimal — one line, no ghost-tool drumbeat.
  return '\n_Memory tools available — capture decisions, bug fixes, and preferences as they happen._\n';
}

function getProjectContext(db, project) {
  const memories = [];

  // Over-fetch a candidate pool (raw salience is a stable pre-filter), then
  // rank by *effective* salience in JS and slice. Widening the SQL LIMIT past
  // MAX gives the effective-salience sort room to promote a fresher/more-active
  // row over a higher raw-salience one *within the candidate window* — it is a
  // pragmatic widening, not a guarantee that every deep-tail row is reconsidered.
  // The projected pinned/access_count/last_accessed/downvote_count columns feed
  // computeEffectiveSalience.
  const candidates = db.prepare(`
    SELECT id, title, content, category, type, salience, tags, created_at,
           pinned, access_count, last_accessed, COALESCE(downvote_count, 0) AS downvote_count
    FROM memories
    WHERE (project = ? OR project IS NULL)
      AND salience >= ?
      AND type IN ('long_term', 'episodic')
    ORDER BY salience DESC, last_accessed DESC
    LIMIT ?
  `).all(project, MIN_SALIENCE_THRESHOLD, MAX_CONTEXT_MEMORIES * 8);

  const ranked = orderByEffectiveSalience(candidates).slice(0, MAX_CONTEXT_MEMORIES);

  memories.push(...ranked);

  if (memories.length < MAX_CONTEXT_MEMORIES) {
    const excludeIds = memories.map(m => m.id);
    const placeholders = excludeIds.length > 0 ? excludeIds.map(() => '?').join(',') : '0';
    const recent = db.prepare(`
      SELECT id, title, content, category, type, salience, tags, created_at
      FROM memories
      WHERE (project = ? OR project IS NULL)
        AND id NOT IN (${placeholders})
      ORDER BY created_at DESC
      LIMIT ?
    `).all(project, ...excludeIds, MAX_CONTEXT_MEMORIES - memories.length);

    memories.push(...recent);
  }

  return memories;
}

function formatContext(memories, project) {
  if (memories.length === 0) return null;

  const lines = [`# Project Context: ${project}`, ''];
  const byCategory = {};
  for (const mem of memories) {
    const cat = mem.category || 'note';
    if (!byCategory[cat]) byCategory[cat] = [];
    byCategory[cat].push(mem);
  }

  const categoryOrder = ['architecture', 'pattern', 'preference', 'error', 'context', 'learning', 'note', 'todo'];

  for (const cat of categoryOrder) {
    if (!byCategory[cat] || byCategory[cat].length === 0) continue;

    const categoryTitle = cat.charAt(0).toUpperCase() + cat.slice(1);
    lines.push(`## ${categoryTitle}`);

    for (const mem of byCategory[cat]) {
      const salience = Math.round(mem.salience * 100);
      lines.push(`- **${mem.title}** (${salience}% salience)`);
      const content = truncatePreservingWords(mem.content, 200);
      lines.push(`  ${content}`);
    }
    lines.push('');
  }

  return lines.join('\n');
}

function checkProjectInstructionFiles(cwd) {
  const warnings = [];

  const filesToCheck = [
    { path: '.cursorrules', name: '.cursorrules' },
    { path: '.windsurfrules', name: '.windsurfrules' },
    { path: '.clinerules', name: '.clinerules' },
    { path: '.github/copilot-instructions.md', name: 'copilot-instructions.md' },
  ];

  const suspiciousPatterns = [
    { pattern: /ignore\s+(all\s+)?(safety|security|permission)/i, label: 'safety bypass' },
    { pattern: /bypass\s+(the\s+)?(sandbox|permission|safety)/i, label: 'sandbox bypass' },
    { pattern: /disable\s+(the\s+)?(firewall|security|protection)/i, label: 'security disable' },
    { pattern: /curl\s+[\s\S]{0,100}-d\s+[\s\S]{0,100}https?:/i, label: 'data exfiltration' },
    { pattern: /read\s+[\s\S]{0,50}~\/\.ssh/i, label: 'SSH key access' },
    { pattern: /read\s+[\s\S]{0,50}~\/\.aws/i, label: 'AWS credential access' },
    { pattern: /<!--[\s\S]{0,500}?(always|never|must|execute|run|send)[\s\S]{0,500}?-->/i, label: 'hidden HTML instruction' },
    { pattern: /echo\s+[\s\S]{0,100}>\s*\//i, label: 'file write instruction' },
    { pattern: /dangerouslyDisableSandbox/i, label: 'sandbox disable flag' },
  ];

  for (const file of filesToCheck) {
    const fullPath = join(cwd, file.path);
    if (!existsSync(fullPath)) continue;

    try {
      const content = readFileSync(fullPath, 'utf-8');
      for (const { pattern, label } of suspiciousPatterns) {
        if (pattern.test(content)) {
          warnings.push(`${file.name}: suspicious pattern detected (${label})`);
          break;
        }
      }
    } catch {
      // skip unreadable
    }
  }

  return warnings;
}

let input = '';
process.stdin.setEncoding('utf8');

process.stdin.on('readable', () => {
  let chunk;
  while ((chunk = process.stdin.read()) !== null) {
    input += chunk;
  }
});

process.stdin.on('end', () => {
  try {
    const hookData = JSON.parse(input || '{}');
    const source = typeof hookData.source === 'string' ? hookData.source : 'startup';

    if (!EMITTING_SOURCES.has(source)) {
      console.error(`[shieldcortex] Session start: source=${source} — skipping banner`);
      process.exit(0);
    }

    const cwd = hookData.cwd || process.cwd();
    const project = deriveProjectKey(cwd);

    if (!project) {
      process.exit(0);
    }

    const config = loadConfig();
    // v4.11.0: default preamble off. The memory list is the signal — prescriptive
    // "use remember proactively" text is drumbeat noise. Opt in via
    // config.sessionStart.preamble = 'minimal' | 'full'.
    const preambleMode = config.sessionStart?.preamble ?? 'off';
    const preamble = preambleFor(preambleMode);

    let memories = [];
    let context = null;
    if (!existsSync(DB_PATH)) {
      console.error('[shieldcortex] Memory database not found, skipping context retrieval');
    } else {
      const db = new Database(DB_PATH, { readonly: true, timeout: 5000 });
      memories = getProjectContext(db, project);
      context = formatContext(memories, project);
      db.close();
    }

    if (context) {
      console.log(`
🧠 SHIELDCORTEX - Project "${project}"

${context}${preamble}`);
      console.error(`[shieldcortex] Session start: loaded ${memories.length} memories for "${project}"`);
    } else {
      // No memories — only emit a banner when the preamble mode asks for one.
      // 'off' and 'minimal' stay silent here; the banner was the primary source
      // of context pollution in the #27 bug and there's no context to load.
      if (preambleMode === 'full') {
        console.log(`
🧠 SHIELDCORTEX - New project "${project}"

No stored memories yet for this project.${preamble}`);
      }
      console.error(`[shieldcortex] Session start: no memories found for "${project}"`);
    }

    try {
      const skillWarnings = checkProjectInstructionFiles(cwd);
      if (skillWarnings.length > 0) {
        console.log(`\n⚠️  ShieldCortex detected suspicious instruction files:`);
        for (const w of skillWarnings) console.log(`  - ${w}`);
        console.log(`Run \`shieldcortex scan-skills\` for a full report.\n`);
        console.error(`[shieldcortex] WARNING: ${skillWarnings.length} suspicious file(s) detected`);
      }
    } catch {
      // best-effort
    }

    process.exit(0);
  } catch (error) {
    console.error(`[session-start] Error: ${error.message}`);
    process.exit(0);
  }
});
