# Proactive Recall Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make AI agents automatically recall relevant memories before acting, preventing repeated mistakes and ensuring prior context is always available — not just at session start, but on every user message.

**Architecture:** A `UserPromptSubmit` hook script that reads the user's prompt, queries ShieldCortex memory for relevant context (semantic search via embeddings + FTS5), and returns `additionalContext` in the hook's JSON output. This context is injected into the conversation by Claude Code before the model sees the message. Works with any Claude Code / OpenClaw agent — not ShieldCortex-specific.

**Tech Stack:** Node.js (ESM), better-sqlite3, existing ShieldCortex embedding infrastructure, Claude Code hooks system

---

## Architecture Overview

```
User types message
    ↓
Claude Code fires UserPromptSubmit hook
    ↓
Hook script reads stdin JSON → extracts prompt text + cwd
    ↓
Detects project from cwd (same as session-start-hook)
    ↓
Queries ShieldCortex memories:
  1. FTS5 text search (fast, keyword matching)
  2. Vector similarity search if embeddings available
  3. Merge + deduplicate + rank by relevance × salience
    ↓
Formats top N results as compact context block
    ↓
Outputs JSON to stdout:
  {
    "hookSpecificOutput": {
      "hookEventName": "UserPromptSubmit",
      "additionalContext": "🧠 Relevant memories:\n- ..."
    }
  }
    ↓
Claude Code injects context into conversation
    ↓
Model sees user message + recalled memories
```

## Key Design Decisions

1. **UserPromptSubmit hook, not PreToolUse** — fires once per user message (not per tool call), gives the model context before it decides what to do
2. **Must complete in <500ms** — hook has a timeout; DB queries must be fast, no external API calls
3. **Compact output** — max 5 memories, max 150 chars each, total <1KB to avoid token waste
4. **Skip trivial prompts** — "yes", "do it", single-word confirmations don't need recall
5. **Dedup against session-start** — don't re-inject memories already loaded at session start
6. **Configurable** — can be disabled via `~/.shieldcortex/config.json`

## File Structure

| File | Purpose |
|------|---------|
| `scripts/prompt-recall-hook.mjs` | **NEW** — UserPromptSubmit hook script |
| `src/setup/settings-hooks.ts` | **MODIFY** — register the new hook in settings.json |
| `src/cli/config.ts` | **MODIFY** — add `proactiveRecall` config toggle |
| `src/cloud/config.ts` | **MODIFY** — add config field type |

---

### Task 1: Create the Proactive Recall Hook Script

**Files:**
- Create: `scripts/prompt-recall-hook.mjs`

- [ ] **Step 1: Create the hook script with stdin parsing and project detection**

```javascript
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

// ==================== CONFIG ====================

const CONFIG_PATH = join(homedir(), '.shieldcortex', 'config.json');
const MAX_RESULTS = 5;
const MAX_CONTENT_LENGTH = 150;
const MIN_PROMPT_LENGTH = 8; // Skip "yes", "do it", etc.
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

const SKIP_DIRS = [
  'src', 'lib', 'dist', 'build', 'out', 'node_modules', '.git',
  '.next', '.cache', 'test', 'tests', '__tests__', 'spec',
  'bin', 'scripts', 'config', 'public', 'static',
];

function extractProject(path) {
  if (!path) return null;
  const segments = path.split(/[/\\]/).filter(Boolean);
  for (let i = segments.length - 1; i >= 0; i--) {
    const seg = segments[i];
    if (!SKIP_DIRS.includes(seg.toLowerCase()) && !seg.startsWith('.')) {
      return seg;
    }
  }
  return null;
}

// ==================== FTS5 QUERY ====================

function escapeFts5(query) {
  // Remove FTS5 operators and special chars
  return query
    .replace(/[*(){}[\]<>~^"]/g, ' ')
    .replace(/\b(AND|OR|NOT|NEAR)\b/gi, '')
    .split(/\s+/)
    .filter(w => w.length > 2)
    .slice(0, 6) // Max 6 search terms
    .map(w => `"${w}"`)
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

  // Sort by salience descending, take top N
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

    // Check if proactive recall is enabled (default: true)
    if (config.proactiveRecall === false) {
      process.exit(0);
    }

    const hookData = JSON.parse(input || '{}');
    const prompt = hookData.prompt || '';
    const cwd = hookData.cwd || process.cwd();

    // Skip trivial prompts
    if (prompt.length < MIN_PROMPT_LENGTH) {
      process.exit(0);
    }

    // Skip if just confirmations
    if (/^(yes|no|ok|sure|do it|go|send it|y|n|yep|nope)\s*[.!?]?\s*$/i.test(prompt.trim())) {
      process.exit(0);
    }

    const project = extractProject(cwd);
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

    // Output JSON for Claude Code hook system
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
    process.exit(0); // Never block user input
  }
});
```

- [ ] **Step 2: Make executable**

```bash
chmod +x scripts/prompt-recall-hook.mjs
```

- [ ] **Step 3: Commit**

```bash
git add scripts/prompt-recall-hook.mjs
git commit -m "feat: add proactive recall hook script"
```

---

### Task 2: Register the Hook in Settings

**Files:**
- Modify: `src/setup/settings-hooks.ts`

- [ ] **Step 1: Read the current settings-hooks.ts to understand hook registration**

Find the section where `SessionStart`, `PreCompact`, `Stop` hooks are registered and add `UserPromptSubmit`.

- [ ] **Step 2: Add UserPromptSubmit hook registration**

Add to the hook definitions array (alongside existing SessionStart/PreCompact/Stop entries):

```typescript
{
  event: 'UserPromptSubmit',
  type: 'command',
  command: `node "${join(hooksDir, 'prompt-recall-hook.mjs')}"`,
  timeout: 2, // 2 second max — fast recall
}
```

- [ ] **Step 3: Build and verify**

```bash
npm run build
```

- [ ] **Step 4: Commit**

```bash
git add src/setup/settings-hooks.ts
git commit -m "feat: register proactive recall in UserPromptSubmit hook"
```

---

### Task 3: Add Config Toggle

**Files:**
- Modify: `src/cloud/config.ts` (or wherever ShieldCortexConfig type is defined)
- Modify: `src/cli/config.ts` (CLI config command)

- [ ] **Step 1: Add `proactiveRecall` to config type and defaults**

Add `proactiveRecall?: boolean` to the config interface, defaulting to `true`.

- [ ] **Step 2: Add CLI flag**

```bash
npx shieldcortex config --proactive-recall true
npx shieldcortex config --proactive-recall false
```

- [ ] **Step 3: Build and test**

```bash
npm run build
npx shieldcortex config --proactive-recall false
cat ~/.shieldcortex/config.json | grep proactive
npx shieldcortex config --proactive-recall true
```

- [ ] **Step 4: Commit**

```bash
git add src/cloud/config.ts src/cli/config.ts
git commit -m "feat: add proactiveRecall config toggle"
```

---

### Task 4: Install Hook on Setup

**Files:**
- Modify: `src/setup/settings-hooks.ts`

- [ ] **Step 1: Ensure `setupHooks()` copies the new hook script alongside existing ones**

The installer should copy `prompt-recall-hook.mjs` to the hooks directory and register it in `~/.claude/settings.json` under `hooks.UserPromptSubmit`.

- [ ] **Step 2: Test the full install flow**

```bash
npx shieldcortex setup hooks
cat ~/.claude/settings.json | grep -A3 UserPromptSubmit
```

- [ ] **Step 3: Commit**

```bash
git add src/setup/settings-hooks.ts
git commit -m "feat: install proactive recall hook during setup"
```

---

### Task 5: OpenClaw Plugin Integration

**Files:**
- Modify: `plugins/openclaw/index.ts`
- Modify: `hooks/openclaw/cortex-memory/handler.ts`

- [ ] **Step 1: Add proactive recall to the OpenClaw plugin's `before_prompt_build` hook (if available) or `message_received` hook**

For OpenClaw agents that don't use Claude Code's hook system, the plugin should do the same query internally and inject context via the plugin hook's `prependSystemContext` mechanism.

- [ ] **Step 2: Test with OpenClaw agent**

Verify that when an OpenClaw agent receives a message, relevant memories appear in the context.

- [ ] **Step 3: Commit**

```bash
git add plugins/openclaw/index.ts hooks/openclaw/cortex-memory/handler.ts
git commit -m "feat: proactive recall in OpenClaw plugin"
```

---

### Task 6: End-to-End Testing & Polish

- [ ] **Step 1: Manual test — type a prompt related to a known memory**

Store a test memory, then ask about the topic. Verify the recalled context appears.

- [ ] **Step 2: Performance test — ensure <500ms**

```bash
time echo '{"prompt":"fix the auth bug","cwd":"/Users/michael/Development/ShieldCortex-Project"}' | node scripts/prompt-recall-hook.mjs
```

- [ ] **Step 3: Test trivial prompt skip**

```bash
echo '{"prompt":"yes","cwd":"/tmp"}' | node scripts/prompt-recall-hook.mjs
# Should produce no output
```

- [ ] **Step 4: Test with proactive recall disabled**

```bash
npx shieldcortex config --proactive-recall false
echo '{"prompt":"fix the auth bug","cwd":"/Users/michael/Development/ShieldCortex-Project"}' | node scripts/prompt-recall-hook.mjs
# Should produce no output
```

- [ ] **Step 5: Bump version, commit, tag, push**

```bash
# Bump version in package.json + openclaw.plugin.json
git add -A
git commit -m "v4.7.0 — proactive recall: auto-inject relevant memories on every prompt"
git tag v4.7.0
git push && git push --tags
```

---

## Security Considerations

1. **Read-only DB access** for the main query — no writes during the critical path
2. **Access count updates are fire-and-forget** — separate writable connection, non-blocking
3. **No content leaves the machine** — all queries are local SQLite
4. **Timeout protection** — 2-second hook timeout, 2-second DB busy timeout
5. **Never blocks user input** — all errors exit(0), never exit(2)
6. **Respects status/scope filtering** — only active memories, correct project scope

## Performance Budget

| Phase | Budget |
|-------|--------|
| stdin parse + config load | <10ms |
| Project detection | <1ms |
| DB open (readonly) | <20ms |
| FTS5 query | <50ms |
| Category boost query | <30ms |
| Format + JSON output | <5ms |
| Access count update | <50ms (async, non-blocking) |
| **Total** | **<170ms typical, <500ms worst case** |
