#!/usr/bin/env node
/**
 * Pre-compact hook for ShieldCortex - Automatic Memory Extraction
 *
 * This script runs before context compaction and:
 * 1. Analyzes conversation content for important information
 * 2. Auto-extracts high-salience items (decisions, patterns, errors, etc.)
 * 3. Saves them to the memory database automatically
 * 4. Creates a session marker for continuity
 *
 * The goal: Never lose important context during compaction.
 */

import Database from 'better-sqlite3';
import { mkdirSecure } from './lib/state-perms.mjs';
import { existsSync, mkdirSync, readdirSync, statSync } from 'fs';
import { join } from 'path';
import { homedir } from 'os';
import { encodeClaudeProjectDir } from './lib/claude-project-dir.mjs';
import { saveAutoExtractedMemory } from './lib/save-memory.mjs';
import { readTranscriptText } from './lib/transcript-reader.mjs';
import { getAutoMemoryConfig } from './lib/auto-memory-config.mjs';
import { recordHookInvocation } from './lib/telemetry.mjs';
import { deriveProjectKey } from './lib/project-key.mjs';
import { recordSessionEvent } from './lib/session-capture.mjs';
import { writePrecompactLog } from './lib/precompact-log.mjs';
import {
  extractMemorableSegments,
  processSegments,
  PRE_COMPACT_CATEGORY_THRESHOLDS,
} from './lib/extract-memorable-segments.mjs';

// Database paths (with legacy fallback)
const NEW_DB_DIR = join(homedir(), '.shieldcortex');
const LEGACY_DB_DIR = join(homedir(), '.claude-cortex');

// Auto-detect: use new path if it exists, or if legacy doesn't exist (new install)
function getDbPath() {
  const newPath = join(NEW_DB_DIR, 'memories.db');
  const legacyPath = join(LEGACY_DB_DIR, 'memories.db');
  if (existsSync(newPath) || !existsSync(legacyPath)) {
    return { dir: NEW_DB_DIR, path: newPath };
  }
  return { dir: LEGACY_DB_DIR, path: legacyPath };
}

const { dir: DB_DIR, path: DB_PATH } = getDbPath();

// Memory limits (should match src/memory/types.ts DEFAULT_CONFIG)
const MAX_SHORT_TERM_MEMORIES = 100;
const MAX_LONG_TERM_MEMORIES = 1000;

// Maximum memories to auto-create per compaction.
// Dropped 5 → 2 in v4.11.0 for the same reason thresholds were raised.
const MAX_AUTO_MEMORIES = 2;

// Pre-compact uses tighter category thresholds (raised +0.10 in v4.11.0)
// — see PRE_COMPACT_CATEGORY_THRESHOLDS in scripts/lib/extract-memorable-segments.mjs.

// ==================== DYNAMIC THRESHOLD CALCULATION ====================

/**
 * Get current memory stats from database
 */
function getMemoryStats(db) {
  try {
    const stats = db.prepare(`
      SELECT
        COUNT(*) as total,
        SUM(CASE WHEN type = 'short_term' THEN 1 ELSE 0 END) as shortTerm,
        SUM(CASE WHEN type = 'long_term' THEN 1 ELSE 0 END) as longTerm
      FROM memories
    `).get();
    return stats || { total: 0, shortTerm: 0, longTerm: 0 };
  } catch {
    return { total: 0, shortTerm: 0, longTerm: 0 };
  }
}

/**
 * Calculate dynamic threshold based on memory fullness
 * When memory is full, be more selective. When sparse, be more permissive.
 * Lowered thresholds to capture more content.
 */
function getDynamicThreshold(memoryCount, maxMemories) {
  const fullness = memoryCount / maxMemories;

  // More selective when memory is full, more permissive when sparse
  if (fullness > 0.8) return 0.50;  // Very full - highly selective
  if (fullness > 0.6) return 0.42;  // Getting full - moderately selective
  if (fullness > 0.4) return 0.35;  // Normal - standard threshold
  if (fullness > 0.2) return 0.30;  // Sparse - more permissive
  return 0.25;                       // Very sparse - accept most valuable items
}

// getExtractionThreshold lives in the shared chunker module.

// Salience detection, content extraction, and segment processing now
// live in scripts/lib/extract-memorable-segments.mjs (imported above).

// ==================== DATABASE OPERATIONS ====================

// Thin wrapper to keep the existing call sites unchanged. The actual
// write lives in scripts/lib/save-memory.mjs so pre-compact and
// session-end share one code path (and one regression test).
function saveMemory(db, memory, project) {
  return saveAutoExtractedMemory(db, memory, project, { source: 'pre-compact-hook' });
}


// ==================== MAIN HOOK LOGIC ====================

let input = '';
process.stdin.setEncoding('utf8');

process.stdin.on('readable', () => {
  let chunk;
  while ((chunk = process.stdin.read()) !== null) {
    input += chunk;
  }
});

process.stdin.on('end', async () => {
  const startedAt = Date.now();
  let db = null;
  let autoExtractedCount = 0;
  let bytesRead = 0;
  let exitCode = 0;
  let notes = null;
  try {
    const hookData = JSON.parse(input || '{}');

    const trigger = hookData.trigger || 'unknown';
    const project = deriveProjectKey(hookData.cwd);
    const autoMemConfig = getAutoMemoryConfig();

    // Extract conversation text from hook data
    // Claude Code passes conversation in various formats
    const conversationOut = extractConversationText(hookData, autoMemConfig);
    const conversationText = conversationOut.text;
    bytesRead = conversationOut.bytesRead;

    // Ensure database directory exists
    if (!existsSync(DB_DIR)) {
      mkdirSecure(DB_DIR);
    }

    // Check if database exists
    if (!existsSync(DB_PATH)) {
      console.error('[pre-compact] Memory database not found, skipping auto-extraction');
      outputReminder(0, BASE_THRESHOLD);
      notes = 'no-database';
      process.exit(0);
    }

    // Connect to database with timeout to handle concurrent access
    // timeout: 5000ms prevents hook from hanging if DB is locked
    db = new Database(DB_PATH, { timeout: 5000 });

    // ── Session capture (v4.17): mark the compaction boundary in the
    //    replay timeline. Reuses the already-open write connection so
    //    no extra better-sqlite3 handle is created.
    {
      const sessionId = hookData.session_id || hookData.sessionId || null;
      if (sessionId) {
        try {
          recordSessionEvent(db, {
            session_id: sessionId,
            ts: new Date().toISOString(),
            kind: 'hook_fire',
            payload: { hook: 'pre-compact', trigger, transcript_path: hookData.transcript_path ?? null },
            project: project || null,
          });
        } catch { /* best-effort */ }
      }
    }

    // Get current memory stats for dynamic threshold calculation
    const stats = getMemoryStats(db);
    const totalMemories = stats.shortTerm + stats.longTerm;
    const maxMemories = MAX_SHORT_TERM_MEMORIES + MAX_LONG_TERM_MEMORIES;
    const dynamicThreshold = getDynamicThreshold(totalMemories, maxMemories);

    console.error(`[auto-extract] Memory status: ${totalMemories}/${maxMemories} (${(totalMemories/maxMemories*100).toFixed(0)}% full)`);
    console.error(`[auto-extract] Dynamic threshold: ${dynamicThreshold.toFixed(2)}`);

    // Only attempt extraction if we have conversation content
    let precompactCandidates = [];
    let rawSegmentCount = 0;
    if (conversationText && conversationText.length > 100) {
      // Extract memorable segments
      const segments = extractMemorableSegments(conversationText);
      rawSegmentCount = segments.length;
      const processedSegments = processSegments(segments, dynamicThreshold, {
        maxMemories: MAX_AUTO_MEMORIES,
        categoryThresholds: PRE_COMPACT_CATEGORY_THRESHOLDS,
        conversationText,
      });

      // Save auto-extracted memories
      for (const memory of processedSegments) {
        // v4.25.0: collect candidate metadata for the precompact ring buffer.
        // Operators read this via `shieldcortex inspect last-precompact`
        // when diagnosing why extraction did/didn't pick a particular line.
        const candidate = {
          extractorType: memory.extractorType,
          category: memory.category,
          memoryPurpose: memory.memoryPurpose,
          title: memory.title,
          salience: memory.salience,
          frequencyBoost: memory.frequencyBoost ?? 0,
          saved: false,
          error: null,
        };
        try {
          await saveMemory(db, memory, project);
          autoExtractedCount++;
          candidate.saved = true;
          const boostInfo = memory.frequencyBoost > 0 ? ` +${memory.frequencyBoost.toFixed(2)} boost` : '';
          console.error(`[auto-extract] Saved: ${memory.title} (salience: ${memory.salience.toFixed(2)}${boostInfo}, category: ${memory.category})`);
        } catch (err) {
          candidate.error = err.message;
          console.error(`[auto-extract] Failed to save "${memory.title}": ${err.message}`);
        }
        precompactCandidates.push(candidate);
      }
    } else {
      notes = 'no-content';
    }

    // v4.25.0: write the run to the rolling ring buffer at
    // ~/.shieldcortex/precompact-log/. Best-effort — never throw.
    try {
      writePrecompactLog({
        thresholdUsed: dynamicThreshold,
        contextFullnessPct: maxMemories > 0 ? Math.round((totalMemories / maxMemories) * 100) : null,
        totalMemories,
        rawSegmentCount,
        candidates: precompactCandidates,
      });
    } catch { /* best-effort */ }

    console.error(`[shieldcortex] Pre-compact complete: ${autoExtractedCount} memories auto-extracted`);

    outputReminder(autoExtractedCount, dynamicThreshold);
  } catch (error) {
    console.error(`[pre-compact] Error: ${error.message}`);
    notes = `error: ${error.message}`;
    exitCode = 0; // Don't block compaction on errors
    outputReminder(0, BASE_THRESHOLD);
  } finally {
    if (db) {
      recordHookInvocation(db, {
        hookName: 'pre-compact',
        exitCode,
        durationMs: Date.now() - startedAt,
        memoriesExtracted: autoExtractedCount,
        transcriptBytes: bytesRead,
        notes,
      });
      try { db.close(); } catch { /* ignore */ }
    }
    process.exit(exitCode);
  }
});

/**
 * Resolve the most-recently-modified JSONL transcript for the given cwd
 * (Claude Code stores sessions under ~/.claude/projects/<encoded-cwd>/).
 */
function findLatestTranscriptForCwd(cwd) {
  if (!cwd) return null;
  const projectDir = join(homedir(), '.claude', 'projects', encodeClaudeProjectDir(cwd));
  if (!existsSync(projectDir)) return null;
  let files;
  try {
    files = readdirSync(projectDir)
      .filter((f) => f.endsWith('.jsonl'))
      .map((f) => ({ name: f, mtime: statSync(join(projectDir, f)).mtimeMs }))
      .sort((a, b) => b.mtime - a.mtime);
  } catch {
    return null;
  }
  if (files.length === 0) return null;
  return join(projectDir, files[0].name);
}

/**
 * Extract conversation text from hook data, with three fallbacks:
 *   1. transcript_path supplied by Claude Code
 *   2. inline payload fields (conversation, messages, etc.)
 *   3. auto-detect latest JSONL under ~/.claude/projects/<encoded cwd>/
 *
 * Delegates JSONL parsing to scripts/lib/transcript-reader.mjs so the
 * byte-cap and slash-command rules are shared with session-end-hook.
 */
function extractConversationText(hookData, autoMemConfig) {
  const readerOpts = {
    maxBytes: autoMemConfig.maxTranscriptBytes,
    maxLines: autoMemConfig.maxTranscriptLines,
    keepSlashCommandProse: autoMemConfig.keepSlashCommandProse,
  };

  if (hookData.transcript_path) {
    const out = readTranscriptText(hookData.transcript_path, readerOpts);
    if (out.text) {
      console.error(`[auto-extract] Read ${out.messageCount} messages from transcript_path (${out.text.length} chars, ${out.bytesRead} bytes scanned)`);
      return { text: out.text, bytesRead: out.bytesRead };
    }
  }

  const sources = [
    hookData.conversation,
    hookData.messages,
    hookData.transcript,
    hookData.content,
    hookData.context,
    hookData.text,
  ];
  for (const source of sources) {
    if (typeof source === 'string' && source.length > 0) return { text: source, bytesRead: 0 };
    if (Array.isArray(source)) {
      const text = source
        .map((msg) => {
          if (typeof msg === 'string') return msg;
          if (msg.content) return msg.content;
          if (msg.text) return msg.text;
          return '';
        })
        .join('\n');
      return { text, bytesRead: 0 };
    }
  }

  const latest = findLatestTranscriptForCwd(hookData.cwd);
  if (!latest) {
    console.error('[auto-extract] No transcript located for cwd');
    return { text: '', bytesRead: 0 };
  }
  const out = readTranscriptText(latest, readerOpts);
  console.error(`[auto-extract] Read ${out.messageCount} messages from session JSONL (${out.text.length} chars, ${out.bytesRead} bytes scanned)`);
  return { text: out.text, bytesRead: out.bytesRead };
}

/**
 * Output reminder message to stdout.
 * v4.11.0: preamble instructions removed. The memories themselves are the
 * signal; repeating "use remember proactively" every compaction just eats
 * context. The one-line status note is kept for human visibility when the
 * hook runs interactively.
 */
function outputReminder(autoExtractedCount, dynamicThreshold) {
  if (autoExtractedCount > 0) {
    console.log(`\n🧠 AUTO-MEMORY: ${autoExtractedCount} item(s) saved before compaction.`);
  }
  // No stdout when nothing was extracted — silence is cheaper than chatter.
}
