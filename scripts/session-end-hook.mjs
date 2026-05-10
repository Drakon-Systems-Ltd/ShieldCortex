#!/usr/bin/env node
/**
 * Session-end hook for ShieldCortex - Automatic Memory Extraction on Exit
 *
 * This script runs when a Claude Code session ends and:
 * 1. Reads the session transcript from the JSONL file
 * 2. Analyzes conversation content for important information
 * 3. Auto-extracts high-salience items (decisions, patterns, errors, etc.)
 * 4. Saves them to the memory database automatically
 *
 * NOTE: SessionEnd doesn't always fire reliably (e.g. terminal killed, SSH drops).
 * PreCompact remains the primary safety net for context preservation.
 *
 * Input (stdin JSON):
 * {
 *   "session_id": "abc123",
 *   "transcript_path": "~/.claude/projects/.../abc.jsonl",
 *   "cwd": "/path/to/project",
 *   "hook_event_name": "SessionEnd",
 *   "reason": "exit" | "clear" | "logout" | "prompt_input_exit" | "other"
 * }
 */

import Database from 'better-sqlite3';
import { existsSync, mkdirSync } from 'fs';
import { join } from 'path';
import { homedir } from 'os';
import { saveAutoExtractedMemory } from './lib/save-memory.mjs';
import { readTranscriptText } from './lib/transcript-reader.mjs';
import { getAutoMemoryConfig } from './lib/auto-memory-config.mjs';
import { recordHookInvocation } from './lib/telemetry.mjs';
import { deriveProjectKey } from './lib/project-key.mjs';
import {
  extractMemorableSegments,
  processSegments,
} from './lib/extract-memorable-segments.mjs';

// Database paths (with legacy fallback)
const NEW_DB_DIR = join(homedir(), '.shieldcortex');
const LEGACY_DB_DIR = join(homedir(), '.claude-cortex');

function getDbPath() {
  const newPath = join(NEW_DB_DIR, 'memories.db');
  const legacyPath = join(LEGACY_DB_DIR, 'memories.db');
  if (existsSync(newPath) || !existsSync(legacyPath)) {
    return { dir: NEW_DB_DIR, path: newPath };
  }
  return { dir: LEGACY_DB_DIR, path: legacyPath };
}

const { dir: DB_DIR, path: DB_PATH } = getDbPath();

// Memory limits
const MAX_SHORT_TERM_MEMORIES = 100;
const MAX_LONG_TERM_MEMORIES = 1000;

// ==================== DYNAMIC THRESHOLD ====================

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

function getDynamicThreshold(memoryCount, maxMemories) {
  const fullness = memoryCount / maxMemories;
  if (fullness > 0.8) return 0.50;
  if (fullness > 0.6) return 0.42;
  if (fullness > 0.4) return 0.35;
  if (fullness > 0.2) return 0.30;
  return 0.25;
}

// Salience detection, content extraction, and segment processing now
// live in scripts/lib/extract-memorable-segments.mjs (imported above).

// ==================== DATABASE OPERATIONS ====================

// Thin wrapper that stamps this hook's source identifier so defence_audit
// rows are attributable. saveAutoExtractedMemory is async (it loads the
// dist'd pipeline lazily and routes through it).
function saveMemory(db, memory, project) {
  return saveAutoExtractedMemory(db, memory, project, { source: 'session-end-hook' });
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

function looksLikeOpenClawContext() {
  // OpenClaw spawns Claude Code agents as subprocesses. When SessionEnd fires
  // inside that subprocess, the OpenClaw runtime has often already torn down
  // shared state (lock files, IPC channels) — extracting from there has caused
  // fatal failures historically (settings-hooks.ts:23-25). Detect via env.
  if (process.env.OPENCLAW_AGENT_ID) return true;
  if (process.env.OPENCLAW_SESSION_ID) return true;
  if (process.env.OPENCLAW_PARENT_PID) return true;
  if (typeof process.env.OPENCLAW === 'string' && process.env.OPENCLAW.length > 0) return true;
  return false;
}

process.stdin.on('end', async () => {
  const startedAt = Date.now();
  let db = null;
  let autoExtractedCount = 0;
  let bytesRead = 0;
  let notes = null;
  try {
    const hookData = JSON.parse(input || '{}');

    const reason = hookData.reason || 'unknown';
    const project = deriveProjectKey(hookData.cwd);
    const autoMemConfig = getAutoMemoryConfig();

    // Config gate: opt-in (default off). Preserves the historical default
    // that protected OpenClaw users. We exit before touching the DB so a
    // disabled hook never opens better-sqlite3 — telemetry stays silent too.
    if (!autoMemConfig.enableSessionEnd) {
      console.error('[session-end] Disabled by config (autoMemory.enableSessionEnd=false)');
      process.exit(0);
    }

    // OpenClaw subprocess guard (extra defence on top of the config gate).
    if (looksLikeOpenClawContext()) {
      console.error('[session-end] OpenClaw context detected, skipping extraction');
      process.exit(0);
    }

    // Skip extraction on /clear — session is being intentionally wiped
    if (reason === 'clear') {
      console.error('[session-end] Session cleared, skipping extraction');
      notes = 'reason=clear';
      // fall through to telemetry record so 'fired but skipped' is visible
    } else {
      // Read conversation from transcript_path (provided by Claude Code)
      const transcriptOut = readTranscriptText(hookData.transcript_path, {
        maxBytes: autoMemConfig.maxTranscriptBytes,
        maxLines: autoMemConfig.maxTranscriptLines,
        keepSlashCommandProse: autoMemConfig.keepSlashCommandProse,
      });
      const conversationText = transcriptOut.text;
      bytesRead = transcriptOut.bytesRead;
      if (transcriptOut.messageCount > 0) {
        console.error(`[session-end] Read ${transcriptOut.messageCount} messages from transcript (${conversationText.length} chars, ${bytesRead} bytes scanned)`);
      }

      if (conversationText && conversationText.length >= 100) {
        // Ensure database directory exists
        if (!existsSync(DB_DIR)) {
          mkdirSync(DB_DIR, { recursive: true });
        }

        if (!existsSync(DB_PATH)) {
          console.error('[session-end] Memory database not found, skipping extraction');
          notes = 'no-database';
          process.exit(0);
        }

        db = new Database(DB_PATH, { timeout: 5000 });

        const stats = getMemoryStats(db);
        const totalMemories = stats.shortTerm + stats.longTerm;
        const maxMemories = MAX_SHORT_TERM_MEMORIES + MAX_LONG_TERM_MEMORIES;
        const dynamicThreshold = getDynamicThreshold(totalMemories, maxMemories);

        console.error(`[session-end] Memory status: ${totalMemories}/${maxMemories} (${(totalMemories/maxMemories*100).toFixed(0)}% full)`);
        console.error(`[session-end] Reason: ${reason}, Dynamic threshold: ${dynamicThreshold.toFixed(2)}`);

        // Extract memorable segments
        const segments = extractMemorableSegments(conversationText);
        const processedSegments = processSegments(segments, dynamicThreshold, { hookTag: 'session-end' });

        for (const memory of processedSegments) {
          try {
            await saveMemory(db, memory, project);
            autoExtractedCount++;
            const boostInfo = memory.frequencyBoost > 0 ? ` +${memory.frequencyBoost.toFixed(2)} boost` : '';
            console.error(`[session-end] Saved: ${memory.title} (salience: ${memory.salience.toFixed(2)}${boostInfo}, category: ${memory.category})`);
          } catch (err) {
            console.error(`[session-end] Failed to save "${memory.title}": ${err.message}`);
          }
        }

        console.error(`[session-end] Complete: ${autoExtractedCount} memories auto-extracted on session ${reason}`);
      } else {
        console.error('[session-end] Not enough conversation content to extract from');
        notes = 'no-content';
      }
    }
  } catch (error) {
    console.error(`[session-end] Error: ${error.message}`);
    notes = `error: ${error.message}`;
    // Don't block session exit on errors
  } finally {
    if (db) {
      recordHookInvocation(db, {
        hookName: 'session-end',
        exitCode: 0,
        durationMs: Date.now() - startedAt,
        memoriesExtracted: autoExtractedCount,
        transcriptBytes: bytesRead,
        notes,
      });
      try { db.close(); } catch { /* ignore */ }
    }
    process.exit(0);
  }
});
