#!/usr/bin/env node

/**
 * ShieldCortex — Stop Hook (sampling extractor)
 *
 * Replaces the v4.x exit-2 "nudge Claude to call remember" behaviour with
 * silent, sampled, server-side extraction:
 *
 *   - Counts assistant turns in the transcript.
 *   - Every Nth turn (default 10), runs the standard salience pipeline over
 *     the most recent window of conversation and saves any memories that
 *     clear the per-category threshold.
 *   - Always exits 0. Never blocks Claude from finishing its response.
 *
 * The transcript reader is bounded by `autoMemory.stopHookWindowBytes`
 * (default 256 KiB) to keep per-turn cost predictable.
 */

import Database from 'better-sqlite3';
import { existsSync, mkdirSync, openSync, readSync, closeSync, statSync, writeFileSync } from 'fs';
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
  PRE_COMPACT_CATEGORY_THRESHOLDS,
  ARCHITECTURE_KEYWORDS,
  ERROR_KEYWORDS,
  DECISION_KEYWORDS,
  LEARNING_KEYWORDS,
  PATTERN_KEYWORDS,
  detectKeywords,
  detectCodeReferences,
} from './lib/extract-memorable-segments.mjs';

// Sentinel directory for once-per-session "disabled" log lines. Without this
// the stop hook bails silently on every turn when autoMemory.enableStop is
// false — the user-visible symptom is "ShieldCortex never captured anything"
// with zero feedback (filed in #41 as silent-amnesia). One sentinel file
// per session keeps the log to a single line for the lifetime of the session.
const SC_LOG_DIR = join(homedir(), '.shieldcortex', 'logs');
const STOP_DISABLED_SENTINEL_DIR = join(SC_LOG_DIR, 'stop-hook-disabled-sessions');

function logDisabledOnceForSession(sessionId, reason) {
  // Always print the line — stderr is the existing channel for hook diagnostics
  // (mirrors session-end-hook). Then plant a sentinel so subsequent fires in
  // the same session stay quiet.
  if (!sessionId) {
    console.error(`[shieldcortex stop-hook] ${reason}`);
    return;
  }
  try {
    mkdirSync(STOP_DISABLED_SENTINEL_DIR, { recursive: true });
    const sentinel = join(STOP_DISABLED_SENTINEL_DIR, sessionId.replace(/[^a-zA-Z0-9_.-]/g, '_'));
    if (existsSync(sentinel)) return;
    writeFileSync(sentinel, new Date().toISOString(), { mode: 0o600 });
    console.error(`[shieldcortex stop-hook] ${reason}`);
  } catch {
    // Sentinel write failed — fall back to printing once per fire rather than
    // staying silent. Better noisy-but-discoverable than silent-amnesia.
    console.error(`[shieldcortex stop-hook] ${reason}`);
  }
}

// ==================== DB ====================

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

// Memory limits (kept in sync with pre-compact)
const MAX_SHORT_TERM_MEMORIES = 100;
const MAX_LONG_TERM_MEMORIES = 1000;
const MAX_AUTO_MEMORIES = 2;
// Stop-hook uses pre-compact's tighter category thresholds — see
// PRE_COMPACT_CATEGORY_THRESHOLDS in scripts/lib/extract-memorable-segments.mjs.

// Salience detection, content extraction, and segment processing live in
// scripts/lib/extract-memorable-segments.mjs. Stop-hook uses the lighter
// 'stop' extractor set (no architecture / important-note) for backward
// compatibility with its pre-refactor behaviour.

function getMemoryStats(db) {
  try {
    return db.prepare(`
      SELECT
        SUM(CASE WHEN type='short_term' THEN 1 ELSE 0 END) AS shortTerm,
        SUM(CASE WHEN type='long_term' THEN 1 ELSE 0 END) AS longTerm
      FROM memories
    `).get() || { shortTerm: 0, longTerm: 0 };
  } catch { return { shortTerm: 0, longTerm: 0 }; }
}

function getDynamicThreshold(count, max) {
  const f = count / max;
  if (f > 0.8) return 0.50;
  if (f > 0.6) return 0.42;
  if (f > 0.4) return 0.35;
  if (f > 0.2) return 0.30;
  return 0.25;
}

// ==================== TRANSCRIPT PEEK (cheap, partial-read) ====================

/**
 * Read the last `windowBytes` of the transcript as raw text and count
 * assistant-role markers. Used for both the modulo sampling gate and the
 * salience-bypass probe — one disk read serves both decisions.
 */
function peekRecentTranscript(transcriptPath, windowBytes) {
  if (!transcriptPath) return { turnCount: 0, raw: '' };
  const resolved = transcriptPath.replace(/^~/, homedir());
  if (!existsSync(resolved)) return { turnCount: 0, raw: '' };
  try {
    const stat = statSync(resolved);
    const bytes = Math.min(stat.size, windowBytes);
    const fd = openSync(resolved, 'r');
    let raw;
    try {
      const buf = Buffer.alloc(bytes);
      readSync(fd, buf, 0, bytes, stat.size - bytes);
      raw = buf.toString('utf-8');
    } finally {
      closeSync(fd);
    }
    const turnCount = (raw.match(/"role":"assistant"|"type":"assistant"/g) || []).length;
    return { turnCount, raw };
  } catch {
    return { turnCount: 0, raw: '' };
  }
}

/**
 * Cheap salience probe over the recent transcript window. A turn is "salient"
 * (and worth bypassing the modulo gate for) when:
 *   - it carries a fenced code block — strong signal of code work / errors / diffs
 *   - or ≥2 keyword categories hit (architecture, error, decision, learning,
 *     pattern, code-reference)
 */
function isSalientWindow(rawText) {
  if (!rawText) return false;
  if (/```/.test(rawText)) return true;
  let hits = 0;
  if (detectKeywords(rawText, ARCHITECTURE_KEYWORDS)) hits++;
  if (detectKeywords(rawText, ERROR_KEYWORDS)) hits++;
  if (detectKeywords(rawText, DECISION_KEYWORDS)) hits++;
  if (detectKeywords(rawText, LEARNING_KEYWORDS)) hits++;
  if (detectKeywords(rawText, PATTERN_KEYWORDS)) hits++;
  if (detectCodeReferences(rawText)) hits++;
  return hits >= 2;
}

// ==================== MAIN ====================

let input = '';
process.stdin.setEncoding('utf8');
process.stdin.on('readable', () => {
  let chunk;
  while ((chunk = process.stdin.read()) !== null) input += chunk;
});

process.stdin.on('end', () => {
  const startedAt = Date.now();
  let db = null;
  let extractedCount = 0;
  let bytesRead = 0;
  let notes = null;

  try {
    let hookData = {};
    try { hookData = JSON.parse(input || '{}'); } catch { /* allow empty */ }

    if (hookData.stop_hook_active === true) {
      // Loop prevention — never re-engage from an already-engaged stop hook.
      process.exit(0);
    }

    const autoMemConfig = getAutoMemoryConfig();
    if (!autoMemConfig.enableStop) {
      // Opt-in by config. As of v4.13.1 the install flag (`--with-stop-hook`)
      // flips this gate at install time so wiring the hook and enabling it are
      // a single user action. If the gate is still false here, the user wired
      // the hook by hand without setting autoMemory.enableStop=true. Log once
      // per session so the failure is visible (was silent-amnesia in #41).
      logDisabledOnceForSession(
        hookData.session_id,
        `disabled — set autoMemory.enableStop=true in ~/.shieldcortex/config.json (or re-run \`shieldcortex setup --with-stop-hook\`)`,
      );
      process.exit(0);
    }

    const samplingTurns = autoMemConfig.stopHookSamplingTurns;
    const windowBytes = autoMemConfig.stopHookWindowBytes;
    const salienceBypassEnabled = autoMemConfig.stopHookSalienceBypass;

    // Use a smaller window for the cheap peek so off-sample turns stay fast.
    // The full extraction below still uses the configured windowBytes.
    const peekBytes = Math.min(32 * 1024, windowBytes);
    const peek = peekRecentTranscript(hookData.transcript_path, peekBytes);
    const turnCount = peek.turnCount;
    const onSample = turnCount > 0 && turnCount % samplingTurns === 0;
    const salientBypass = salienceBypassEnabled && !onSample && isSalientWindow(peek.raw);

    if (!onSample && !salientBypass) {
      // Off-sample, no salience bypass. Surface the sampling decision to stderr
      // so the "1-in-N turns" behaviour stops being invisible (#41), and still
      // record telemetry so the dashboard shows the hook is wired and active.
      console.error(`[shieldcortex stop-hook] telemetry-only turn=${turnCount}/${samplingTurns}`);
      if (existsSync(DB_PATH)) {
        try {
          const tdb = new Database(DB_PATH, { timeout: 1500 });
          recordHookInvocation(tdb, {
            hookName: 'stop',
            exitCode: 0,
            durationMs: Date.now() - startedAt,
            memoriesExtracted: 0,
            transcriptBytes: 0,
            notes: `off-sample turn=${turnCount}`,
          });
          tdb.close();
        } catch { /* ignore */ }
      }
      process.exit(0);
    }

    const project = deriveProjectKey(hookData.cwd);
    const transcriptOut = readTranscriptText(hookData.transcript_path, {
      maxBytes: windowBytes,
      maxLines: autoMemConfig.maxTranscriptLines,
      keepSlashCommandProse: autoMemConfig.keepSlashCommandProse,
    });
    bytesRead = transcriptOut.bytesRead;

    if (!transcriptOut.text || transcriptOut.text.length < 100) {
      notes = 'no-content';
      if (existsSync(DB_PATH)) {
        try {
          db = new Database(DB_PATH, { timeout: 1500 });
        } catch { db = null; }
      }
    } else {
      if (!existsSync(DB_DIR)) mkdirSync(DB_DIR, { recursive: true });
      if (!existsSync(DB_PATH)) {
        notes = 'no-database';
      } else {
        db = new Database(DB_PATH, { timeout: 5000 });
        const stats = getMemoryStats(db);
        const total = (stats.shortTerm || 0) + (stats.longTerm || 0);
        const max = MAX_SHORT_TERM_MEMORIES + MAX_LONG_TERM_MEMORIES;
        const dyn = getDynamicThreshold(total, max);

        const segments = extractMemorableSegments(transcriptOut.text, { mode: 'stop' });
        const processed = processSegments(segments, dyn, {
          hookTag: 'source:stop-hook',
          maxMemories: MAX_AUTO_MEMORIES,
          categoryThresholds: PRE_COMPACT_CATEGORY_THRESHOLDS,
          applyFrequencyBoost: false,
        });

        for (const memory of processed) {
          try {
            saveAutoExtractedMemory(db, memory, project);
            extractedCount++;
            console.error(`[stop] Saved: ${memory.title} (salience: ${memory.salience.toFixed(2)}, category: ${memory.category})`);
          } catch (err) {
            console.error(`[stop] Failed to save "${memory.title}": ${err.message}`);
          }
        }
        const sampleReason = salientBypass ? `bypass=salience turn=${turnCount}` : `turn=${turnCount}`;
        console.error(`[stop] Sampled ${sampleReason}: ${extractedCount} memories extracted`);
      }
    }
  } catch (err) {
    notes = `error: ${err.message}`;
    console.error(`[stop] Error: ${err.message}`);
  } finally {
    if (db) {
      recordHookInvocation(db, {
        hookName: 'stop',
        exitCode: 0,
        durationMs: Date.now() - startedAt,
        memoriesExtracted: extractedCount,
        transcriptBytes: bytesRead,
        notes,
      });
      try { db.close(); } catch { /* ignore */ }
    }
    process.exit(0);
  }
});
