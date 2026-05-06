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
const BASE_THRESHOLD = 0.35;
const MAX_AUTO_MEMORIES = 2;

const CATEGORY_EXTRACTION_THRESHOLDS = {
  architecture: 0.38,
  error: 0.40,
  context: 0.42,
  learning: 0.42,
  pattern: 0.45,
  preference: 0.48,
  note: 0.52,
  todo: 0.50,
  relationship: 0.45,
  custom: 0.45,
};

// ==================== SALIENCE (mirrors pre-compact) ====================

const ARCHITECTURE_KEYWORDS = ['architecture','design','pattern','structure','system','database','api','schema','model','framework','stack','microservice','monolith','serverless','infrastructure'];
const ERROR_KEYWORDS = ['error','bug','fix','issue','problem','crash','fail','exception','debug','resolve','solution','workaround'];
const PREFERENCE_KEYWORDS = ['prefer','always','never','style','convention','standard','like','want','should','must','require'];
const PATTERN_KEYWORDS = ['pattern','practice','approach','method','technique','implementation','strategy','algorithm','workflow'];
const DECISION_KEYWORDS = ['decided','decision','chose','chosen','selected','going with','will use','opted for','settled on','agreed'];
const LEARNING_KEYWORDS = ['learned','discovered','realized','found out','turns out','TIL','now know','understand now','figured out'];
const EMOTIONAL_MARKERS = ['important','critical','crucial','essential','key','finally','breakthrough','eureka','aha','got it','frustrating','annoying','tricky','remember'];
const CODE_REFERENCE_PATTERNS = [
  /\b[A-Z][a-zA-Z]*\.[a-zA-Z]+\b/,
  /\b[a-z_][a-zA-Z0-9_]*\.(ts|js|py|go|rs)\b/,
  /`[^`]+`/,
  /\b(function|class|interface|type|const|let|var)\s+\w+/i,
  /\bline\s*\d+\b/i,
  /\b(src|lib|app|components?)\/\S+/,
];

function detectKeywords(text, keywords) {
  const lower = text.toLowerCase();
  return keywords.some((k) => lower.includes(k.toLowerCase()));
}
function detectCodeReferences(c) {
  return CODE_REFERENCE_PATTERNS.some((p) => p.test(c));
}
function detectExplicitRequest(t) {
  const patterns = [
    /\bremember\s+(this|that)\b/i, /\bdon'?t\s+forget\b/i, /\bkeep\s+(in\s+)?mind\b/i,
    /\bnote\s+(this|that)\b/i, /\bsave\s+(this|that)\b/i, /\bimportant[:\s]/i,
    /\bfor\s+future\s+reference\b/i,
  ];
  return patterns.some((p) => p.test(t));
}
function calculateSalience(text) {
  let score = 0.25;
  if (detectExplicitRequest(text)) score += 0.5;
  if (detectKeywords(text, ARCHITECTURE_KEYWORDS)) score += 0.4;
  if (detectKeywords(text, ERROR_KEYWORDS)) score += 0.35;
  if (detectKeywords(text, DECISION_KEYWORDS)) score += 0.35;
  if (detectKeywords(text, LEARNING_KEYWORDS)) score += 0.3;
  if (detectKeywords(text, PATTERN_KEYWORDS)) score += 0.25;
  if (detectKeywords(text, PREFERENCE_KEYWORDS)) score += 0.25;
  if (detectCodeReferences(text)) score += 0.15;
  if (detectKeywords(text, EMOTIONAL_MARKERS)) score += 0.2;
  return Math.min(1.0, score);
}
function suggestCategory(text) {
  const lower = text.toLowerCase();
  if (detectKeywords(lower, ARCHITECTURE_KEYWORDS)) return 'architecture';
  if (detectKeywords(lower, ERROR_KEYWORDS)) return 'error';
  if (detectKeywords(lower, DECISION_KEYWORDS)) return 'context';
  if (detectKeywords(lower, LEARNING_KEYWORDS)) return 'learning';
  if (detectKeywords(lower, PREFERENCE_KEYWORDS)) return 'preference';
  if (detectKeywords(lower, PATTERN_KEYWORDS)) return 'pattern';
  if (/\b(todo|fixme|hack|xxx)\b/i.test(lower)) return 'todo';
  return 'note';
}
function extractTags(text, extractorName) {
  const tags = new Set();
  const hashtags = text.match(/#[a-zA-Z][a-zA-Z0-9_-]*/g);
  if (hashtags) hashtags.forEach((t) => tags.add(t.slice(1).toLowerCase()));
  ['react','vue','angular','node','python','typescript','javascript','api','database','sql','mongodb','postgresql','mysql','docker','kubernetes','aws','git','testing','auth','security']
    .forEach((t) => { if (text.toLowerCase().includes(t)) tags.add(t); });
  tags.add('auto-extracted');
  tags.add('source:stop-hook');
  if (extractorName) tags.add(`source:${extractorName}`);
  return Array.from(tags).slice(0, 12);
}

// ==================== EXTRACTORS ====================

function extractMemorableSegments(text) {
  const segments = [];
  const extractors = [
    { name: 'decision', titlePrefix: 'Decision: ', patterns: [
      /(?:we\s+)?decided\s+(?:to\s+)?(.{15,200})/gi,
      /(?:going|went)\s+with\s+(.{15,150})/gi,
      /(?:chose|chosen|selected)\s+(.{15,150})/gi,
      /the\s+(?:approach|solution|fix)\s+(?:is|was)\s+(.{15,200})/gi,
      /(?:using|will\s+use)\s+(.{15,150})/gi,
      /(?:opted\s+for|settled\s+on)\s+(.{15,150})/gi,
    ]},
    { name: 'error-fix', titlePrefix: 'Fix: ', patterns: [
      /(?:fixed|solved|resolved)\s+(?:by\s+)?(.{15,200})/gi,
      /the\s+(?:fix|solution|workaround)\s+(?:is|was)\s+(.{15,200})/gi,
      /(?:root\s+cause|issue)\s+(?:is|was)\s+(.{15,200})/gi,
      /(?:error|bug)\s+(?:was\s+)?caused\s+by\s+(.{15,200})/gi,
    ]},
    { name: 'learning', titlePrefix: 'Learned: ', patterns: [
      /(?:learned|discovered|realized|found\s+out)\s+(?:that\s+)?(.{15,200})/gi,
      /turns\s+out\s+(?:that\s+)?(.{15,200})/gi,
      /(?:figured\s+out|worked\s+out)\s+(.{15,150})/gi,
    ]},
    { name: 'preference', titlePrefix: 'Preference: ', patterns: [
      /(?:always|never)\s+(.{10,150})/gi,
      /(?:prefer|want)\s+to\s+(.{10,150})/gi,
    ]},
  ];
  for (const ex of extractors) {
    for (const p of ex.patterns) {
      let m;
      while ((m = p.exec(text)) !== null) {
        const content = m[1].trim();
        if (content.length >= 20) {
          const titleContent = content.slice(0, 50).replace(/\s+/g, ' ').trim();
          const title = ex.titlePrefix + (titleContent.length < 50 ? titleContent : titleContent + '...');
          segments.push({ title, content: content.slice(0, 500), extractorType: ex.name });
        }
      }
    }
  }
  return segments;
}

function calculateOverlap(t1, t2) {
  const w1 = new Set(t1.toLowerCase().split(/\s+/));
  const w2 = new Set(t2.toLowerCase().split(/\s+/));
  const inter = new Set([...w1].filter((w) => w2.has(w)));
  const union = new Set([...w1, ...w2]);
  return inter.size / Math.max(1, union.size);
}

function processSegments(segments, dynamicThreshold) {
  const unique = [];
  for (const seg of segments) {
    if (unique.some((u) => calculateOverlap(u.content, seg.content) > 0.8)) continue;
    const text = seg.title + ' ' + seg.content;
    unique.push({
      ...seg,
      salience: calculateSalience(text),
      category: suggestCategory(text),
      tags: extractTags(text, seg.extractorType),
    });
  }
  unique.sort((a, b) => b.salience - a.salience);
  const filtered = unique.filter((s) => {
    const cat = CATEGORY_EXTRACTION_THRESHOLDS[s.category] ?? BASE_THRESHOLD;
    return s.salience >= Math.min(cat, dynamicThreshold);
  });
  return filtered.slice(0, MAX_AUTO_MEMORIES);
}

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

        const segments = extractMemorableSegments(transcriptOut.text);
        const processed = processSegments(segments, dyn);

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
