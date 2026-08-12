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
import { constants, existsSync, fstatSync, linkSync, lstatSync, mkdirSync, openSync, readSync, closeSync, statSync, writeFileSync, readFileSync, readdirSync, unlinkSync } from 'fs';
import { mkdirSecure } from './lib/state-perms.mjs';
import { basename, dirname, join, resolve, sep } from 'path';
import { homedir } from 'os';
import { createHash, createHmac, randomBytes } from 'crypto';
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
    mkdirSecure(STOP_DISABLED_SENTINEL_DIR);
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

const AUDIT_DIR = join(homedir(), '.shieldcortex', 'audit');
const SESSION_GUARD_DIR = join(AUDIT_DIR, 'session-guard');
const PRIMARY_RECENT_FALLBACK_SKEW_MS = 5_000;
const MAX_AUDIT_SCAN_FILES = 256;
const MAX_AUDIT_SCAN_BYTES = 64 * 1024 * 1024;
const PRIMARY_RECENT_FALLBACK_LIMIT = 8;
const PRIMARY_RECENT_TAIL_BYTES = 1_048_576;
const MAX_SESSION_SALT_RECOVERY_ATTEMPTS = 256;
const GUARD_DEGRADED_OUTCOMES = new Set([
  'auto_denied',
  'denied_no_prompt_surface',
  'failure_denied',
  'warned',
  'failure_allowed',
]);

function cleanLogToken(value, max = 120) {
  return String(value ?? 'unknown').replace(/[\u0000-\u001f\u007f]/g, '?').slice(0, max);
}

function readExistingSessionSalt(file) {
  try {
    const st = lstatSync(file);
    if (!st.isFile() || st.isSymbolicLink()) return null;
    const salt = readFileSync(file, 'utf8').trim();
    return /^[a-f0-9]{64}$/i.test(salt) ? salt.toLowerCase() : null;
  } catch {
    return null;
  }
}



function fdPathForDescriptor(fd) {
  if (existsSync('/proc/self/fd')) return `/proc/self/fd/${fd}`;
  return null;
}

function withAnchoredDirectory(dir, fn) {
  if (!ensureDirectoryNoSymlink(dir)) return false;
  let dirFd;
  try {
    dirFd = openSync(dir, constants.O_RDONLY | constants.O_DIRECTORY | constants.O_NOFOLLOW);
    if (!ensureDirectoryNoSymlink(dir)) return false;
    const fdPath = fdPathForDescriptor(dirFd);
    if (!fdPath) return fn(dir);
    return fn(fdPath);
  } catch {
    return false;
  } finally {
    if (dirFd !== undefined) {
      try { closeSync(dirFd); } catch { /* ignore */ }
    }
  }
}

function publishFileAtomically(file, contents) {
  const dir = dirname(file);
  const tmpName = `${basename(file)}.tmp.${process.pid}.${randomBytes(6).toString('hex')}`;
  const finalName = basename(file);
  return withAnchoredDirectory(dir, (dirPath) => {
    const tmp = `${dirPath}/${tmpName}`;
    const final = `${dirPath}/${finalName}`;
    try {
      writeFileSync(tmp, contents, { flag: 'wx', mode: 0o600 });
      linkSync(tmp, final);
      return true;
    } catch {
      return false;
    } finally {
      try { unlinkSync(tmp); } catch { /* ignore */ }
    }
  });
}

function legacySessionSaltFiles(primary) {
  return [primary, `${primary}.recovered`, `${primary}.recovered2`, `${primary}.recovered3`];
}

function discoveredSessionSaltFiles(primary) {
  try {
    const dir = dirname(primary);
    const entries = [];
    for (const name of readdirSync(dir)) {
      const match = name.match(/^action-guard-session-salt\.recovered(\d+)$/);
      if (!match) continue;
      const slot = Number(match[1]);
      if (!Number.isInteger(slot) || String(slot) !== match[1]) continue;
      if (slot < 4 || slot >= 4 + MAX_SESSION_SALT_RECOVERY_ATTEMPTS) continue;
      entries.push({ slot, file: join(dir, name) });
    }
    entries.sort((a, b) => a.slot - b.slot);
    return entries.map((entry) => entry.file);
  } catch {
    return [];
  }
}

function sessionKeySalt() {
  const fromEnv = process.env.SHIELDCORTEX_SESSION_SALT;
  if (typeof fromEnv === 'string' && /^[a-f0-9]{64}$/i.test(fromEnv)) return fromEnv.toLowerCase();
  try {
    const dir = join(homedir(), '.shieldcortex');
    const primary = join(dir, 'action-guard-session-salt');
    if (!ensureDirectoryNoSymlink(dir)) return undefined;
    const readableFiles = [...legacySessionSaltFiles(primary), ...discoveredSessionSaltFiles(primary)];
    for (const file of readableFiles) {
      const existing = readExistingSessionSalt(file);
      if (existing) return existing;
    }
    const salt = randomBytes(32).toString('hex');
    for (const file of legacySessionSaltFiles(primary)) {
      if (publishFileAtomically(file, `${salt}\n`)) return salt;
      const raced = readExistingSessionSalt(file);
      if (raced) return raced;
    }
    for (let i = 4; i < 4 + MAX_SESSION_SALT_RECOVERY_ATTEMPTS; i += 1) {
      const file = `${primary}.recovered${i}`;
      const existing = readExistingSessionSalt(file);
      if (existing) return existing;
      if (publishFileAtomically(file, `${salt}\n`)) return salt;
      const raced = readExistingSessionSalt(file);
      if (raced) return raced;
    }
    return null;
  } catch {
    return null;
  }
}

function sessionKeyFor(value) {
  if (typeof value !== 'string' || !value.trim()) return null;
  const salt = sessionKeySalt();
  if (!salt) return null;
  return `sc-${createHmac('sha256', salt).update(`action-guard-session:${value}`).digest('hex').slice(0, 16)}`;
}

const SAFE_SUMMARY_SIGNALS = new Set([
  'secret-egress', 'approval-required', 'fallback-scan', 'privilege-escalation',
  'filesystem-destructive', 'destructive-filesystem', 'dangerous-shell',
  'command-exec', 'network-egress', 'credential-access', 'data-exfiltration',
  'untrusted-script', 'reviewed-script', 'shell-injection', 'persistence-risk',
]);

function cleanSignal(value) {
  const signal = String(value ?? '').trim();
  return SAFE_SUMMARY_SIGNALS.has(signal) ? signal : signal ? 'redacted-signal' : null;
}


const MAX_JSONL_LINE_BYTES = 1024 * 1024;


function ensureDirectoryNoSymlink(dir) {
  const root = resolve(homedir());
  const target = resolve(dir);
  if (target !== root && !target.startsWith(`${root}${sep}`)) return false;
  let current = root;
  const rest = target.slice(root.length).split(sep).filter(Boolean);
  for (const part of rest) {
    current = join(current, part);
    try {
      const st = lstatSync(current);
      if (!st.isDirectory() || st.isSymbolicLink()) return false;
    } catch {
      try {
        mkdirSecure(current);
        const st = lstatSync(current);
        if (!st.isDirectory() || st.isSymbolicLink()) return false;
      } catch {
        return false;
      }
    }
  }
  return true;
}

function testOnlyPauseAppendOpen() {
  const ms = Number(process.env.SHIELDCORTEX_TEST_APPEND_OPEN_DELAY_MS ?? 0);
  if (!Number.isFinite(ms) || ms <= 0) return;
  try {
    Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, Math.min(ms, 1000));
  } catch { /* ignore */ }
}

function testOnlyPausePostAppendValidation() {
  const ms = Number(process.env.SHIELDCORTEX_TEST_POST_APPEND_VALIDATION_DELAY_MS ?? 0);
  if (!Number.isFinite(ms) || ms <= 0) return;
  try {
    Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, Math.min(ms, 1000));
  } catch { /* ignore */ }
}

function fdMatchesExpectedPath(fd, file) {
  try {
    const actual = fstatSync(fd);
    const expected = lstatSync(file);
    return expected.isFile()
      && !expected.isSymbolicLink()
      && actual.dev === expected.dev
      && actual.ino === expected.ino;
  } catch {
    return false;
  }
}

function noteAuditSinkFailure(detail) {
  console.error(
    `[shieldcortex stop-hook] audit sink UNWRITABLE (~/.shieldcortex/audit): ${cleanLogToken(detail, 160)} — action_guard_degraded evidence was DROPPED.`,
  );
}

function appendFileNoFollow(file, line) {
  let fd;
  try {
    if (!ensureDirectoryNoSymlink(dirname(file))) return false;
    testOnlyPauseAppendOpen();
    if (!ensureDirectoryNoSymlink(dirname(file))) return false;
    testOnlyPausePostAppendValidation();
    if (!ensureDirectoryNoSymlink(dirname(file))) return false;
    fd = openSync(file, constants.O_CREAT | constants.O_APPEND | constants.O_WRONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK, 0o600);
    const st = fstatSync(fd);
    if (!st.isFile() || st.nlink > 1 || !fdMatchesExpectedPath(fd, file)) return false;
    writeFileSync(fd, line);
    return true;
  } catch {
    return false;
  } finally {
    if (fd !== undefined) {
      try { closeSync(fd); } catch { /* ignore */ }
    }
  }
}

function testOnlyPauseLockPublish() {
  const ms = Number(process.env.SHIELDCORTEX_TEST_LOCK_PUBLISH_DELAY_MS ?? 0);
  if (!Number.isFinite(ms) || ms <= 0) return;
  try {
    Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, Math.min(ms, 1000));
  } catch { /* ignore */ }
}

function testOnlyPauseAuditOpen() {
  const ms = Number(process.env.SHIELDCORTEX_TEST_AUDIT_OPEN_DELAY_MS ?? 0);
  if (!Number.isFinite(ms) || ms <= 0) return;
  try {
    Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, Math.min(ms, 1000));
  } catch { /* ignore */ }
}

function createFileAtomically(file, contents) {
  const dir = dirname(file);
  const tmpName = `${basename(file)}.tmp.${process.pid}.${randomBytes(6).toString('hex')}`;
  const finalName = basename(file);
  return withAnchoredDirectory(dir, (dirPath) => {
    const tmp = `${dirPath}/${tmpName}`;
    const final = `${dirPath}/${finalName}`;
    try {
      writeFileSync(tmp, contents, { flag: 'wx', mode: 0o600 });
      testOnlyPauseLockPublish();
      linkSync(tmp, final);
      return true;
    } catch {
      return false;
    } finally {
      try { unlinkSync(tmp); } catch { /* ignore */ }
    }
  });
}

function unlinkIfSameIdentity(file, expected) {
  try {
    if (sameLockIdentity(expected, lockIdentity(file))) unlinkSync(file);
  } catch { /* ignore */ }
}

function guardFingerprint(row) {
  const payload = JSON.stringify({
    sessionKey: row.sessionKey,
    action: row.action,
    outcome: row.outcome,
    tool: row.tool,
    ts: row.ts,
    auditEventId: /^[a-f0-9]{32}$/.test(String(row.auditEventId ?? '')) ? String(row.auditEventId) : row._auditLineKey,
    threats: Array.isArray(row.threats) ? row.threats.map(cleanSignal).filter(Boolean).sort() : [],
  });
  return createHash('sha256').update(payload).digest('hex').slice(0, 16);
}

function sessionGuardIndexFile(sessionKey) {
  return /^sc-[a-f0-9]{16}$/.test(String(sessionKey ?? ''))
    ? join(SESSION_GUARD_DIR, `${sessionKey}.jsonl`)
    : null;
}

function addSummaryFingerprints(row, seen) {
  if (Array.isArray(row.guardFingerprints)) {
    for (const fp of row.guardFingerprints) {
      if (/^[a-f0-9]{16}$/.test(String(fp))) seen.add(String(fp));
    }
  }
}

function collectSummariesFromLines(lines, sessionKey, alreadySummarised) {
  for (const line of lines) {
    if (!line.trim()) continue;
    try {
      const row = JSON.parse(line);
      const isSummary = (row?.recordKind === 'summary' || row?.type === 'session_summary')
        && row.origin === 'claude-code-stop-hook'
        && row.sessionKey === sessionKey
        && row.outcome === 'action_guard_degraded';
      if (isSummary) addSummaryFingerprints(row, alreadySummarised);
    } catch { /* ignore malformed audit lines */ }
  }
}

function collectGuardsFromLines(lines, file, sessionKey, alreadySummarised, rows, baseLineIndex = 0) {
  for (const [offset, line] of lines.entries()) {
    const lineIndex = baseLineIndex + offset;
    if (!line.trim()) continue;
    try {
      const row = JSON.parse(line);
      const isGuard = (row?.recordKind === 'guard' || row?.type === 'intercept')
        && row.origin === 'claude-code-hook'
        && row.action !== 'notify'
        && row.sessionKey === sessionKey
        && GUARD_DEGRADED_OUTCOMES.has(String(row.outcome));
      if (!isGuard) continue;
      row._auditLineKey = `${file}:${lineIndex}`;
      const fp = guardFingerprint(row);
      if (alreadySummarised.has(fp)) continue;
      alreadySummarised.add(fp);
      rows.push({ ...row, _guardFingerprint: fp });
    } catch { /* ignore malformed audit lines */ }
  }
}


function forEachJsonlLine(file, visitor, maxBytes = MAX_AUDIT_SCAN_BYTES, expectedIdentity = null) {
  let fd;
  try {
    const st = lstatSync(file);
    if (!st.isFile() || st.isSymbolicLink()) return;
    testOnlyPauseAuditOpen();
    fd = openSync(file, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
    const opened = fstatSync(fd);
    if (expectedIdentity && (opened.dev !== expectedIdentity.dev || opened.ino !== expectedIdentity.ino)) {
      try { closeSync(fd); } catch { /* ignore */ }
      fd = undefined;
      return;
    }
    if (!opened.isFile() || opened.nlink > 1) {
      try { closeSync(fd); } catch { /* ignore */ }
      fd = undefined;
      return;
    }
    maxBytes = Math.max(0, Math.min(Number(maxBytes) || 0, opened.size, MAX_AUDIT_SCAN_BYTES));
    if (maxBytes <= 0) {
      try { closeSync(fd); } catch { /* ignore */ }
      fd = undefined;
      return;
    }
  } catch {
    if (fd !== undefined) {
      try { closeSync(fd); } catch { /* ignore */ }
    }
    return;
  }
  try {
    const buf = Buffer.alloc(64 * 1024);
    let carry = '';
    let lineIndex = 0;
    let bytesRead = 0;
    let totalRead = 0;
    let droppingOversizedLine = false;
    while (totalRead < maxBytes && (bytesRead = readSync(fd, buf, 0, Math.min(buf.length, maxBytes - totalRead), null)) > 0) {
      totalRead += bytesRead;
      carry += buf.subarray(0, bytesRead).toString('utf8');
      while (true) {
        const newline = carry.indexOf('\n');
        if (newline < 0) break;
        const line = carry.slice(0, newline);
        carry = carry.slice(newline + 1);
        if (droppingOversizedLine) {
          droppingOversizedLine = false;
          lineIndex += 1;
          continue;
        }
        if (Buffer.byteLength(line, 'utf8') > MAX_JSONL_LINE_BYTES) {
          lineIndex += 1;
          continue;
        }
        visitor(line, lineIndex++);
      }
      if (Buffer.byteLength(carry, 'utf8') > MAX_JSONL_LINE_BYTES) {
        carry = '';
        droppingOversizedLine = true;
      }
    }
    if (!droppingOversizedLine && carry && Buffer.byteLength(carry, 'utf8') <= MAX_JSONL_LINE_BYTES) visitor(carry, lineIndex);
  } finally {
    try { closeSync(fd); } catch { /* ignore */ }
  }
}

function collectSummariesFromFile(source, sessionKey, alreadySummarised) {
  forEachJsonlLine(source.file, (line) => collectSummariesFromLines([line], sessionKey, alreadySummarised), source.maxBytes, source.identity ?? null);
}

function collectGuardsFromFile(source, sessionKey, alreadySummarised, rows) {
  forEachJsonlLine(source.file, (line, lineIndex) => collectGuardsFromLines([line], source.file, sessionKey, alreadySummarised, rows, lineIndex), source.maxBytes, source.identity ?? null);
}

function auditFilesNewestFirst({ sinceMs = null, limit = null } = {}) {
  try {
    if (!existsSync(AUDIT_DIR)) return [];
    const auditDirStat = lstatSync(AUDIT_DIR);
    if (!auditDirStat.isDirectory() || auditDirStat.isSymbolicLink()) return [];
    let candidates = readdirSync(AUDIT_DIR)
      .filter((f) => /^realtime-\d{4}-\d{2}-\d{2}\.jsonl$/.test(f))
      .map((f) => join(AUDIT_DIR, f))
      .map((file) => {
        try {
          const st = lstatSync(file);
          if (!st.isFile() || st.isSymbolicLink()) return null;
          return { file, mtimeMs: st.mtimeMs, size: st.size, dev: st.dev, ino: st.ino };
        } catch { return null; }
      })
      .filter(Boolean);
    if (sinceMs !== null) candidates = candidates.filter((f) => f.mtimeMs >= sinceMs);
    candidates.sort((a, b) => b.file.localeCompare(a.file));
    const maxFiles = limit === null ? MAX_AUDIT_SCAN_FILES : Math.min(limit, MAX_AUDIT_SCAN_FILES);
    const files = [];
    let bytes = 0;
    for (const item of candidates) {
      if (files.length >= maxFiles) break;
      if (item.size > MAX_AUDIT_SCAN_BYTES) continue;
      const remaining = MAX_AUDIT_SCAN_BYTES - bytes;
      if (remaining <= 0) break;
      if (item.size > remaining) continue;
      files.push({ file: item.file, maxBytes: item.size, identity: { dev: item.dev, ino: item.ino } });
      bytes += item.size;
    }
    return files;
  } catch {
    return [];
  }
}

function collectGuardStateForSessionKey(sessionKey) {
  const alreadySummarised = new Set();
  const rows = [];
  const sourceFiles = [];
  const indexFile = sessionGuardIndexFile(sessionKey);
  let hasIndex = false;
  if (indexFile && existsSync(indexFile)) {
    try {
      const st = lstatSync(indexFile);
      if (st.isFile() && !st.isSymbolicLink()) {
        try { const st = lstatSync(indexFile); sourceFiles.push({ file: indexFile, maxBytes: MAX_AUDIT_SCAN_BYTES, identity: { dev: st.dev, ino: st.ino } }); } catch { /* ignore */ }
        hasIndex = true;
      }
    } catch { /* fall back to audit */ }
  }
  for (const source of auditFilesNewestFirst()) sourceFiles.push(source);
  // Two-pass collection is deliberate: summaries usually appear after guard rows
  // in the primary audit file. Reading guards first would re-summarise rows that
  // were already accounted for later in the same file. The per-session index is
  // an acceleration source only; it is explicitly best-effort, so the canonical
  // primary audit remains the recovery source even when an index exists. Files
  // are streamed line-by-line so recovery stays memory-bounded under large audit
  // histories and malformed oversized lines.
  for (const source of sourceFiles) {
    try { collectSummariesFromFile(source, sessionKey, alreadySummarised); } catch { /* ignore */ }
  }
  for (const source of sourceFiles) {
    try { collectGuardsFromFile(source, sessionKey, alreadySummarised, rows); } catch { /* ignore */ }
  }
  return { alreadySummarised, rows, source: hasIndex ? 'index+audit' : 'audit' };
}

function appendSessionGuardSummary(sessionKey, entry) {
  const indexFile = sessionGuardIndexFile(sessionKey);
  if (!indexFile) return;
  try {
    if (!ensureDirectoryNoSymlink(AUDIT_DIR)) return;
    if (!ensureDirectoryNoSymlink(SESSION_GUARD_DIR)) return;
    appendFileNoFollow(indexFile, JSON.stringify({ recordKind: 'summary', ...entry }) + '\n');
  } catch { /* primary audit row remains canonical */ }
}

function safeAuditTimestamp(value) {
  const text = String(value ?? '').trim();
  if (!/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/.test(text)) return null;
  const parsed = new Date(text);
  return Number.isFinite(parsed.getTime()) && parsed.toISOString() === text ? text : null;
}

function processStartToken(pid) {
  try {
    const stat = readFileSync(`/proc/${pid}/stat`, 'utf8');
    const rest = stat.slice(stat.lastIndexOf(')') + 2).trim().split(/\s+/);
    return rest[19] ? String(rest[19]) : null;
  } catch {
    return null;
  }
}

function processAlive(pid, expectedStartToken = null) {
  if (!Number.isInteger(pid) || pid <= 0) return false;
  try {
    process.kill(pid, 0);
    if (expectedStartToken) return processStartToken(pid) === String(expectedStartToken);
    return true;
  } catch (err) {
    return err?.code === 'EPERM';
  }
}


function testOnlyPauseRecoveryReclaim() {
  const ms = Number(process.env.SHIELDCORTEX_TEST_RECOVERY_LOCK_RECLAIM_DELAY_MS ?? 0);
  if (!Number.isFinite(ms) || ms <= 0) return;
  try {
    Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, Math.min(ms, 1000));
  } catch { /* ignore */ }
}


function lockIdentity(file) {
  try {
    const st = lstatSync(file);
    return { dev: st.dev, ino: st.ino, mtimeMs: st.mtimeMs, size: st.size };
  } catch {
    return null;
  }
}

function sameLockIdentity(a, b) {
  return !!a && !!b && a.dev === b.dev && a.ino === b.ino;
}

function acquireSummaryLock(sessionKey) {
  const lockDir = join(AUDIT_DIR, '.locks');
  if (!ensureDirectoryNoSymlink(AUDIT_DIR)) return null;
  if (!ensureDirectoryNoSymlink(lockDir)) return null;
  const lockPath = join(lockDir, `${sessionKey}.lock`);
  const ownerPayload = () => JSON.stringify({
    pid: process.pid,
    processStartToken: processStartToken(process.pid),
    startedAt: new Date().toISOString(),
  });
  const writeLock = () => {
    if (!createFileAtomically(lockPath, ownerPayload())) {
      const err = new Error('lock exists');
      err.code = 'EEXIST';
      throw err;
    }
    return { lockPath, lockIdentity: lockIdentity(lockPath) };
  };
  const writeRecoveryLock = () => {
    const recoveryPath = join(lockDir, `${sessionKey}.recovery.lock`);
    try {
      if (!createFileAtomically(recoveryPath, ownerPayload())) {
        const err = new Error('recovery lock exists');
        err.code = 'EEXIST';
        throw err;
      }
      return { lockPath: recoveryPath, recovery: true, lockIdentity: lockIdentity(recoveryPath) };
    } catch (err) {
      if (err?.code !== 'EEXIST') return null;
      let observed = null;
      let live = false;
      try {
        observed = lstatSync(recoveryPath);
        if (!observed.isFile() || observed.isSymbolicLink()) return null;
        const owner = JSON.parse(readFileSync(recoveryPath, 'utf8'));
        live = processAlive(Number(owner?.pid), owner?.processStartToken ?? null);
      } catch {
        try { observed = lstatSync(recoveryPath); } catch { return null; }
        if (!observed.isFile() || observed.isSymbolicLink()) return null;
        live = false;
      }
      if (live) return null;
      testOnlyPauseRecoveryReclaim();
      const claimPath = `${recoveryPath}.claim.${observed.dev}.${observed.ino}.lock`;
      try {
        if (createFileAtomically(claimPath, ownerPayload())) {
          return { lockPath: claimPath, recovery: true, lockIdentity: lockIdentity(claimPath) };
        }
        const claimIdentity = lockIdentity(claimPath);
        try {
          const claimOwner = JSON.parse(readFileSync(claimPath, 'utf8'));
          if (processAlive(Number(claimOwner?.pid), claimOwner?.processStartToken ?? null)) return null;
        } catch { /* stale or malformed claim */ }
        unlinkIfSameIdentity(claimPath, claimIdentity);
        if (createFileAtomically(claimPath, ownerPayload())) {
          return { lockPath: claimPath, recovery: true, lockIdentity: lockIdentity(claimPath) };
        }
        return null;
      } catch (claimErr) {
        if (claimErr?.code !== 'EEXIST') return null;
        return null;
      }
    }
  };
  try {
    return writeLock();
  } catch (err) {
    if (err?.code !== 'EEXIST') return null;
    try {
      const raw = readFileSync(lockPath, 'utf8');
      const owner = JSON.parse(raw);
      if (processAlive(Number(owner?.pid), owner?.processStartToken ?? null)) return null;
      // Do not unlink the original lock: another process can replace it between
      // inspection and deletion. A separate recovery lock gives stale/malformed
      // owners a forward path without ever deleting a potentially live lock.
      return writeRecoveryLock();
    } catch {
      return writeRecoveryLock();
    }
  }
}

function releaseSummaryLock(lock) {
  if (!lock) return;
  try {
    if (sameLockIdentity(lock.lockIdentity, lockIdentity(lock.lockPath))) unlinkSync(lock.lockPath);
  } catch { /* ignore */ }
  if (lock.reclaimedLockPath) {
    try { unlinkSync(lock.reclaimedLockPath); } catch { /* ignore */ }
  }
}

function recordActionGuardSessionOutcome(rawSessionId) {
  const sessionKey = sessionKeyFor(rawSessionId);
  if (!sessionKey) return { recorded: false, count: 0 };
  const lock = acquireSummaryLock(sessionKey);
  if (!lock) {
    const state = collectGuardStateForSessionKey(sessionKey);
    if (state.rows.length > 0) return { recorded: false, count: state.rows.length, pending: true, sessionKey };
    return state.alreadySummarised.size > 0
      ? { recorded: true, count: 0, existing: true, sessionKey }
      : { recorded: false, count: 0, sessionKey };
  }
  try {
    const state = collectGuardStateForSessionKey(sessionKey);
    const { rows, alreadySummarised } = state;
    if (rows.length === 0) return alreadySummarised.size > 0 ? { recorded: true, count: 0, existing: true, sessionKey } : { recorded: false, count: 0, sessionKey };
    const counts = rows.reduce((acc, row) => {
      const outcome = String(row.outcome ?? 'unknown');
      acc[outcome] = (acc[outcome] ?? 0) + 1;
      return acc;
    }, {});
    const threats = rows
      .flatMap((r) => Array.isArray(r.threats) ? r.threats.map(cleanSignal).filter(Boolean) : [])
      .filter((signal, index, arr) => arr.indexOf(signal) === index)
      .slice(0, 25);
    const times = rows.map((r) => safeAuditTimestamp(r.ts)).filter(Boolean).sort();
    const entry = {
      type: 'session_summary',
      origin: 'claude-code-stop-hook',
      sessionKey,
      action: 'session_health',
      outcome: 'action_guard_degraded',
      guardOutcomeCount: rows.length,
      guardFingerprints: rows.map((r) => r._guardFingerprint).filter((fp) => /^[a-f0-9]{16}$/.test(String(fp))),
      outcomes: counts,
      threats,
      firstGuardTs: times[0],
      lastGuardTs: times[times.length - 1],
      ts: new Date().toISOString(),
    };
    try {
      if (!ensureDirectoryNoSymlink(AUDIT_DIR)) {
        noteAuditSinkFailure('audit directory is unsafe or outside the state tree');
        return { recorded: false, count: rows.length, sessionKey };
      }
      const date = new Date().toISOString().slice(0, 10);
      if (!appendFileNoFollow(join(AUDIT_DIR, `realtime-${date}.jsonl`), JSON.stringify(entry) + '\n')) {
        noteAuditSinkFailure(`append failed for realtime-${date}.jsonl`);
        return { recorded: false, count: rows.length, sessionKey };
      }
      appendSessionGuardSummary(sessionKey, entry);
      console.error(`[shieldcortex stop-hook] action_guard_degraded sessionKey=${sessionKey} guardOutcomes=${rows.length}`);
      return { recorded: true, count: rows.length, sessionKey };
    } catch (err) {
      noteAuditSinkFailure(err?.message ?? err);
      return { recorded: false, count: rows.length, sessionKey };
    }
  } finally {
    releaseSummaryLock(lock);
  }
}

function recordStopTelemetry(startedAt, { exitCode = 0, memoriesExtracted = 0, transcriptBytes = 0, notes = null } = {}) {
  if (!existsSync(DB_PATH)) return;
  let tdb = null;
  try {
    tdb = new Database(DB_PATH, { timeout: 1500 });
    recordHookInvocation(tdb, {
      hookName: 'stop',
      exitCode,
      durationMs: Date.now() - startedAt,
      memoriesExtracted,
      transcriptBytes,
      notes,
    });
  } catch { /* telemetry must not block stop-hook */ }
  finally { try { if (tdb) tdb.close(); } catch { /* ignore */ } }
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
  let db = null;
  let extractedCount = 0;
  let bytesRead = 0;
  let notes = null;
  let guardHealthNote = null;
  let hookTelemetryExitCode = 0;

  try {
    let hookData = {};
    try { hookData = JSON.parse(input || '{}'); } catch { /* allow empty */ }

    if (hookData.stop_hook_active === true) {
      // Loop prevention — never re-engage from an already-engaged stop hook.
      process.exit(0);
    }

    const guardSummary = recordActionGuardSessionOutcome(
      typeof hookData.session_id === 'string' ? hookData.session_id : hookData.sessionId,
    );
    if (guardSummary.recorded || guardSummary.count > 0) {
      hookTelemetryExitCode = 1;
      guardHealthNote = guardSummary.existing
        ? 'action_guard_degraded_existing'
        : guardSummary.pending
          ? 'action_guard_degraded_pending'
          : 'action_guard_degraded';
    }
    const autoMemConfig = getAutoMemoryConfig();
    if (!autoMemConfig.enableStop) {
      // Opt-in by config. As of v4.13.1 the install flag (`--with-stop-hook`)
      // flips this gate at install time so wiring the hook and enabling it are
      // a single user action. If the gate is still false here, the user wired
      // the hook by hand without setting autoMemory.enableStop=true. Log once
      // per session so the failure is visible (was silent-amnesia in #41).
      logDisabledOnceForSession(
        guardSummary.sessionKey || sessionKeyFor(hookData.session_id),
        `disabled — set autoMemory.enableStop=true in ~/.shieldcortex/config.json (or re-run \`shieldcortex setup --with-stop-hook\`)`,
      );
      if (guardHealthNote) {
        recordStopTelemetry(startedAt, { exitCode: hookTelemetryExitCode, notes: guardHealthNote });
      }
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
      recordStopTelemetry(startedAt, {
        exitCode: hookTelemetryExitCode,
        notes: [guardHealthNote, `off-sample turn=${turnCount}`].filter(Boolean).join('; '),
      });
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
          conversationText: transcriptOut.text,
        });

        for (const memory of processed) {
          try {
            await saveAutoExtractedMemory(db, memory, project, { source: 'stop-hook' });
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
        exitCode: hookTelemetryExitCode,
        durationMs: Date.now() - startedAt,
        memoriesExtracted: extractedCount,
        transcriptBytes: bytesRead,
        notes: [guardHealthNote, notes].filter(Boolean).join('; ') || null,
      });
      try { db.close(); } catch { /* ignore */ }
    }
    process.exit(0);
  }
});
