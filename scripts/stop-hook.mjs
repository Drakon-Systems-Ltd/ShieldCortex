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
import { extractCaptureMemories } from './lib/capture-distill.mjs';
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

// #654 — identity resolution. Kept byte-for-byte in step with guardIdentity()
// in src/defence/iron-dome/session-guard.ts, which this hook cannot import; the
// #654 parity vectors pin the two. guardFingerprint above stays VERBATIM as the
// v1 formula: every receipt already on disk was written with it.
const BINDING_PLANES = new Set(['action_guard', 'conversation_firewall']);
const BINDING_STRING_FIELDS = ['gatewayInstanceId', 'hookName', 'pluginId', 'nonce', 'actionKey'];
const MAX_RECEIPT_IDENTITIES = 16384;

// Pure structural copy of hasRequiredBinding (enforcement-binding.ts).
function hasValidBindingNonce(row) {
  if (!BINDING_PLANES.has(String(row.plane ?? ''))) return false;
  if (typeof row.seq !== 'number' || !Number.isInteger(row.seq) || row.seq < 1) return false;
  for (const field of BINDING_STRING_FIELDS) {
    if (typeof row[field] !== 'string' || row[field].length === 0) return false;
  }
  return /^[0-9a-f]{32}$/.test(String(row.nonce));
}

function nonceFingerprint(row) {
  const payload = JSON.stringify({
    sessionKey: row.sessionKey,
    action: row.action,
    outcome: row.outcome,
    tool: row.tool,
    ts: row.ts,
    bindingNonce: `n:${String(row.nonce)}`,
    threats: Array.isArray(row.threats) ? row.threats.map(cleanSignal).filter(Boolean).sort() : [],
  });
  return createHash('sha256').update(payload).digest('hex').slice(0, 16);
}

// ID → nonce → physical position. Only a strictly valid string ID is the
// eventId basis; a value that merely coerces to 32 hex keeps HEAD's v1 bytes
// (so old receipts still match) but is not claimed as an exact identity.
function guardIdentity(row, physKey) {
  const v1 = guardFingerprint({ ...row, _auditLineKey: physKey });
  if (typeof row.auditEventId === 'string' && /^[a-f0-9]{32}$/.test(row.auditEventId)) {
    return { primary: v1, basis: 'eventId', v1 };
  }
  if (hasValidBindingNonce(row)) return { primary: nonceFingerprint(row), basis: 'bindingNonce', v1 };
  return { primary: v1, basis: 'physicalRow', v1 };
}

function sessionGuardIndexFile(sessionKey) {
  return /^sc-[a-f0-9]{16}$/.test(String(sessionKey ?? ''))
    ? join(SESSION_GUARD_DIR, `${sessionKey}.jsonl`)
    : null;
}

// Keep in step with src/defence/iron-dome/session-guard.ts — the hook cannot
// import that module. OpenClaw rows must be readable here so a mixed-plane
// box does not double-summarise (#260) and so an interceptor deny is not
// silently dropped by an exact-string origin check.
const GUARD_INDEX_ORIGINS = new Set(['claude-code-hook', 'openclaw-interceptor']);
const SUMMARY_ORIGINS = new Set(['claude-code-stop-hook', 'openclaw-session-end']);

function parseAuditLine(line) {
  if (!line.trim()) return null;
  try {
    const row = JSON.parse(line);
    return row && typeof row === 'object' && !Array.isArray(row) ? row : null;
  } catch {
    return null;
  }
}

function isSummaryRow(row, sessionKey) {
  return (row.recordKind === 'summary' || row.type === 'session_summary')
    && SUMMARY_ORIGINS.has(String(row.origin ?? ''))
    && row.sessionKey === sessionKey
    && row.outcome === 'action_guard_degraded';
}

function isGuardRow(row, sessionKey) {
  return (row.recordKind === 'guard' || row.type === 'intercept')
    && GUARD_INDEX_ORIGINS.has(String(row.origin ?? ''))
    && row.action !== 'notify'
    && row.sessionKey === sessionKey
    && GUARD_DEGRADED_OUTCOMES.has(String(row.outcome));
}

// Test seam (#654 B11), in the SHIELDCORTEX_TEST_* idiom: `<pass>:<basename>`
// makes the second chunk read of that file throw in that pass only, so a
// mid-stream failure can be driven without touching a real disk.
function testOnlyFailAuditRead(pass, file, chunk) {
  const spec = process.env.SHIELDCORTEX_TEST_AUDIT_READ_FAIL;
  if (!spec || chunk < 1) return;
  if (spec === `${pass}:${basename(file)}`) throw new Error('test-only audit read failure');
}

/**
 * Stream one JSONL source and report how the read ENDED: `read` only when it
 * reached the size it set out to read (realtime: the size seen at discovery;
 * index: its 64 MiB prefix, `truncated` beyond). A refused identity check is
 * `refused`; an lstat/open/fstat error, a shrunk file, an early EOF or a
 * mid-stream throw is `failed`; ENOENT on lstat is `absent` (the caller decides
 * whether that is a known absence or a vanished candidate). Chunks are decoded
 * per chunk, exactly as before — the TS reader reproduces that for parity.
 */
function forEachJsonlLine(source, visitor, pass) {
  const file = source.file;
  let droppedLines = 0;
  let st;
  try {
    st = lstatSync(file);
  } catch (err) {
    return { status: err?.code === 'ENOENT' ? 'absent' : 'failed', droppedLines };
  }
  if (!st.isFile() || st.isSymbolicLink()) return { status: 'refused', droppedLines };
  let fd;
  try {
    testOnlyPauseAuditOpen();
    fd = openSync(file, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
  } catch (err) {
    return { status: err?.code === 'ELOOP' ? 'refused' : 'failed', droppedLines };
  }
  try {
    const opened = fstatSync(fd);
    const expected = source.identity ?? { dev: st.dev, ino: st.ino };
    if (opened.dev !== expected.dev || opened.ino !== expected.ino) return { status: 'refused', droppedLines };
    if (!opened.isFile() || opened.nlink > 1) return { status: 'refused', droppedLines };
    let target;
    let truncated = false;
    if (source.isIndex) {
      target = Math.min(opened.size, MAX_AUDIT_SCAN_BYTES);
      truncated = opened.size > MAX_AUDIT_SCAN_BYTES;
    } else {
      target = Number(source.maxBytes) || 0;
      if (opened.size < target) return { status: 'failed', droppedLines };
    }
    const buf = Buffer.alloc(64 * 1024);
    let carry = '';
    let lineIndex = 0;
    let totalRead = 0;
    let chunk = 0;
    let droppingOversizedLine = false;
    while (totalRead < target) {
      testOnlyFailAuditRead(pass, file, chunk);
      chunk += 1;
      const bytesRead = readSync(fd, buf, 0, Math.min(buf.length, target - totalRead), null);
      if (bytesRead <= 0) break;
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
          droppedLines += 1;
          lineIndex += 1;
          continue;
        }
        visitor(line, lineIndex++);
      }
      if (Buffer.byteLength(carry, 'utf8') > MAX_JSONL_LINE_BYTES) {
        carry = '';
        droppingOversizedLine = true;
        droppedLines += 1;
      }
    }
    if (totalRead !== target) return { status: 'failed', droppedLines };
    if (!droppingOversizedLine && carry && Buffer.byteLength(carry, 'utf8') <= MAX_JSONL_LINE_BYTES) visitor(carry, lineIndex);
    return { status: truncated ? 'truncated' : 'read', droppedLines };
  } catch {
    return { status: 'failed', droppedLines };
  } finally {
    try { closeSync(fd); } catch { /* ignore */ }
  }
}

// Discovery reports what it could NOT see instead of returning [] on every
// error: only ENOENT on the audit dir is a known absence (existsSync maps every
// error to false, which is exactly the absent-vs-failed conflation #654 fixes).
function auditFilesNewestFirst({ sinceMs = null, limit = null } = {}) {
  const out = { state: 'failed', files: [], skipped: 0, refused: 0, failed: 0 };
  try {
    let auditDirStat;
    try {
      auditDirStat = lstatSync(AUDIT_DIR);
    } catch (err) {
      if (err?.code === 'ENOENT') out.state = 'absent';
      return out;
    }
    if (!auditDirStat.isDirectory() || auditDirStat.isSymbolicLink()) {
      out.state = 'refused';
      return out;
    }
    let candidates = [];
    for (const name of readdirSync(AUDIT_DIR).filter((f) => /^realtime-\d{4}-\d{2}-\d{2}\.jsonl$/.test(f))) {
      const file = join(AUDIT_DIR, name);
      let st;
      try {
        st = lstatSync(file);
      } catch {
        out.failed += 1;
        continue;
      }
      if (!st.isFile() || st.isSymbolicLink()) {
        out.refused += 1;
        continue;
      }
      candidates.push({ file, mtimeMs: st.mtimeMs, size: st.size, dev: st.dev, ino: st.ino });
    }
    if (sinceMs !== null) candidates = candidates.filter((f) => f.mtimeMs >= sinceMs);
    candidates.sort((a, b) => b.file.localeCompare(a.file));
    const maxFiles = limit === null ? MAX_AUDIT_SCAN_FILES : Math.min(limit, MAX_AUDIT_SCAN_FILES);
    let bytes = 0;
    for (const [i, item] of candidates.entries()) {
      if (out.files.length >= maxFiles) { out.skipped += candidates.length - i; break; }
      if (item.size > MAX_AUDIT_SCAN_BYTES) { out.skipped += 1; continue; }
      const remaining = MAX_AUDIT_SCAN_BYTES - bytes;
      if (remaining <= 0) { out.skipped += candidates.length - i; break; }
      if (item.size > remaining) { out.skipped += 1; continue; }
      out.files.push({ file: item.file, maxBytes: item.size, identity: { dev: item.dev, ino: item.ino } });
      bytes += item.size;
    }
    out.state = 'listed';
    return out;
  } catch {
    return { state: 'failed', files: [], skipped: 0, refused: 0, failed: 0 };
  }
}

function newPassGaps() {
  // Positive completion: every source starts as a failure and is promoted
  // only on the normal path that proves otherwise.
  return { auditDir: 'failed', index: 'failed', skippedFiles: 0, refusedFiles: 0, failedFiles: 0, droppedLines: 0 };
}

function passComplete(g) {
  return (g.auditDir === 'absent' || g.auditDir === 'listed')
    && (g.index === 'absent' || g.index === 'read')
    && g.skippedFiles === 0 && g.refusedFiles === 0 && g.failedFiles === 0 && g.droppedLines === 0;
}

// Rows from a refused or failed source (including a mid-stream failure) are
// neither counted nor allowed to suppress: each source's rows are buffered and
// committed only when the source was read to its target.
function runPass(pass, sources, gaps, visit) {
  const committed = [];
  let processed = 0;
  try {
    for (const source of sources) {
      const local = [];
      const res = forEachJsonlLine(source, (line, lineIndex) => visit(line, lineIndex, source.file, local), pass);
      gaps.droppedLines += res.droppedLines;
      if (source.isIndex) gaps.index = res.status;
      else if (res.status === 'refused') gaps.refusedFiles += 1;
      else if (res.status !== 'read') gaps.failedFiles += 1;
      if (res.status === 'read' || res.status === 'truncated') committed.push(...local);
      processed += 1;
    }
  } catch {
    for (const source of sources.slice(processed)) {
      if (source.isIndex) gaps.index = 'failed';
      else gaps.failedFiles += 1;
    }
  }
  return committed;
}

function collectGuardStateForSessionKey(sessionKey) {
  const coverageGaps = { receipts: newPassGaps(), guards: newPassGaps() };
  const sources = [];
  let indexState = 'failed';
  const indexFile = sessionGuardIndexFile(sessionKey);
  if (!indexFile) {
    indexState = 'absent';
  } else {
    try {
      const st = lstatSync(indexFile);
      if (!st.isFile() || st.isSymbolicLink()) indexState = 'refused';
      else {
        sources.push({ file: indexFile, isIndex: true, identity: { dev: st.dev, ino: st.ino } });
        indexState = null;
      }
    } catch (err) {
      indexState = err?.code === 'ENOENT' ? 'absent' : 'failed';
    }
  }
  const listing = auditFilesNewestFirst();
  for (const source of listing.files) sources.push(source);
  for (const gaps of [coverageGaps.receipts, coverageGaps.guards]) {
    gaps.auditDir = listing.state;
    gaps.skippedFiles = listing.skipped;
    gaps.refusedFiles = listing.refused;
    gaps.failedFiles = listing.failed;
    if (indexState) gaps.index = indexState;
  }
  // Two passes over the same sources: every receipt is known before any guard
  // is judged, so a summary that sits after its guard rows still covers them.
  // The per-session index is an acceleration source only; the canonical
  // primary audit remains the recovery source even when an index exists.
  const receipts = runPass('receipts', sources, coverageGaps.receipts, (line, _lineIndex, _file, out) => {
    const row = parseAuditLine(line);
    if (!row || !isSummaryRow(row, sessionKey)) return;
    out.push(Array.isArray(row.guardFingerprints)
      ? { fingerprints: row.guardFingerprints.map(String).filter((fp) => /^[a-f0-9]{16}$/.test(fp)), legacy: row.fingerprintScheme !== 2 }
      : { fingerprints: null, legacy: false });
  });
  const guards = runPass('guards', sources, coverageGaps.guards, (line, lineIndex, file, out) => {
    const row = parseAuditLine(line);
    if (!row || !isGuardRow(row, sessionKey)) return;
    out.push({ row, id: guardIdentity(row, `${file}:${lineIndex}`) });
  });

  const covered = new Set();
  const receiptKinds = { fingerprinted: 0, legacy: 0, fingerprintless: 0 };
  for (const r of receipts) {
    if (r.fingerprints === null) { receiptKinds.fingerprintless += 1; continue; }
    receiptKinds.fingerprinted += 1;
    if (r.legacy) receiptKinds.legacy += 1;
    for (const fp of r.fingerprints) covered.add(fp);
  }
  const receiptFingerprints = covered.size;
  // Step A: an observable historical v1 alias covers its row's primary (a
  // receipt that listed one copy of a bound row by position covers the mirror).
  for (const g of guards) {
    if (covered.has(g.id.primary) || covered.has(g.id.v1)) covered.add(g.id.primary);
  }
  // Step B: pending = what no receipt lists, one entry per identity.
  const pending = [];
  const seen = new Set();
  for (const g of guards) {
    if (covered.has(g.id.primary) || seen.has(g.id.primary)) continue;
    seen.add(g.id.primary);
    pending.push(g);
  }
  const coverage = passComplete(coverageGaps.receipts) && passComplete(coverageGaps.guards) ? 'bounded-complete' : 'partial';
  return {
    pending,
    receiptFingerprints,
    receiptKinds,
    receiptsComplete: passComplete(coverageGaps.receipts),
    coverage,
    coverageGaps,
    source: sources.some((src) => src.isIndex) ? 'index+audit' : 'audit',
  };
}

// Gap kinds and counts only — never a path.
function noteCoveragePartial(sessionKey, state) {
  if (state.coverage !== 'partial') return;
  const parts = [];
  for (const pass of ['receipts', 'guards']) {
    const g = state.coverageGaps[pass];
    const kinds = [];
    if (g.auditDir !== 'absent' && g.auditDir !== 'listed') kinds.push(`auditDir=${g.auditDir}`);
    if (g.index !== 'absent' && g.index !== 'read') kinds.push(`index=${g.index}`);
    for (const k of ['skippedFiles', 'refusedFiles', 'failedFiles', 'droppedLines']) {
      if (g[k] > 0) kinds.push(`${k}=${g[k]}`);
    }
    if (kinds.length) parts.push(`${pass}:${kinds.join(',')}`);
  }
  console.error(`[shieldcortex stop-hook] action_guard_degraded coverage=partial sessionKey=${sessionKey} ${parts.join(' ')}`);
}

function appendSessionGuardSummary(sessionKey, entry) {
  const indexFile = sessionGuardIndexFile(sessionKey);
  if (!indexFile) return false;
  try {
    if (!ensureDirectoryNoSymlink(AUDIT_DIR)) return false;
    if (!ensureDirectoryNoSymlink(SESSION_GUARD_DIR)) return false;
    return appendFileNoFollow(indexFile, JSON.stringify({ recordKind: 'summary', ...entry }) + '\n');
  } catch {
    return false; /* primary audit row remains canonical */
  }
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
    noteCoveragePartial(sessionKey, state);
    const status = { coverage: state.coverage, coverageGaps: state.coverageGaps };
    if (state.pending.length > 0) return { recorded: false, count: state.pending.length, pending: true, sessionKey, ...status };
    return state.receiptFingerprints > 0
      ? { recorded: true, count: 0, existing: true, sessionKey, ...status }
      : { recorded: false, count: 0, sessionKey, ...status };
  }
  try {
    const state = collectGuardStateForSessionKey(sessionKey);
    noteCoveragePartial(sessionKey, state);
    const status = { coverage: state.coverage, coverageGaps: state.coverageGaps };
    // `existing` means "nothing pending in what this reader inspected" — it is
    // only as strong as the `coverage` it travels with.
    if (state.pending.length === 0) {
      return state.receiptFingerprints > 0
        ? { recorded: true, count: 0, existing: true, sessionKey, ...status }
        : { recorded: false, count: 0, sessionKey, ...status };
    }
    // Batched so a receipt always fits the 1 MiB line cap both readers apply;
    // the rest stays pending for the next call. Never a receipt for rows it
    // does not list.
    const batch = state.pending.slice(0, MAX_RECEIPT_IDENTITIES);
    const pendingRemaining = state.pending.length - batch.length;
    const extra = pendingRemaining > 0 ? { pendingRemaining } : {};
    const rows = batch.map((g) => g.row);
    const identityBasis = { eventId: 0, bindingNonce: 0, physicalRow: 0 };
    for (const g of batch) identityBasis[g.id.basis] += 1;
    const overlapReasons = [];
    if (state.receiptKinds.fingerprintless > 0) overlapReasons.push('fingerprintless-summary');
    // Coarse on purpose: position-based prior coverage cannot be ruled out.
    // Never inferred from a missing file, a timestamp or matching content.
    if ((state.receiptKinds.legacy > 0 && identityBasis.bindingNonce > 0)
      || (state.receiptKinds.fingerprinted > 0 && identityBasis.physicalRow > 0)) {
      overlapReasons.push('position-dependent-receipt');
    }
    if (!state.receiptsComplete) overlapReasons.push('receipt-coverage-partial');
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
      guardOutcomeCount: batch.length,
      guardFingerprints: batch.map((g) => g.id.primary),
      fingerprintScheme: 2,
      identityBasis,
      // Cardinality of THIS batch only — not novelty, not coverage.
      eventCountExact: identityBasis.physicalRow === 0,
      ...(overlapReasons.length ? { historicalOverlap: 'possible', overlapReasons } : {}),
      ...(state.receiptKinds.fingerprintless > 0 ? { unknownMembershipSummaryRows: state.receiptKinds.fingerprintless } : {}),
      ...status,
      ...extra,
      outcomes: counts,
      threats,
      firstGuardTs: times[0],
      lastGuardTs: times[times.length - 1],
      ts: new Date().toISOString(),
    };
    const notWritten = { recorded: false, count: batch.length, sessionKey, receipt: 'none', indexMirror: 'not-attempted', ...status, ...extra };
    try {
      if (!ensureDirectoryNoSymlink(AUDIT_DIR)) {
        noteAuditSinkFailure('audit directory is unsafe or outside the state tree');
        return notWritten;
      }
      const date = new Date().toISOString().slice(0, 10);
      if (!appendFileNoFollow(join(AUDIT_DIR, `realtime-${date}.jsonl`), JSON.stringify(entry) + '\n')) {
        noteAuditSinkFailure(`append failed for realtime-${date}.jsonl`);
        return notWritten;
      }
      // Write outcomes are known only now: they live on the return value and
      // stderr, never patched back onto a row (history stays append-only).
      const mirrored = appendSessionGuardSummary(sessionKey, entry);
      if (!mirrored) console.error(`[shieldcortex stop-hook] action_guard_degraded index mirror FAILED sessionKey=${sessionKey}; the primary receipt stands`);
      console.error(`[shieldcortex stop-hook] action_guard_degraded sessionKey=${sessionKey} guardOutcomes=${batch.length}`);
      return {
        recorded: true,
        count: batch.length,
        sessionKey,
        receipt: mirrored ? 'primary+index' : 'primary-only',
        indexMirror: mirrored ? 'ok' : 'failed',
        ...status,
        ...extra,
      };
    } catch (err) {
      noteAuditSinkFailure(err?.message ?? err);
      return notWritten;
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
    // Test seam (#654): the result shape is otherwise only visible through
    // what it wrote, and the no-pending / existing / no-lock shapes write nothing.
    if (process.env.SHIELDCORTEX_TEST_EMIT_GUARD_RESULT === '1') {
      console.error(`[shieldcortex stop-hook] test-guard-result ${JSON.stringify(guardSummary)}`);
    }
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
        // #381 class: never prescribe hand-editing the signed config — that
        // invalidates _sig and forces strict mode. The setup flag is the
        // signed write path for this gate.
        `disabled — re-run \`shieldcortex setup --with-stop-hook\` to enable auto-memory (this sets autoMemory.enableStop via the signed config path)`,
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

        const capture = await extractCaptureMemories(transcriptOut.text, {
          mode: autoMemConfig.captureMode,
          config: autoMemConfig.rawConfig,
          regexExtract: () => {
            const segments = extractMemorableSegments(transcriptOut.text, { mode: 'stop' });
            return processSegments(segments, dyn, {
              hookTag: 'source:stop-hook',
              maxMemories: MAX_AUTO_MEMORIES,
              categoryThresholds: PRE_COMPACT_CATEGORY_THRESHOLDS,
              applyFrequencyBoost: false,
              conversationText: transcriptOut.text,
            });
          },
          log: (msg) => console.error(msg),
        });
        notes = [notes, `capture=${capture.path}${capture.reason ? ':' + capture.reason : ''}`].filter(Boolean).join('; ');

        for (const memory of capture.memories) {
          try {
            const tags = Array.isArray(memory.tags) ? memory.tags.slice() : [];
            if (capture.path === 'distill' && !tags.includes('distill')) tags.push('distill');
            memory.tags = tags;
            if (!memory.capture_layer && !memory.captureLayer) {
              memory.capture_layer = capture.path === 'distill' ? 'L1' : 'L0';
            }
            await saveAutoExtractedMemory(db, memory, project, { source: 'stop-hook' });
            extractedCount++;
            console.error(`[stop] Saved: ${memory.title} (salience: ${Number(memory.salience).toFixed(2)}, category: ${memory.category}, path=${capture.path})`);
          } catch (err) {
            console.error(`[stop] Failed to save "${memory.title}": ${err.message}`);
          }
        }
        const sampleReason = salientBypass ? `bypass=salience turn=${turnCount}` : `turn=${turnCount}`;
        console.error(`[stop] Sampled ${sampleReason}: ${extractedCount} memories via ${capture.path}`);
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
