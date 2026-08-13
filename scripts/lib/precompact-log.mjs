/**
 * Precompact ring buffer (v4.25.0).
 *
 * Each precompact hook run writes a debug log of "what did the extractor
 * propose this time, and which proposals actually landed in `memories`?"
 * Operators can read it via `shieldcortex inspect last-precompact` when
 * tuning thresholds or chasing weird auto-extract behaviour.
 *
 * Ring buffer at `~/.shieldcortex/precompact-log/{0..9}.json` — index 0 is
 * the most recent. On every write we rotate (delete 9, rename 8→9, ..., 0→1)
 * and atomically write the new run to index 0 via a temp-file + rename so a
 * crash mid-rotation never leaves a torn JSON file.
 *
 * Size cap: 10 files × ~5KB each = ~50KB. Negligible disk impact.
 *
 * Designed to be best-effort — never throws into the caller. The hook
 * absolutely must not block compaction on a missing ~/.shieldcortex
 * directory or a transient EBUSY.
 */

import { existsSync, mkdirSync, readFileSync, renameSync, unlinkSync, writeFileSync } from 'fs';
import { mkdirSecure } from './state-perms.mjs';
import { homedir } from 'os';
import { join } from 'path';

const RING_SIZE = 10;

// Resolved per-call so tests can swap HOME between cases. Read
// `process.env.HOME` directly rather than going through `os.homedir()`
// because jest's ESM VM loader doesn't reliably reflect HOME mutations
// through homedir(), causing test-suite cross-contamination.
function logDir() {
  return join(process.env.HOME || homedir(), '.shieldcortex', 'precompact-log');
}

function logPath(index) {
  return join(logDir(), `${index}.json`);
}

function ensureDir() {
  const dir = logDir();
  if (!existsSync(dir)) {
    mkdirSecure(dir);
  }
}

/**
 * Rotate the ring buffer one slot. Oldest entry (index 9) is unlinked,
 * remaining entries shift up by one. Safe to call when slots are missing.
 */
function rotate() {
  try {
    unlinkSync(logPath(RING_SIZE - 1));
  } catch {
    // No file at the oldest slot — fine.
  }
  for (let i = RING_SIZE - 2; i >= 0; i--) {
    const from = logPath(i);
    const to = logPath(i + 1);
    if (existsSync(from)) {
      try {
        renameSync(from, to);
      } catch {
        // Best-effort — skip if EBUSY/EACCES.
      }
    }
  }
}

/**
 * Atomically write a precompact run entry to slot 0 (the newest slot).
 * Rotates the ring beforehand.
 *
 * @param {{
 *   ranAt?: string,
 *   thresholdUsed?: number,
 *   contextFullnessPct?: number,
 *   totalMemories?: number,
 *   candidates: Array<{
 *     extractorType?: string,
 *     category?: string,
 *     memoryPurpose?: string,
 *     title?: string,
 *     salience?: number,
 *     saved?: boolean,
 *     memoryId?: number | null,
 *     dropReason?: string | null,
 *   }>,
 * }} entry
 */
export function writePrecompactLog(entry) {
  try {
    ensureDir();
    rotate();
    const payload = {
      ranAt: entry.ranAt ?? new Date().toISOString(),
      thresholdUsed: entry.thresholdUsed ?? null,
      contextFullnessPct: entry.contextFullnessPct ?? null,
      totalMemories: entry.totalMemories ?? null,
      candidates: Array.isArray(entry.candidates) ? entry.candidates : [],
    };
    const target = logPath(0);
    const tmp = `${target}.tmp`;
    writeFileSync(tmp, JSON.stringify(payload, null, 2), 'utf8');
    renameSync(tmp, target);
  } catch {
    // Best-effort. The hook continues without a log entry rather than
    // blocking compaction on a disk error.
  }
}

/**
 * Read a precompact log entry by ring index.
 *
 * @param {number} index — 0 = newest, RING_SIZE-1 = oldest
 * @returns {object | null} parsed entry, or null if missing/corrupt
 */
export function readPrecompactLog(index = 0) {
  try {
    const raw = readFileSync(logPath(index), 'utf8');
    return JSON.parse(raw);
  } catch {
    return null;
  }
}

/**
 * Read all present precompact log entries, newest first. Missing slots are
 * skipped (no nulls in the returned array).
 *
 * @returns {Array<{ index: number, entry: object }>}
 */
export function listPrecompactLogs() {
  const out = [];
  for (let i = 0; i < RING_SIZE; i++) {
    const entry = readPrecompactLog(i);
    if (entry) out.push({ index: i, entry });
  }
  return out;
}

export const PRECOMPACT_RING_SIZE = RING_SIZE;
export { logDir as getPrecompactLogDir };
