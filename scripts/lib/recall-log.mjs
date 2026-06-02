/**
 * Recall ring buffer (v4.25.1).
 *
 * Each prompt-recall hook run logs "what prompt fired, what candidates did
 * we consider, which were injected, which were dropped, and why?" Operators
 * read it via `shieldcortex inspect last-recall` when diagnosing why a
 * particular memory surfaced (or didn't) for a particular prompt.
 *
 * Designed to gather the data needed to scope v4.26.x recall-quality fixes
 * from real fleet usage instead of one-anecdote guesses. See the v4.25.1
 * plan for the diagnostic context (Jarvis's "Google Slides memory for a
 * ShieldCortex-versions prompt" report, 2026-05-27).
 *
 * Ring buffer at `~/.shieldcortex/recall-log/{0..9}.json` — index 0 is the
 * most recent. On every write we rotate (delete 9, rename 8→9, …, 0→1) and
 * atomically write the new run to index 0 via a temp-file + rename so a
 * crash mid-rotation never leaves a torn JSON file.
 *
 * Size cap: 10 files × ~15KB each (~150KB max). Each entry is slightly
 * larger than precompact because it carries the prompt + per-candidate
 * FTS rank / effective salience metadata.
 *
 * Best-effort — never throws into the caller. The hook must not block recall
 * on a missing ~/.shieldcortex directory or a transient EBUSY.
 *
 * Trust boundary: identical to ~/.shieldcortex/memories.db (already stores
 * raw memory content). Prompts are capped at 200 chars and the upstream
 * sanitiser (scripts/lib/prompt-sanitiser.mjs) has already stripped
 * framework metadata + fenced JSON before we see the prompt.
 */

import { existsSync, mkdirSync, readFileSync, renameSync, unlinkSync, writeFileSync } from 'fs';
import { homedir } from 'os';
import { join } from 'path';

const RING_SIZE = 10;

// Resolved per-call so tests can swap HOME between cases. Read
// `process.env.HOME` directly rather than going through `os.homedir()`
// because jest's ESM VM loader doesn't reliably reflect HOME mutations
// through homedir() (same gotcha as precompact-log.mjs).
function logDir() {
  return join(process.env.HOME || homedir(), '.shieldcortex', 'recall-log');
}

function logPath(index) {
  return join(logDir(), `${index}.json`);
}

function ensureDir() {
  const dir = logDir();
  if (!existsSync(dir)) {
    mkdirSync(dir, { recursive: true });
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
 * Atomically write a recall run entry to slot 0 (the newest slot).
 * Rotates the ring beforehand.
 *
 * @param {{
 *   ranAt?: string,
 *   prompt?: string,
 *   promptHash?: string,
 *   sessionId?: string,
 *   project?: string,
 *   minSalience?: number,
 *   candidates: Array<{
 *     id?: number,
 *     title?: string,
 *     category?: string,
 *     memoryPurpose?: string,
 *     salience?: number,
 *     ftsRank?: number | null,
 *     source?: 'fts' | 'category-boost',
 *     effectiveSalience?: number,
 *     injected?: boolean,
 *     // Why a candidate was not injected (null = injected). Recognised values:
 *     //   'dedupe'                — content hash seen in a recent turn
 *     //   'outside_top_n'         — ranked below the MAX_RESULTS cut
 *     //   'not_injected'          — early-exit before the dedupe filter ran
 *     //   'below_term_coverage'   — P4 gate: matched too few distinct query terms
 *     //   'below_relevance_floor' — P4 gate: BM25 rank below the relative floor
 *     // The two P4 reasons appear in SHADOW mode too (the row is still
 *     // injected then) so `shieldcortex inspect last-recall` can show
 *     // "considered but below floor" for threshold tuning before enforcement.
 *     dropReason?:
 *       | 'dedupe'
 *       | 'outside_top_n'
 *       | 'not_injected'
 *       | 'below_term_coverage'
 *       | 'below_relevance_floor'
 *       | null,
 *   }>,
 *   injectedCount?: number,
 *   finalContextChars?: number,
 * }} entry
 */
export function writeRecallLog(entry) {
  try {
    ensureDir();
    rotate();
    const payload = {
      ranAt: entry.ranAt ?? new Date().toISOString(),
      prompt: entry.prompt ?? null,
      promptHash: entry.promptHash ?? null,
      sessionId: entry.sessionId ?? null,
      project: entry.project ?? null,
      minSalience: entry.minSalience ?? null,
      candidates: Array.isArray(entry.candidates) ? entry.candidates : [],
      injectedCount: entry.injectedCount ?? null,
      finalContextChars: entry.finalContextChars ?? null,
    };
    const target = logPath(0);
    const tmp = `${target}.tmp`;
    writeFileSync(tmp, JSON.stringify(payload, null, 2), 'utf8');
    renameSync(tmp, target);
  } catch {
    // Best-effort. The hook continues without a log entry rather than
    // blocking recall on a disk error.
  }
}

/**
 * Read a recall log entry by ring index.
 *
 * @param {number} index — 0 = newest, RING_SIZE-1 = oldest
 * @returns {object | null} parsed entry, or null if missing/corrupt
 */
export function readRecallLog(index = 0) {
  try {
    const raw = readFileSync(logPath(index), 'utf8');
    return JSON.parse(raw);
  } catch {
    return null;
  }
}

/**
 * Read all present recall log entries, newest first. Missing slots are
 * skipped (no nulls in the returned array).
 *
 * @returns {Array<{ index: number, entry: object }>}
 */
export function listRecallLogs() {
  const out = [];
  for (let i = 0; i < RING_SIZE; i++) {
    const entry = readRecallLog(i);
    if (entry) out.push({ index: i, entry });
  }
  return out;
}

export const RECALL_RING_SIZE = RING_SIZE;
export { logDir as getRecallLogDir };
