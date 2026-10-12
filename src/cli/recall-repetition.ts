/**
 * Repeated top-k recall sets (#717 doctor diagnostic).
 *
 * #717's field report: four unrelated owner prompts all got the same six
 * candidates, because the recall query was built from the OpenClaw envelope
 * rather than the owner's words. #720 fixed that envelope; this is the
 * deferred check that would have caught it — a doctor WARN when the most
 * recent interactive prompt-recall runs all returned the same non-empty
 * top-k candidate set.
 *
 * What it reads: the existing recall ring buffer
 * (`<home>/.shieldcortex/recall-log/{0..9}.json`, written by
 * scripts/lib/recall-log.mjs). It consumes only fields the hook already
 * records — `lane`, `promptHash`, and each candidate's `id` and `dropReason`.
 * It never reads `prompt`, titles or any other candidate field into its
 * result, and the result carries counts only: no ids, hashes, text or paths.
 *
 * Deliberate limits:
 *
 *   - **Repetition is evidence, not a root cause.** An envelope- or
 *     wrapper-dominated query does this; so does asking about one topic
 *     several times, or an unmarked scheduled job recalling as `interactive`.
 *     The doctor row says so.
 *   - **Interactive lane only.** `cron` / `automation` / `subagent` runs
 *     repeat by design (a watchdog asks the same thing every 15 minutes), and
 *     a run with no recognised lane (pre-#718 writer) cannot be counted as
 *     interactive evidence. Both are skipped, never promoted.
 *   - **Prompt identity is the stored `promptHash` only** (a truncated sha256
 *     of the sanitised prompt). Equal hashes on every sampled run mean the
 *     same prompt was repeated, which explains the repetition: no WARN. Any
 *     run without a hash leaves prompt identity unknown, and the row says that
 *     rather than claiming the prompts differed.
 *   - **A sample it could not fully read is never healthy.** A corrupt,
 *     unreadable, oversized, non-regular or malformed slot met before the
 *     sample is complete stops the evaluation and reports why (by count).
 *   - **Read-only and bounded.** Fixed slot names (no directory listing),
 *     `O_NOFOLLOW` opens, regular files only, a per-file and total byte budget,
 *     and a per-run candidate cap. Nothing is created, rotated or repaired.
 *
 * Every filesystem call goes through `RecallRepetitionDeps`, including the
 * home directory, so tests drive it against fixtures and never the live HOME.
 */

import * as nodeFs from 'node:fs';
import { join } from 'node:path';

/** Interactive runs compared: the issue's example was four prompts. */
export const REPEAT_SAMPLE_RUNS = 4;
/**
 * Smallest shared top-k set that counts. The issue's set was five or six;
 * one or two dominant memories recurring on a focused project is ordinary.
 */
export const REPEAT_MIN_SET_SIZE = 3;
/** Ring slots the recall-log writer keeps (RECALL_RING_SIZE). */
export const RECALL_LOG_SLOTS = 10;
/** One recall-log entry is ~15 KB; anything far larger is not one. */
export const RECALL_LOG_MAX_ENTRY_BYTES = 64 * 1024;
/** Total bytes this check will read across all slots. */
export const RECALL_LOG_MAX_TOTAL_BYTES = 320 * 1024;
/** The hook logs its full candidate set, about 2 × top-N plus a top-up. */
export const RECALL_LOG_MAX_CANDIDATES = 64;

/**
 * The hook marks a candidate below its top-N cut `outside_top_n`, and a row a
 * non-interactive lane withheld `lane_policy:*`. Every other candidate was in
 * the top-k that recall ranked for injection.
 */
const OUTSIDE_TOP_K = 'outside_top_n';
const LANE_POLICY_PREFIX = 'lane_policy:';

export type SlotProblem = 'corrupt' | 'unreadable' | 'oversized' | 'unsafe' | 'malformed' | 'budget';

export type RecallRepetitionVerdict =
  /** No recall-log directory: recall has not logged a run here. */
  | { kind: 'absent' }
  /** The directory exists but is not a plain directory, or cannot be inspected. */
  | { kind: 'unavailable'; reason: 'unsafe' | 'unreadable' }
  /** A slot could not be used before the sample was complete. */
  | { kind: 'incomplete'; problems: Partial<Record<SlotProblem, number>>; interactiveRuns: number }
  /** Fewer than REPEAT_SAMPLE_RUNS interactive runs in the ring. */
  | { kind: 'insufficient'; interactiveRuns: number; otherLaneRuns: number; unknownLaneRuns: number }
  /** Runs share a set, but it is smaller than REPEAT_MIN_SET_SIZE. */
  | { kind: 'below-floor'; runs: number; setSize: number }
  /** Runs share a set, and every run carries the same prompt hash. */
  | { kind: 'same-prompt'; runs: number; setSize: number }
  /** At least one run returned a different or empty top-k set. */
  | { kind: 'varied'; runs: number }
  /** Every sampled run returned the same non-empty top-k set. */
  | { kind: 'repeated'; runs: number; setSize: number; distinctPromptHashes: number | null };

/** The filesystem surface the check needs. Production passes node:fs. */
export interface RecallRepetitionFs {
  lstatSync(p: string): { isDirectory(): boolean; isSymbolicLink(): boolean };
  openSync(p: string, flags: number): number;
  fstatSync(fd: number): { isFile(): boolean; size: number };
  readSync(fd: number, buf: Buffer, offset: number, length: number, position: number | null): number;
  closeSync(fd: number): void;
}

export interface RecallRepetitionDeps {
  /** Home directory holding `.shieldcortex/`. Required: no live-HOME fallback here. */
  homeDir: string;
  fs?: RecallRepetitionFs;
}

export function recallLogDirFor(homeDir: string): string {
  return join(homeDir, '.shieldcortex', 'recall-log');
}

function errCode(err: unknown): string | undefined {
  return typeof err === 'object' && err !== null && 'code' in err
    ? String((err as { code?: unknown }).code)
    : undefined;
}

type SlotRead =
  | { ok: true; text: string; bytes: number }
  | { ok: false; missing: true }
  | { ok: false; missing: false; problem: SlotProblem };

/**
 * Read one slot without following a symlink, refusing anything that is not a
 * regular file or that would exceed either byte budget.
 */
function readSlot(fs: RecallRepetitionFs, file: string, budgetLeft: number): SlotRead {
  const noFollow = nodeFs.constants.O_NOFOLLOW ?? 0;
  const nonBlock = nodeFs.constants.O_NONBLOCK ?? 0;
  let fd: number;
  try {
    // O_NONBLOCK so a FIFO planted at a slot name cannot hang doctor on open.
    fd = fs.openSync(file, nodeFs.constants.O_RDONLY | noFollow | nonBlock);
  } catch (err) {
    const code = errCode(err);
    if (code === 'ENOENT') return { ok: false, missing: true };
    // O_NOFOLLOW on a symlink fails with ELOOP (Linux) or EMLINK (BSD/macOS).
    if (code === 'ELOOP' || code === 'EMLINK') return { ok: false, missing: false, problem: 'unsafe' };
    return { ok: false, missing: false, problem: 'unreadable' };
  }
  try {
    const st = fs.fstatSync(fd);
    if (!st.isFile()) return { ok: false, missing: false, problem: 'unsafe' };
    if (st.size > RECALL_LOG_MAX_ENTRY_BYTES) return { ok: false, missing: false, problem: 'oversized' };
    if (st.size > budgetLeft) return { ok: false, missing: false, problem: 'budget' };
    // Read one byte past the cap so a file that grew after fstat is caught.
    const cap = Math.min(RECALL_LOG_MAX_ENTRY_BYTES, budgetLeft) + 1;
    const buf = Buffer.alloc(cap);
    let total = 0;
    while (total < cap) {
      const n = fs.readSync(fd, buf, total, cap - total, total);
      if (n <= 0) break;
      total += n;
    }
    if (total > RECALL_LOG_MAX_ENTRY_BYTES) return { ok: false, missing: false, problem: 'oversized' };
    if (total > budgetLeft) return { ok: false, missing: false, problem: 'budget' };
    return { ok: true, text: buf.subarray(0, total).toString('utf8'), bytes: total };
  } catch {
    return { ok: false, missing: false, problem: 'unreadable' };
  } finally {
    try { fs.closeSync(fd); } catch { /* read-only; nothing to undo */ }
  }
}

interface InteractiveRun {
  /** Canonical top-k key: sorted, de-duplicated candidate ids. Never surfaced. */
  key: string;
  setSize: number;
  promptHash: string | null;
}

type Classified =
  | { lane: 'interactive'; run: InteractiveRun }
  | { lane: 'other' }
  | { lane: 'unknown' }
  | { lane: 'malformed' };

const NON_INTERACTIVE_LANES = new Set(['cron', 'automation', 'subagent']);

function classify(entry: unknown): Classified {
  if (typeof entry !== 'object' || entry === null || Array.isArray(entry)) return { lane: 'malformed' };
  const e = entry as Record<string, unknown>;
  if (typeof e.lane === 'string' && NON_INTERACTIVE_LANES.has(e.lane)) return { lane: 'other' };
  if (e.lane !== 'interactive') return { lane: 'unknown' };

  const candidates = e.candidates;
  if (!Array.isArray(candidates) || candidates.length > RECALL_LOG_MAX_CANDIDATES) return { lane: 'malformed' };
  const ids = new Set<number>();
  for (const c of candidates) {
    if (typeof c !== 'object' || c === null) return { lane: 'malformed' };
    const { id, dropReason } = c as { id?: unknown; dropReason?: unknown };
    if (typeof id !== 'number' || !Number.isSafeInteger(id)) return { lane: 'malformed' };
    if (dropReason !== null && typeof dropReason !== 'string') return { lane: 'malformed' };
    if (dropReason === OUTSIDE_TOP_K) continue;
    if (typeof dropReason === 'string' && dropReason.startsWith(LANE_POLICY_PREFIX)) continue;
    ids.add(id);
  }
  // Sorted so the hook's candidate order (or a tie broken differently) never
  // makes two equal sets look different.
  const key = [...ids].sort((a, b) => a - b).join(',');
  const promptHash = typeof e.promptHash === 'string' && e.promptHash.length > 0 ? e.promptHash : null;
  return { lane: 'interactive', run: { key, setSize: ids.size, promptHash } };
}

/**
 * Evaluate the newest REPEAT_SAMPLE_RUNS interactive runs in the recall ring.
 * Read-only: never creates, rotates or rewrites anything.
 */
export function evaluateRecallRepetition(deps: RecallRepetitionDeps): RecallRepetitionVerdict {
  const fs = deps.fs ?? (nodeFs as unknown as RecallRepetitionFs);
  const dir = recallLogDirFor(deps.homeDir);

  try {
    const st = fs.lstatSync(dir);
    if (st.isSymbolicLink() || !st.isDirectory()) return { kind: 'unavailable', reason: 'unsafe' };
  } catch (err) {
    if (errCode(err) === 'ENOENT') return { kind: 'absent' };
    return { kind: 'unavailable', reason: 'unreadable' };
  }

  const runs: InteractiveRun[] = [];
  const problems: Partial<Record<SlotProblem, number>> = {};
  let otherLaneRuns = 0;
  let unknownLaneRuns = 0;
  let budgetLeft = RECALL_LOG_MAX_TOTAL_BYTES;

  // Slot 0 is newest. Stop at the first slot that cannot be used: a run hidden
  // behind it could break or make the streak, so no verdict is safe past it.
  for (let slot = 0; slot < RECALL_LOG_SLOTS && runs.length < REPEAT_SAMPLE_RUNS; slot++) {
    const read = readSlot(fs, join(dir, `${slot}.json`), budgetLeft);
    if (!read.ok) {
      if (read.missing) continue;
      problems[read.problem] = (problems[read.problem] ?? 0) + 1;
      break;
    }
    budgetLeft -= read.bytes;
    let parsed: unknown;
    try {
      parsed = JSON.parse(read.text);
    } catch {
      problems.corrupt = (problems.corrupt ?? 0) + 1;
      break;
    }
    const c = classify(parsed);
    if (c.lane === 'malformed') {
      problems.malformed = (problems.malformed ?? 0) + 1;
      break;
    }
    if (c.lane === 'other') otherLaneRuns++;
    else if (c.lane === 'unknown') unknownLaneRuns++;
    else runs.push(c.run);
  }

  if (Object.keys(problems).length > 0) {
    return { kind: 'incomplete', problems, interactiveRuns: runs.length };
  }
  if (runs.length < REPEAT_SAMPLE_RUNS) {
    return { kind: 'insufficient', interactiveRuns: runs.length, otherLaneRuns, unknownLaneRuns };
  }

  const first = runs[0];
  const same = first.setSize > 0 && runs.every((r) => r.key === first.key);
  if (!same) return { kind: 'varied', runs: runs.length };
  if (first.setSize < REPEAT_MIN_SET_SIZE) return { kind: 'below-floor', runs: runs.length, setSize: first.setSize };

  const hashes = runs.map((r) => r.promptHash);
  const allHashed = hashes.every((h): h is string => h !== null);
  const distinct = allHashed ? new Set(hashes).size : null;
  if (distinct === 1) return { kind: 'same-prompt', runs: runs.length, setSize: first.setSize };
  return { kind: 'repeated', runs: runs.length, setSize: first.setSize, distinctPromptHashes: distinct };
}
