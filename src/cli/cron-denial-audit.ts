/**
 * Cron denial correlation (#375 P2) — the honest half of "last_run_status: ok".
 *
 * A guard denial inside a scheduled turn does not fail the turn. OpenClaw
 * records `last_run_status: ok` and the operator sees green while the job has
 * in fact done nothing for weeks (two such crons were dead 2+ weeks on Edith).
 * ShieldCortex cannot rewrite OpenClaw's status — it CAN join its own denial
 * log to OpenClaw's run log and say out loud that the green is a lie.
 *
 * Deliberate limits, all of them chosen so a wrong answer is impossible rather
 * than unlikely:
 *
 *   - **Match A only.** A denial is attributed to a job only when its session
 *     key is literally OpenClaw's cron run key (`agent:<agent>:cron:<uuid>:
 *     run:<...>`) and the job id is the exact token inside it. Everything else
 *     is counted as unattributed and shown as a number. There is no fuzzy
 *     matching, and the hook lane (Match B) is deferred until denials carry a
 *     join key — guessing would print a job name next to someone else's
 *     denial.
 *   - **No nearest-run fallback.** The run row is found by EXACT session_key
 *     inside an SQL-bounded window, or not at all. A nearest-in-time fallback
 *     can glue a denial to an unrelated run that happened to succeed, and then
 *     print a green lie with more confidence than the lie it replaced.
 *   - **No row means unconfirmed, never silent and never a pass.** "We could
 *     not look" is reported as its own count.
 *   - **Nothing from the denial surface is ever surfaced.** Correlation reads
 *     `actionId`, the session key and timestamps only; pinnable paths come
 *     from the job's own discovered scripts (#375 P1), never from denial text.
 *
 * Lives under `src/cli/` and imports no guard-runtime module: importing this
 * from the hot path is forbidden and asserted by test.
 */

import { closeSync, fstatSync, openSync, readSync } from 'node:fs';
import { homedir } from 'node:os';
import { join } from 'node:path';
import {
  CRON_RUN_LOGS_TABLE,
  defaultOpenClawCronDbPath,
  discoverDbCronScripts,
  isIncomplete,
  openCronStore,
  type CronProbeStatus,
} from './openclaw-cron-store.js';
import type { Database as SqliteDatabase } from 'better-sqlite3';

/** The window every surface quotes as "the last 7 days". */
export const CRON_DENIAL_WINDOW_MS = 7 * 24 * 60 * 60 * 1000;

/** denials.jsonl is append-only and unrotated on long-lived hosts. Read the
 *  tail, not the file: correlation must stay bounded on a 300MB log. */
export const DENIALS_TAIL_BYTES = 4 * 1024 * 1024;

/**
 * Match A. The capture group is the job id — an exact token, not a prefix
 * match, so the key shape cannot be satisfied by a lookalike.
 */
export const CRON_SESSION_KEY_RE = /^agent:[A-Za-z0-9_-]+:cron:([0-9a-f-]{36}):run:/;

export type DenialsLogStatus = 'ok' | 'absent' | 'unreadable';

export interface CronDenialJob {
  jobId: string;
  /** From the cron store when the job still exists; the job id otherwise. */
  name: string;
  enabled: boolean;
  denialCount: number;
  /** Epoch ms of the most recent attributed denial, or null. */
  lastDenialTs: number | null;
  /** Denials whose EXACTLY-matched run row reported `ok` — the silent kills. */
  silentCount: number;
  /** Scripts this job names (#375 P1 extraction). Never denial-derived. */
  pinnablePaths: string[];
}

export interface CronDenialReport {
  windowMs: number;
  windowStart: number;
  now: number;

  denialsPath: string;
  denialsStatus: DenialsLogStatus;

  dbPath: string;
  /** `cron_jobs` probe status — names/paths come from here. */
  jobsStatus: CronProbeStatus;
  /** `cron_run_logs` probe status — the silence verdict comes from here. */
  storeStatus: CronProbeStatus;

  /**
   * Null when the join actually ran. A short reason when it could not, in
   * which case `silentCount` is 0 because it is unknown, NOT because it is
   * zero — every caller must render cannot-look rather than a pass.
   */
  cannotCorrelate: string | null;

  /** Attributed jobs, most-silent first. Present even when correlation was
   *  impossible, so the operator still sees which jobs were denied. */
  jobs: CronDenialJob[];

  attributedCount: number;
  /** Denials whose session key is not an OpenClaw cron run key. A count, not
   *  a guess. */
  unattributedCount: number;
  /** Attributed denials with no exactly-matching run row. */
  unconfirmedCount: number;
  /** Rows with no parseable timestamp — cannot be claimed to be in the
   *  window, and never silently dropped. */
  undatedCount: number;
  /** Total silent denials across `jobs`. */
  silentCount: number;
}

export interface CorrelateCronDenialsOptions {
  home?: string;
  openclawDbPath?: string;
  denialsPath?: string;
  windowMs?: number;
  /** Test seam. */
  now?: number;
  /**
   * Test seam for the store opener. Production always uses the read-only
   * {@link openCronStore}; the seam exists so the fail-closed branch for a
   * run-log query that dies MID-correlation (after the probe passed) can be
   * proven, which no fixture on disk can reproduce deterministically.
   */
  openStore?: (dbPath: string) => SqliteDatabase;
}

// ── denials.jsonl ───────────────────────────────────────────

function readDenialsTail(path: string): { status: DenialsLogStatus; text: string } {
  let fd: number | undefined;
  try {
    fd = openSync(path, 'r');
    const st = fstatSync(fd);
    if (!st.isFile()) return { status: 'unreadable', text: '' };
    const size = st.size;
    const start = size > DENIALS_TAIL_BYTES ? size - DENIALS_TAIL_BYTES : 0;
    const length = size - start;
    const buf = Buffer.alloc(length);
    let read = 0;
    while (read < length) {
      const n = readSync(fd, buf, read, length - read, start + read);
      if (n <= 0) break;
      read += n;
    }
    let text = buf.subarray(0, read).toString('utf8');
    if (start > 0) {
      // The first line of a tail read is a fragment of a record we did not
      // start reading. A half-parsed denial is worse than a dropped one.
      const nl = text.indexOf('\n');
      text = nl === -1 ? '' : text.slice(nl + 1);
    }
    return { status: 'ok', text };
  } catch (e) {
    const err = e as NodeJS.ErrnoException;
    if (err && err.code === 'ENOENT') return { status: 'absent', text: '' };
    return { status: 'unreadable', text: '' };
  } finally {
    if (fd !== undefined) {
      try {
        closeSync(fd);
      } catch {
        /* ignore */
      }
    }
  }
}

interface DenialRow {
  actionId?: unknown;
  sessionKey?: unknown;
  sessionId?: unknown;
  detectedAt?: unknown;
}

/**
 * The key the denial was recorded under.
 *
 * `sessionKey` is the field the spec names and the one the gateway lane
 * writes. `sessionId` is read as a second look because the Claude Code hook
 * lane stores the same logical value under that name; it can only ever match
 * when it literally holds an OpenClaw cron run key, because Match A is an
 * exact-shape regex. Neither field is ever printed.
 */
function sessionKeyOf(row: DenialRow): string {
  if (typeof row.sessionKey === 'string') return row.sessionKey;
  if (typeof row.sessionId === 'string') return row.sessionId;
  return '';
}

function timestampOf(row: DenialRow): number | null {
  const raw = row.detectedAt;
  if (typeof raw === 'number' && Number.isFinite(raw)) return raw;
  if (typeof raw === 'string') {
    const t = Date.parse(raw);
    if (Number.isFinite(t)) return t;
  }
  return null;
}

interface Denial {
  sessionKey: string;
  ts: number;
}

/**
 * Parse, dedupe and window the denial log.
 *
 * Every denial writes two lines (the outcome, then the notify status) under
 * one `actionId`, so the id is the dedupe key. Rows without one cannot be
 * deduped and are kept individually rather than merged — merging unrelated
 * rows would undercount, and undercounting is the failure mode this whole
 * module exists to stop.
 */
export function parseDenials(
  text: string,
  bounds: { windowStart: number; now: number },
): { denials: Denial[]; undated: number } {
  const byAction = new Map<string, Denial>();
  const loose: Denial[] = [];
  let undated = 0;

  for (const line of text.split('\n')) {
    const trimmed = line.trim();
    if (!trimmed) continue;
    let row: DenialRow;
    try {
      row = JSON.parse(trimmed) as DenialRow;
    } catch {
      continue; // a torn or non-JSON line carries no join key
    }
    if (!row || typeof row !== 'object') continue;

    const ts = timestampOf(row);
    if (ts === null) {
      undated += 1;
      continue;
    }
    if (ts < bounds.windowStart || ts > bounds.now) continue;

    const denial: Denial = { sessionKey: sessionKeyOf(row), ts };
    const actionId = typeof row.actionId === 'string' && row.actionId ? row.actionId : null;
    if (!actionId) {
      loose.push(denial);
      continue;
    }
    const seen = byAction.get(actionId);
    if (!seen) {
      byAction.set(actionId, denial);
      continue;
    }
    // Keep the earliest sighting (the denial itself, not its notify receipt)
    // and the session key of whichever line carried one.
    if (denial.ts < seen.ts) seen.ts = denial.ts;
    if (!seen.sessionKey && denial.sessionKey) seen.sessionKey = denial.sessionKey;
  }

  return { denials: [...byAction.values(), ...loose], undated };
}

// ── Correlation ─────────────────────────────────────────────

interface Attributed {
  jobId: string;
  ts: number;
  sessionKey: string;
}

interface Aggregate {
  jobId: string;
  denialCount: number;
  lastDenialTs: number | null;
  silentCount: number;
}

/**
 * Join ShieldCortex denials to OpenClaw cron runs and report where a denial
 * happened inside a run the gateway called `ok`.
 *
 * Never throws and never writes. Every failure mode resolves to a status the
 * caller must render as cannot-look.
 */
export function correlateCronDenials(opts: CorrelateCronDenialsOptions = {}): CronDenialReport {
  const home = opts.home ?? homedir();
  const denialsPath = opts.denialsPath ?? join(home, '.shieldcortex', 'denials.jsonl');
  const dbPath = opts.openclawDbPath ?? defaultOpenClawCronDbPath(home);
  const windowMs = opts.windowMs ?? CRON_DENIAL_WINDOW_MS;
  const now = opts.now ?? Date.now();
  const windowStart = now - windowMs;

  const discovery = discoverDbCronScripts({ dbPath, home });
  const base: CronDenialReport = {
    windowMs,
    windowStart,
    now,
    denialsPath,
    denialsStatus: 'absent',
    dbPath,
    jobsStatus: discovery.probe.jobs,
    storeStatus: discovery.probe.runLogs,
    cannotCorrelate: null,
    jobs: [],
    attributedCount: 0,
    unattributedCount: 0,
    unconfirmedCount: 0,
    undatedCount: 0,
    silentCount: 0,
  };

  const log = readDenialsTail(denialsPath);
  base.denialsStatus = log.status;
  if (log.status === 'unreadable') {
    return { ...base, cannotCorrelate: 'denial log unreadable' };
  }

  // A cron store whose run log is present-but-wrong (or unreadable) is
  // cannot-look on its own terms, denials or not: reporting "0 silent" from a
  // table we cannot read is the green lie in a new costume.
  if (isIncomplete(discovery.probe.runLogs)) {
    base.cannotCorrelate = `${CRON_RUN_LOGS_TABLE} ${discovery.probe.runLogs}`;
  }

  if (log.status === 'absent') {
    // Nothing was ever denied on this host. Nothing to correlate; the
    // cannot-look verdict above (if any) still stands.
    return base;
  }

  const parsed = parseDenials(log.text, { windowStart, now });
  base.undatedCount = parsed.undated;

  const attributed: Attributed[] = [];
  for (const denial of parsed.denials) {
    const match = CRON_SESSION_KEY_RE.exec(denial.sessionKey);
    if (!match) {
      base.unattributedCount += 1;
      continue;
    }
    attributed.push({ jobId: match[1], ts: denial.ts, sessionKey: denial.sessionKey });
  }
  base.attributedCount = attributed.length;

  const aggregates = new Map<string, Aggregate>();
  const bump = (jobId: string, ts: number): Aggregate => {
    const agg = aggregates.get(jobId) ?? { jobId, denialCount: 0, lastDenialTs: null, silentCount: 0 };
    agg.denialCount += 1;
    agg.lastDenialTs = agg.lastDenialTs === null ? ts : Math.max(agg.lastDenialTs, ts);
    aggregates.set(jobId, agg);
    return agg;
  };

  if (attributed.length === 0) return base;

  // Count every attributed denial BEFORE looking at run status, so a
  // correlation that dies halfway still reports what was denied. Silence is
  // the only thing the run log gets to decide.
  for (const a of attributed) bump(a.jobId, a.ts);

  // A run log we cannot read while denials ARE attributed is the fail-closed
  // case: count the denials, refuse to rule on silence.
  if (base.cannotCorrelate === null && discovery.probe.runLogs !== 'ok') {
    base.cannotCorrelate = `${CRON_RUN_LOGS_TABLE} ${discovery.probe.runLogs}`;
  }

  if (base.cannotCorrelate !== null) {
    return { ...base, jobs: renderJobs(aggregates, discovery.jobsById) };
  }

  let db: SqliteDatabase | null = null;
  try {
    db = (opts.openStore ?? openCronStore)(dbPath);
    const findRun = db.prepare(
      `SELECT status FROM ${CRON_RUN_LOGS_TABLE}
        WHERE job_id = ? AND run_at_ms BETWEEN ? AND ? AND session_key = ?
        ORDER BY run_at_ms DESC LIMIT 1`,
    );
    for (const a of attributed) {
      const agg = aggregates.get(a.jobId);
      const row = findRun.get(a.jobId, windowStart, now, a.sessionKey) as { status?: unknown } | undefined;
      if (!row) {
        // No exactly-matched run row. Not silent, not clean — unconfirmed.
        base.unconfirmedCount += 1;
        continue;
      }
      if (agg && String(row.status ?? '').toLowerCase() === 'ok') {
        agg.silentCount += 1;
        base.silentCount += 1;
      }
    }
  } catch {
    // A query that fails mid-correlation invalidates the verdict, not just
    // the remaining rows: drop every silence claim made so far.
    base.silentCount = 0;
    base.unconfirmedCount = 0;
    for (const agg of aggregates.values()) agg.silentCount = 0;
    return {
      ...base,
      storeStatus: 'unreadable',
      cannotCorrelate: `${CRON_RUN_LOGS_TABLE} unreadable`,
      jobs: renderJobs(aggregates, discovery.jobsById),
    };
  } finally {
    try {
      db?.close();
    } catch {
      /* ignore */
    }
  }

  return { ...base, jobs: renderJobs(aggregates, discovery.jobsById) };
}

function renderJobs(
  aggregates: Map<string, Aggregate>,
  jobsById: Map<string, { name: string; enabled: boolean; paths: string[] }>,
): CronDenialJob[] {
  const out: CronDenialJob[] = [];
  for (const agg of aggregates.values()) {
    const job = jobsById.get(agg.jobId);
    out.push({
      jobId: agg.jobId,
      name: job?.name ?? agg.jobId,
      // A job that is no longer in the store cannot be claimed to be enabled.
      enabled: job?.enabled ?? false,
      denialCount: agg.denialCount,
      lastDenialTs: agg.lastDenialTs,
      silentCount: agg.silentCount,
      pinnablePaths: job ? [...job.paths] : [],
    });
  }
  return out.sort(
    (a, b) =>
      b.silentCount - a.silentCount ||
      b.denialCount - a.denialCount ||
      a.name.localeCompare(b.name) ||
      a.jobId.localeCompare(b.jobId),
  );
}

/** Every script path a denied job names — the denied-first key `allowlist
 *  scan` sorts on, mapped to the job that names it. */
export function deniedScriptPaths(report: CronDenialReport): Map<string, string> {
  const byPath = new Map<string, string>();
  for (const job of report.jobs) {
    for (const p of job.pinnablePaths) if (!byPath.has(p)) byPath.set(p, job.name);
  }
  return byPath;
}
