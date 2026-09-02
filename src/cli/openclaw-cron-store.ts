/**
 * Read-only reader for OpenClaw's SQLite cron store (#375, #456).
 *
 * OpenClaw migrated `~/.openclaw/cron/jobs.json` into
 * `~/.openclaw/state/openclaw.sqlite` (`cron_jobs`, `cron_run_logs`) and
 * deleted the JSON, leaving `.bak`/`.migrated` siblings behind. `allowlist
 * scan` (#309) only knew the JSON, so on a migrated host it discovered zero
 * gateway cron scripts and reported "all clear" — every new cron script broke
 * silently on its first run. This module is the single place that reads the
 * new store.
 *
 * OpenClaw 2026.8.1 changed the schema again (#456, measured on a live
 * 82-job host), so the store now has two recognised generations:
 *
 *   - **gen1** (OpenClaw 1): `cron_jobs` with `payload_message` +
 *     `trigger_script`, run outcomes in `cron_run_logs`
 *     (`job_id`/`session_key`/`run_at_ms`/`status`).
 *   - **gen2** (OpenClaw 2): `cron_jobs` WITHOUT those two columns — the
 *     message lives at `job_json` → `payload.message` — and run outcomes in
 *     `cron_run_receipts` (`job_id`/`status`/`started_at_ms`/`finished_at_ms`;
 *     there is no `session_key` and no `run_at_ms`).
 *
 * A `cron_jobs` table matching NEITHER generation stays `schema_mismatch`:
 * recognising gen2 must not soften the "unknown shape is cannot-look" rule
 * that made the original bug visible.
 *
 * Two rules hold everywhere below:
 *
 *   1. **Never write.** `openCronStore` is the only open, and it is
 *      `readonly: true, fileMustExist: true`. There is no RW branch, no
 *      `node:sqlite`, and no `sqlite3` spawn. (SQLite may still materialise
 *      `-wal`/`-shm` siblings on open — we claim no SQL writes, not zero
 *      filesystem side effects.)
 *   2. **"We could not look" is never "all clear."** {@link probeCronSource}
 *      returns the honesty enum both `allowlist scan` and `doctor` key off,
 *      and {@link isIncomplete} is the one predicate that decides whether a
 *      status is a finding (scan exit 1 / doctor WARN) rather than a pass.
 */

import { statSync } from 'node:fs';
import { createRequire } from 'node:module';
import { join } from 'node:path';
import type { Database as SqliteDatabase } from 'better-sqlite3';
import { extractScriptPaths } from './script-paths.js';

const require = createRequire(import.meta.url);

/** Where OpenClaw keeps the migrated store. Injectable everywhere; the real
 *  `~/.openclaw` is never read under test (#309 rule). */
export function defaultOpenClawCronDbPath(home: string): string {
  return join(home, '.openclaw', 'state', 'openclaw.sqlite');
}

export const CRON_JOBS_TABLE = 'cron_jobs';
export const CRON_RUN_LOGS_TABLE = 'cron_run_logs';
export const CRON_RUN_RECEIPTS_TABLE = 'cron_run_receipts';

/** The two store shapes we know how to read (see module header). */
export type CronStoreGeneration = 'gen1' | 'gen2';

/** Columns P1 discovery reads on a gen1 store. A store missing any of them —
 *  and not matching gen2 either — is a shape we do not understand: reported,
 *  never silently skipped. */
export const REQUIRED_CRON_JOB_COLUMNS = [
  'job_id',
  'name',
  'enabled',
  'payload_message',
  'trigger_script',
  'job_json',
] as const;

/** Columns P1 discovery reads on a gen2 store. The message lives inside
 *  `job_json` (payload.message); the two legacy columns must be ABSENT for a
 *  store to classify as gen2 — their presence alongside a failed gen1 match
 *  is an unknown shape, not a newer one. */
export const REQUIRED_CRON_JOB_COLUMNS_GEN2 = ['job_id', 'name', 'enabled', 'job_json'] as const;

/** Columns P2 correlation reads. The run log is the silent-source-of-truth:
 *  it is what says a run "reported ok" while the guard denied inside it. */
export const REQUIRED_CRON_RUN_LOG_COLUMNS = ['job_id', 'session_key', 'run_at_ms', 'status'] as const;

/** The gen2 run-outcome columns. `request_run_id` exists but was NULL on
 *  every sampled live row, so correlation cannot key on it and we do not
 *  require it. */
export const REQUIRED_CRON_RUN_RECEIPT_COLUMNS = [
  'job_id',
  'status',
  'started_at_ms',
  'finished_at_ms',
] as const;

/**
 * The shared honesty enum.
 *
 *   `ok`               — table present with every required column.
 *   `absent`           — file missing, or the table simply is not there. On a
 *                        host with no OpenClaw at all this is the honest
 *                        "nothing to read"; `allowlist scan` layers a
 *                        visibility rule on top for the case where OpenClaw
 *                        IS installed and no cron source is readable.
 *   `unreadable`       — open or query failed (EACCES, corrupt file, …).
 *   `schema_mismatch`  — table present, required columns missing.
 */
export type CronProbeStatus = 'ok' | 'absent' | 'unreadable' | 'schema_mismatch';

/**
 * Statuses that mean "we could not look", as opposed to "we looked and there
 * was nothing". Scan exits 1 on these; doctor renders WARN — never INFO, and
 * never a pass with a zeroed count.
 */
export function isIncomplete(status: CronProbeStatus): boolean {
  return status === 'unreadable' || status === 'schema_mismatch';
}

export interface CronSourceProbe {
  path: string;
  /**
   * `cron_jobs` health — the source-level status. P1 discovery keys off this,
   * and it is what `allowlist scan` prints and exits on: a store whose run
   * log is broken can still yield a complete script list.
   */
  status: CronProbeStatus;
  /** Same as {@link CronSourceProbe.status}; named for the reader. */
  jobs: CronProbeStatus;
  /**
   * Run-outcome table health — what P2 correlation keys off. Probed against
   * {@link CronSourceProbe.runTable} for the detected generation.
   *
   * One deliberate promotion: when `cron_jobs` is `ok` the file demonstrably
   * IS an OpenClaw cron store, so a missing run-outcome table is not "not
   * this shape" — it is a store we cannot read run outcomes from. That is
   * cannot-look, so it is reported `schema_mismatch` rather than `absent`;
   * otherwise a broken run log would collapse into a green `silentCount = 0`,
   * which is the exact lie #375 exists to stop. Holds for both generations:
   * a gen2 store missing `cron_run_receipts` is the same promotion.
   */
  runLogs: CronProbeStatus;
  /** Which generation `cron_jobs` matched; null when it matched neither (or
   *  could not be read at all). */
  generation: CronStoreGeneration | null;
  /** The run-outcome table {@link CronSourceProbe.runLogs} reports on —
   *  `cron_run_logs` (gen1 / unknown) or `cron_run_receipts` (gen2). Callers
   *  must name THIS table in cannot-look messages, not assume the legacy one. */
  runTable: string;
}

/**
 * The ONLY open of an OpenClaw store in ShieldCortex's cron path. Read-only
 * and `fileMustExist` — the same pattern `doctor` already uses — so no code
 * path can create or mutate the gateway's database.
 */
export function openCronStore(dbPath: string): SqliteDatabase {
  const Database = require('better-sqlite3');
  return new Database(dbPath, { readonly: true, fileMustExist: true }) as SqliteDatabase;
}

/** ENOENT is genuinely absent; anything else at that path is unreadable. */
function fileState(dbPath: string): 'absent' | 'present' | 'unreadable' {
  try {
    statSync(dbPath);
    return 'present';
  } catch (e) {
    const err = e as NodeJS.ErrnoException;
    if (err && err.code === 'ENOENT') return 'absent';
    return 'unreadable';
  }
}

/** Probed independently per table: a broken run-outcome table must not make a
 *  perfectly readable `cron_jobs` look unreadable, and vice versa. */
function probeTable(db: SqliteDatabase, table: string, required: readonly string[]): CronProbeStatus {
  try {
    const cols = tableColumns(db, table);
    if (cols === null) return 'absent';
    for (const col of required) if (!cols.has(col)) return 'schema_mismatch';
    return 'ok';
  } catch {
    return 'unreadable';
  }
}

/** Column names of a table, or null when the table is not there. Throws on a
 *  query failure — callers turn that into `unreadable`. */
function tableColumns(db: SqliteDatabase, table: string): Set<string> | null {
  const present = db
    .prepare("SELECT 1 AS present FROM sqlite_master WHERE type = 'table' AND name = ?")
    .get(table) as { present?: number } | undefined;
  if (!present) return null;
  // Table names here are module constants, never caller input.
  const cols = db.prepare(`PRAGMA table_info(${table})`).all() as Array<{ name?: string }>;
  return new Set(cols.map((c) => String(c?.name ?? '')));
}

/** Which generation a `cron_jobs` column set matches, or null for neither.
 *  gen1 is checked first; gen2 additionally requires the legacy columns to be
 *  ABSENT, so a half-migrated hybrid cannot pass as either. */
function classifyJobColumns(cols: Set<string>): CronStoreGeneration | null {
  if (REQUIRED_CRON_JOB_COLUMNS.every((c) => cols.has(c))) return 'gen1';
  if (
    REQUIRED_CRON_JOB_COLUMNS_GEN2.every((c) => cols.has(c)) &&
    !cols.has('payload_message') &&
    !cols.has('trigger_script')
  ) {
    return 'gen2';
  }
  return null;
}

/**
 * Probe both load-bearing tables without reading a single job row.
 *
 * Never throws: every failure lands in the enum, because a probe that threw
 * would be caught somewhere upstream and turned back into silence.
 */
export function probeCronSource(dbPath: string): CronSourceProbe {
  const fail = (status: 'absent' | 'unreadable'): CronSourceProbe => ({
    path: dbPath,
    status,
    jobs: status,
    runLogs: status,
    generation: null,
    runTable: CRON_RUN_LOGS_TABLE,
  });
  const state = fileState(dbPath);
  if (state === 'absent') return fail('absent');
  if (state === 'unreadable') return fail('unreadable');

  let db: SqliteDatabase | null = null;
  try {
    db = openCronStore(dbPath);
    let jobs: CronProbeStatus;
    let generation: CronStoreGeneration | null = null;
    try {
      const cols = tableColumns(db, CRON_JOBS_TABLE);
      if (cols === null) {
        jobs = 'absent';
      } else {
        generation = classifyJobColumns(cols);
        jobs = generation === null ? 'schema_mismatch' : 'ok';
      }
    } catch {
      jobs = 'unreadable';
    }
    // An unknown/unreadable cron_jobs still probes the legacy run table, so
    // the pre-gen2 statuses are unchanged on stores we never understood.
    const runTable = generation === 'gen2' ? CRON_RUN_RECEIPTS_TABLE : CRON_RUN_LOGS_TABLE;
    const runRequired =
      generation === 'gen2' ? REQUIRED_CRON_RUN_RECEIPT_COLUMNS : REQUIRED_CRON_RUN_LOG_COLUMNS;
    let runLogs = probeTable(db, runTable, runRequired);
    // See CronSourceProbe.runLogs — a cron store with no run-outcome table is
    // cannot-look, not "not a cron store". Both generations.
    if (jobs === 'ok' && runLogs === 'absent') runLogs = 'schema_mismatch';
    return { path: dbPath, status: jobs, jobs, runLogs, generation, runTable };
  } catch {
    return fail('unreadable');
  } finally {
    try {
      db?.close();
    } catch {
      /* closing a store we only read from cannot fail meaningfully */
    }
  }
}

// ── Discovery ───────────────────────────────────────────────

export const OPENCLAW_CRON_DB_SOURCE = 'openclaw-cron-db';

export interface DiscoveredCronJob {
  jobId: string;
  /** Control characters stripped — this string reaches a terminal. */
  name: string;
  enabled: boolean;
  /** Script paths extracted from THIS job. The only place a correlation
   *  result is allowed to get a pinnable path from (never a denial surface). */
  paths: string[];
}

export interface DbCronDiscovery {
  /** `cron_jobs` probe status — `absent`/`unreadable`/`schema_mismatch` all
   *  mean the lists below are empty because we could not look. */
  status: CronProbeStatus;
  probe: CronSourceProbe;
  /** `DiscoveredScript`-compatible entries, enabled jobs only. */
  scripts: Array<{ path: string; sources: string[] }>;
  /** EVERY job, enabled or not — correlation must be able to name the job a
   *  denial belongs to even after an operator disables it. */
  jobsById: Map<string, DiscoveredCronJob>;
}

/**
 * Strip escape sequences and control characters, and cap the length, before a
 * store-supplied string can reach a terminal. Job names are attacker-
 * influenced on a compromised host and this text prints next to paths — the
 * same discipline `allowlist scan` already applies to script previews.
 */
export function sanitiseJobName(raw: unknown): string {
  const s = typeof raw === 'string' ? raw : '';
  const clean = s
    .replace(/\u001b\[[0-9;?]*[ -/]*[@-~]/g, '')
    .replace(/\u001b\][^\u0007]*(?:\u0007|\u001b\\)?/g, '')
    .replace(/\u001b./g, '')
    .replace(/[\u0000-\u001f\u007f]/g, ' ')
    .replace(/\s+/g, ' ')
    .trim();
  return clean.length > 80 ? `${clean.slice(0, 80)}…` : clean;
}

/**
 * `enabled` is coerced HERE, not in SQL.
 *
 * `WHERE enabled = 1` against a store that writes textual `'1'`/`'true'`
 * matches nothing, and a live 63-job store would then report empty-ok — the
 * discovery blindness this issue is about, reintroduced by a type mismatch.
 * So: select every row, decide in JS, and only the unambiguous off-values
 * count as disabled. Anything we cannot prove is off (including NULL) is
 * treated as live, because over-reporting costs a reviewer one extra line
 * and under-reporting costs them a silently broken cron.
 */
export function isJobEnabled(value: unknown): boolean {
  if (value === null || value === undefined) return true;
  if (typeof value === 'boolean') return value;
  if (typeof value === 'number') return value !== 0;
  if (typeof value === 'bigint') return value !== 0n;
  if (typeof value === 'string') {
    const s = value.trim().toLowerCase();
    if (s === '' || s === 'false' || s === 'no' || s === 'off') return false;
    // A numeric string is the flag written through a TEXT column: '0', '0.0'
    // and ' 0 ' all mean off. Non-numeric text ('true', 'yes', a job label)
    // falls through to visible.
    const n = Number(s);
    if (Number.isFinite(n)) return n !== 0;
    return true;
  }
  return true;
}

const WALK_MAX_DEPTH = 12;
const WALK_MAX_NODES = 20_000;

/**
 * Structural walk of a parsed `job_json`: every string leaf goes through the
 * conservative extractor. Deliberately NOT `JSON.stringify` + one regex sweep
 * — a stringified blob glues adjacent values together and lets escaped
 * content masquerade as a path. Bounded in depth and node count so a hostile
 * store cannot turn discovery into a hang.
 */
export function walkStringLeaves(value: unknown, visit: (leaf: string) => void): void {
  const budget = { nodes: WALK_MAX_NODES };
  const seen = new Set<object>();
  const walk = (node: unknown, depth: number): void => {
    if (budget.nodes-- <= 0 || depth > WALK_MAX_DEPTH) return;
    if (typeof node === 'string') {
      visit(node);
      return;
    }
    if (!node || typeof node !== 'object') return;
    if (seen.has(node as object)) return;
    seen.add(node as object);
    if (Array.isArray(node)) {
      for (const item of node) walk(item, depth + 1);
      return;
    }
    for (const item of Object.values(node as Record<string, unknown>)) walk(item, depth + 1);
  };
  walk(value, 0);
}

interface CronJobRow {
  job_id?: unknown;
  name?: unknown;
  enabled?: unknown;
  payload_message?: unknown;
  trigger_script?: unknown;
  job_json?: unknown;
}

/**
 * Read every cron job out of the SQLite store and extract the scripts it
 * names. Never throws — a store we cannot read returns the failing status
 * with empty lists, and the caller reports that as incomplete discovery.
 */
export function discoverDbCronScripts(opts: { dbPath: string; home: string }): DbCronDiscovery {
  const probe = probeCronSource(opts.dbPath);
  if (probe.status !== 'ok') {
    return { status: probe.status, probe, scripts: [], jobsById: new Map() };
  }

  let db: SqliteDatabase | null = null;
  try {
    db = openCronStore(opts.dbPath);
    // gen2 has no payload_message/trigger_script columns to read; its message
    // lives at job_json → payload.message, which the structural walk below
    // already visits as a string leaf.
    const columns =
      probe.generation === 'gen2'
        ? 'job_id, name, enabled, job_json'
        : 'job_id, name, enabled, payload_message, trigger_script, job_json';
    const rows = db.prepare(`SELECT ${columns} FROM ${CRON_JOBS_TABLE}`).all() as CronJobRow[];

    const jobsById = new Map<string, DiscoveredCronJob>();
    const enabledPaths = new Set<string>();

    for (const row of rows) {
      const jobId = typeof row.job_id === 'string' ? row.job_id : String(row.job_id ?? '');
      if (!jobId) continue;
      const paths = new Set<string>();
      const collect = (text: unknown): void => {
        if (typeof text !== 'string' || text.length === 0) return;
        for (const p of extractScriptPaths(text, opts.home)) paths.add(p);
      };
      collect(row.payload_message);
      collect(row.trigger_script);
      if (typeof row.job_json === 'string' && row.job_json.length > 0) {
        try {
          walkStringLeaves(JSON.parse(row.job_json), collect);
        } catch {
          /* a job_json that is not JSON contributes nothing — the two
             dedicated columns above are already covered */
        }
      }

      const enabled = isJobEnabled(row.enabled);
      const job: DiscoveredCronJob = {
        jobId,
        name: sanitiseJobName(row.name) || sanitiseJobName(jobId) || 'unnamed-job',
        enabled,
        paths: [...paths].sort(),
      };
      jobsById.set(jobId, job);
      if (enabled) for (const p of job.paths) enabledPaths.add(p);
    }

    return {
      status: 'ok',
      probe,
      scripts: [...enabledPaths].sort().map((path) => ({ path, sources: [OPENCLAW_CRON_DB_SOURCE] })),
      jobsById,
    };
  } catch {
    // The probe passed and the read still failed (locked, truncated mid-read,
    // corrupt page). That is cannot-look, not empty.
    const failed: CronSourceProbe = { ...probe, status: 'unreadable', jobs: 'unreadable' };
    return { status: 'unreadable', probe: failed, scripts: [], jobsById: new Map() };
  } finally {
    try {
      db?.close();
    } catch {
      /* ignore */
    }
  }
}
