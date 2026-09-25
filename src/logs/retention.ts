/**
 * Retention for `project-key-repair-*.json` (issue #573).
 *
 * THE PLANE THIS BOUNDS, AND THE ONE IT DOES NOT.
 *
 * `shieldcortex memories repair-project-keys --execute` writes one JSON log per
 * run. Nothing ever deleted one. Measured on the reporting host: 3,508 of them
 * in `~/.shieldcortex/logs`, peak 357 in a single day. (All 3,508 described a
 * throwaway database — see src/cli/migrate-legacy.ts for that half of the fix.)
 * These are diagnostics, they have no reader, and they are not evidence, so a
 * newest-N bound is the whole policy: no compression, no rewrite, no rename, no
 * temporary file. One unlink of one regular file, only when an operator asks.
 *
 * The realtime audit ledger under `~/.shieldcortex/audit/` is deliberately NOT
 * managed here. It is an unread queue with concurrent writers, a projector
 * cursor and stop-hook recovery reading it, so bounding it is a design problem
 * of its own — tracked separately in #579. Nothing in this module opens,
 * stats, lists or removes anything under `audit/`.
 *
 * THREAT MODEL. A process running as this user with write access to
 * `~/.shieldcortex` (or to the repaired database's own directory) can already
 * delete or rewrite every file there directly, by itself, without our help.
 * Defending that plane against that process is not a goal, and could not be
 * met anyway: Node exposes no `openat`/`unlinkat`, so there is no way to bind
 * a path operation to a directory file descriptor we have already checked.
 *
 * What IS in scope, and what each rule below buys:
 *   1. Accidental races with our own writers. A record younger than
 *      `REPAIR_LOG_MIN_AGE_MS` is never a deletion candidate, so a repair that
 *      is still writing its log — or has just finished — cannot lose it. No
 *      repair takes an hour to serialise a few KB of JSON.
 *   2. Benign concurrent runs. Two `logs prune --execute` passes, or a prune
 *      racing a repair, see the same rules and the same minimum age; a
 *      candidate that vanished between planning and acting is reported, not
 *      retried blindly.
 *   3. A symlink planted by ANYTHING must never make us delete outside the
 *      directory we meant. The logs directory and every component from a
 *      `.shieldcortex` ancestor down is `lstat`ed before the listing, the
 *      directory's own (dev, ino) is pinned there, and it is re-`lstat`ed
 *      immediately before every unlink — a replaced or relinked directory
 *      stops the pass. The residual window between that check and the
 *      `unlink` cannot be closed without `unlinkat`, and per the threat model
 *      above a same-user process that could exploit it does not need to.
 *   4. Only names matching the repair-log shape exactly, only directly in the
 *      logs directory (no recursion), only regular files by `lstat`, only with
 *      `nlink === 1` — a record someone hard-linked elsewhere is left alone,
 *      because unlinking it would not be the deletion we reported.
 *
 * PER DATABASE, NOT PER DIRECTORY. The bound is "newest N of the records
 * describing THIS database". `repairLogDirForDb` deliberately puts the log
 * beside the DB, so several databases in one directory share one logs
 * directory; a plain newest-N over the directory would let a busy database's
 * repairs evict another database's only record. The filename therefore carries
 * `repairLogDbId` — the first 12 hex of the sha256 of the database's resolved
 * absolute path — and records are grouped by it. Records written before this
 * change carry no id and are grouped together as one "legacy" set.
 */

import crypto from 'crypto';
import fs from 'fs';
import os from 'os';
import path from 'path';

/** Newest `project-key-repair-*.json` files kept, per database. Never below 1. */
export const DEFAULT_REPAIR_LOG_KEEP = 20;

/**
 * A record this young is never deleted, whatever the keep count says.
 *
 * It is the whole answer to "did we just unlink a log a repair is still
 * writing?": an in-flight record is seconds old, and nothing that serialises a
 * few KB of JSON is an hour late.
 */
export const REPAIR_LOG_MIN_AGE_MS = 60 * 60 * 1000;

/**
 * The one name shape this module will ever act on, with the optional database
 * id `repairLogName` writes. A legacy name is `project-key-repair-<iso>.json`
 * and cannot be mistaken for an id-bearing one: the ISO stamp's first 12
 * characters are `2026-09-25T0`, which is not 12 hex digits.
 */
const REPAIR_LOG_RE = /^project-key-repair-(?:([0-9a-f]{12})-)?.+\.json$/;

/** Records with no database id in the name: everything written before #573. */
const LEGACY_GROUP = 'legacy';

/** Default `project-key-repair-*.json` location — beside the default database. */
export function defaultRepairLogDir(): string {
  return path.join(os.homedir(), '.shieldcortex', 'logs');
}

/**
 * Where the repair log for a given database belongs: beside the database it
 * describes, exactly as the safety backup (`<dbPath>.bak.<ts>`) already is.
 * For the default DB at `~/.shieldcortex/memories.db` this resolves to the
 * documented `~/.shieldcortex/logs`, so nothing moves for the real install.
 */
export function repairLogDirForDb(dbPath: string): string {
  return path.join(path.dirname(path.resolve(dbPath)), 'logs');
}

/**
 * The short, stable identity of the database a record describes.
 *
 * A hash, not the path itself: the path can be long, can contain separators
 * and characters a filename may not, and is not something a diagnostics
 * filename should publish. 12 hex is ample to separate the handful of
 * databases that ever share one directory, and collisions only ever merge two
 * groups — the failure mode is "retention is per-pair", never a deletion
 * outside the plane.
 */
export function repairLogDbId(dbPath: string): string {
  return crypto.createHash('sha256').update(path.resolve(dbPath)).digest('hex').slice(0, 12);
}

/** The record filename for one repair of one database at one instant. */
export function repairLogName(dbPath: string, when: Date): string {
  return `project-key-repair-${repairLogDbId(dbPath)}-${when.toISOString().replace(/[:.]/g, '-')}.json`;
}

export interface RepairLogKeepResolution {
  keep: number;
  /** One line per rejected override — surfaced in the report, never swallowed. */
  warnings: string[];
}

/**
 * Resolve `SHIELDCORTEX_REPAIR_LOG_KEEP`, strictly.
 *
 * `Number(' ')` is 0, and 0 means "delete every repair log" — so a stray space
 * in a unit file must not be able to express that. The value must be a
 * trimmed, non-empty, base-10 integer of at least 1: `/^\d+$/` also rejects
 * negatives, floats, `1e3`, `0x10`, `Infinity` and `NaN`, all of which
 * `Number()` happily converts or rounds. Anything else takes the default AND
 * says so out loud.
 *
 * The empty string is the one exception: it is how a shell exports an unset
 * variable, so it means "unset", not "typo".
 */
export function resolveRepairLogKeep(
  env: NodeJS.ProcessEnv = process.env,
): RepairLogKeepResolution {
  const raw = env.SHIELDCORTEX_REPAIR_LOG_KEEP;
  const warnings: string[] = [];
  if (raw === undefined || raw === '') return { keep: DEFAULT_REPAIR_LOG_KEEP, warnings };

  const text = raw.trim();
  const reject = (why: string): RepairLogKeepResolution => {
    warnings.push(
      `ignoring SHIELDCORTEX_REPAIR_LOG_KEEP=${JSON.stringify(raw)} — ${why}; ` +
      `using the default ${DEFAULT_REPAIR_LOG_KEEP}`,
    );
    return { keep: DEFAULT_REPAIR_LOG_KEEP, warnings };
  };
  if (!/^\d+$/.test(text)) return reject('expected a whole number of at least 1');
  const parsed = Number(text);
  if (!Number.isSafeInteger(parsed)) return reject('expected a whole number of at least 1');
  if (parsed < 1) return reject('the minimum is 1 — 0 would keep no repair log at all');
  return { keep: parsed, warnings };
}

export interface RepairLogDeletion {
  path: string;
  bytes: number;
}

export interface RepairLogPruneResult {
  dir: string;
  /** True when nothing on disk was touched — the default. */
  dryRun: boolean;
  /** The keep count actually applied, PER DATABASE. */
  keep: number;
  /** Regular `project-key-repair-*.json` files found directly in `dir`. */
  matched: number;
  /** Distinct databases those records describe (`legacy` counts as one). */
  databases: number;
  bytesBefore: number;
  kept: number;
  deleted: RepairLogDeletion[];
  freedBytes: number;
  /**
   * Records past their database's bound that were spared for being younger
   * than `REPAIR_LOG_MIN_AGE_MS` — an in-flight repair's log, most likely.
   */
  tooYoung: number;
  /** Non-null when the whole pass was refused; nothing was read or removed. */
  refused: string | null;
  /** Rejected overrides and per-file faults, for the operator to read. */
  errors: string[];
}

export interface RepairLogPruneOptions {
  /** Defaults to `~/.shieldcortex/logs`. */
  dir?: string;
  /** Defaults to the environment's resolved keep count. */
  keep?: number;
  /** Without this nothing on disk is removed. */
  execute?: boolean;
  /** Injectable for tests; production callers use the real environment. */
  env?: NodeJS.ProcessEnv;
  /** Injectable clock, for the minimum-age rule. Defaults to `Date.now()`. */
  nowMs?: number;
}

/** `lstat`, and only a regular file counts. Never follows a link. */
function lstatRegular(target: string): fs.Stats | null {
  try {
    const st = fs.lstatSync(target);
    return st.isFile() ? st : null;
  } catch {
    return null;
  }
}

/** A directory's identity, as far as `lstat` can state one. */
interface DirIdentity {
  dev: number;
  ino: number;
}

/**
 * Refuse a plane reachable through a symlink, and pin the directory we agreed
 * to act in.
 *
 * Checked components: the directory itself, plus every component from a
 * `.shieldcortex` ancestor downwards — the part of the path this project owns.
 * A link anywhere along there means every unlink below it would land somewhere
 * we never intended, so the honest answer is to report it and do nothing.
 *
 * `id` is the final component's (dev, ino), which `beforeEachUnlink` below
 * re-checks: a directory swapped for another directory passes the symlink test
 * but is not the plane that was listed. A plane that does not exist yet is
 * safe with no identity — there is nothing under it to retain.
 */
function checkPlane(dir: string): { fault: string | null; id: DirIdentity | null } {
  const parts = path.resolve(dir).split(path.sep);
  const rootIdx = parts.lastIndexOf('.shieldcortex');
  for (let i = rootIdx >= 0 ? rootIdx : parts.length - 1; i < parts.length; i++) {
    const probe = parts.slice(0, i + 1).join(path.sep) || path.sep;
    let st: fs.Stats;
    try {
      st = fs.lstatSync(probe);
    } catch {
      return { fault: null, id: null }; // absent — nothing under it to prune
    }
    if (st.isSymbolicLink()) {
      return { fault: `${probe} is a symlink — refusing to prune repair logs through it`, id: null };
    }
    if (i === parts.length - 1) {
      if (!st.isDirectory()) {
        return { fault: `${probe} is not a directory — refusing to prune repair logs in it`, id: null };
      }
      return { fault: null, id: { dev: st.dev, ino: st.ino } };
    }
  }
  return { fault: null, id: null };
}

function describe(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}

/**
 * Keep the newest `keep` repair logs PER DATABASE in `dir` and delete the rest.
 *
 * Dry-run by default: with `execute` unset the returned `deleted` list is
 * exactly what `execute: true` would remove, and nothing on disk changes.
 */
export function pruneRepairLogs(options: RepairLogPruneOptions = {}): RepairLogPruneResult {
  const dir = options.dir ?? defaultRepairLogDir();
  const execute = options.execute === true;
  const nowMs = options.nowMs ?? Date.now();
  const errors: string[] = [];

  let keep: number;
  if (options.keep === undefined) {
    const resolved = resolveRepairLogKeep(options.env);
    keep = resolved.keep;
    errors.push(...resolved.warnings);
  } else {
    // Defence in depth behind resolveRepairLogKeep's minimum: a keep of 0
    // reaching here would mean "delete every repair log", which is not a
    // policy this module is willing to express.
    keep = Math.max(1, Math.floor(Number.isFinite(options.keep) ? options.keep : DEFAULT_REPAIR_LOG_KEEP));
  }

  const empty = (refused: string | null): RepairLogPruneResult => ({
    dir, dryRun: !execute, keep, matched: 0, databases: 0, bytesBefore: 0, kept: 0,
    deleted: [], freedBytes: 0, tooYoung: 0, refused, errors,
  });

  const plane = checkPlane(dir);
  if (plane.fault) return empty(plane.fault);

  let names: string[];
  try {
    names = fs.readdirSync(dir);
  } catch {
    return empty(null); // absent or unreadable — nothing this pass can bound
  }

  interface Candidate { path: string; name: string; group: string; size: number; mtimeMs: number }
  const groups = new Map<string, Candidate[]>();
  let matched = 0;
  let bytesBefore = 0;
  for (const name of names) {
    const m = REPAIR_LOG_RE.exec(name);
    if (!m) continue;
    const full = path.join(dir, name);
    const st = lstatRegular(full);
    if (!st) continue; // symlink, directory, socket, or gone
    matched++;
    bytesBefore += st.size;
    if (st.nlink !== 1) {
      // Unlinking this would free nothing and would not be the deletion we
      // reported: the inode survives under its other name.
      errors.push(`${name}: has ${st.nlink} hard links — left in place`);
      continue;
    }
    const group = m[1] ?? LEGACY_GROUP;
    const list = groups.get(group);
    if (list) list.push({ path: full, name, group, size: st.size, mtimeMs: st.mtimeMs });
    else groups.set(group, [{ path: full, name, group, size: st.size, mtimeMs: st.mtimeMs }]);
  }

  // Plan per database, oldest first. The names embed a fixed-width ISO stamp so
  // the name usually agrees with mtime — but mtime is what "newest" means, and
  // the name tie-break keeps identically-timed records in a stable order.
  const doomed: Candidate[] = [];
  let tooYoung = 0;
  for (const list of groups.values()) {
    list.sort((a, b) => (a.mtimeMs - b.mtimeMs) || a.name.localeCompare(b.name));
    for (const f of list.slice(0, Math.max(0, list.length - keep))) {
      if (nowMs - f.mtimeMs < REPAIR_LOG_MIN_AGE_MS) {
        // Possibly still being written. Kept, and it will be a candidate on
        // the next pass — an hour is not a retention problem.
        tooYoung++;
        continue;
      }
      doomed.push(f);
    }
  }

  /**
   * Is `dir` still the directory `checkPlane` agreed to? Re-`lstat`ed before
   * EVERY unlink, because the cheap wins are the ones worth taking: a
   * directory replaced by a symlink, or by a different directory, stops the
   * pass here instead of deleting from somewhere we never listed. The window
   * between this and the `unlink` itself is the residual TOCTOU the module
   * header discloses; closing it needs `unlinkat`, which Node does not expose.
   */
  const planeUnchanged = (): boolean => {
    try {
      const st = fs.lstatSync(dir);
      return !st.isSymbolicLink() && st.isDirectory()
        && plane.id !== null && st.dev === plane.id.dev && st.ino === plane.id.ino;
    } catch {
      return false;
    }
  };

  const deleted: RepairLogDeletion[] = [];
  for (const f of doomed) {
    if (execute) {
      if (!planeUnchanged()) {
        errors.push(`${dir} is no longer the directory that was listed — stopped after ${deleted.length} deletion(s)`);
        break;
      }
      // Re-check THIS path too. The plan was built from an earlier lstat;
      // between then and now the name could have been swapped for a symlink,
      // hard-linked, or replaced by the next repair's record.
      const still = lstatRegular(f.path);
      if (!still) {
        errors.push(`${f.name}: no longer a regular file — left in place`);
        continue;
      }
      if (still.nlink !== 1 || still.mtimeMs !== f.mtimeMs || still.size !== f.size) {
        errors.push(`${f.name}: changed since it was selected — left in place`);
        continue;
      }
      try {
        fs.unlinkSync(f.path);
      } catch (err) {
        errors.push(`${f.name}: could not delete — ${describe(err)}`);
        continue;
      }
    }
    deleted.push({ path: f.path, bytes: f.size });
  }

  return {
    dir,
    dryRun: !execute,
    keep,
    matched,
    databases: groups.size,
    bytesBefore,
    kept: matched - deleted.length,
    deleted,
    freedBytes: deleted.reduce((sum, d) => sum + d.bytes, 0),
    tooYoung,
    refused: null,
    errors,
  };
}

/**
 * Resolve, create and prove the record destination BEFORE the database is
 * touched (#573 round 2, blockers 4 and 5).
 *
 * The repair used to `mkdirSecure` the logs directory AFTER committing its
 * rewrite. A regular file sitting at `<db-dir>/logs` therefore threw EEXIST
 * with the project keys already changed and no per-rewrite log written — the
 * operator had a silently-unlogged repair and an exception that never said the
 * commit had happened. And because nothing checked the path's shape, a `logs`
 * symlinked at the realtime audit directory made the repair write its JSON
 * into the audit plane.
 *
 * So the destination is settled first, and a refusal here means the repair
 * never runs and nothing has changed:
 *   - every component from a `.shieldcortex` ancestor down must not be a
 *     symlink, and the destination itself must be a directory;
 *   - it is created (0700) if absent, then re-checked, because a recursive
 *     `mkdir` onto an existing symlink-to-directory succeeds silently;
 *   - it must be writable and searchable by this process, so "disk full" is
 *     the only write failure left that the pre-check could not have caught.
 *
 * Throws with an operator-facing reason. Returns the directory to write into.
 */
export function prepareRepairLogDir(dbPath: string): string {
  const dir = repairLogDirForDb(dbPath);
  const refuse = (why: string): never => {
    throw new Error(`refusing to repair ${dbPath}: its repair log cannot be written — ${why}`);
  };
  const before = checkPlane(dir);
  if (before.fault) refuse(before.fault);
  try {
    fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
  } catch (err) {
    refuse(`${dir} could not be created — ${describe(err)}`);
  }
  const after = checkPlane(dir);
  if (after.fault) refuse(after.fault);
  if (after.id === null) refuse(`${dir} is not a directory`);
  try {
    fs.accessSync(dir, fs.constants.W_OK | fs.constants.X_OK);
  } catch (err) {
    refuse(`${dir} is not writable — ${describe(err)}`);
  }
  return dir;
}

/**
 * Create one repair-log record, exclusively.
 *
 * `'wx'` is `O_CREAT | O_EXCL`, which fails rather than following a symlink at
 * the final component and never truncates an existing file. A preplanted
 * `project-key-repair-<id>-<stamp>.json` symlink aimed at a realtime audit file
 * used to be followed and the evidence overwritten; now that name is simply
 * EEXIST and the record takes the next free suffix. Both shapes match the
 * retention regex, so a suffixed record is still bounded.
 *
 * Returns the path written. Throws only when no unique name could be created or
 * the write itself failed — the caller must report that as a partial success,
 * because by then the rewrite is committed.
 */
export function writeRepairLogRecord(
  dir: string,
  dbPath: string,
  body: unknown,
  when: Date = new Date(),
): string {
  const base = repairLogName(dbPath, when);
  for (let attempt = 0; attempt < 32; attempt++) {
    const target = path.join(dir, attempt === 0 ? base : base.replace(/\.json$/, `-${attempt}.json`));
    let fd: number;
    try {
      fd = fs.openSync(target, 'wx', 0o600);
    } catch (err) {
      if ((err as NodeJS.ErrnoException).code === 'EEXIST') continue;
      throw err;
    }
    try {
      fs.writeFileSync(fd, JSON.stringify(body, null, 2), 'utf-8');
    } finally {
      fs.closeSync(fd);
    }
    return target;
  }
  throw new Error(`no unique name available for a repair log in ${dir} (tried ${base} and 31 suffixes)`);
}
