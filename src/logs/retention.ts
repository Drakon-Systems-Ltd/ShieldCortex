/**
 * Retention for `project-key-repair-*.json` (issue #573).
 *
 * `shieldcortex memories repair-project-keys --execute` writes one JSON log per
 * run, and nothing ever deleted one: 3,508 of them on the reporting host, every
 * one describing a throwaway database (src/cli/migrate-legacy.ts is the other
 * half of that fix). They are diagnostics with no reader and no evidential
 * value, so a newest-N bound is the whole policy — one unlink of one regular
 * file, only when an operator asks. No compression, rewrite, rename or
 * temporary file.
 *
 * THE AUDIT PLANE IS NOT OURS. `~/.shieldcortex/audit/` is an unread queue with
 * concurrent writers, a projector cursor and stop-hook recovery reading it;
 * bounding it is #579's problem. Nothing here may write into it or delete from
 * it — so both entry points resolve their directory with `realpath` FIRST and
 * refuse when the result lands inside the audit plane. That is one rule for
 * every symlink, wherever it sits: a link at the logs directory itself, at the
 * repaired database's own directory, or at any component above either.
 * Choosing a trusted boundary by basename could not do that job, and did not:
 * `.shieldcortex/alias/.shieldcortex/logs` took `lastIndexOf('.shieldcortex')`
 * to the inner root and never looked at `alias`.
 *
 * THREAT MODEL. A process running as this user with write access to
 * `~/.shieldcortex` (or to the repaired database's directory) can already
 * delete or rewrite every file there directly, without our help. Defending that
 * plane against that process is not a goal and could not be met: Node exposes
 * no `openat`/`unlinkat`, so no path operation can be bound to a directory
 * descriptor already checked. What IS in scope, and what each rule buys:
 *   1. A record younger than `REPAIR_LOG_MIN_AGE_MS` is never a candidate, so
 *      a repair still writing its log cannot lose it. Nothing that serialises
 *      a few KB of JSON is an hour late.
 *   2. The resolved directory's (dev, ino) is pinned before the listing and
 *      re-checked immediately before every unlink, so a directory swapped for
 *      another stops the pass. The residual window needs `unlinkat` to close.
 *   3. Only the exact record grammar below, only directly in that directory,
 *      only regular files by `lstat`, only with `nlink === 1` — a hard-linked
 *      record's inode survives its other name, so unlinking it would not be
 *      the deletion we reported.
 *
 * PER DATABASE, NOT PER DIRECTORY. The log lives beside the database it
 * describes, so one directory can hold records for several; a plain newest-N
 * would let a busy database evict another's only record. The name therefore
 * carries `repairLogDbId`, the first 12 hex of the sha256 of the database's
 * resolved path. Records written before this change carry no id and form one
 * "legacy" group.
 */

import crypto from 'crypto';
import fs from 'fs';
import os from 'os';
import path from 'path';

/** Newest `project-key-repair-*.json` files kept, per database. Never below 1. */
export const DEFAULT_REPAIR_LOG_KEEP = 20;

/** A record this young is never deleted, whatever the keep count says. */
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
 *
 * FULLY RESOLVED: `realpath` of the database's own directory, so no symlink in
 * any ancestor can decide where the record lands. Throws when that directory
 * does not exist; the caller turns that into a refusal.
 */
export function repairLogDirForDb(dbPath: string): string {
  return path.join(fs.realpathSync(path.dirname(path.resolve(dbPath))), 'logs');
}

/**
 * The short, stable identity of the database a record describes.
 *
 * A hash, not the path itself: the path can be long, can contain separators and
 * characters a filename may not, and is not something a diagnostics filename
 * should publish. 12 hex is ample to separate the handful of databases that
 * ever share one directory, and a collision only merges two groups — the
 * failure mode is "retention is per-pair", never a deletion outside the plane.
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
 * in a unit file must not be able to express that. The value must be a trimmed,
 * non-empty, base-10 integer of at least 1: `/^\d+$/` also rejects negatives,
 * floats, `1e3`, `0x10`, `Infinity` and `NaN`, all of which `Number()` happily
 * converts or rounds. Anything else takes the default AND says so out loud.
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
  /** The directory actually acted in — fully resolved. */
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
 * The realtime audit plane, fully resolved, or null when it does not exist —
 * then nothing can be inside it.
 *
 * Same formula as `defaultRealtimeAuditDir()` in src/threat-graph/shared.ts,
 * restated rather than imported: that module pulls in the database layer, and
 * `logs prune` is deliberately usable on a host whose database is at the hard
 * size block — exactly the host that needs it.
 */
function resolvedAuditPlane(): string | null {
  const configured = process.env.SHIELDCORTEX_AUDIT_DIR?.trim();
  try {
    return fs.realpathSync(configured || path.join(os.homedir(), '.shieldcortex', 'audit'));
  } catch {
    return null;
  }
}

/** Is `child` the directory `parent`, or inside it? Both must be resolved. */
function isWithin(child: string, parent: string): boolean {
  return child === parent || child.startsWith(parent + path.sep);
}

/**
 * Settle the directory to prune, before anything is listed.
 *
 * `resolved` is the fully-resolved path to act in, `id` its pinned identity for
 * the pre-unlink recheck, `fault` a refusal to report. All three null with no
 * fault means "there is nothing there", which is not a refusal.
 */
function resolvePlane(dir: string): {
  resolved: string | null;
  id: DirIdentity | null;
  fault: string | null;
} {
  const none = { resolved: null, id: null };
  let st: fs.Stats;
  try {
    st = fs.lstatSync(dir);
  } catch {
    return { ...none, fault: null }; // absent — nothing under it to prune
  }
  if (st.isSymbolicLink()) {
    return { ...none, fault: `${dir} is a symlink — refusing to prune repair logs through it` };
  }
  if (!st.isDirectory()) {
    return { ...none, fault: `${dir} is not a directory — refusing to prune repair logs in it` };
  }
  let resolved: string;
  try {
    resolved = fs.realpathSync(dir);
  } catch {
    return { ...none, fault: null };
  }
  const audit = resolvedAuditPlane();
  if (audit !== null && isWithin(resolved, audit)) {
    return {
      ...none,
      fault: `${dir} resolves to ${resolved}, inside the realtime audit plane ${audit} — `
        + 'refusing; that plane has no retention here (#579)',
    };
  }
  return { resolved, id: { dev: st.dev, ino: st.ino }, fault: null };
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
  const requested = options.dir ?? defaultRepairLogDir();
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

  const plane = resolvePlane(requested);
  // Everything below acts on the RESOLVED directory, never on the path as
  // given: that is what makes a symlinked ancestor unable to redirect a single
  // readdir or unlink.
  const dir = plane.resolved ?? requested;
  const empty = (refused: string | null): RepairLogPruneResult => ({
    dir, dryRun: !execute, keep, matched: 0, databases: 0, bytesBefore: 0, kept: 0,
    deleted: [], freedBytes: 0, tooYoung: 0, refused, errors,
  });
  if (plane.fault !== null) return empty(plane.fault);
  if (plane.resolved === null) return empty(null);

  let names: string[];
  try {
    names = fs.readdirSync(dir);
  } catch {
    return empty(null); // unreadable — nothing this pass can bound
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
   * Is `dir` still the directory `resolvePlane` agreed to? Re-`lstat`ed before
   * EVERY unlink, because the cheap wins are the ones worth taking: a directory
   * replaced by a symlink, or by a different directory, stops the pass here
   * instead of deleting from somewhere we never listed. The window between this
   * and the `unlink` itself is the residual TOCTOU the module header discloses.
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
 * touched (#573).
 *
 * The repair used to create the logs directory AFTER committing its rewrite. A
 * regular file sitting at `<db-dir>/logs` therefore threw EEXIST with the
 * project keys already changed and no log written, and the exception never said
 * the commit had happened. And because nothing checked the path's shape, a
 * `logs` symlinked at the realtime audit directory made the repair write its
 * JSON into the audit plane.
 *
 * So the destination is settled first, from the database's REAL directory, and
 * a refusal here means the repair never runs and nothing has changed:
 *   - the destination must not resolve inside the realtime audit plane;
 *   - `logs` itself must be a real directory, by `lstat` — a symlink there is
 *     refused rather than followed, and created (0700) only when absent;
 *   - it must be writable and searchable by this process, so "disk full" is
 *     the only write failure left that the pre-check could not have caught.
 *
 * Throws with an operator-facing reason. Returns the directory to write into.
 */
export function prepareRepairLogDir(dbPath: string): string {
  const refuse = (why: string): never => {
    throw new Error(`refusing to repair ${dbPath}: its repair log cannot be written — ${why}`);
  };
  let dir: string;
  try {
    dir = repairLogDirForDb(dbPath);
  } catch (err) {
    return refuse(`${path.dirname(path.resolve(dbPath))} could not be resolved — ${describe(err)}`);
  }
  const audit = resolvedAuditPlane();
  if (audit !== null && isWithin(dir, audit)) {
    refuse(`${dir} is inside the realtime audit plane ${audit}, which this release never writes to (#579)`);
  }
  let st: fs.Stats | null;
  try {
    st = fs.lstatSync(dir);
  } catch {
    st = null;
  }
  if (st !== null && !st.isDirectory()) {
    refuse(`${dir} is ${st.isSymbolicLink() ? 'a symlink' : 'not a directory'}`);
  }
  if (st === null) {
    // Non-recursive: its parent is the database's own resolved directory, which
    // exists by construction. A `mkdir` that loses a race to anything at all
    // fails here rather than succeeding onto whatever won.
    try {
      fs.mkdirSync(dir, { mode: 0o700 });
    } catch (err) {
      refuse(`${dir} could not be created — ${describe(err)}`);
    }
  }
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
 * retention grammar, so a suffixed record is still bounded.
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
