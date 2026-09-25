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
 * temporary file. One unlink of one regular file.
 *
 * The realtime audit ledger under `~/.shieldcortex/audit/` is deliberately NOT
 * managed here. It is an unread queue with concurrent writers, a projector
 * cursor and stop-hook recovery reading it, so bounding it is a design problem
 * of its own — tracked separately in #579. Nothing in this module opens,
 * stats, lists or removes anything under `audit/`.
 *
 * FILESYSTEM RULES. `~/.shieldcortex/logs` is same-user-writable, so every
 * rule here assumes a same-account attacker can rename and link inside it:
 *   1. A plane reachable through a symlink — the logs directory itself, or any
 *      component below a `.shieldcortex` ancestor — refuses the whole pass and
 *      says so. Every unlink below such a path would land somewhere else.
 *   2. Only names matching `project-key-repair-*.json` exactly, only directly
 *      in the logs directory (no recursion), only regular files by `lstat`.
 *   3. Deletion re-`lstat`s the exact path immediately before `unlink`, so a
 *      name swapped for a symlink between planning and acting is left alone.
 */

import fs from 'fs';
import os from 'os';
import path from 'path';

/** Newest `project-key-repair-*.json` files kept. Never below 1. */
export const DEFAULT_REPAIR_LOG_KEEP = 20;

/** The one name shape this module will ever act on. */
const REPAIR_LOG_RE = /^project-key-repair-.+\.json$/;

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
  /** The keep count actually applied. */
  keep: number;
  /** Regular `project-key-repair-*.json` files found directly in `dir`. */
  matched: number;
  bytesBefore: number;
  kept: number;
  deleted: RepairLogDeletion[];
  freedBytes: number;
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

/**
 * Refuse a plane reachable through a symlink.
 *
 * Checked components: the directory itself, plus every component from a
 * `.shieldcortex` ancestor downwards — the part of the path this project owns
 * and a same-account attacker can rewrite. A link anywhere along there means
 * every unlink below it would land somewhere we never intended, so the honest
 * answer is to report it and do nothing at all.
 *
 * Returns the operator-facing reason, or null when the plane is safe. A plane
 * that does not exist yet is safe: there is nothing under it to retain.
 */
function planeSymlinkFault(dir: string): string | null {
  const resolved = path.resolve(dir);
  const parts = resolved.split(path.sep);
  const rootIdx = parts.lastIndexOf('.shieldcortex');
  const from = rootIdx >= 0 ? rootIdx : parts.length - 1;
  for (let i = from; i < parts.length; i++) {
    const probe = parts.slice(0, i + 1).join(path.sep) || path.sep;
    let st: fs.Stats;
    try {
      st = fs.lstatSync(probe);
    } catch {
      return null; // absent — nothing under it to prune
    }
    if (st.isSymbolicLink()) {
      return `${probe} is a symlink — refusing to prune repair logs through it`;
    }
    if (i === parts.length - 1 && !st.isDirectory()) {
      return `${probe} is not a directory — refusing to prune repair logs in it`;
    }
  }
  return null;
}

function describe(err: unknown): string {
  return err instanceof Error ? err.message : String(err);
}

/**
 * Keep the newest `keep` repair logs in `dir` and delete the rest.
 *
 * Dry-run by default: with `execute` unset the returned `deleted` list is
 * exactly what `execute: true` would remove, and nothing on disk changes.
 */
export function pruneRepairLogs(options: RepairLogPruneOptions = {}): RepairLogPruneResult {
  const dir = options.dir ?? defaultRepairLogDir();
  const execute = options.execute === true;
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
    dir, dryRun: !execute, keep, matched: 0, bytesBefore: 0, kept: 0,
    deleted: [], freedBytes: 0, refused, errors,
  });

  const fault = planeSymlinkFault(dir);
  if (fault) return empty(fault);

  let names: string[];
  try {
    names = fs.readdirSync(dir);
  } catch {
    return empty(null); // absent or unreadable — nothing this pass can bound
  }

  const files: Array<{ path: string; size: number; mtimeMs: number; name: string }> = [];
  for (const name of names) {
    if (!REPAIR_LOG_RE.test(name)) continue;
    const full = path.join(dir, name);
    const st = lstatRegular(full);
    if (!st) continue; // symlink, directory, socket, or gone
    files.push({ path: full, size: st.size, mtimeMs: st.mtimeMs, name });
  }

  // Newest by mtime. The names embed a fixed-width ISO timestamp, so the name
  // usually agrees — but mtime is what "newest" actually means, and the name
  // tie-break keeps identically-timed files in a stable order.
  files.sort((a, b) => (a.mtimeMs - b.mtimeMs) || a.name.localeCompare(b.name));

  const bytesBefore = files.reduce((sum, f) => sum + f.size, 0);
  const doomed = files.slice(0, Math.max(0, files.length - keep));
  const deleted: RepairLogDeletion[] = [];
  for (const f of doomed) {
    if (execute) {
      // Re-check THIS path immediately before unlinking it. The plan above was
      // built from an earlier lstat; between then and now the name could have
      // been swapped for a symlink to something that must not be removed.
      const still = lstatRegular(f.path);
      if (!still) {
        errors.push(`${f.name}: no longer a regular file — left in place`);
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

  const freedBytes = deleted.reduce((sum, d) => sum + d.bytes, 0);
  return {
    dir,
    dryRun: !execute,
    keep,
    matched: files.length,
    bytesBefore,
    kept: files.length - deleted.length,
    deleted,
    freedBytes,
    refused: null,
    errors,
  };
}
