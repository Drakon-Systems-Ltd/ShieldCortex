/**
 * ShieldCortex — publishing the packaged copy of a file-copied host
 * integration, and the one lock that serialises it (#574 / #576, round 3).
 *
 * ## Why there is no journal here
 *
 * Round 2 shipped a crash journal: the swap wrote `{target, backup, staged}`
 * to disk before the first rename, and the next run READ THAT FILE AND MOVED
 * THE PATHS IT NAMED. Review found six ways that ends badly, and every one of
 * them is the same defect — a recovery that takes its destination from a file
 * is a recovery that can be told where to write. Constraining the schema does
 * not fix it: any validation is a guess about which paths "belong" to a
 * transaction nobody can authenticate.
 *
 * So the journal is gone, and with it the whole idea of finishing somebody
 * else's swap. The packaged plugin and hook ship inside this npm package and
 * are always correct for the installed version, so the only recovery anyone
 * ever needs is "the standard target is missing or does not match the package
 * -> copy the packaged set into the STANDARD target again". The inputs are the
 * resolved home, the integration's layout and the package; nothing on disk
 * supplies a destination, so a planted journal, a planted
 * `.shieldcortex-staging-*` or a hostile `backups/` entry is inert.
 *
 * ## What a publication does, in order
 *
 *   1. preflight — no symlink on any component of the target, the backup or
 *      the staged tree, bounded at the integration root;
 *   2. `fsync` every staged file and every staged directory, so the bytes are
 *      on the medium BEFORE any rename makes them reachable;
 *   3. verify the staged tree byte-for-byte against the package;
 *   4. `rename(target -> backup)` when there is a target to displace, then
 *      `fsync` both parent directories;
 *   5. `rename(staged -> target)`, then `fsync` both parent directories.
 *
 * A failure at 5 leaves the host with no target, so the backup is renamed
 * straight back and both parents are synced again. If THAT fails, the caller
 * names the integration's installer, which is this same publication run from
 * the package.
 *
 * ## Why nothing here HEALS a missing target (r4)
 *
 * Round 3 went one step further than it could prove: if the standard target
 * was missing and `backups/<name>-preupdate-*` existed, `update` reinstalled
 * the packaged set. Review showed the predicate cannot tell the two states
 * apart. A successful refresh leaves a permanent backup; the operator then
 * runs `uninstall`; the next `update` reads the same evidence and puts the
 * integration back. A planted empty `backups/shieldcortex-preupdate-x` does
 * the same on a host that never had it. Backup-shaped directories are not
 * installation intent, and nothing short of a stored marker can make them one.
 *
 * So a missing target is REPORTED, never repaired. The one moment anybody
 * knows a swap was interrupted is the moment it fails, inside this function,
 * with the backup path in hand — so that is where the sentence gets printed
 * (`targetMissing` below), naming the integration's installer and the backup
 * to restore from. Nothing deletes a backup, ever.
 */

import fs from 'fs';
import path from 'path';
import { describeFsError } from './hermes-plugins.js';
import {
  deviceUnder,
  findLinkOnPath,
  lstatAnswer,
  readdirAnswer,
  releaseReservation,
  reserveBackupDir,
} from './fs-answers.js';

/** One exclusive lock per integration root. Same name on both integrations. */
export const UPDATE_LOCK_NAME = '.shieldcortex-update.lock';

/** A lock older than this whose holder is gone is a crash leftover, not a run. */
export const STALE_LOCK_MS = 10 * 60 * 1000;

export function updateLockPath(root: string): string {
  return path.join(root, UPDATE_LOCK_NAME);
}

/** Refused-because-busy, in the words every caller reports it with. */
export const LOCK_BUSY_REASON = 'another ShieldCortex update/install is running';

export interface UpdateLock {
  /** Idempotent, and never removes a lock this process does not hold. */
  release(): void;
}

export type LockResult = { lock: UpdateLock } | { busy: string };

/** `O_NOFOLLOW` where the platform has it; 0 (and no protection) on Windows. */
const NOFOLLOW = fs.constants.O_NOFOLLOW ?? 0;

const LOCK_LINE = /^shieldcortex-update (\d+) (\S+)$/m;

/**
 * Read a lock file WITHOUT following it. A symlink at the lock path is not a
 * lock we wrote, so it is never parsed, never replaced and never unlinked —
 * the run simply refuses, which is the safe answer for a path somebody else
 * is clearly using.
 */
function readLock(target: string): { pid: number; at: number } | null {
  let fd: number;
  try {
    fd = fs.openSync(target, fs.constants.O_RDONLY | NOFOLLOW);
  } catch {
    return null;
  }
  try {
    const found = fs.readFileSync(fd, 'utf-8').trim().match(LOCK_LINE);
    if (found === null) return null;
    const at = Date.parse(found[2]);
    return { pid: Number(found[1]), at: Number.isNaN(at) ? 0 : at };
  } catch {
    return null;
  } finally {
    try { fs.closeSync(fd); } catch { /* already gone */ }
  }
}

/** EPERM means the pid exists and is not ours to signal — which is ALIVE. */
function processAlive(pid: number): boolean {
  if (!Number.isInteger(pid) || pid <= 0) return false;
  try {
    process.kill(pid, 0);
    return true;
  } catch (err: unknown) {
    return (err as NodeJS.ErrnoException)?.code === 'EPERM';
  }
}

/**
 * Take the one write lock for an integration root.
 *
 * `open(O_CREAT|O_EXCL|O_NOFOLLOW)` is the check and the act in one syscall, so
 * there is no window between "is anyone writing" and "I am writing". A lock is
 * only ever cleared when BOTH of the things that could make it a lie are true:
 * its recorded pid is dead, and it is older than ten minutes. A live pid holds
 * the lock however old the file is, and a fresh file holds it however dead the
 * pid looks — pids are recycled, and half an argument is not enough to delete
 * somebody else's lock.
 */
export function acquireUpdateLock(
  root: string,
  opts: { now?: Date; createRoot?: boolean } = {},
): LockResult {
  const now = opts.now ?? new Date();
  const target = updateLockPath(root);
  if (opts.createRoot === true) {
    try {
      fs.mkdirSync(root, { recursive: true });
    } catch (err: unknown) {
      return { busy: `${root} could not be created — ${describeFsError(err)}` };
    }
  }
  for (let attempt = 0; attempt < 2; attempt += 1) {
    try {
      const fd = fs.openSync(
        target,
        fs.constants.O_CREAT | fs.constants.O_EXCL | fs.constants.O_WRONLY | NOFOLLOW,
        0o600,
      );
      try {
        fs.writeFileSync(fd, `shieldcortex-update ${process.pid} ${now.toISOString()}\n`);
        fs.fsyncSync(fd);
      } finally {
        fs.closeSync(fd);
      }
      return { lock: { release: () => releaseLock(target) } };
    } catch (err: unknown) {
      if ((err as NodeJS.ErrnoException)?.code !== 'EEXIST') {
        return { busy: `the update lock at ${target} could not be taken — ${describeFsError(err)}` };
      }
    }
    if (attempt > 0) break;
    const held = readLock(target);
    if (held === null || processAlive(held.pid) || now.getTime() - held.at < STALE_LOCK_MS) break;
    try {
      fs.unlinkSync(target);
    } catch {
      break;
    }
  }
  // Naming the file matters: a run that is SIGKILLed mid-swap leaves its lock
  // behind, and the conjunction above then holds it for up to ten minutes. An
  // operator who knows nothing else is running can delete it and carry on.
  return {
    busy: `${LOCK_BUSY_REASON} (${target}) — a lock left behind by a killed run is ignored ` +
      'ten minutes later, or can be deleted once you know nothing else is writing',
  };
}

function releaseLock(target: string): void {
  const held = readLock(target);
  // Only ever the lock this process wrote. A lock whose pid moved on belongs
  // to whoever cleared and retook it, and it is not ours to remove.
  if (held === null || held.pid !== process.pid) return;
  try {
    fs.unlinkSync(target);
  } catch {
    /* a leftover lock is cleared as stale by the next run ten minutes later */
  }
}

/**
 * `fsync` a directory so the NAMES in it are durable, not just the bytes of
 * the files. Best effort BY PLATFORM, not by accident: several filesystems and
 * every Windows build refuse a directory fd outright, and a refresh must not
 * fail on a host where the call is simply unavailable. Every refusal is
 * RETURNED (see `SyncReport.unsynced`) and surfaced by the caller, so the one
 * thing the previous round was faulted for — swallowing them — cannot happen.
 */
function syncDir(dir: string): string | null {
  let fd: number | null = null;
  try {
    fd = fs.openSync(dir, 'r');
    fs.fsyncSync(fd);
    return null;
  } catch (err: unknown) {
    return `${dir} could not be flushed (${describeFsError(err)})`;
  } finally {
    if (fd !== null) {
      try { fs.closeSync(fd); } catch { /* already gone */ }
    }
  }
}

export interface SyncReport {
  /** A FILE that could not be flushed, or a tree that could not be walked. */
  error: string | null;
  /** Directories the platform would not flush. Reported, never swallowed. */
  unsynced: string[];
}

/**
 * Flush a staged tree to the medium: every file first, then every directory
 * bottom-up, so a rename that publishes the tree cannot expose a name whose
 * contents are still only in page cache.
 *
 * A file that will not flush is FATAL and returns `error`. That is the honest
 * answer: nothing has been published yet, so refusing costs an operator one
 * warning, while publishing bytes that may not survive a power cut costs them
 * the gate the package exists to run.
 */
export function syncTree(root: string): SyncReport {
  const dirs: string[] = [];
  const stack: string[] = [root];
  while (stack.length > 0) {
    const current = stack.pop()!;
    dirs.push(current);
    const listing = readdirAnswer(current);
    if (!('value' in listing)) {
      return {
        error: 'absent' in listing
          ? `${current} disappeared while it was being flushed`
          : `${current} could not be read (${listing.error})`,
        unsynced: [],
      };
    }
    for (const entry of listing.value) {
      const full = path.join(current, entry.name);
      if (entry.isDirectory()) {
        stack.push(full);
        continue;
      }
      let fd: number | null = null;
      try {
        fd = fs.openSync(full, 'r');
        fs.fsyncSync(fd);
      } catch (err: unknown) {
        return { error: `${full} could not be flushed to disk (${describeFsError(err)})`, unsynced: [] };
      } finally {
        if (fd !== null) {
          try { fs.closeSync(fd); } catch { /* already gone */ }
        }
      }
    }
  }
  const unsynced: string[] = [];
  for (const dir of dirs.reverse()) {
    const failed = syncDir(dir);
    if (failed !== null) unsynced.push(failed);
  }
  return { error: null, unsynced };
}

export interface StagedInstallParams {
  /**
   * The integration root every one of these paths must sit under, and the
   * outermost component the symlink preflight checks. `<hermesHome>` /
   * `<configRoot>` — never `/`, so a box whose `/home` is legitimately a link
   * is not refused for a fact about the box.
   */
  bound: string;
  /** The STANDARD target. Computed by the caller; never read from disk. */
  target: string;
  /** Where the staging container goes — outside every discovery root. */
  stagingParent: string;
  /** Where a displaced copy goes. Nothing ever deletes anything under it. */
  backupsRoot: string;
  /** Names both reserved directories, so one refresh's are recognisable. */
  stamp: string;
  stagingPrefix: string;
  backupPrefix: string;
  /** Fill the staged directory from the PACKAGE. The only source of bytes. */
  stage: (staged: string) => void;
  /** Byte-equality against the package: the first difference, or null. */
  verify: (staged: string) => string | null;
  /** What an operator runs when a move is refused outright. */
  reinstallCommand: string;
}

export type StagedInstallOutcome =
  | { ok: true; backup: string | null; unsynced: string[] }
  | {
    ok: false;
    error: string;
    /**
     * True only for the one state a caller must not gloss over: the target was
     * moved away and could be neither replaced nor restored, so the host has
     * no installed copy and the operator has to be sent to the installer.
     */
    targetMissing: boolean;
    /** Where the displaced copy is, when `targetMissing`. Never deleted. */
    backup: string | null;
    unsynced: string[];
  };

/**
 * Stage the packaged set beside the target and publish it — the ONE write both
 * file-copied integrations go through (#574 / #576 r3).
 *
 * Round 2 had this sequence written out twice, once per integration, and the
 * two copies had already drifted: only one of them checked both rename hops
 * for EXDEV. One routine is the point. Its inputs are the caller's own path
 * arithmetic plus a `stage` callback that reads the package, so a self-heal
 * and an ordinary refresh are the same call with the same preflights — there
 * is no second, quieter path to forget to harden.
 *
 * Whether the old copy is backed up is decided HERE, by `lstat` on the target:
 * a refresh displaces what it finds, a self-heal over an empty path has
 * nothing to displace, and a self-heal over a half-written husk still keeps
 * the husk. The caller does not get to assert which case it is.
 */
export function stageAndPublish(params: StagedInstallParams): StagedInstallOutcome {
  const unsynced: string[] = [];
  const fail = (error: string): StagedInstallOutcome =>
    ({ ok: false, error, targetMissing: false, backup: null, unsynced });
  const why = (err: unknown): string => (err instanceof Error ? err.message : String(err));

  // `lstat`, not `existsSync`: a permission error must never read as "nothing
  // is there" (#569 r6), because that is the answer that makes a move look safe.
  const present = lstatAnswer(params.target);
  if ('error' in present) {
    return fail(`${params.target} could not be read (${present.error}); nothing written`);
  }
  const displace = 'value' in present;

  let staging: string;
  try {
    staging = reserveBackupDir(params.stagingParent, `${params.stagingPrefix}-${params.stamp}`);
  } catch (err: unknown) {
    return fail(`could not stage the new copy — ${why(err)}`);
  }
  const staged = path.join(staging, path.basename(params.target));
  // Only ever a directory this run created moments ago, and only ever when the
  // publication it was made for did not happen. Nothing recovers from staging:
  // the package it was copied from is still on disk.
  const dropStaging = (): void => {
    try {
      fs.rmSync(staging, { recursive: true, force: true });
    } catch { /* our own staging dir; a leftover costs nothing */ }
  };
  const refuse = (error: string): StagedInstallOutcome => {
    dropStaging();
    return fail(error);
  };

  const targetParent = path.dirname(params.target);
  try {
    params.stage(staged);
    fs.mkdirSync(targetParent, { recursive: true });
  } catch (err: unknown) {
    return refuse(`could not stage the new copy — ${why(err)}`);
  }

  // `rename(2)` refuses to cross a filesystem, and this never turns a move
  // into a copy-then-delete of the operator's directory. EVERY hop is checked
  // before the first one runs.
  const devices = [deviceUnder(staged), deviceUnder(targetParent)];
  if (displace) devices.push(deviceUnder(params.backupsRoot));
  if (devices.some((d) => 'error' in d)) return refuse('could not stat the move endpoints; nothing written');
  if (new Set(devices.filter((d): d is { value: number } => 'value' in d).map((d) => d.value)).size > 1) {
    return refuse(
      `is on a different filesystem from ${params.backupsRoot} (EXDEV) — a cross-filesystem move ` +
      `is a copy followed by a delete of the original, which this never does; ${params.reinstallCommand}`,
    );
  }

  let reserved: string | null = null;
  let backup: string | null = null;
  if (displace) {
    try {
      reserved = reserveBackupDir(params.backupsRoot, `${params.backupPrefix}-preupdate-${params.stamp}`);
    } catch (err: unknown) {
      return refuse(`no backup destination could be reserved under ${params.backupsRoot} — ${why(err)}`);
    }
    backup = path.join(reserved, path.basename(params.target));
  }
  /** Give the reservation back when the move it was made for did not happen. */
  const giveBack = (): void => {
    if (reserved !== null) releaseReservation(reserved);
  };

  // Every component of every path about to be renamed. A refresh and a
  // self-heal are the same call, so neither can have a preflight the other
  // does not — which is what a separate "recovery" path cost in round 2.
  for (const checked of [params.target, backup, staged]) {
    if (checked === null) continue;
    const { link, unreadable } = findLinkOnPath(params.bound, checked);
    if (unreadable !== null) {
      giveBack();
      return refuse(`${unreadable.path} could not be read (${unreadable.error}); nothing written`);
    }
    if (link !== null) {
      giveBack();
      return refuse(`${link} is a symlink; nothing written`);
    }
  }

  // Durable before reachable.
  const sync = syncTree(staged);
  unsynced.push(...sync.unsynced);
  if (sync.error !== null) {
    giveBack();
    return refuse(`${sync.error}; nothing written`);
  }

  // Nothing is published that has not been proved to be the package.
  const difference = params.verify(staged);
  if (difference !== null) {
    giveBack();
    return refuse(`the staged copy did not verify against the packaged source (${difference}); nothing written`);
  }

  const flush = (...dirs: string[]): void => {
    for (const dir of dirs) {
      const failed = syncDir(dir);
      if (failed !== null) unsynced.push(failed);
    }
  };

  // Displace the old copy, if there is one.
  if (backup !== null) {
    try {
      fs.renameSync(params.target, backup);
    } catch (err: unknown) {
      giveBack();
      return refuse(`could not be moved to ${backup} — ${describeFsError(err)}`);
    }
    flush(targetParent, path.dirname(backup));
  }

  // Publish.
  try {
    fs.renameSync(staged, params.target);
  } catch (err: unknown) {
    const error = describeFsError(err);
    dropStaging();
    // Nothing was displaced, so nothing is missing that was not missing before
    // this call: the host is exactly where it started.
    if (backup === null) {
      giveBack();
      return { ok: false, error, targetMissing: false, backup: null, unsynced };
    }
    try {
      fs.renameSync(backup, params.target);
    } catch {
      return { ok: false, error, targetMissing: true, backup, unsynced };
    }
    flush(targetParent, path.dirname(backup));
    giveBack();
    // Said out loud, because "the refresh failed" and "the refresh failed and
    // your plugin is gone" are different sentences for an operator.
    return {
      ok: false,
      error: `${error}; the previous copy was restored`,
      targetMissing: false,
      backup: null,
      unsynced,
    };
  }
  flush(targetParent, staging);
  dropStaging();
  return { ok: true, backup, unsynced };
}
