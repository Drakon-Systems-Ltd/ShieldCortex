/**
 * ShieldCortex — publishing the packaged copy of a file-copied host
 * integration, and the one lock that serialises it (#574 / #576).
 *
 * ## Why nothing here finishes somebody else's swap
 *
 * Round 2 shipped a crash journal: the swap wrote `{target, backup, staged}`
 * to disk and the next run READ THAT FILE AND MOVED THE PATHS IT NAMED. Round
 * 3 dropped the journal but kept the healing, on "the standard target is
 * missing AND `backups/<name>-preupdate-*` exists". Review took both apart,
 * and it is one lesson: a recovery that infers authority from the filesystem
 * can be handed that authority. A journal names paths; a backup directory is
 * also what a SUCCESSFUL refresh leaves, so healing from one reinstalls an
 * integration the operator just removed — and an empty planted one installs it
 * on a host that never had it.
 *
 * So this publishes over targets the CALLER already found, and never creates
 * one. A planted journal, a planted `.shieldcortex-staging-*` and a hostile
 * `backups/` entry are all inert. A swap that dies after the first rename is
 * reported at that moment (`targetMissing` below), naming the integration's
 * installer and the backup to restore from; nothing deletes a backup, ever.
 *
 * ## What a publication does, in order
 *
 *   1. preflight — no symlink on any component of the target, the backup or
 *      the staged tree, bounded at the integration root;
 *   2. `fsync` every staged file and every staged directory, so the bytes are
 *      on the medium BEFORE any rename makes them reachable;
 *   3. verify the staged tree byte-for-byte against the package;
 *   4. `fsync` the backup's newly created ancestry — the reservation,
 *      `backups/` and the integration root — so the name that will hold the
 *      displaced copy is durable BEFORE the copy is displaced;
 *   5. `rename(target -> backup)` when there is a target to displace, then
 *      `fsync` both parent directories;
 *   6. `rename(staged -> target)`, then `fsync` both parent directories.
 *
 * Steps 2, 4 and every other flush distinguish "this platform will not sync a
 * directory fd" from "the device refused" (`DIR_SYNC_UNSUPPORTED`). The first
 * is reported and carried on with; the second is fatal before the first rename
 * and reported after it.
 *
 * A failure at 6 leaves the host with no target, so the backup is renamed
 * straight back and both parents are synced again. If THAT fails, the caller
 * names the integration's installer, which is this same publication run from
 * the package.
 */

import fs from 'fs';
import path from 'path';
import { randomUUID } from 'crypto';
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

export function updateLockPath(root: string): string {
  return path.join(root, UPDATE_LOCK_NAME);
}

/** Refused-because-busy, in the words every caller reports it with. */
export const LOCK_BUSY_REASON = 'another ShieldCortex update/install is running';

export interface UpdateLock {
  /** Idempotent, and never removes a lock this handle did not create. */
  release(): void;
}

export type LockResult = { lock: UpdateLock } | { busy: string };

/** `O_NOFOLLOW` where the platform has it; 0 (and no protection) on Windows. */
const NOFOLLOW = fs.constants.O_NOFOLLOW ?? 0;

const LOCK_LINE = /^shieldcortex-update (\d+) (\S+) (\S+)$/m;

/**
 * Read a lock file WITHOUT following it. A symlink at the lock path is not a
 * lock we wrote, so it is never parsed and never removed — the run simply
 * refuses, which is the safe answer for a path somebody else is clearly using.
 */
function readLock(target: string): { pid: string; at: string; token: string } | null {
  let fd: number;
  try {
    fd = fs.openSync(target, fs.constants.O_RDONLY | NOFOLLOW);
  } catch {
    return null;
  }
  try {
    const found = fs.readFileSync(fd, 'utf-8').trim().match(LOCK_LINE);
    return found === null ? null : { pid: found[1], at: found[2], token: found[3] };
  } catch {
    return null;
  } finally {
    try { fs.closeSync(fd); } catch { /* already gone */ }
  }
}

/**
 * Take the one write lock for an integration root — or refuse.
 *
 * `open(O_CREAT|O_EXCL|O_NOFOLLOW)` is the check and the act in one syscall, so
 * there is no window between "is anyone writing" and "I am writing".
 *
 * NOTHING here reclaims a lock (r3 blocker 2). Round 3 deleted one whose pid
 * was dead and whose stamp was over ten minutes old, which races two
 * contenders into deleting each other's live lock — an `unlink` by pathname
 * after a separate read cannot establish ownership of what is at that pathname
 * now. The ten-minute promise was false anyway: a kill between the exclusive
 * create and the write leaves a record no age check clears, and a recycled pid
 * keeps a dead lock alive indefinitely. So an existing lock is simply an
 * existing lock; clearing it needs knowledge this process does not have.
 *
 * `bound` is the outermost component the root is validated from, and the
 * validation runs BEFORE the lock is created (blocker 4): a symlinked
 * `~/.openclaw`, `~/.hermes` or profile root is refused having written nothing
 * at all, lock included. It defaults to the root itself.
 */
export function acquireUpdateLock(
  root: string,
  opts: { now?: Date; createRoot?: boolean; bound?: string } = {},
): LockResult {
  const now = opts.now ?? new Date();
  const target = updateLockPath(root);

  const { link, unreadable } = findLinkOnPath(opts.bound ?? root, root);
  if (unreadable !== null) {
    return { busy: `${unreadable.path} could not be read (${unreadable.error}); nothing written` };
  }
  if (link !== null) return { busy: `${link} is a symlink; nothing written` };

  if (opts.createRoot === true) {
    try {
      fs.mkdirSync(root, { recursive: true });
    } catch (err: unknown) {
      return { busy: `${root} could not be created — ${describeFsError(err)}` };
    }
  }

  // The token is what makes `release` safe. A pid is not an identity: the same
  // process can acquire, release and acquire again, and round 3's pid-only
  // release then deleted the SECOND lock when the first handle was released
  // twice (review nit 1).
  const token = randomUUID();
  try {
    const fd = fs.openSync(
      target,
      fs.constants.O_CREAT | fs.constants.O_EXCL | fs.constants.O_WRONLY | NOFOLLOW,
      0o600,
    );
    try {
      fs.writeFileSync(fd, `shieldcortex-update ${process.pid} ${now.toISOString()} ${token}\n`);
      fs.fsyncSync(fd);
    } finally {
      fs.closeSync(fd);
    }
  } catch (err: unknown) {
    if ((err as NodeJS.ErrnoException)?.code !== 'EEXIST') {
      return { busy: `the update lock at ${target} could not be taken — ${describeFsError(err)}` };
    }
    const held = readLock(target);
    return {
      busy: `${LOCK_BUSY_REASON} (${target}) — ` +
        (held === null
          ? 'its contents are not a lock record, so there is no run to identify'
          : `recorded pid ${held.pid}, taken ${held.at}`) +
        '; delete that file only once you have confirmed no ShieldCortex update or install is ' +
        'running, because nothing removes it for you',
    };
  }

  let released = false;
  return {
    lock: {
      release: () => {
        if (released) return;
        released = true;
        // Only ever the file this call created. A lock carrying a different
        // token belongs to whoever cleared this one and took it afterwards.
        if (readLock(target)?.token !== token) return;
        try {
          fs.unlinkSync(target);
        } catch { /* a leftover lock is the operator's to clear */ }
      },
    },
  };
}

/**
 * Codes that mean "this platform has no directory fsync", as opposed to "it
 * was attempted and the device said no" (r3 blocker 5). Round 3 bucketed EVERY
 * refusal the first way, so an injected `EIO` on every directory flush still
 * produced a published copy reported as a clean refresh. `EACCES`/`EPERM` sit
 * on the unsupported side on purpose: they mean the directory would not OPEN,
 * and if the following rename cannot happen, the rename itself says so.
 */
const DIR_SYNC_UNSUPPORTED: ReadonlySet<string> = new Set([
  'EACCES', 'EBADF', 'EINVAL', 'EISDIR', 'ENOTSUP', 'EOPNOTSUPP', 'EPERM',
]);

type DirSync = { ok: true } | { unsupported: string } | { error: string };

/**
 * `fsync` a directory so the NAMES in it are durable, not just the bytes of
 * the files. Three answers, never two: it worked, the platform will not do it,
 * or it was tried and failed.
 */
function syncDir(dir: string): DirSync {
  let fd: number | null = null;
  try {
    fd = fs.openSync(dir, 'r');
    fs.fsyncSync(fd);
    return { ok: true };
  } catch (err: unknown) {
    const code = (err as NodeJS.ErrnoException)?.code;
    const said = `${dir} could not be flushed (${describeFsError(err)})`;
    return typeof code === 'string' && DIR_SYNC_UNSUPPORTED.has(code)
      ? { unsupported: said }
      : { error: said };
  } finally {
    if (fd !== null) {
      try { fs.closeSync(fd); } catch { /* already gone */ }
    }
  }
}

export interface SyncReport {
  /** An unflushable FILE, an unwalkable tree, or a DIRECTORY the device refused. */
  error: string | null;
  /** Directories the platform cannot flush. Reported, never swallowed. */
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
    const answer = syncDir(dir);
    if ('error' in answer) return { error: answer.error, unsynced };
    if ('unsupported' in answer) unsynced.push(answer.unsupported);
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

  /** Flush, keeping "will not" apart from "refused". First real failure, or null. */
  const flush = (...dirs: string[]): string | null => {
    for (const dir of dirs) {
      const answer = syncDir(dir);
      if ('error' in answer) return answer.error;
      if ('unsupported' in answer) unsynced.push(answer.unsupported);
    }
    return null;
  };
  /** After a rename there is nothing left to abort, so the note is the answer. */
  const note = (...dirs: string[]): void => {
    const failed = flush(...dirs);
    if (failed !== null) unsynced.push(failed);
  };

  // Displace the old copy, if there is one.
  if (backup !== null) {
    // The backup's ANCESTRY first (r3 blocker 5): `backups/` and the
    // reservation inside it are both brand new, and the rename below can
    // become durable before either NAME does — leaving a host whose plugin is
    // gone and whose backup is not reachably on the medium.
    const ancestry = flush(reserved!, params.backupsRoot, path.dirname(params.backupsRoot));
    if (ancestry !== null) {
      giveBack();
      return refuse(`${ancestry}; nothing written`);
    }
    try {
      fs.renameSync(params.target, backup);
    } catch (err: unknown) {
      giveBack();
      return refuse(`could not be moved to ${backup} — ${describeFsError(err)}`);
    }
    note(targetParent, path.dirname(backup));
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
    note(targetParent, path.dirname(backup));
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
  note(targetParent, staging);
  dropStaging();
  return { ok: true, backup, unsynced };
}
