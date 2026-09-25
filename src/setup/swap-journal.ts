/**
 * ShieldCortex — the crash-safe directory swap `update` publishes through
 * (#574 / #576, round 2 blockers 1 and 2).
 *
 * ## Why a journal at all
 *
 * Both file-copied host integrations are refreshed by replacing a whole
 * directory: `~/.hermes/plugins/shieldcortex` and
 * `~/.openclaw/hooks/cortex-memory`. Node has no atomic directory exchange —
 * there is no binding for `renameat2(RENAME_EXCHANGE)` — so a swap is two
 * `rename(2)` calls:
 *
 *     1. target  → backup      ("moving-old")
 *     2. staged  → target      ("publishing")
 *
 * Between them the host has NO installed copy. A SIGKILL, a power cut or an
 * OOM there leaves a gateway with nothing to load and, worse, leaves the next
 * `update` looking at an empty `plugins/` and reporting "not installed" — the
 * exact state the first review reproduced. A `try/catch` cannot help: the
 * process that would run the `catch` is gone.
 *
 * So the swap writes a JOURNAL before the first rename, and the next run reads
 * it and finishes the job. The journal is durable (exclusive create, `fsync`
 * on the file, `fsync` on the containing directory) and lives OUTSIDE every
 * discovery root the host scans, so it can never itself be loaded as a plugin
 * or a hook.
 *
 * ## The recovery rule, and why it is this one
 *
 * Recovery is decided by WHAT IS ON DISK, never by the recorded `phase`. The
 * phase is written for an operator reading the file and for diagnostics; a
 * crash can land between a rename and the phase update, so a decision that
 * trusted the phase would be trusting a value that is allowed to be stale.
 * The three paths have distinguishable on-disk states, which is all the
 * decision needs:
 *
 *   - **target present** — the swap either completed (rename 2 landed) or
 *     never started (rename 1 had not run). Either way the host has its copy.
 *     Drop the staging tree, delete the journal, LEAVE the backup in
 *     `backups/` (nothing here ever deletes an operator's old copy).
 *   - **target absent, backup present** — the crash was between the renames.
 *     Move the backup back. This is the default and the safe one: that copy
 *     is the one this host was demonstrably running, and putting it back
 *     returns the box to exactly the state it was in before the refresh began.
 *     The next `update` then re-attempts the refresh from scratch, against
 *     whatever package is installed NOW.
 *   - **target absent, backup absent, staged complete** — there is no old copy
 *     left to restore (an operator moved it, or a `backups/` cleaner took it),
 *     so the alternative to publishing the staged tree is leaving the host
 *     with no plugin at all. Publish it, but only after the caller's
 *     `stagedIsComplete` predicate has verified the staged tree byte-for-byte
 *     against the packaged source. This is deliberately the LAST rule, not the
 *     first: a staged tree was assembled by a process that then died, and its
 *     completeness is only attestable against the package version on disk
 *     today — which is not necessarily the one it was built from.
 *
 * Anything else — an unreadable path, a staged tree that does not verify —
 * is BLOCKED: the journal is left exactly where it is, nothing is written, and
 * the caller prints the recovery command. "I could not look" is never "there
 * is nothing there" (#569 r6), and that rule does not relax because the host
 * is already in a bad state.
 */

import fs from 'fs';
import path from 'path';
import { describeFsError } from './hermes-plugins.js';
import { lstatAnswer } from './fs-answers.js';

/** The journal's file name. One unresolved swap per root, by construction. */
export const REFRESH_JOURNAL_NAME = '.shieldcortex-refresh-journal.json';

/** Which integration a journal belongs to — for the operator, not for logic. */
export type SwapKind = 'hermes-plugin' | 'openclaw-hook';

/**
 * The phase the swap had REACHED when the journal was last written. Advisory:
 * see the module comment — recovery reads the filesystem, not this field.
 */
export type SwapPhase = 'moving-old' | 'publishing';

export interface RefreshJournal {
  /** Bumped if the shape ever changes; an unknown version is refused, not guessed. */
  version: 1;
  kind: SwapKind;
  /** The directory the journal itself lives in. */
  root: string;
  /** The directory being replaced — what the host loads. */
  target: string;
  /** Where the displaced copy was (or will be) moved to. Never deleted. */
  backup: string;
  /** The prepared replacement, outside every discovery root. */
  staged: string;
  /** The container holding `staged`, removed once the swap resolves. */
  stagingRoot: string;
  /** The ShieldCortex version the staged copy was built from. */
  packagedVersion: string;
  phase: SwapPhase;
  startedAt: string;
  pid: number;
}

export function journalPath(root: string): string {
  return path.join(root, REFRESH_JOURNAL_NAME);
}

/**
 * `fsync` the directory so the journal's NAME is durable, not just its bytes.
 * Best effort: some platforms and filesystems refuse a directory fd, and a
 * refusal here must not stop a refresh that is otherwise fine.
 */
function fsyncDir(dir: string): void {
  let fd: number | null = null;
  try {
    fd = fs.openSync(dir, 'r');
    fs.fsyncSync(fd);
  } catch {
    /* directory fsync is unavailable on this platform/filesystem */
  } finally {
    if (fd !== null) {
      try { fs.closeSync(fd); } catch { /* already gone */ }
    }
  }
}

/**
 * Write the journal with EXCLUSIVE create, so a second refresh racing this one
 * cannot overwrite an unresolved swap — `open(O_CREAT|O_EXCL)` is the check and
 * the act in one syscall, the same reservation trick `reserveBackupDir` uses.
 * Throws EEXIST when a journal is already there, which the caller reads as
 * "a previous refresh is unresolved".
 */
export function writeJournal(entry: RefreshJournal): void {
  const target = journalPath(entry.root);
  const fd = fs.openSync(target, 'wx', 0o600);
  try {
    fs.writeFileSync(fd, `${JSON.stringify(entry, null, 2)}\n`);
    fs.fsyncSync(fd);
  } finally {
    fs.closeSync(fd);
  }
  fsyncDir(entry.root);
}

/**
 * Record that rename 1 landed. Written to a temp name and `rename`d over the
 * journal, so the journal is never observed half-rewritten; a failure here is
 * swallowed because the phase is advisory and the swap must not abort over a
 * diagnostic.
 */
export function advanceJournalPhase(entry: RefreshJournal, phase: SwapPhase): void {
  const target = journalPath(entry.root);
  const temp = `${target}.next`;
  try {
    const fd = fs.openSync(temp, 'w', 0o600);
    try {
      fs.writeFileSync(fd, `${JSON.stringify({ ...entry, phase }, null, 2)}\n`);
      fs.fsyncSync(fd);
    } finally {
      fs.closeSync(fd);
    }
    fs.renameSync(temp, target);
    fsyncDir(entry.root);
  } catch {
    try { fs.rmSync(temp, { force: true }); } catch { /* best effort */ }
  }
}

/** Delete the journal — the LAST act of a swap that worked. */
export function clearJournal(root: string): void {
  try {
    fs.rmSync(journalPath(root), { force: true });
    fsyncDir(root);
  } catch {
    /* a leftover journal is recovered (and cleaned) by the next run */
  }
}

export type JournalRead =
  | { journal: RefreshJournal }
  | { absent: true }
  | { error: string };

/** Read the journal, keeping "not there" and "could not read" apart. */
export function readJournal(root: string): JournalRead {
  let raw: string;
  try {
    raw = fs.readFileSync(journalPath(root), 'utf-8');
  } catch (err: unknown) {
    if ((err as NodeJS.ErrnoException)?.code === 'ENOENT') return { absent: true };
    return { error: describeFsError(err) };
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(raw);
  } catch {
    return { error: 'the journal is not readable JSON' };
  }
  const j = parsed as Partial<RefreshJournal>;
  if (j?.version !== 1 || typeof j.target !== 'string' || typeof j.backup !== 'string'
    || typeof j.staged !== 'string' || typeof j.root !== 'string') {
    return { error: 'the journal is not a shape this version understands' };
  }
  return { journal: j as RefreshJournal };
}

/**
 * Remove a staging container this command created. Guarded twice: the name
 * must be one of ours, and the path must not be a symlink. Everything else is
 * left standing — the rule that nothing here removes a directory it did not
 * create holds even during recovery.
 */
function dropStaging(stagingRoot: string): void {
  if (!path.basename(stagingRoot).startsWith('.shieldcortex-')) return;
  const self = lstatAnswer(stagingRoot);
  if (!('value' in self) || self.value.isSymbolicLink()) return;
  try {
    fs.rmSync(stagingRoot, { recursive: true, force: true });
  } catch {
    /* our own staging tree; a leftover costs nothing */
  }
}

/** Which of the swap's three writes failed, so a caller can phrase it. */
export type SwapStage = 'journal' | 'moving-old' | 'publishing';

export type SwapOutcome =
  | { ok: true }
  /**
   * `targetMissing` is the only state that must never be cleaned up after:
   * the host has no installed copy, and the staged tree plus the journal are
   * what the next run recovers from.
   */
  | { ok: false; stage: SwapStage; restored: boolean; targetMissing: boolean; error: string };

/**
 * Publish `staged` over `target`, keeping the displaced copy at `backup`.
 *
 * Every write this performs is described by a durable journal first. On the
 * failure that matters — rename 2 refused and the old copy could not be put
 * back — the journal is deliberately LEFT so the next `update`, `hermes
 * install` or `openclaw install` can finish the job, and the caller is told
 * not to clean up staging.
 */
export function journalledSwap(params: {
  kind: SwapKind;
  root: string;
  target: string;
  backup: string;
  staged: string;
  stagingRoot: string;
  packagedVersion: string;
  now: Date;
}): SwapOutcome {
  const entry: RefreshJournal = {
    version: 1,
    kind: params.kind,
    root: params.root,
    target: params.target,
    backup: params.backup,
    staged: params.staged,
    stagingRoot: params.stagingRoot,
    packagedVersion: params.packagedVersion,
    phase: 'moving-old',
    startedAt: params.now.toISOString(),
    pid: process.pid,
  };
  try {
    writeJournal(entry);
  } catch (err: unknown) {
    const code = (err as NodeJS.ErrnoException)?.code;
    return {
      ok: false,
      stage: 'journal',
      restored: true,
      targetMissing: false,
      error: code === 'EEXIST'
        ? `an unresolved refresh journal is already at ${journalPath(params.root)}`
        : `the refresh journal could not be written — ${describeFsError(err)}`,
    };
  }

  try {
    fs.renameSync(params.target, params.backup);
  } catch (err: unknown) {
    // Nothing moved, so there is nothing to recover: the journal describes a
    // swap that never began and must not outlive this call.
    clearJournal(params.root);
    return {
      ok: false,
      stage: 'moving-old',
      restored: true,
      targetMissing: false,
      error: `could not be moved to ${params.backup} — ${describeFsError(err)}`,
    };
  }

  advanceJournalPhase(entry, 'publishing');

  try {
    fs.renameSync(params.staged, params.target);
  } catch (err: unknown) {
    const why = describeFsError(err);
    let restored = true;
    try {
      fs.renameSync(params.backup, params.target);
    } catch {
      restored = false;
    }
    if (restored) {
      clearJournal(params.root);
      return { ok: false, stage: 'publishing', restored: true, targetMissing: false, error: why };
    }
    // The host has no installed copy. The journal stays, staging stays, and
    // the caller prints the command that finishes this.
    return { ok: false, stage: 'publishing', restored: false, targetMissing: true, error: why };
  }

  dropStaging(params.stagingRoot);
  clearJournal(params.root);
  return { ok: true };
}

export type RecoveryStatus = 'none' | 'cleaned' | 'restored' | 'published' | 'blocked';

export interface RecoveryOutcome {
  status: RecoveryStatus;
  /** Operator-facing lines. Empty when `status` is `none`. */
  detail: string[];
  /** The journal that was found, for a caller that wants to name paths. */
  journal: RefreshJournal | null;
}

/**
 * Finish an interrupted swap, or say why it cannot be finished.
 *
 * Runs at the START of every refresh and of both installers, so an operator
 * who reboots mid-upgrade gets their plugin back by running the same command
 * they were already going to run. Never creates anything: with no journal it
 * does nothing at all and says nothing.
 */
export function recoverInterruptedSwap(
  root: string,
  opts: { stagedIsComplete?: (staged: string) => boolean } = {},
): RecoveryOutcome {
  const read = readJournal(root);
  if ('absent' in read) return { status: 'none', detail: [], journal: null };
  if ('error' in read) {
    return {
      status: 'blocked',
      detail: [`${journalPath(root)}: ${read.error} — remove it by hand once the install is sound`],
      journal: null,
    };
  }
  const j = read.journal;
  const blocked = (line: string): RecoveryOutcome => ({ status: 'blocked', detail: [line], journal: j });

  const target = lstatAnswer(j.target);
  if ('error' in target) {
    return blocked(`an interrupted refresh was found, but ${j.target} could not be read (${target.error})`);
  }
  if ('value' in target) {
    // Completed, or never started. Either way the host has its copy back.
    dropStaging(j.stagingRoot);
    clearJournal(root);
    return {
      status: 'cleaned',
      detail: [`an interrupted refresh was found; ${j.target} is in place, so it was cleared` +
        (existsForReport(j.backup) ? ` (the previous copy is kept at ${j.backup})` : '')],
      journal: j,
    };
  }

  const backup = lstatAnswer(j.backup);
  if ('error' in backup) {
    return blocked(`an interrupted refresh left ${j.target} missing, and ${j.backup} could not be read (${backup.error})`);
  }
  if ('value' in backup) {
    try {
      fs.renameSync(j.backup, j.target);
    } catch (err: unknown) {
      return blocked(
        `an interrupted refresh left ${j.target} missing and the previous copy at ${j.backup} ` +
        `could not be moved back — ${describeFsError(err)}`,
      );
    }
    dropStaging(j.stagingRoot);
    clearJournal(root);
    return {
      status: 'restored',
      detail: [`an interrupted refresh was found; the previous copy was restored to ${j.target}`],
      journal: j,
    };
  }

  // No target and no backup: the staged tree is the only copy left anywhere,
  // and it is published only if it verifies complete against the package.
  const staged = lstatAnswer(j.staged);
  if ('error' in staged) {
    return blocked(`an interrupted refresh left ${j.target} missing, and ${j.staged} could not be read (${staged.error})`);
  }
  const verify = opts.stagedIsComplete;
  if ('value' in staged && verify !== undefined && verify(j.staged)) {
    try {
      fs.renameSync(j.staged, j.target);
    } catch (err: unknown) {
      return blocked(
        `an interrupted refresh left ${j.target} missing and the staged copy at ${j.staged} ` +
        `could not be published — ${describeFsError(err)}`,
      );
    }
    dropStaging(j.stagingRoot);
    clearJournal(root);
    return {
      status: 'published',
      detail: [
        `an interrupted refresh was found with no previous copy left to restore; the verified ` +
        `staged copy was published to ${j.target}`,
      ],
      journal: j,
    };
  }
  return blocked(
    `an interrupted refresh left ${j.target} missing: the previous copy is not at ${j.backup} and ` +
    `the staged copy at ${j.staged} is ${'value' in staged ? 'incomplete' : 'gone'}`,
  );
}

/** Only ever used to decorate a message; never to decide anything. */
function existsForReport(target: string): boolean {
  return 'value' in lstatAnswer(target);
}
