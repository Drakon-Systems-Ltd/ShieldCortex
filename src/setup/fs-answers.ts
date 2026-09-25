/**
 * ShieldCortex — the filesystem answers a host-tree repair is allowed to act on.
 *
 * Lifted out of `src/cli/doctor.ts` unchanged (#574/#576). The #569 repair was
 * not the last command that has to move a directory another gateway may be
 * loading through: `update` now refreshes the installed Hermes plugin copy, and
 * a second copy of these readers would be a second place for "I could not look"
 * to decay back into "there is nothing there".
 */

import fs from 'fs';
import path from 'path';
import { describeFsError } from './hermes-plugins.js';

/**
 * What the filesystem said, with the two answers a repair must never conflate
 * kept apart (#569 r6): `absent` is "there is nothing at this path", `error` is
 * "I could not look". Only the first one may ever permit a move.
 *
 * Every `lstat`, `realpath` and `readdir` on the repair and preflight path goes
 * through one of the readers below. None of them is allowed to be written as a
 * `try { … } catch { return false }`, and `fs.existsSync` is not allowed here at
 * all: it returns false for a permission error, which is precisely the answer
 * that makes a move look safe.
 */
export type FsAnswer<T> = { value: T } | { absent: true } | { error: string };

/** Absence for a STAT: nothing at the path, or nothing under a non-directory. */
export const STAT_ABSENT_CODES: ReadonlySet<string> = new Set(['ENOENT', 'ENOTDIR']);

/**
 * Absence for an ENUMERATION: only ENOENT. `ENOTDIR` here means a directory
 * was expected and something else is there — that is a fact about the layout
 * nobody has explained, not an empty directory.
 */
export const READ_ABSENT_CODES: ReadonlySet<string> = new Set(['ENOENT']);

export function fsAnswer<T>(read: () => T, absentCodes: ReadonlySet<string>): FsAnswer<T> {
  try {
    return { value: read() };
  } catch (err: unknown) {
    const code = (err as NodeJS.ErrnoException)?.code;
    if (typeof code === 'string' && absentCodes.has(code)) return { absent: true };
    return { error: describeFsError(err) };
  }
}

/** `lstat`, following nothing: absent, the stats, or why not. */
export function lstatAnswer(target: string): FsAnswer<fs.Stats> {
  return fsAnswer(() => fs.lstatSync(target), STAT_ABSENT_CODES);
}

/** `realpath`: absent covers a dangling link, whose ENOENT is the truth. */
export function realPathAnswer(target: string): FsAnswer<string> {
  return fsAnswer(() => fs.realpathSync(target), STAT_ABSENT_CODES);
}

/** `readdir` with types, so entries are classified by `lstat` semantics. */
export function readdirAnswer(dir: string): FsAnswer<fs.Dirent[]> {
  return fsAnswer(() => fs.readdirSync(dir, { withFileTypes: true }), READ_ABSENT_CODES);
}

/** `stat`, FOLLOWING links: what a rename would actually land on. */
export function statAnswer(target: string): FsAnswer<fs.Stats> {
  return fsAnswer(() => fs.statSync(target), STAT_ABSENT_CODES);
}

/**
 * The device `target` sits on — or, when it does not exist yet, the device of
 * the nearest existing ancestor, which is the device `mkdir` would create it
 * on (#569 r7 nit 1).
 *
 * `rename(2)` refuses to cross a filesystem, and `backups/` is commonly a
 * fresh directory that does not exist until the first reservation is made. So
 * the question "will this move be EXDEV" has to be asked of the tree that WILL
 * hold it, before any of the plan runs. Links are followed on purpose: a
 * `backups` symlinked onto another volume puts the copies on that volume.
 */
export function deviceUnder(target: string): FsAnswer<number> {
  let cursor = path.resolve(target);
  for (;;) {
    const answer = statAnswer(cursor);
    if ('error' in answer) return { error: answer.error };
    if ('value' in answer) return { value: answer.value.dev };
    const parent = path.dirname(cursor);
    if (parent === cursor) return { absent: true };
    cursor = parent;
  }
}

/** Whether `inner` is `outer` or lives underneath it, lexically on real paths. */
export function pathContains(outer: string, inner: string): boolean {
  if (outer === inner) return true;
  const rel = path.relative(outer, inner);
  return rel !== '' && !rel.startsWith('..') && !path.isAbsolute(rel);
}

/**
 * How many directory entries the whole symlink preflight may look at before it
 * gives up. A plugin tree is hundreds of files; a budget this size is never
 * reached by a real one, and an unbounded recursive walk inside a repair
 * command is a hazard of its own. Exhausting it REFUSES (see `findLinkInTree`):
 * "I did not finish looking" is not "there is nothing there".
 */
export const SYMLINK_PREFLIGHT_ENTRY_BUDGET = 20_000;

/**
 * The first symlink at or under `dir`, or null when the tree demonstrably holds
 * none. There are two other answers, and neither of them is "none":
 *
 *   - `exhausted` — the walk ran out of budget, so it did not finish looking;
 *   - `unreadable` — a path in the tree could not be read, and it says which
 *     one and why (#569 r6). A directory that raises EACCES could be holding
 *     the link that another plugin root resolves through, and a walk that
 *     treats it as empty reports a clean tree.
 *
 * Nothing here follows a link. `readdirSync(withFileTypes)` reports the entry
 * itself (`lstat` semantics), and a directory entry that IS a link stops the
 * walk before it is descended into — so a link loop cannot be entered and a
 * link out of the tree is never followed out of it.
 */
export function findLinkInTree(dir: string, budget: { left: number }): {
  link: string | null;
  exhausted: boolean;
  unreadable: { path: string; error: string } | null;
} {
  const self = lstatAnswer(dir);
  if ('error' in self) return { link: null, exhausted: false, unreadable: { path: dir, error: self.error } };
  // Absent is possible under a race with the operator's own shell; it holds no
  // links, which is all this walk is asked about.
  if ('value' in self && self.value.isSymbolicLink()) {
    return { link: dir, exhausted: false, unreadable: null };
  }
  const stack = [dir];
  while (stack.length > 0) {
    const current = stack.pop()!;
    const listing = readdirAnswer(current);
    if ('error' in listing) {
      return { link: null, exhausted: false, unreadable: { path: current, error: listing.error } };
    }
    if ('absent' in listing) continue;
    for (const entry of listing.value) {
      if (budget.left <= 0) return { link: null, exhausted: true, unreadable: null };
      budget.left -= 1;
      const full = path.join(current, entry.name);
      if (entry.isSymbolicLink()) return { link: full, exhausted: false, unreadable: null };
      if (entry.isDirectory()) stack.push(full);
    }
  }
  return { link: null, exhausted: false, unreadable: null };
}

/**
 * Reserve a fresh, unique directory under `backupsRoot` and return it.
 *
 * `fs.mkdirSync` WITHOUT `recursive` on the leaf is the reservation: mkdir(2)
 * fails EEXIST when anything already occupies the name — including a DANGLING
 * SYMLINK, which `existsSync` reports as absent and which a rename would
 * happily follow or replace. There is no check-then-act window to lose, because
 * the check and the act are the same syscall; a squatter that wins the race
 * simply sends us to the next suffix.
 */
export function reserveBackupDir(
  backupsRoot: string,
  leafBase: string,
  /** How the caller shows a path to an operator (doctor tildifies; nothing else does). */
  describe: (target: string) => string = (target) => target,
): string {
  fs.mkdirSync(backupsRoot, { recursive: true });
  for (let attempt = 1; attempt <= 64; attempt += 1) {
    const leaf = attempt === 1 ? leafBase : `${leafBase}-${attempt}`;
    const candidate = path.join(backupsRoot, leaf);
    try {
      fs.mkdirSync(candidate);
      return candidate;
    } catch (err: unknown) {
      if ((err as NodeJS.ErrnoException)?.code !== 'EEXIST') throw err;
    }
  }
  throw new Error(`could not reserve a free name under ${describe(backupsRoot)} after 64 tries`);
}

/**
 * Give a reservation back when the move it was made for did not happen.
 *
 * Only ever an EMPTY directory this function itself created moments ago:
 * `fs.rmdirSync` fails on a non-empty directory, so a reservation that somehow
 * acquired contents is left standing rather than forced. Nothing here follows
 * a symlink either — `rmdir(2)` operates on the directory named, and a symlink
 * is not one.
 *
 * Residual race, documented rather than papered over (#569 r3): between the
 * exclusive `mkdir` that made the reservation and this call, an arbitrary
 * writer can put something inside our freshly created container. If it does,
 * the release fails and an empty-named-but-not-empty directory is left under
 * `backups/`, which costs nothing and destroys nothing. We do not escalate to
 * a recursive removal: the whole point of this command is that it never
 * removes a directory it did not create, and "I created the container" is not
 * "I created what is now inside it".
 */
export function releaseReservation(reserved: string): void {
  try {
    fs.rmdirSync(reserved);
  } catch {
    /* an unreleased empty directory under backups/ costs nothing */
  }
}

/**
 * The first symlink among the PATH COMPONENTS of `target`, from `base`
 * downwards (#574/#576 r2 blocker 4).
 *
 * `findLinkInTree` above walks the CONTENTS of a directory. That is the wrong
 * question for a write path: a refresh that moves `<hermesHome>/plugins/x`
 * into `<hermesHome>/backups/` follows `plugins` and `backups` themselves, and
 * either of them being a link puts the operator's directory somewhere nobody
 * asked for — on another volume, inside a discovery root, or into a tree this
 * command has no business writing to. The reviewer reproduced exactly that
 * with a symlinked `backups/` and again with a symlinked plugins root.
 *
 * The walk is BOUNDED at `base` on purpose. Checking every component up to `/`
 * would refuse on hosts where `/home` or `/tmp` is legitimately a link, which
 * is a fact about the box and not about this write. `base` is the integration's
 * own root — `<hermesHome>`, `~/.openclaw` — and it is CHECKED TOO: it is the
 * outermost component any of these writes depends on.
 *
 * Three answers, as everywhere on this path: a link (refuse), nothing (proceed),
 * or a component that could not be read (refuse, and say which).
 */
export function findLinkOnPath(base: string, target: string): {
  link: string | null;
  unreadable: { path: string; error: string } | null;
} {
  const from = path.resolve(base);
  const to = path.resolve(target);
  if (!pathContains(from, to)) {
    return { link: null, unreadable: { path: to, error: `is not under ${from}` } };
  }
  const rest = path.relative(from, to);
  const steps = rest === '' ? [] : rest.split(path.sep);
  let cursor = from;
  for (let i = 0; i <= steps.length; i += 1) {
    if (i > 0) cursor = path.join(cursor, steps[i - 1]);
    const answer = lstatAnswer(cursor);
    if ('error' in answer) return { link: null, unreadable: { path: cursor, error: answer.error } };
    // A component that is not there yet cannot be a link, and nothing deeper
    // can exist either: `mkdir -p` will create real directories under it.
    if ('absent' in answer) return { link: null, unreadable: null };
    if (answer.value.isSymbolicLink()) return { link: cursor, unreadable: null };
  }
  return { link: null, unreadable: null };
}

/**
 * Refuse an overlay copy onto a symlink, at the exact path about to be written
 * (#574/#576 r3 blocker 4, second half).
 *
 * Both installers copy the packaged set OVER whatever is at the destination,
 * file by file. `fs.copyFileSync` and `fs.mkdirSync` FOLLOW a link at the
 * destination, so a symlink planted at `plugins/shieldcortex/shadow.py` — or
 * at the plugin directory itself — makes an install truncate a file somewhere
 * else on the box. The reviewer reproduced that with an explicit fake home.
 *
 * This is the file-level counterpart of `findLinkOnPath`, which checks the
 * COMPONENTS of a path; here every leaf the copy will write is checked too.
 * Absence is fine — nothing is there to follow. Unreadable is a refusal, for
 * the reason everything else in this module is: "I could not look" must never
 * become "there is nothing there".
 */
export function refuseLinkedDestination(dest: string): void {
  const answer = lstatAnswer(dest);
  if ('error' in answer) throw new Error(`${dest} could not be read (${answer.error}); nothing written`);
  if ('value' in answer && answer.value.isSymbolicLink()) {
    throw new Error(`${dest} is a symlink; nothing written`);
  }
}
