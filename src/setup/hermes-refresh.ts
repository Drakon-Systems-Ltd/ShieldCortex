/**
 * ShieldCortex — refreshing the INSTALLED Hermes plugin copy (#576).
 *
 * `~/.hermes/plugins/shieldcortex` is a FILE COPY (see `installHermes`), so
 * upgrading the npm package moves the packaged source and leaves the copy
 * Hermes loads on the previous release. Observed on 5.1.0 → 5.2.0: `__init__.py`
 * differed and `shadow.py` was not there at all, so the gateway kept running
 * the old `pre_tool_call` gate until somebody ran `shieldcortex hermes install`
 * by hand.
 *
 * Two jobs live here, and `update` and `doctor` share both of them so they can
 * never disagree about the same host:
 *
 *   - `hermesPluginCopyStale` — is the installed copy behind the packaged one?
 *   - `refreshHermesPluginCopies` — bring it forward, or say why it was left
 *     alone.
 *
 * ## What may be written, and when
 *
 * Only a copy that ALREADY EXISTS, only the one Hermes itself says it loads,
 * and only when Hermes' own discovery answered completely and cleanly. A scan
 * that is undetermined, has a hole in it, holds shadowing copies, meets a
 * symlink anywhere in a discovered plugin directory, or has project plugins in
 * play writes NOTHING and points at `doctor --fix-hermes-plugin-copies`. The
 * question "which copy does the gateway load" is the whole basis for touching
 * anything, and #569 is the standing proof that guessing it is worse than
 * leaving the host alone.
 *
 * ## Why the new bytes are staged OUTSIDE `plugins/`
 *
 * A directory under a plugins root that holds a `plugin.yaml` declaring
 * `name: shieldcortex` IS a shadowing copy — that is #569 exactly. So a
 * half-written `plugins/shieldcortex.new/` would, for as long as it existed,
 * be a copy that sorts AFTER the install and wins the key on any gateway that
 * started in that window. The staging directory therefore lives beside the
 * plugins root (`<hermesHome>/.shieldcortex-staging-*`), never inside it, and
 * the install is swapped in with two renames.
 *
 * The old copy is MOVED to `<hermesHome>/backups/`, never deleted — the same
 * rule `--fix-hermes-plugin-copies` follows. If the second rename fails, the
 * backup is renamed back and the failure is reported with both paths.
 *
 * ## Why the swap is JOURNALLED (r2 blocker 1)
 *
 * Two renames means a window in which `plugins/` holds no copy at all, and a
 * `try/catch` cannot close it: a SIGKILL or a power cut there leaves the host
 * with nothing to load and the next `update` reporting "Hermes plugin not
 * installed". Node has no atomic directory exchange to reach for — there is no
 * `renameat2(RENAME_EXCHANGE)` binding — so the swap records a durable journal
 * at `<hermesHome>/.shieldcortex-refresh-journal.json` (outside every plugins
 * root) before the first rename, and `recoverInterruptedSwap` finishes the job
 * on the next run. See `swap-journal.ts` for the recovery rule and why
 * restoring the previous copy is the default.
 */

import fs from 'fs';
import os from 'os';
import path from 'path';
import { fileURLToPath } from 'url';
import {
  deviceUnder,
  findLinkInTree,
  findLinkOnPath,
  lstatAnswer,
  pathContains,
  releaseReservation,
  reserveBackupDir,
  SYMLINK_PREFLIGHT_ENTRY_BUDGET,
} from './fs-answers.js';
import {
  journalledSwap,
  journalPath,
  recoverInterruptedSwap,
  type RecoveryOutcome,
} from './swap-journal.js';
import {
  hermesEnvironment,
  protectedDirs,
  scanHermesPluginCopies,
  undeterminedSummary,
  type HermesPluginScan,
  type HermesScanOptions,
} from './hermes-plugins.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

/**
 * Directory names the installer never copies, and which therefore can never be
 * evidence of staleness. `tests/` ships in the package and is deliberately left
 * out of the install; `__pycache__` / `.pytest_cache` are produced by whatever
 * ran the plugin. Exported so `copyDir` in hermes.ts and the comparator here
 * are one rule and not two (#576).
 */
export const HERMES_UNCOPIED_DIRS: ReadonlySet<string> = new Set([
  '__pycache__',
  '.pytest_cache',
  'tests',
]);

/** dist/setup/hermes-refresh.js → package root / plugins/hermes/shieldcortex */
export function hermesPluginSourceDir(): string {
  return path.resolve(__dirname, '..', '..', 'plugins', 'hermes', 'shieldcortex');
}

/** Every file the installer would copy, as paths relative to `dir`, sorted. */
function copiedFiles(dir: string, prefix = ''): string[] {
  const out: string[] = [];
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    if (HERMES_UNCOPIED_DIRS.has(entry.name)) continue;
    const rel = prefix === '' ? entry.name : `${prefix}/${entry.name}`;
    if (entry.isDirectory()) out.push(...copiedFiles(path.join(dir, entry.name), rel));
    else out.push(rel);
  }
  return out.sort();
}

export interface HermesCopyStaleness {
  /** True when the installed copy is missing a packaged file or differs from one. */
  stale: boolean;
  /**
   * False when the PACKAGED source could not be read — a partial package, or a
   * layout that has no `plugins/hermes` at all. `stale` is then false, for the
   * same reason `hookFilesStale` says false there: nothing can be proven behind
   * a source nobody can read, and "refresh needed" would be unactionable.
   */
  comparable: boolean;
  /** The first difference, in an operator's words. Null when not stale. */
  reason: string | null;
  /** How many packaged files are missing from, or differ in, the installed copy. */
  differing: number;
}

/**
 * Is the installed Hermes plugin copy behind the packaged one?
 *
 * Compares exactly the set `installHermes` copies — every packaged file except
 * `tests/`, `__pycache__/` and `.pytest_cache/` — byte for byte. The single
 * source of truth for both `update`'s refresh step and `doctor`'s row, the same
 * way `hookFilesStale` is for the OpenClaw hook (#574).
 *
 * Files present in the INSTALLED copy but not in the package are deliberately
 * NOT staleness. The installer overlays rather than replaces, so anything a
 * gateway or an operator left in that directory would otherwise make every
 * `doctor` run warn and every `update` re-copy — a refresh loop over a host
 * that is already current. (A refresh does relocate them with the old copy into
 * `backups/`; nothing is deleted.)
 *
 * On an unreadable file it answers STALE, matching `hookFilesStale`: a
 * half-readable install is never reported as current.
 */
export function hermesPluginCopyStale(
  installedDir: string,
  sourceDir: string = hermesPluginSourceDir(),
): HermesCopyStaleness {
  let expected: string[];
  try {
    if (!fs.existsSync(path.join(sourceDir, 'plugin.yaml'))) {
      return { stale: false, comparable: false, reason: null, differing: 0 };
    }
    expected = copiedFiles(sourceDir);
  } catch {
    return { stale: false, comparable: false, reason: null, differing: 0 };
  }

  let differing = 0;
  let reason: string | null = null;
  for (const rel of expected) {
    const src = path.join(sourceDir, ...rel.split('/'));
    const dest = path.join(installedDir, ...rel.split('/'));
    let why: string | null = null;
    try {
      if (!fs.existsSync(dest)) why = `${rel} is missing`;
      else if (!fs.readFileSync(src).equals(fs.readFileSync(dest))) why = `${rel} differs`;
    } catch (err: unknown) {
      why = `${rel} could not be read (${(err as NodeJS.ErrnoException)?.code ?? 'error'})`;
    }
    if (why !== null) {
      differing += 1;
      reason ??= why;
    }
  }
  return { stale: differing > 0, comparable: true, reason, differing };
}

/** Copy `src` into `dest`, skipping exactly what the installer skips. */
function copyPluginTree(src: string, dest: string): void {
  fs.mkdirSync(dest, { recursive: true });
  for (const entry of fs.readdirSync(src, { withFileTypes: true })) {
    if (HERMES_UNCOPIED_DIRS.has(entry.name)) continue;
    const from = path.join(src, entry.name);
    const to = path.join(dest, entry.name);
    if (entry.isDirectory()) copyPluginTree(from, to);
    else fs.copyFileSync(from, to);
  }
}

export type HermesRefreshStatus = 'refreshed' | 'current' | 'not-installed' | 'warn';

export interface HermesRefreshResult {
  status: HermesRefreshStatus;
  /** One line, for the `update` step and nothing else. */
  summary: string;
  /** Extra lines printed under the step: backup paths, refusal detail. */
  detail: string[];
  /** The copies actually rewritten, with where the previous one went. */
  refreshed: Array<{ dir: string; backup: string }>;
}

const FIX_POINTER =
  'run `shieldcortex doctor --fix-hermes-plugin-copies`, then `shieldcortex hermes install`';

/** The gateway reads plugins once, at start-up — so say so, and never do it. */
export const HERMES_RESTART_NOTE =
  'restart the Hermes gateway to load it — plugin discovery only re-runs at start-up';

/** What finishes an interrupted refresh. Printed wherever one is left behind. */
export const HERMES_RECOVERY_COMMAND =
  'run `shieldcortex update` (or `shieldcortex hermes install`) to finish it';

function warn(summary: string, detail: string[] = []): HermesRefreshResult {
  return { status: 'warn', summary, detail, refreshed: [] };
}

/** The package version the staged bytes came from — recorded in the journal. */
function packagedVersion(): string {
  try {
    const pkg = path.resolve(__dirname, '..', '..', 'package.json');
    const parsed = JSON.parse(fs.readFileSync(pkg, 'utf-8')) as { version?: unknown };
    return typeof parsed.version === 'string' ? parsed.version : 'unknown';
  } catch {
    return 'unknown';
  }
}

/**
 * Finish an interrupted Hermes plugin swap, if one is recorded at
 * `<hermesHome>`.
 *
 * Exported because three surfaces have to agree about it: `update`'s refresh
 * step runs it before anything else, `shieldcortex hermes install` runs it so
 * the documented manual remedy is also the recovery, and doctor REPORTS an
 * unresolved journal without touching it (doctor repairs only under an
 * explicit `--fix-*` flag).
 *
 * The completeness predicate is the same comparator everything else here uses:
 * a staged tree may be published only when it is byte-identical to the
 * packaged source, over exactly the file set `hermes install` copies.
 */
export function recoverHermesRefresh(
  hermesHome: string,
  sourceDir: string = hermesPluginSourceDir(),
): RecoveryOutcome {
  return recoverInterruptedSwap(hermesHome, {
    stagedIsComplete: (staged) => {
      const verdict = hermesPluginCopyStale(staged, sourceDir);
      return verdict.comparable && !verdict.stale;
    },
  });
}

/**
 * Every root Hermes discovers plugins in, for the containment proof below.
 * The project directory counts when it is enabled: a `backups/` that landed
 * inside it would be loaded as a project plugin, which outranks every install.
 */
function discoveryRoots(scan: HermesPluginScan): string[] {
  const roots = scan.roots.map((r) => r.root);
  if (scan.project.enabled && scan.project.dir !== null) roots.push(scan.project.dir);
  return roots;
}

/**
 * The whole write path, checked before the first write (r2 blocker 4).
 *
 * The round-1 preflight walked the CONTENTS of every discovered plugin
 * directory, which is the #569 question ("could this copy be what another root
 * resolves through"). It is not the question a WRITE asks. The reviewer
 * symlinked `<hermesHome>/backups` at another directory and symlinked the
 * plugins root itself, and the refresh followed both: neither path was ever
 * lstat'd, because neither is inside a discovered copy.
 *
 * So every component of every path this refresh writes through — the plugins
 * root and its ancestors, the target, `backups/`, the staging parent, and the
 * directory the journal lives in — is checked here, bounded at the Hermes tree
 * (`hermesRoot` when Hermes named one, else `hermesHome`) so a host whose
 * `/home` is legitimately a link is not refused for a fact about the box.
 *
 * Returns the refusal reason, or null when the path is clean.
 */
function writePathRefusal(scan: HermesPluginScan, targets: string[]): string | null {
  const bounds = [scan.hermesRoot, scan.hermesHome]
    .filter((b): b is string => typeof b === 'string' && b !== '')
    // Outermost first: checking from `hermesRoot` covers more components than
    // checking from a profile home inside it.
    .sort((a, b) => a.length - b.length);
  for (const target of targets) {
    const base = bounds.find((b) => pathContains(b, target));
    if (base === undefined) {
      return `${target} is outside the Hermes tree this refresh may write in`;
    }
    const { link, unreadable } = findLinkOnPath(base, target);
    if (unreadable !== null) return `${unreadable.path} could not be read (${unreadable.error})`;
    if (link !== null) return `${link} is a symlink`;
  }
  return null;
}

/**
 * Refresh every installed `shieldcortex` copy Hermes actually loads, or say why
 * none was touched. Never creates an install that was not already there, and
 * never restarts anything.
 *
 * `now` is a test seam for the backup/staging stamp; production passes the
 * current time.
 */
export function refreshHermesPluginCopies(
  home: string = os.homedir(),
  opts: {
    now?: Date;
    scan?: HermesScanOptions;
    sourceDir?: string;
  } = {},
): HermesRefreshResult {
  const sourceDir = opts.sourceDir ?? hermesPluginSourceDir();
  const rescan = (): HermesPluginScan | string => {
    try {
      return scanHermesPluginCopies(hermesEnvironment(home), opts.scan ?? {});
    } catch (err: unknown) {
      return err instanceof Error ? err.message : String(err);
    }
  };
  const firstScan = rescan();
  if (typeof firstScan === 'string') {
    return warn(`Hermes could not be scanned — ${firstScan}; nothing written`);
  }
  let scan = firstScan;

  // FIRST, before any judgement about what is installed: finish a refresh a
  // crash interrupted. Without this the host that most needs help — the one
  // whose `plugins/shieldcortex` is missing because the process died between
  // the two renames — reads as "not installed" and is walked straight past.
  const recovery = recoverHermesRefresh(scan.hermesHome, sourceDir);
  if (recovery.status === 'blocked') {
    return warn(
      `an interrupted Hermes plugin refresh could not be finished — nothing written (${FIX_POINTER})`,
      recovery.detail,
    );
  }
  if (recovery.status === 'restored' || recovery.status === 'published') {
    const again = rescan();
    if (typeof again === 'string') {
      return {
        status: 'warn',
        summary: `Hermes could not be re-scanned after recovery — ${again}`,
        detail: recovery.detail,
        refreshed: [],
      };
    }
    scan = again;
  }
  // Carried onto whatever this run concludes, so a recovery is never silent.
  const carried = recovery.detail;
  const withCarried = (result: HermesRefreshResult): HermesRefreshResult =>
    carried.length === 0 ? result : { ...result, detail: [...carried, ...result.detail] };

  // A tree that could not be read is not an empty one. Ahead of "not detected"
  // for the reason the #569 row puts it there: an EACCES must never be
  // reported as "there is no Hermes here".
  if (scan.undetermined.length > 0) {
    return withCarried(warn(
      `could not scan every plugin root — nothing written (${FIX_POINTER})`,
      [undeterminedSummary(scan.undetermined)],
    ));
  }
  if (!scan.present) {
    return withCarried({ status: 'not-installed', summary: 'Hermes not detected', detail: [], refreshed: [] });
  }

  // Without Hermes' own discovery there is no answer to the only question that
  // makes a write safe: which copy does the gateway load (#569 r4). A host with
  // no copy at the conventional path is simply not installed, and saying so is
  // quieter and just as true as a warning nobody can act on.
  if (!scan.fromHermes) {
    const conventional = path.join(scan.hermesHome, 'plugins', 'shieldcortex', 'plugin.yaml');
    if (!fs.existsSync(conventional)) {
      return withCarried({ status: 'not-installed', summary: 'Hermes plugin not installed', detail: [], refreshed: [] });
    }
    return withCarried(warn(
      `could not determine which copy Hermes loads — nothing written (${FIX_POINTER})`,
      [scan.undeterminedReason ?? 'reason unrecorded'],
    ));
  }

  // Shadowing copies and project plugins both mean the copy the gateway loads
  // is not the one this would write, or is not ours to decide. Neither is
  // repaired here: `update` refreshes an install, it does not adjudicate a
  // layout (#569).
  const projectCopies = scan.project.enabled ? scan.project.copies : [];
  if (scan.shadowed || projectCopies.length > 0) {
    const what = projectCopies.length > 0
      ? `a project plugin copy (${projectCopies[projectCopies.length - 1].dir}) outranks every installed copy`
      : `shadowing copies are present (${scan.copies.map((c) => c.dir).join(', ')})`;
    // No restart note on a refusal: nothing was written, so there is nothing
    // new for a restart to load, and saying otherwise sends an operator to
    // bounce a gateway for no reason. The commands named above print their own.
    return withCarried(warn(`${what} — nothing written (${FIX_POINTER})`));
  }

  // The copy Hermes loads for each root, and nothing else: `effective` is the
  // winner once the project source is taken into account, and a root without
  // one holds no install to refresh.
  const targets: Array<{ dir: string; root: string }> = [];
  const seen = new Set<string>();
  for (const rootScan of scan.roots) {
    const winner = rootScan.effective;
    if (winner === null || winner.source !== 'user') continue;
    if (seen.has(winner.dir)) continue;
    seen.add(winner.dir);
    targets.push({ dir: winner.dir, root: rootScan.root });
  }
  if (targets.length === 0) {
    return withCarried({ status: 'not-installed', summary: 'Hermes plugin not installed', detail: [], refreshed: [] });
  }

  const stale = targets.filter((t) => hermesPluginCopyStale(t.dir, sourceDir).stale);
  if (stale.length === 0) {
    const comparable = hermesPluginCopyStale(targets[0].dir, sourceDir).comparable;
    if (!comparable) {
      return withCarried(warn('packaged Hermes plugin source not found — nothing to compare against'));
    }
    return withCarried({
      status: 'current',
      summary: `current (${targets.length} cop${targets.length === 1 ? 'y' : 'ies'})`,
      detail: [],
      refreshed: [],
    });
  }

  const stamp = (opts.now ?? new Date()).toISOString().replace(/[:.]/g, '-');
  const backupsRoot = path.join(scan.hermesHome, 'backups');
  const journalRoot = scan.hermesHome;

  // Every path about to be written through, and every path the journal and the
  // staging trees will live under. Checked as ONE preflight, before the first
  // write, because a refusal after a partial write is not a refusal.
  const writePaths = [
    backupsRoot,
    journalRoot,
    ...stale.map((t) => t.root),
    ...stale.map((t) => t.dir),
    ...stale.map((t) => path.dirname(t.root)),
  ];
  const refusal = writePathRefusal(scan, writePaths);
  if (refusal !== null) {
    return withCarried(warn(
      `${refusal} — nothing written; a link on the write path puts the copy somewhere nobody ` +
      `asked for (${FIX_POINTER})`,
    ));
  }

  // Staging and backups must be outside EVERY root Hermes discovers, not only
  // the one being refreshed: a `backups/` inside a sibling profile's plugins
  // root would be a shadowing copy the moment the old install landed in it.
  const roots = discoveryRoots(scan);
  for (const outside of [backupsRoot, journalPath(journalRoot), ...stale.map((t) => path.dirname(t.root))]) {
    const inside = roots.find((root) => pathContains(root, outside));
    if (inside !== undefined) {
      return withCarried(warn(
        `${outside} is inside the plugin root ${inside} — nothing written; anything there is a ` +
        `copy Hermes can load (${FIX_POINTER})`,
      ));
    }
  }

  // A link ANYWHERE in a discovered plugin directory stops the whole refresh,
  // exactly as it stops the #569 repair: the copy about to be moved into
  // `backups/` can be what another root resolves through, and the walk is the
  // only thing that can tell.
  const budget = { left: SYMLINK_PREFLIGHT_ENTRY_BUDGET };
  for (const dir of protectedDirs(scan)) {
    const { link, exhausted, unreadable } = findLinkInTree(dir, budget);
    if (unreadable !== null) {
      return withCarried(warn(
        `${unreadable.path} could not be read (${unreadable.error}) — nothing written (${FIX_POINTER})`,
      ));
    }
    if (link !== null) {
      return withCarried(warn(
        `${link} is a symlink — nothing written; a link in a discovered copy can be what another ` +
        `plugin root loads through (${FIX_POINTER})`,
      ));
    }
    if (exhausted) {
      return withCarried(warn(
        `${dir} could not be checked for symlinks (more than ${SYMLINK_PREFLIGHT_ENTRY_BUDGET} ` +
        'entries) — nothing written',
      ));
    }
  }

  const version = packagedVersion();
  const refreshed: Array<{ dir: string; backup: string }> = [];
  const detail: string[] = [];

  for (const target of stale) {
    // Beside the plugins root, never inside it: a staged `plugin.yaml` under
    // `plugins/` IS a shadowing copy while it exists (#569).
    const stagingParent = path.dirname(target.root);
    let staging: string;
    try {
      staging = reserveBackupDir(stagingParent, `.shieldcortex-staging-${stamp}`);
    } catch (err: unknown) {
      const msg = err instanceof Error ? err.message : String(err);
      detail.push(`${target.dir}: could not stage the new copy — ${msg}; left in place`);
      continue;
    }
    const staged = path.join(staging, path.basename(target.dir));
    // Only ever a directory this run created moments ago, and only ever when
    // the swap it was made for did not happen.
    const cleanupStaging = (): void => {
      try {
        fs.rmSync(staging, { recursive: true, force: true });
      } catch { /* our own staging dir; a leftover costs nothing */ }
    };
    try {
      copyPluginTree(sourceDir, staged);
    } catch (err: unknown) {
      cleanupStaging();
      const msg = err instanceof Error ? err.message : String(err);
      detail.push(`${target.dir}: could not stage the new copy — ${msg}; left in place`);
      continue;
    }

    // Nothing is published that has not been proved complete first. The same
    // comparator that decided the install was stale decides that the staged
    // replacement is whole — a half-copied tree must never become the copy the
    // gateway loads.
    const stagedVerdict = hermesPluginCopyStale(staged, sourceDir);
    if (!stagedVerdict.comparable || stagedVerdict.stale) {
      cleanupStaging();
      detail.push(
        `${target.dir}: the staged copy did not verify against the packaged source ` +
        `(${stagedVerdict.reason ?? 'source unreadable'}); left in place`,
      );
      continue;
    }

    // `rename(2)` refuses to cross a filesystem, and this never turns a move
    // into a copy-then-delete of the operator's directory. Both hops are
    // checked before the first one runs.
    const destDevice = deviceUnder(backupsRoot);
    const sourceStat = lstatAnswer(target.dir);
    const stagedDevice = deviceUnder(staged);
    if ('error' in destDevice || 'error' in sourceStat || 'error' in stagedDevice) {
      cleanupStaging();
      detail.push(`${target.dir}: could not stat the move endpoints; left in place`);
      continue;
    }
    if ('absent' in sourceStat) {
      cleanupStaging();
      detail.push(`${target.dir}: disappeared while refreshing; left alone`);
      continue;
    }
    if (
      ('value' in destDevice && sourceStat.value.dev !== destDevice.value) ||
      ('value' in stagedDevice && stagedDevice.value !== sourceStat.value.dev)
    ) {
      cleanupStaging();
      detail.push(
        `${target.dir}: is on a different filesystem from ${backupsRoot} (EXDEV) — a ` +
        'cross-filesystem move is a copy followed by a delete of the original, which this ' +
        'never does; refresh it by hand with `shieldcortex hermes install`',
      );
      continue;
    }

    let reserved: string;
    try {
      reserved = reserveBackupDir(backupsRoot, `shieldcortex-preupdate-${stamp}`);
    } catch (err: unknown) {
      cleanupStaging();
      const msg = err instanceof Error ? err.message : String(err);
      detail.push(`${target.dir}: no backup destination could be reserved under ${backupsRoot} — ${msg}`);
      continue;
    }
    const backup = path.join(reserved, path.basename(target.dir));

    const outcome = journalledSwap({
      kind: 'hermes-plugin',
      root: journalRoot,
      target: target.dir,
      backup,
      staged,
      stagingRoot: staging,
      packagedVersion: version,
      now: opts.now ?? new Date(),
    });
    if (outcome.ok) {
      refreshed.push({ dir: target.dir, backup });
      continue;
    }
    if (outcome.targetMissing) {
      // The one state nothing may be cleaned up after: the host has no plugin
      // directory, and the staged copy plus the journal beside it are what the
      // next run recovers from. Deleting either would destroy the recovery.
      detail.push(
        `${target.dir}: the new copy could not be swapped in — ${outcome.error}, AND the previous ` +
        `copy could not be restored; it is at ${backup}. The staged replacement and the refresh ` +
        `journal (${journalPath(journalRoot)}) were LEFT for recovery — ${HERMES_RECOVERY_COMMAND}`,
      );
      continue;
    }
    releaseReservation(reserved);
    cleanupStaging();
    detail.push(
      outcome.stage === 'publishing'
        ? `${target.dir}: the new copy could not be swapped in — ${outcome.error}; the previous copy was restored`
        : `${target.dir}: ${outcome.error}; left in place`,
    );
  }

  if (refreshed.length === 0) {
    return withCarried(warn(
      `could not refresh ${stale.length} stale cop${stale.length === 1 ? 'y' : 'ies'}`,
      detail,
    ));
  }
  const partial = detail.length > 0;
  return withCarried({
    status: partial ? 'warn' : 'refreshed',
    summary: partial
      ? `refreshed ${refreshed.length} of ${stale.length} stale copies — ${HERMES_RESTART_NOTE}`
      : `refreshed ${refreshed.length} cop${refreshed.length === 1 ? 'y' : 'ies'} — ${HERMES_RESTART_NOTE}`,
    detail: [
      ...refreshed.map((r) => `${r.dir} refreshed; previous copy kept at ${r.backup}`),
      ...detail,
    ],
    refreshed,
  });
}
