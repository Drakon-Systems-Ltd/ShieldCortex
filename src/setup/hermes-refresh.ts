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
 * sort AFTER the install and win the key on any gateway that started in that
 * window. The staging directory therefore lives beside the plugins root
 * (`<hermesHome>/.shieldcortex-staging-*`), never inside it, and the install
 * is swapped in with two renames. The old copy is MOVED to
 * `<hermesHome>/backups/`, never deleted — the same rule
 * `--fix-hermes-plugin-copies` follows.
 *
 * ## The crash between the two renames (r4)
 *
 * Two renames means a window in which `plugins/` holds no copy at all, and a
 * `try/catch` cannot close it: the process that would run the `catch` is gone.
 * Round 2 closed that with an on-disk journal the next run read and ACTED ON;
 * round 3 replaced it with "a `backups/` entry plus a missing target means
 * reinstall". Review took both apart (see `host-swap.ts`): the second one
 * cannot tell an interrupted refresh from a deliberate `hermes uninstall`.
 *
 * So this refreshes copies that EXIST and are stale, and nothing else. It
 * never creates a plugin that is absent. A swap that fails after the first
 * rename says so at that moment, naming `shieldcortex hermes install` and the
 * backup it left — see `publishJobs`. Nothing deletes a backup.
 */

import fs from 'fs';
import os from 'os';
import path from 'path';
import { fileURLToPath } from 'url';
import {
  findLinkInTree,
  findLinkOnPath,
  pathContains,
  SYMLINK_PREFLIGHT_ENTRY_BUDGET,
} from './fs-answers.js';
import { acquireUpdateLock, stageAndPublish } from './host-swap.js';
import {
  hermesEnvironment,
  HERMES_PLUGIN_NAME,
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

/**
 * The conventional install path for a given Hermes home — the one
 * `hermes install` writes and the one an operator means by "the plugin".
 * Computed from the home Hermes itself resolved, and from nothing else.
 */
export function standardHermesTarget(hermesHome: string): string {
  return path.join(hermesHome, 'plugins', HERMES_PLUGIN_NAME);
}

/**
 * Is there an installed plugin at this path — not just a directory, but one
 * carrying the manifest Hermes keys on?
 *
 * "The directory exists" is not "the plugin is installed": a partial copy left
 * by a failed install has a `README.md` and no `plugin.yaml`, and treating it
 * as healthy is how a broken host gets walked past. A directory that exists
 * with its manifest but whose bytes are behind the package is a different
 * thing again — that one is STALE, and the ordinary refresh handles it.
 */
export function hermesPluginPresentAt(dir: string): boolean {
  return fs.existsSync(path.join(dir, 'plugin.yaml'));
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
  /** The copies actually rewritten, with where each previous one went. */
  refreshed: Array<{ dir: string; backup: string | null }>;
}

const FIX_POINTER =
  'run `shieldcortex doctor --fix-hermes-plugin-copies`, then `shieldcortex hermes install`';

/** The gateway reads plugins once, at start-up — so say so, and never do it. */
export const HERMES_RESTART_NOTE =
  'restart the Hermes gateway to load it — plugin discovery only re-runs at start-up';

/** What puts a plugin back when this could not. Always the packaged install. */
export const HERMES_REINSTALL_COMMAND = 'run `shieldcortex hermes install`';

function warn(summary: string, detail: string[] = []): HermesRefreshResult {
  return { status: 'warn', summary, detail, refreshed: [] };
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
 * The Hermes tree a write may happen inside, outermost first. Checking from
 * `hermesRoot` covers more components than checking from a profile home inside
 * it, and a bound at `/` would refuse on hosts where `/home` is legitimately a
 * link — a fact about the box, not about this write.
 */
function writeBounds(scan: HermesPluginScan): string[] {
  return [scan.hermesRoot, scan.hermesHome]
    .filter((b): b is string => typeof b === 'string' && b !== '')
    .sort((a, b) => a.length - b.length);
}

/**
 * The whole write path, checked before the first write (r2 blocker 4).
 *
 * `findLinkInTree` walks the CONTENTS of a discovered copy, which is the #569
 * question. It is not the question a WRITE asks: the reviewer symlinked
 * `<hermesHome>/backups` and then the plugins root itself, and the refresh
 * followed both, because neither path is inside a discovered copy. So every
 * component of every path this refresh writes through is checked here, bounded
 * at the Hermes tree. `stageAndPublish` re-checks the three paths it renames,
 * so the SELF-HEAL is covered by construction rather than by remembering to
 * call this first (r3). Returns the refusal reason, or null.
 */
function writePathRefusal(scan: HermesPluginScan, targets: string[]): string | null {
  const bounds = writeBounds(scan);
  for (const target of targets) {
    const base = bounds.find((b) => pathContains(b, target));
    if (base === undefined) {
      return `${target} is outside the Hermes tree this refresh may write in — nothing written ` +
        `(${FIX_POINTER})`;
    }
    const { link, unreadable } = findLinkOnPath(base, target);
    if (unreadable !== null) {
      return `${unreadable.path} could not be read (${unreadable.error}) — nothing written ` +
        `(${FIX_POINTER})`;
    }
    if (link !== null) {
      return `${link} is a symlink — nothing written; a link on the write path puts the copy ` +
        `somewhere nobody asked for (${FIX_POINTER})`;
    }
  }
  return null;
}

/** One existing, stale copy this run will publish the packaged tree over. */
interface RefreshJob {
  /** The destination. Always a copy Hermes reported, never read off disk. */
  dir: string;
  /** The `plugins/` root it sits in. */
  root: string;
}

/**
 * Refresh every installed `shieldcortex` copy Hermes actually loads, or say why
 * nothing was touched. Only ever rewrites a copy that is already there: it
 * never creates an install on a host that does not have one, and never
 * restarts anything.
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
  const now = opts.now ?? new Date();
  let scan: HermesPluginScan;
  try {
    scan = scanHermesPluginCopies(hermesEnvironment(home), opts.scan ?? {});
  } catch (err: unknown) {
    const why = err instanceof Error ? err.message : String(err);
    return warn(`Hermes could not be scanned — ${why}; nothing written`);
  }

  // A tree that could not be read is not an empty one. Ahead of "not detected"
  // for the reason the #569 row puts it there: an EACCES must never be
  // reported as "there is no Hermes here".
  if (scan.undetermined.length > 0) {
    return warn(
      `could not scan every plugin root — nothing written (${FIX_POINTER})`,
      [undeterminedSummary(scan.undetermined)],
    );
  }
  if (!scan.present) {
    return { status: 'not-installed', summary: 'Hermes not detected', detail: [], refreshed: [] };
  }

  const backupsRoot = path.join(scan.hermesHome, 'backups');

  // Without Hermes' own discovery there is no answer to the only question that
  // makes a write safe: which copy does the gateway load (#569 r4). A host with
  // no copy at the conventional path is simply not installed, and saying so is
  // quieter and just as true as a warning nobody can act on.
  if (!scan.fromHermes) {
    if (!hermesPluginPresentAt(standardHermesTarget(scan.hermesHome))) {
      return { status: 'not-installed', summary: 'Hermes plugin not installed', detail: [], refreshed: [] };
    }
    return warn(
      `could not determine which copy Hermes loads — nothing written (${FIX_POINTER})`,
      [scan.undeterminedReason ?? 'reason unrecorded'],
    );
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
    return warn(`${what} — nothing written (${FIX_POINTER})`);
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
    return { status: 'not-installed', summary: 'Hermes plugin not installed', detail: [], refreshed: [] };
  }

  // A copy that fails byte-verification is REFRESHED by the ordinary path; it
  // is never treated as healthy just because the directory is there.
  const stale = targets.filter((t) => hermesPluginCopyStale(t.dir, sourceDir).stale);
  if (stale.length === 0) {
    if (!hermesPluginCopyStale(targets[0].dir, sourceDir).comparable) {
      return warn('packaged Hermes plugin source not found — nothing to compare against');
    }
    return {
      status: 'current',
      summary: `current (${targets.length} cop${targets.length === 1 ? 'y' : 'ies'})`,
      detail: [],
      refreshed: [],
    };
  }

  const jobs: RefreshJob[] = stale.map((t) => ({ dir: t.dir, root: t.root }));

  const stamp = now.toISOString().replace(/[:.]/g, '-');

  // Every path about to be written through, and every path the staging trees
  // will live under. Checked as ONE preflight, before the first write, because
  // a refusal after a partial write is not a refusal.
  const refusal = writePathRefusal(scan, [
    backupsRoot,
    ...jobs.map((j) => j.root),
    ...jobs.map((j) => j.dir),
    ...jobs.map((j) => path.dirname(j.root)),
  ]);
  if (refusal !== null) return warn(refusal);

  // Staging and backups must be outside EVERY root Hermes discovers, not only
  // the one being refreshed: a `backups/` inside a sibling profile's plugins
  // root would be a shadowing copy the moment the old install landed in it.
  const roots = discoveryRoots(scan);
  for (const outside of [backupsRoot, ...jobs.map((j) => path.dirname(j.root))]) {
    const inside = roots.find((root) => pathContains(root, outside));
    if (inside !== undefined) {
      return warn(
        `${outside} is inside the plugin root ${inside} — nothing written; anything there is a ` +
        `copy Hermes can load (${FIX_POINTER})`,
      );
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
      return warn(`${unreadable.path} could not be read (${unreadable.error}) — nothing written (${FIX_POINTER})`);
    }
    if (link !== null) {
      return warn(
        `${link} is a symlink — nothing written; a link in a discovered copy can be what another ` +
        `plugin root loads through (${FIX_POINTER})`,
      );
    }
    if (exhausted) {
      return warn(
        `${dir} could not be checked for symlinks (more than ${SYMLINK_PREFLIGHT_ENTRY_BUDGET} ` +
        'entries) — nothing written',
      );
    }
  }

  // One writer per integration root. `hermes install` takes the same lock, so
  // two commands can never interleave their renames over one plugins tree.
  // Bounded at the Hermes tree, so a symlinked home or profile root is refused
  // before the lock file itself is created (r3 blocker 4).
  const acquired = acquireUpdateLock(scan.hermesHome, { now, bound: writeBounds(scan)[0] });
  if ('busy' in acquired) return warn(`${acquired.busy} — nothing written`);
  try {
    return publishJobs({ jobs, scan, sourceDir, backupsRoot, stamp });
  } finally {
    acquired.lock.release();
  }
}

/** The write half, run under the root's lock and nowhere else. */
function publishJobs(params: {
  jobs: RefreshJob[];
  scan: HermesPluginScan;
  sourceDir: string;
  backupsRoot: string;
  stamp: string;
}): HermesRefreshResult {
  const { jobs, scan, sourceDir, backupsRoot, stamp } = params;
  const bound = writeBounds(scan)[0] ?? scan.hermesHome;
  const refreshed: Array<{ dir: string; backup: string | null }> = [];
  const detail: string[] = [];

  for (const job of jobs) {
    const outcome = stageAndPublish({
      bound,
      target: job.dir,
      // Beside the plugins root, never inside it: a staged `plugin.yaml` under
      // `plugins/` IS a shadowing copy for as long as it exists (#569).
      stagingParent: path.dirname(job.root),
      backupsRoot,
      stamp,
      stagingPrefix: '.shieldcortex-staging',
      backupPrefix: HERMES_PLUGIN_NAME,
      stage: (staged) => copyPluginTree(sourceDir, staged),
      verify: (staged) => {
        const verdict = hermesPluginCopyStale(staged, sourceDir);
        if (!verdict.comparable) return 'the packaged source could not be read';
        return verdict.stale ? (verdict.reason ?? 'it differs from the package') : null;
      },
      reinstallCommand: `${HERMES_REINSTALL_COMMAND} by hand`,
    });
    detail.push(...outcome.unsynced.map((line) => `${job.dir}: ${line}`));
    if (outcome.ok) {
      refreshed.push({ dir: job.dir, backup: outcome.backup });
      continue;
    }
    detail.push(outcome.targetMissing
      ? `${job.dir}: the new copy could not be swapped in — ${outcome.error}, AND the previous ` +
        `copy could not be restored; it is at ${outcome.backup}. ${HERMES_REINSTALL_COMMAND} to ` +
        'put the packaged plugin back'
      : `${job.dir}: ${outcome.error}`);
  }

  if (refreshed.length === 0) {
    return warn(`could not refresh ${jobs.length} cop${jobs.length === 1 ? 'y' : 'ies'}`, detail);
  }
  const partial = refreshed.length < jobs.length;
  return {
    status: partial ? 'warn' : 'refreshed',
    summary: (partial
      ? `refreshed ${refreshed.length} of ${jobs.length} copies`
      : `refreshed ${refreshed.length} cop${refreshed.length === 1 ? 'y' : 'ies'}`
    ) + ` — ${HERMES_RESTART_NOTE}`,
    detail: [
      ...refreshed.map((r) => `${r.dir} refreshed; previous copy kept at ${r.backup}`),
      ...detail,
    ],
    refreshed,
  };
}
