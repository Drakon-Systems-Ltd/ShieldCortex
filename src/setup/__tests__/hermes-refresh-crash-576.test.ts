import fs from 'fs';
import os from 'os';
import path from 'path';
import { afterEach, beforeEach, describe, expect, it, jest } from '@jest/globals';
import {
  hermesPluginCopyStale,
  hermesPluginSourceDir,
  refreshHermesPluginCopies,
} from '../hermes-refresh.js';
import { probeHermesDiscovery } from '../hermes-plugins.js';
import { installHermes, uninstallHermes } from '../hermes.js';
import { updateLockPath } from '../host-swap.js';

/**
 * #574 / #576 round 4 — the crash between the two renames, and the two ways
 * earlier rounds tried to finish somebody else's swap.
 *
 * Round 2 recorded `{target, backup, staged}` in
 * `<hermesHome>/.shieldcortex-refresh-journal.json` and let the next run MOVE
 * THE PATHS IT NAMED. Round 3 dropped the journal but kept the healing, keyed
 * on "the standard target has no `plugin.yaml` AND one of our own swaps left a
 * `backups/…-preupdate-*`" — a predicate the ordinary sequence refresh →
 * `hermes uninstall` satisfies exactly, so `update` reinstalled the plugin an
 * operator had just removed.
 *
 * So there is no healing either. A refresh rewrites copies that EXIST and are
 * stale; a swap that dies after the first rename SAYS SO at that moment, with
 * the backup path and `shieldcortex hermes install` in the same sentence, and
 * the next run leaves the host exactly as it found it.
 *
 * Every case is a fake home under a temp dir. The real `~/.hermes` is never
 * read or written; `HERMES_HOME` and `HERMES_ENABLE_PROJECT_PLUGINS` are
 * scrubbed per test.
 */
let home: string;
let hermes: string;
let plugins: string;
let installed: string;
let elsewhere: string;
const savedHermesHome = process.env.HERMES_HOME;
const savedProjectPlugins = process.env.HERMES_ENABLE_PROJECT_PLUGINS;
const SOURCE = hermesPluginSourceDir();
const FROZEN = new Date('2026-09-24T12:34:56.789Z');
const STAMP = '2026-09-24T12-34-56-789Z';
const JOURNAL = '.shieldcortex-refresh-journal.json';

beforeEach(() => {
  home = fs.mkdtempSync(path.join(os.tmpdir(), 'sc-hermes-crash-'));
  elsewhere = fs.mkdtempSync(path.join(os.tmpdir(), 'sc-hermes-elsewhere-'));
  hermes = path.join(home, '.hermes');
  plugins = path.join(hermes, 'plugins');
  installed = path.join(plugins, 'shieldcortex');
  fs.mkdirSync(plugins, { recursive: true });
  delete process.env.HERMES_HOME;
  delete process.env.HERMES_ENABLE_PROJECT_PLUGINS;
});

afterEach(() => {
  jest.restoreAllMocks();
  fs.rmSync(home, { recursive: true, force: true });
  fs.rmSync(elsewhere, { recursive: true, force: true });
  if (savedHermesHome === undefined) delete process.env.HERMES_HOME;
  else process.env.HERMES_HOME = savedHermesHome;
  if (savedProjectPlugins === undefined) delete process.env.HERMES_ENABLE_PROJECT_PLUGINS;
  else process.env.HERMES_ENABLE_PROJECT_PLUGINS = savedProjectPlugins;
});

function installCopy(dest: string = installed): void {
  fs.cpSync(SOURCE, dest, {
    recursive: true,
    filter: (src) => !['tests', '__pycache__', '.pytest_cache'].includes(path.basename(src)),
  });
}

function makeStale(dir: string = installed): void {
  fs.writeFileSync(path.join(dir, '__init__.py'), '# shieldcortex 5.1.0\n');
  fs.rmSync(path.join(dir, 'shadow.py'), { force: true });
}

/** Every path under `root`, relative and sorted — a whole-tree fingerprint. */
function treeOf(root: string): string[] {
  const out: string[] = [];
  const walk = (dir: string, prefix: string): void => {
    for (const entry of fs.readdirSync(dir, { withFileTypes: true }).sort((a, b) => a.name.localeCompare(b.name))) {
      const rel = prefix === '' ? entry.name : `${prefix}/${entry.name}`;
      if (entry.isSymbolicLink()) out.push(`${rel} -> ${fs.readlinkSync(path.join(dir, entry.name))}`);
      else if (entry.isDirectory()) { out.push(`${rel}/`); walk(path.join(dir, entry.name), rel); }
      else out.push(`${rel} ${fs.readFileSync(path.join(dir, entry.name), 'utf-8')}`);
    }
  };
  walk(root, '');
  return out;
}

/**
 * How many directories under a plugins root Hermes would key `shieldcortex` —
 * the #569 count that must never exceed one, at any moment of a refresh.
 */
function shieldcortexDirsIn(root: string): string[] {
  if (!fs.existsSync(root)) return [];
  return fs.readdirSync(root, { withFileTypes: true })
    .filter((e) => e.isDirectory())
    .filter((e) => {
      try {
        return /^name:\s*shieldcortex\s*$/m.test(
          fs.readFileSync(path.join(root, e.name, 'plugin.yaml'), 'utf-8'),
        );
      } catch {
        return false;
      }
    })
    .map((e) => e.name);
}

const HAS_HERMES = (() => {
  const probeDir = fs.mkdtempSync(path.join(os.tmpdir(), 'sc-hermes-probe-'));
  try {
    fs.mkdirSync(path.join(probeDir, '.hermes', 'plugins'), { recursive: true });
    return 'roots' in probeHermesDiscovery({ home: probeDir, hermesHome: null });
  } finally {
    fs.rmSync(probeDir, { recursive: true, force: true });
  }
})();
const describeWithHermes = HAS_HERMES ? describe : describe.skip;

/**
 * Drive a real refresh to the exact state a SIGKILL after rename 1 leaves:
 * both the publish and the restore refuse, so the process "dies" with the
 * plugin directory gone and the previous copy in `backups/`.
 */
function crashAfterFirstRename(): ReturnType<typeof refreshHermesPluginCopies> {
  const real = fs.renameSync;
  const spy = jest.spyOn(fs, 'renameSync').mockImplementation((from, to) => {
    if (String(to) === installed) throw Object.assign(new Error('EIO: simulated'), { code: 'EIO' });
    return real(from, to);
  });
  try {
    return refreshHermesPluginCopies(home, { now: FROZEN });
  } finally {
    spy.mockRestore();
  }
}

describeWithHermes('a crash between the two renames is reported, never repaired (r4)', () => {
  it('leaves the backup and nothing else, and names the command that puts it back', () => {
    installCopy();
    makeStale();

    const result = crashAfterFirstRename();

    expect(result.status).toBe('warn');
    expect(fs.existsSync(installed)).toBe(false);
    // The previous copy is in `backups/`, which nothing here ever deletes.
    const backups = fs.readdirSync(path.join(hermes, 'backups'));
    expect(backups).toHaveLength(1);
    expect(backups[0].startsWith('shieldcortex-preupdate-')).toBe(true);
    expect(result.detail.join('\n')).toMatch(/shieldcortex hermes install/);
    // No journal, no phase file, no staging tree survives the failure: there
    // is nothing for a later run to read a destination out of.
    expect(fs.readdirSync(hermes).filter((n) => n.startsWith('.shieldcortex-'))).toEqual([]);
  });

  it('is not recreated by the next `update` — absence is reported, not repaired (r3 blocker 1)', () => {
    installCopy();
    makeStale();
    const crashed = crashAfterFirstRename();
    expect(fs.existsSync(installed)).toBe(false);
    // The one process that KNOWS the swap was interrupted says so, there and
    // then, with the backup path and the command in the same sentence.
    const backup = fs.readdirSync(path.join(hermes, 'backups'))[0];
    expect(crashed.detail.join('\n')).toContain(path.join(hermes, 'backups', backup));
    expect(crashed.detail.join('\n')).toMatch(/shieldcortex hermes install/);

    const result = refreshHermesPluginCopies(home, { now: FROZEN });

    // The later run has no way to tell this from a deliberate uninstall, so it
    // does not guess: nothing is created, and the backup is left where it is.
    expect(fs.existsSync(installed)).toBe(false);
    expect(result.status).toBe('not-installed');
    expect(result.refreshed).toEqual([]);
    expect(fs.readdirSync(path.join(hermes, 'backups'))).toHaveLength(1);
    expect(fs.readdirSync(hermes).filter((n) => n.startsWith('.shieldcortex-'))).toEqual([]);
  });

  it('a backup-shaped directory grants no installation authority (r3 blocker 1)', () => {
    // No install, and no backup either: not our integration, not our business.
    expect(refreshHermesPluginCopies(home, { now: FROZEN }).status).toBe('not-installed');
    expect(fs.existsSync(installed)).toBe(false);

    // The reviewer's planted layout: an EMPTY `backups/` entry in exactly the
    // shape one of our own swaps writes, on a host with no plugin. Round 3
    // read that as "an interrupted refresh" and installed the package.
    fs.mkdirSync(path.join(hermes, 'backups', 'shieldcortex-preupdate-planted'), { recursive: true });
    expect(refreshHermesPluginCopies(home, { now: FROZEN }).status).toBe('not-installed');
    expect(fs.existsSync(installed)).toBe(false);
  });

  it('does not reinstall the plugin after a refresh followed by an uninstall (r3 blocker 1)', async () => {
    // The ORDINARY sequence, which is the damning one: a successful refresh
    // leaves a permanent backup, the operator uninstalls, and the next update
    // must not undo their decision.
    installCopy();
    makeStale();
    expect(refreshHermesPluginCopies(home, { now: FROZEN }).status).toBe('refreshed');
    expect(fs.readdirSync(path.join(hermes, 'backups'))).toHaveLength(1);

    jest.spyOn(console, 'log').mockImplementation(() => {});
    await uninstallHermes(home);
    expect(fs.existsSync(installed)).toBe(false);

    expect(refreshHermesPluginCopies(home, { now: FROZEN }).status).toBe('not-installed');
    expect(fs.existsSync(installed)).toBe(false);
  });

  it('leaves a PARTIAL target alone rather than adopting it (r2 blocker 5)', () => {
    // The state the reviewer's fault-injection probe left: a target directory
    // holding one file and no manifest, plus the backup from the swap that
    // failed. "The directory exists" is not "the plugin is installed" — and
    // "the plugin is missing" is not permission to write one.
    fs.mkdirSync(installed, { recursive: true });
    fs.writeFileSync(path.join(installed, 'README.md'), 'partial\n');
    fs.mkdirSync(path.join(hermes, 'backups', 'shieldcortex-preupdate-old', 'shieldcortex'), { recursive: true });

    const result = refreshHermesPluginCopies(home, { now: FROZEN });

    expect(result.status).toBe('not-installed');
    expect(fs.readdirSync(installed)).toEqual(['README.md']);
    expect(fs.readdirSync(path.join(hermes, 'backups'))).toEqual(['shieldcortex-preupdate-old']);
  });

  it('never leaves two `shieldcortex` copies inside the plugins root, at any point', () => {
    installCopy();
    makeStale();
    const seen: string[][] = [];
    const real = fs.renameSync;
    jest.spyOn(fs, 'renameSync').mockImplementation((from, to) => {
      seen.push(shieldcortexDirsIn(plugins));
      const out = real(from, to);
      seen.push(shieldcortexDirsIn(plugins));
      return out;
    });

    refreshHermesPluginCopies(home, { now: FROZEN });

    expect(seen.length).toBeGreaterThan(0);
    for (const state of seen) expect(state.length).toBeLessThanOrEqual(1);
    expect(shieldcortexDirsIn(plugins)).toEqual(['shieldcortex']);
  });
});

describeWithHermes('planted files name no destination (r2 blockers 1 and 2)', () => {
  /** A round-2-shaped journal pointing at a directory outside the integration. */
  function plantJournal(): void {
    fs.writeFileSync(path.join(hermes, JOURNAL), `${JSON.stringify({
      version: 1,
      kind: 'hermes-plugin',
      root: hermes,
      target: path.join(elsewhere, 'victim'),
      backup: path.join(elsewhere, 'treasure'),
      staged: path.join(elsewhere, 'staged'),
      stagingRoot: path.join(elsewhere, 'treasure'),
      packagedVersion: '5.2.0',
      phase: 'publishing',
      startedAt: FROZEN.toISOString(),
      pid: 1,
    }, null, 2)}\n`);
  }

  it('a planted journal moves nothing, on a refresh that writes and one that does not', () => {
    fs.mkdirSync(path.join(elsewhere, 'treasure'), { recursive: true });
    fs.writeFileSync(path.join(elsewhere, 'treasure', 'payroll.csv'), 'do not move me\n');
    // A `.shieldcortex-`-named directory somebody else left in the home: the
    // name was round 2's proof that a directory was ours to delete.
    fs.mkdirSync(path.join(hermes, '.shieldcortex-staging-planted'), { recursive: true });
    fs.writeFileSync(path.join(hermes, '.shieldcortex-staging-planted', 'keep.txt'), 'keep\n');
    installCopy();
    plantJournal();
    const before = treeOf(elsewhere);

    // (a) nothing to do
    expect(refreshHermesPluginCopies(home, { now: FROZEN }).status).toBe('current');
    expect(treeOf(elsewhere)).toEqual(before);

    // (b) a real refresh, which does write
    makeStale();
    expect(refreshHermesPluginCopies(home, { now: FROZEN }).status).toBe('refreshed');

    // Nothing outside the standard target and `backups/` moved, and the
    // planted files are all exactly where they were.
    expect(treeOf(elsewhere)).toEqual(before);
    expect(fs.existsSync(path.join(elsewhere, 'victim'))).toBe(false);
    expect(fs.readFileSync(path.join(hermes, '.shieldcortex-staging-planted', 'keep.txt'), 'utf-8')).toBe('keep\n');
    expect(fs.existsSync(path.join(hermes, JOURNAL))).toBe(true);
    expect(fs.readdirSync(hermes).sort()).toEqual([
      JOURNAL, '.shieldcortex-staging-planted', 'backups', 'plugins',
    ].sort());
  });

  it('writes through no predictable temp name — the `.next` link victim survives', () => {
    // Round 2's `advanceJournalPhase` wrote `<journal>.next` with `openSync(…,
    // 'w')`, which FOLLOWS a symlink planted at that name and truncates the
    // referent. The reviewer's probe confirmed both the overwrite and the
    // symlink being installed as the journal.
    const victim = path.join(elsewhere, 'victim.txt');
    fs.writeFileSync(victim, 'important\n');
    const trap = path.join(hermes, `${JOURNAL}.next`);
    fs.symlinkSync(victim, trap);
    installCopy();
    makeStale();

    const opened: string[] = [];
    const realOpen = fs.openSync;
    jest.spyOn(fs, 'openSync').mockImplementation(((p: fs.PathLike, ...rest: unknown[]) => {
      opened.push(String(p));
      return (realOpen as (...a: unknown[]) => number)(p, ...rest);
    }) as typeof fs.openSync);

    expect(refreshHermesPluginCopies(home, { now: FROZEN }).status).toBe('refreshed');

    expect(fs.readFileSync(victim, 'utf-8')).toBe('important\n');
    expect(fs.lstatSync(trap).isSymbolicLink()).toBe(true);
    // Not merely "the victim survived": the trap path was never opened at all.
    expect(opened.filter((p) => p.includes(JOURNAL))).toEqual([]);
  });
});

describeWithHermes('one writer per Hermes root (r2 blocker 3, r3 blocker 2)', () => {
  it('a second refresh that starts mid-swap refuses and writes nothing', () => {
    installCopy();
    makeStale();
    let inner: ReturnType<typeof refreshHermesPluginCopies> | null = null;
    const real = fs.renameSync;
    // Re-enter at the worst possible moment: inside the first refresh's lock,
    // between its two renames. A second `update` on the same host is exactly
    // this interleaving, and round 2's recovery dismantled the first one.
    jest.spyOn(fs, 'renameSync').mockImplementation((from, to) => {
      // BEFORE the displacing rename, not after: the target is still there and
      // still stale, so the re-entrant run has real work to do and the only
      // thing that can stop it is the lock.
      if (inner === null && String(to).includes('-preupdate-')) {
        inner = refreshHermesPluginCopies(home, { now: FROZEN });
      }
      return real(from, to);
    });

    const outer = refreshHermesPluginCopies(home, { now: FROZEN });

    expect(outer.status).toBe('refreshed');
    expect(inner).not.toBeNull();
    expect(inner!.status).toBe('warn');
    expect(inner!.detail.join('\n')).toMatch(/another ShieldCortex update\/install is running/);
    expect(inner!.refreshed).toEqual([]);
    // Exactly ONE writer: one backup, one staging directory (already cleaned),
    // and a plugin that verifies against the package.
    expect(fs.readdirSync(path.join(hermes, 'backups'))).toHaveLength(1);
    expect(fs.readdirSync(hermes).filter((n) => n.startsWith('.shieldcortex-'))).toEqual([]);
    expect(hermesPluginCopyStale(installed).stale).toBe(false);
  });

  it('`hermes install` refuses while the lock is held, and writes nothing', async () => {
    fs.writeFileSync(updateLockPath(hermes), `shieldcortex-update ${process.pid} ${new Date().toISOString()} t\n`);
    const errors: string[] = [];
    jest.spyOn(console, 'error').mockImplementation((...a: unknown[]) => { errors.push(a.join(' ')); });
    jest.spyOn(console, 'log').mockImplementation(() => {});

    await installHermes(home);

    expect(errors.join('\n')).toMatch(/another ShieldCortex update\/install is running/);
    expect(fs.existsSync(installed)).toBe(false);
  });

  it('never reclaims a lock, however stale it looks (r3 blocker 2)', () => {
    installCopy();
    makeStale();
    // pid 2^22 is above every Linux default `pid_max`, so it is never live;
    // the stamp is eleven minutes old. Round 3 deleted this file and carried
    // on, and the read-then-unlink that did it could delete a LIVE lock that
    // replaced it in between.
    const old = new Date(FROZEN.getTime() - 11 * 60 * 1000).toISOString();
    const lock = updateLockPath(hermes);
    fs.writeFileSync(lock, `shieldcortex-update 4194304 ${old} sometoken\n`);

    const blocked = refreshHermesPluginCopies(home, { now: FROZEN });

    expect(blocked.status).toBe('warn');
    const said = blocked.detail.join('\n');
    expect(said).toMatch(/another ShieldCortex update\/install is running/);
    // Named, attributed, and left exactly as it was for the operator to judge.
    expect(said).toContain(lock);
    expect(said).toMatch(/recorded pid 4194304/);
    expect(said).not.toMatch(/ten minutes/);
    expect(fs.readFileSync(lock, 'utf-8')).toBe(`shieldcortex-update 4194304 ${old} sometoken\n`);
    expect(hermesPluginCopyStale(installed).stale).toBe(true);
  });

  it('refuses on a lock nobody can parse, and says so (r3 nit 2)', () => {
    installCopy();
    makeStale();
    // What a SIGKILL between the exclusive create and the write leaves: an
    // empty file no age and no pid check can ever clear.
    const lock = updateLockPath(hermes);
    fs.writeFileSync(lock, '');

    const blocked = refreshHermesPluginCopies(home, { now: FROZEN });

    expect(blocked.status).toBe('warn');
    expect(blocked.detail.join('\n')).toMatch(/not a lock record/);
    expect(blocked.detail.join('\n')).toMatch(/confirmed no ShieldCortex update or install is running/);
    expect(fs.readFileSync(lock, 'utf-8')).toBe('');
  });
});

describeWithHermes('the staged tree is durable before it is reachable (r2 blocker 4)', () => {
  it('every staged file is fsynced before the first rename', () => {
    installCopy();
    makeStale();
    const staged = path.join(hermes, `.shieldcortex-staging-${STAMP}`, 'shieldcortex');
    const byFd = new Map<number, string>();
    const synced: string[] = [];
    let syncedAtFirstRename: string[] | null = null;

    const realOpen = fs.openSync;
    jest.spyOn(fs, 'openSync').mockImplementation(((p: fs.PathLike, ...rest: unknown[]) => {
      const fd = (realOpen as (...a: unknown[]) => number)(p, ...rest);
      byFd.set(fd, String(p));
      return fd;
    }) as typeof fs.openSync);
    const realFsync = fs.fsyncSync;
    jest.spyOn(fs, 'fsyncSync').mockImplementation((fd: number) => {
      synced.push(byFd.get(fd) ?? `fd:${fd}`);
      return realFsync(fd);
    });
    const realRename = fs.renameSync;
    jest.spyOn(fs, 'renameSync').mockImplementation((from, to) => {
      syncedAtFirstRename ??= [...synced];
      return realRename(from, to);
    });

    expect(refreshHermesPluginCopies(home, { now: FROZEN }).status).toBe('refreshed');

    expect(syncedAtFirstRename).not.toBeNull();
    const before = new Set(syncedAtFirstRename!);
    // The staging tree is gone by now (it was renamed into place), so the
    // expected set comes from the PACKAGE — which is the set that had to be
    // flushed, and is what the assertion is really about.
    const packaged = fs.readdirSync(SOURCE, { recursive: true, withFileTypes: true })
      .filter((e) => e.isFile())
      .map((e) => path.relative(SOURCE, path.join(e.parentPath ?? e.path, e.name)))
      .filter((rel) => !rel.split(path.sep).some((part) => ['tests', '__pycache__', '.pytest_cache'].includes(part)));
    expect(packaged.length).toBeGreaterThan(0);
    for (const rel of packaged) expect(before.has(path.join(staged, rel))).toBe(true);
    // And the staged directory itself, so the NAMES are durable too.
    expect(before.has(staged)).toBe(true);
  });

  it('flushes the new backup ancestry before displacing the target (r3 blocker 5)', () => {
    installCopy();
    makeStale();
    const byFd = new Map<number, string>();
    const synced: string[] = [];
    let atFirstRename: string[] | null = null;

    const realOpen = fs.openSync;
    jest.spyOn(fs, 'openSync').mockImplementation(((p: fs.PathLike, ...rest: unknown[]) => {
      const fd = (realOpen as (...a: unknown[]) => number)(p, ...rest);
      byFd.set(fd, String(p));
      return fd;
    }) as typeof fs.openSync);
    const realFsync = fs.fsyncSync;
    jest.spyOn(fs, 'fsyncSync').mockImplementation((fd: number) => {
      synced.push(byFd.get(fd) ?? `fd:${fd}`);
      return realFsync(fd);
    });
    const realRename = fs.renameSync;
    jest.spyOn(fs, 'renameSync').mockImplementation((from, to) => {
      atFirstRename ??= [...synced];
      return realRename(from, to);
    });

    expect(refreshHermesPluginCopies(home, { now: FROZEN }).status).toBe('refreshed');

    // `backups/` and the reservation inside it are BOTH brand new, and the
    // rename that empties `plugins/` can reach the medium before either name
    // does. Round 3 flushed neither.
    const backups = path.join(hermes, 'backups');
    const before = new Set(atFirstRename ?? []);
    expect(before.has(path.join(backups, `shieldcortex-preupdate-${STAMP}`))).toBe(true);
    expect(before.has(backups)).toBe(true);
    expect(before.has(hermes)).toBe(true);
  });
});

describeWithHermes('a device that refuses a flush is not a platform that cannot (r3 blocker 5)', () => {
  /** Fail every DIRECTORY fsync with `code`, leaving file fsyncs alone. */
  function failDirectoryFsync(code: string, only?: (dir: string) => boolean): void {
    const byFd = new Map<number, string>();
    const realOpen = fs.openSync;
    jest.spyOn(fs, 'openSync').mockImplementation(((p: fs.PathLike, ...rest: unknown[]) => {
      const fd = (realOpen as (...a: unknown[]) => number)(p, ...rest);
      byFd.set(fd, String(p));
      return fd;
    }) as typeof fs.openSync);
    const realFsync = fs.fsyncSync;
    jest.spyOn(fs, 'fsyncSync').mockImplementation((fd: number) => {
      const target = byFd.get(fd);
      const isDir = target !== undefined && fs.existsSync(target) && fs.statSync(target).isDirectory();
      if (isDir && (only === undefined || only(target))) {
        throw Object.assign(new Error(`${code}: simulated`), { code });
      }
      return realFsync(fd);
    });
  }

  it('an EIO on the backup ancestry aborts before anything is moved', () => {
    installCopy();
    makeStale();
    const backups = path.join(hermes, 'backups');
    // Only the backup ancestry: the staged tree flushes cleanly, so the abort
    // is provably the pre-rename ancestry check and not an earlier refusal.
    failDirectoryFsync('EIO', (dir) => dir === backups || dir.startsWith(`${backups}${path.sep}`));
    const renames: string[] = [];
    const realRename = fs.renameSync;
    jest.spyOn(fs, 'renameSync').mockImplementation((from, to) => {
      renames.push(String(to));
      return realRename(from, to);
    });

    const result = refreshHermesPluginCopies(home, { now: FROZEN });

    expect(result.status).toBe('warn');
    expect(result.refreshed).toEqual([]);
    expect(result.detail.join('\n')).toMatch(/could not be flushed.*EIO/);
    expect(result.detail.join('\n')).toMatch(/nothing written/);
    // Not one rename ran, and the stale copy is exactly where it was.
    expect(renames).toEqual([]);
    expect(hermesPluginCopyStale(installed).stale).toBe(true);
    expect(fs.readdirSync(hermes).filter((n) => n.startsWith('.shieldcortex-'))).toEqual([]);
  });

  it('an EIO anywhere in the flush path is never a successful refresh', () => {
    installCopy();
    makeStale();
    // The reviewer's injection: EVERY directory fsync fails. Round 3 returned
    // a refreshed copy with `failed: []`.
    failDirectoryFsync('EIO');

    const result = refreshHermesPluginCopies(home, { now: FROZEN });

    expect(result.status).toBe('warn');
    expect(result.refreshed).toEqual([]);
    expect(hermesPluginCopyStale(installed).stale).toBe(true);
  });

  it('a platform that simply cannot flush a directory still refreshes, and says so', () => {
    installCopy();
    makeStale();
    // EINVAL is what a filesystem without directory-fd fsync answers. Failing
    // the refresh there would break every host of that kind.
    failDirectoryFsync('EINVAL');

    const result = refreshHermesPluginCopies(home, { now: FROZEN });

    expect(result.status).toBe('refreshed');
    expect(hermesPluginCopyStale(installed).stale).toBe(false);
    expect(result.detail.join('\n')).toMatch(/could not be flushed.*EINVAL/);
  });
});
