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
import { installHermes } from '../hermes.js';
import { updateLockPath } from '../host-swap.js';

/**
 * #574 / #576 round 3 — the crash between the two renames, and the six ways
 * round 2's JOURNAL answer went wrong.
 *
 * Round 2 recorded `{target, backup, staged}` in
 * `<hermesHome>/.shieldcortex-refresh-journal.json` and let the next run MOVE
 * THE PATHS IT NAMED. There is no journal now: a refresh that was interrupted
 * is recognised from two computed facts — the standard target has no
 * `plugin.yaml`, and one of our own swaps left a `backups/…-preupdate-*` under
 * this root — and the remedy is to reinstall the packaged tree into that same
 * standard path. Nothing on disk names a destination.
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

describeWithHermes('a crash between the two renames is healed from the package (r3)', () => {
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

  it('is healed by the next `update`, which reinstalls the packaged tree', () => {
    installCopy();
    makeStale();
    crashAfterFirstRename();
    expect(fs.existsSync(installed)).toBe(false);

    const result = refreshHermesPluginCopies(home, { now: FROZEN });

    expect(fs.existsSync(path.join(installed, 'plugin.yaml'))).toBe(true);
    expect(hermesPluginCopyStale(installed).stale).toBe(false);
    expect(result.status).toBe('refreshed');
    expect(result.detail.join('\n')).toMatch(/was missing and was reinstalled from the package/);
    // The interrupted run's backup is still there. Nothing was added to it:
    // a reinstall has nothing to displace, so it reserves no second backup.
    expect(fs.readdirSync(path.join(hermes, 'backups'))).toHaveLength(1);
    expect(fs.readdirSync(hermes).filter((n) => n.startsWith('.shieldcortex-'))).toEqual([]);
  });

  it('leaves a host that never had the plugin alone, backup or no backup', () => {
    // No install, and no backup either: not our integration, not our business.
    expect(refreshHermesPluginCopies(home, { now: FROZEN }).status).toBe('not-installed');
    expect(fs.existsSync(installed)).toBe(false);

    // A `backups/` full of somebody else's directories is not evidence: only
    // the `shieldcortex-preupdate-*` shape one of our own swaps writes is.
    fs.mkdirSync(path.join(hermes, 'backups', 'some-other-tool'), { recursive: true });
    expect(refreshHermesPluginCopies(home, { now: FROZEN }).status).toBe('not-installed');
    expect(fs.existsSync(installed)).toBe(false);
  });

  it('refreshes a PARTIAL target rather than accepting it as installed (r2 blocker 5)', () => {
    // The state the reviewer's fault-injection probe left: a target directory
    // holding one file and no manifest, plus the backup from the swap that
    // failed. "The directory exists" is not "the plugin is installed".
    fs.mkdirSync(installed, { recursive: true });
    fs.writeFileSync(path.join(installed, 'README.md'), 'partial\n');
    fs.mkdirSync(path.join(hermes, 'backups', 'shieldcortex-preupdate-old', 'shieldcortex'), { recursive: true });

    const result = refreshHermesPluginCopies(home, { now: FROZEN });

    expect(result.status).toBe('refreshed');
    expect(hermesPluginCopyStale(installed).stale).toBe(false);
    // The husk was kept, not deleted, beside the earlier backup.
    expect(fs.readdirSync(path.join(hermes, 'backups')).sort()).toEqual([
      'shieldcortex-preupdate-old',
      `shieldcortex-preupdate-${STAMP}`,
    ].sort());
    expect(fs.readFileSync(
      path.join(hermes, 'backups', `shieldcortex-preupdate-${STAMP}`, 'shieldcortex', 'README.md'),
      'utf-8',
    )).toBe('partial\n');
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

describeWithHermes('one writer per Hermes home (r2 blocker 3)', () => {
  it('a second refresh that starts mid-swap refuses and writes nothing', () => {
    installCopy();
    makeStale();
    let inner: ReturnType<typeof refreshHermesPluginCopies> | null = null;
    const real = fs.renameSync;
    // Re-enter at the worst possible moment: inside the first refresh's lock,
    // between its two renames. A second `update` on the same host is exactly
    // this interleaving, and round 2's recovery dismantled the first one.
    jest.spyOn(fs, 'renameSync').mockImplementation((from, to) => {
      const out = real(from, to);
      if (inner === null && String(to).includes('-preupdate-')) {
        inner = refreshHermesPluginCopies(home, { now: FROZEN });
      }
      return out;
    });

    const outer = refreshHermesPluginCopies(home, { now: FROZEN });

    expect(outer.status).toBe('refreshed');
    expect(inner).not.toBeNull();
    expect(inner!.status).toBe('warn');
    expect(inner!.summary).toMatch(/another ShieldCortex update\/install is running/);
    expect(inner!.refreshed).toEqual([]);
    // Exactly ONE writer: one backup, one staging directory (already cleaned),
    // and a plugin that verifies against the package.
    expect(fs.readdirSync(path.join(hermes, 'backups'))).toHaveLength(1);
    expect(fs.readdirSync(hermes).filter((n) => n.startsWith('.shieldcortex-'))).toEqual([]);
    expect(hermesPluginCopyStale(installed).stale).toBe(false);
  });

  it('`hermes install` refuses while the lock is held, and writes nothing', async () => {
    fs.writeFileSync(updateLockPath(hermes), `shieldcortex-update ${process.pid} ${new Date().toISOString()}\n`);
    const errors: string[] = [];
    jest.spyOn(console, 'error').mockImplementation((...a: unknown[]) => { errors.push(a.join(' ')); });
    jest.spyOn(console, 'log').mockImplementation(() => {});

    await installHermes(home);

    expect(errors.join('\n')).toMatch(/another ShieldCortex update\/install is running/);
    expect(fs.existsSync(installed)).toBe(false);
  });

  it('a stale lock — dead pid AND older than ten minutes — does not block a refresh', () => {
    installCopy();
    makeStale();
    // pid 2^22 is above every Linux default `pid_max`, so it is never live.
    const old = new Date(FROZEN.getTime() - 11 * 60 * 1000).toISOString();
    fs.writeFileSync(updateLockPath(hermes), `shieldcortex-update 4194304 ${old}\n`);

    expect(refreshHermesPluginCopies(home, { now: FROZEN }).status).toBe('refreshed');

    // A DEAD pid with a FRESH stamp still holds it: half an argument is not
    // enough to delete somebody else's lock.
    makeStale();
    fs.writeFileSync(updateLockPath(hermes), `shieldcortex-update 4194304 ${FROZEN.toISOString()}\n`);
    const blocked = refreshHermesPluginCopies(home, { now: FROZEN });
    expect(blocked.status).toBe('warn');
    expect(blocked.summary).toMatch(/another ShieldCortex update\/install is running/);
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
});
