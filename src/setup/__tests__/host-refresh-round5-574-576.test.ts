import fs from 'fs';
import os from 'os';
import path from 'path';
import { afterEach, beforeEach, describe, expect, it, jest } from '@jest/globals';
import { HOOK_FILES, refreshInstalledHookFiles } from '../openclaw.js';
import {
  hermesPluginCopyStale,
  hermesPluginSourceDir,
  refreshHermesPluginCopies,
} from '../hermes-refresh.js';
import { probeHermesDiscovery } from '../hermes-plugins.js';
import { stageAndPublish, UPDATE_LOCK_NAME } from '../host-swap.js';

/**
 * #574 / #576 round 5 — two refreshers, and a flush that stops too early.
 *
 * Blocker 3: discovery runs BEFORE the lock, so everything it decided is a
 * claim about a tree the lock does not yet protect. The reviewer interleaved
 * two refreshers — B selects a stale target and pauses before its lock, A
 * fails its swap and leaves that target ABSENT, B resumes — and B RECREATED
 * the target, reporting a clean refresh. Two things had to be true for that:
 * `stageAndPublish` treated an absent target as permission to publish without
 * displacing anything, and nothing re-asked "is it still there" once the lock
 * was held. Both are closed below, and either one alone stops the defect.
 *
 * Nit 2: after the renames both parent directories are flushed, and the loop
 * returned at the FIRST refusal — so a device that refused one of them left
 * the other never attempted. A refusal there was also filed as an ordinary
 * successful refresh.
 *
 * Every case runs on a fake home under a temp dir. The real `~/.hermes`,
 * `~/.openclaw` and `~/.shieldcortex` are never read or written.
 */
let home: string;
let configRoot: string;
let hookDir: string;
let hermes: string;
let plugins: string;
let installed: string;
const savedHermesHome = process.env.HERMES_HOME;
const savedProjectPlugins = process.env.HERMES_ENABLE_PROJECT_PLUGINS;
const HERMES_SOURCE = hermesPluginSourceDir();
const FROZEN = new Date('2026-09-24T12:34:56.789Z');
const STAMP = '2026-09-24T12-34-56-789Z';
const OLD = (file: string): string => `// shieldcortex 5.1.0 ${file}\n`;

beforeEach(() => {
  home = fs.mkdtempSync(path.join(os.tmpdir(), 'sc-r5-refresh-'));
  configRoot = path.join(home, '.openclaw');
  hookDir = path.join(configRoot, 'hooks', 'cortex-memory');
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
  if (savedHermesHome === undefined) delete process.env.HERMES_HOME;
  else process.env.HERMES_HOME = savedHermesHome;
  if (savedProjectPlugins === undefined) delete process.env.HERMES_ENABLE_PROJECT_PLUGINS;
  else process.env.HERMES_ENABLE_PROJECT_PLUGINS = savedProjectPlugins;
});

function installStaleHook(): void {
  fs.mkdirSync(hookDir, { recursive: true });
  for (const file of HOOK_FILES) fs.writeFileSync(path.join(hookDir, file), OLD(file));
}

function installStaleHermes(): void {
  fs.cpSync(HERMES_SOURCE, installed, {
    recursive: true,
    filter: (src) => !['tests', '__pycache__', '.pytest_cache'].includes(path.basename(src)),
  });
  fs.writeFileSync(path.join(installed, '__init__.py'), '# shieldcortex 5.1.0\n');
  fs.rmSync(path.join(installed, 'shadow.py'), { force: true });
}

/**
 * Refresher A's damage, landed at exactly the moment B takes its lock.
 *
 * The lock is created with one `open(O_CREAT|O_EXCL)` on `<root>/<lock>`, so
 * intercepting that call is the deterministic stand-in for "B was paused here
 * while A failed its swap and left the target absent". Everything B decided
 * about the target — installed, stale — was decided before this point.
 */
function vanishAtLockAcquisition(target: string): { removed: () => boolean } {
  let done = false;
  const realOpen = fs.openSync;
  jest.spyOn(fs, 'openSync').mockImplementation(((p: fs.PathLike, ...rest: unknown[]) => {
    if (!done && path.basename(String(p)) === UPDATE_LOCK_NAME) {
      done = true;
      fs.rmSync(target, { recursive: true, force: true });
    }
    return (realOpen as (...a: unknown[]) => number)(p, ...rest);
  }) as typeof fs.openSync);
  return { removed: () => done };
}

const HAS_HERMES = (() => {
  const probeDir = fs.mkdtempSync(path.join(os.tmpdir(), 'sc-r5-probe-'));
  try {
    fs.mkdirSync(path.join(probeDir, '.hermes', 'plugins'), { recursive: true });
    return 'roots' in probeHermesDiscovery({ home: probeDir, hermesHome: null });
  } finally {
    fs.rmSync(probeDir, { recursive: true, force: true });
  }
})();
const describeWithHermes = HAS_HERMES ? describe : describe.skip;

describe('a refresh never installs (#574/#576 r4 blocker 3)', () => {
  it('stageAndPublish refuses an absent target rather than publishing into it', () => {
    const root = path.join(home, '.hermes');
    let staged = 0;
    const outcome = stageAndPublish({
      bound: root,
      target: installed,
      stagingParent: root,
      backupsRoot: path.join(root, 'backups'),
      stamp: STAMP,
      stagingPrefix: '.shieldcortex-staging',
      backupPrefix: 'shieldcortex',
      stage: (dir) => {
        staged += 1;
        fs.mkdirSync(dir, { recursive: true });
        fs.writeFileSync(path.join(dir, 'plugin.yaml'), 'name: shieldcortex\n');
      },
      verify: () => null,
      reinstallCommand: 'run `shieldcortex hermes install`',
    });

    expect(outcome.ok).toBe(false);
    expect(outcome.ok === false && outcome.error).toMatch(/not installed, nothing to refresh/);
    expect(outcome.ok === false && outcome.error).toMatch(/shieldcortex hermes install/);
    // Not published, not staged, and no backup destination reserved: the
    // refusal happens before the first byte is written anywhere.
    expect(fs.existsSync(installed)).toBe(false);
    expect(staged).toBe(0);
    expect(fs.existsSync(path.join(root, 'backups'))).toBe(false);
    expect(fs.readdirSync(root).filter((n) => n.startsWith('.shieldcortex-'))).toEqual([]);
  });

  it('does not recreate an OpenClaw hook another refresher removed before the lock', () => {
    installStaleHook();
    const raced = vanishAtLockAcquisition(hookDir);

    const result = refreshInstalledHookFiles(home, { now: FROZEN });

    expect(raced.removed()).toBe(true);
    // B found it installed and stale, then held the lock over an empty path.
    // It does not put the hook back: a refresh cannot tell an interrupted swap
    // from the uninstall the operator just ran.
    expect(fs.existsSync(hookDir)).toBe(false);
    expect(result.refreshed).toEqual([]);
    expect(result.vanished).toEqual([hookDir]);
    expect(result.backups).toEqual([]);
    expect(fs.existsSync(path.join(configRoot, 'backups'))).toBe(false);
  });

  describeWithHermes('on the Hermes plane', () => {
    it('does not recreate a plugin copy another refresher removed before the lock', () => {
      installStaleHermes();
      const raced = vanishAtLockAcquisition(installed);

      const result = refreshHermesPluginCopies(home, { now: FROZEN });

      expect(raced.removed()).toBe(true);
      expect(fs.existsSync(installed)).toBe(false);
      expect(result.refreshed).toEqual([]);
      expect(result.status).toBe('warn');
      expect(result.detail.join('\n')).toMatch(/not installed, nothing to refresh/);
      expect(result.summary).toMatch(/shieldcortex hermes install/);
      // Nothing was displaced, so nothing was reserved under `backups/`.
      expect(fs.existsSync(path.join(hermes, 'backups'))).toBe(false);
    });
  });
});

describeWithHermes('a post-rename flush refusal is a degraded refresh (#574/#576 r4 nit 2)', () => {
  /**
   * The timeline of everything that matters here, in order: each rename and
   * each DIRECTORY fsync that was ATTEMPTED. `plugins/` is the one the device
   * refuses; the question is whether the reservation directory — the other
   * parent of the same rename — is even tried afterwards.
   */
  function record(failing: string): string[] {
    const timeline: string[] = [];
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
      if (!isDir) return realFsync(fd);
      timeline.push(`fsync ${target}`);
      if (target === failing) throw Object.assign(new Error('EIO: simulated'), { code: 'EIO' });
      return realFsync(fd);
    });
    const realRename = fs.renameSync;
    jest.spyOn(fs, 'renameSync').mockImplementation((from, to) => {
      timeline.push(`rename ${String(to)}`);
      return realRename(from, to);
    });
    return timeline;
  }

  it('attempts BOTH rename parents and reports durability, not success', () => {
    installStaleHermes();
    const reservation = path.join(hermes, 'backups', `shieldcortex-preupdate-${STAMP}`);
    // EIO on `plugins/` only. The pre-rename ancestry flush never touches it,
    // so every attempt below is provably a POST-rename one.
    const timeline = record(plugins);

    const result = refreshHermesPluginCopies(home, { now: FROZEN });

    // The copy really was published — this is not a failed refresh.
    expect(result.refreshed.map((r) => r.dir)).toEqual([installed]);
    expect(hermesPluginCopyStale(installed).stale).toBe(false);
    // …but it is not a clean one either.
    expect(result.status).toBe('warn');
    expect(result.summary).toMatch(/durability not confirmed/);
    expect(result.detail.join('\n')).toMatch(/refreshed, durability not confirmed: .*EIO/);

    // The other parent of the first rename is attempted even though `plugins/`
    // had just refused. Before this fix the flush returned at the first
    // failure and the reservation was never flushed after the move into it.
    const firstRename = timeline.findIndex((line) => line.startsWith('rename '));
    expect(firstRename).toBeGreaterThanOrEqual(0);
    expect(timeline.slice(firstRename + 1)).toContain(`fsync ${reservation}`);
    // And `plugins/` itself was still attempted, twice — once per rename.
    expect(timeline.slice(firstRename + 1).filter((l) => l === `fsync ${plugins}`)).toHaveLength(2);
  });
});
