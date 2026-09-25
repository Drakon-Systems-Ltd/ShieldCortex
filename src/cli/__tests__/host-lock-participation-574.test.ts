import fs from 'fs';
import os from 'os';
import path from 'path';
import { afterEach, beforeEach, describe, expect, it, jest } from '@jest/globals';
import { stepOpenClawPlugin } from '../update.js';
import { fixHermesPluginShadowing } from '../doctor.js';
import { updateLockPath } from '../../setup/host-swap.js';
import { probeHermesDiscovery } from '../../setup/hermes-plugins.js';

/**
 * #574 round 4 blocker 2 — the integration lock did not cover all its writers.
 *
 * Round 3 put `~/.openclaw` and every Hermes root behind one exclusive lock and
 * called that a root-wide guarantee. Two named writers went straight past it:
 *
 *   - `update`'s OpenClaw plugin step deletes the legacy extension directory
 *     and then hands the native installer the same root. The reviewer held the
 *     lock, ran the step, and watched the real extension directory be deleted
 *     and the installer invoked, with the step returning "ok" — so `update`
 *     could delete an extension `openclaw install` was copying into under its
 *     supposedly exclusive lock.
 *   - doctor's `--fix-hermes-plugin-copies` repair moves plugin directories
 *     into `backups/` with no lock at all. The reviewer held the Hermes root's
 *     lock and watched it move a copy and report `failed: false`.
 *
 * Both now take the lock of every root they write in, and a busy lock means
 * nothing is written and the root is named.
 *
 * Fake homes under a temp dir throughout; the real `~/.openclaw` and
 * `~/.hermes` are never read or written.
 */
let home: string;
let stdout: string[];
const FOREIGN = 'shieldcortex-update 4194304 2026-09-24T11:00:00.000Z foreign\n';
const FROZEN = new Date('2026-09-24T12:34:56.789Z');
const savedHermesHome = process.env.HERMES_HOME;

beforeEach(() => {
  home = fs.mkdtempSync(path.join(os.tmpdir(), 'sc-lock-writers-'));
  delete process.env.HERMES_HOME;
  stdout = [];
  jest.spyOn(process.stdout, 'write').mockImplementation(((chunk: string | Uint8Array) => {
    stdout.push(String(chunk));
    return true;
  }) as typeof process.stdout.write);
});

afterEach(() => {
  jest.restoreAllMocks();
  fs.rmSync(home, { recursive: true, force: true });
  if (savedHermesHome === undefined) delete process.env.HERMES_HOME;
  else process.env.HERMES_HOME = savedHermesHome;
});

describe("update's OpenClaw plugin step writes under the root's lock (#574 r4 blocker 2)", () => {
  it('deletes no legacy extension and runs no installer while the lock is held', async () => {
    const openclawRoot = path.join(home, '.openclaw');
    const extDir = path.join(openclawRoot, 'extensions', 'shieldcortex-realtime');
    fs.mkdirSync(extDir, { recursive: true });
    fs.writeFileSync(path.join(extDir, 'package.json'), '{"version":"4.30.2"}\n');
    fs.writeFileSync(updateLockPath(openclawRoot), FOREIGN);

    const ran: string[][] = [];
    const removed: string[] = [];
    const result = await stepOpenClawPlugin(home, {
      run: (async (cmd: string, args: string[]) => { ran.push([cmd, ...args]); }) as never,
      rm: ((target: fs.PathLike) => { removed.push(String(target)); }) as typeof fs.rmSync,
      readPluginVersion: (() => '4.30.2') as never,
      readCliVersion: (() => '4.31.0') as never,
    });

    // The two writes the reviewer drove with the lock held.
    expect(removed).toEqual([]);
    expect(ran).toEqual([]);
    expect(fs.existsSync(path.join(extDir, 'package.json'))).toBe(true);
    // Attention, not "ok": the plugin on this host is still the old one.
    expect(result.status).toBe('warn');
    expect(`${result.summary}\n${(result.detail ?? []).join('\n')}`)
      .toMatch(/another ShieldCortex update\/install is running/);
    // And the foreign lock is still the foreign lock.
    expect(fs.readFileSync(updateLockPath(openclawRoot), 'utf-8')).toBe(FOREIGN);
  });

  it('does its work when the lock is free, and hands the lock back', async () => {
    const openclawRoot = path.join(home, '.openclaw');
    const extDir = path.join(openclawRoot, 'extensions', 'shieldcortex-realtime');
    fs.mkdirSync(extDir, { recursive: true });

    const ran: string[][] = [];
    const removed: string[] = [];
    await stepOpenClawPlugin(home, {
      run: (async (cmd: string, args: string[]) => { ran.push([cmd, ...args]); }) as never,
      rm: ((target: fs.PathLike) => { removed.push(String(target)); }) as typeof fs.rmSync,
      readPluginVersion: (() => '4.31.0') as never,
      readCliVersion: (() => '4.31.0') as never,
    });

    expect(removed).toEqual([extDir]);
    expect(ran[0]?.[0]).toBe('openclaw');
    expect(fs.existsSync(updateLockPath(openclawRoot))).toBe(false);
  });
});

const HAS_HERMES = (() => {
  const probeDir = fs.mkdtempSync(path.join(os.tmpdir(), 'sc-lock-probe-'));
  try {
    fs.mkdirSync(path.join(probeDir, '.hermes', 'plugins'), { recursive: true });
    return 'roots' in probeHermesDiscovery({ home: probeDir, hermesHome: null });
  } finally {
    fs.rmSync(probeDir, { recursive: true, force: true });
  }
})();
const describeWithHermes = HAS_HERMES ? describe : describe.skip;

describeWithHermes("doctor's Hermes repair moves under every root's lock (#574 r4 blocker 2)", () => {
  function makePlugin(root: string, dirName: string): string {
    const dir = path.join(root, dirName);
    fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(
      path.join(dir, 'plugin.yaml'),
      '# a manifest\nname: shieldcortex\nkind: standalone\nversion: 0.1.0\n',
    );
    return dir;
  }

  it('moves nothing and names the root when that root is locked', () => {
    const hermes = path.join(home, '.hermes');
    const plugins = path.join(hermes, 'plugins');
    makePlugin(plugins, 'shieldcortex');
    const backupShaped = makePlugin(plugins, 'shieldcortex.bak-pre510');
    fs.writeFileSync(updateLockPath(hermes), FOREIGN);

    const result = fixHermesPluginShadowing(home, FROZEN);

    // The reviewer's probe: this used to move the copy and report failed:false.
    expect(result.moved).toEqual([]);
    expect(result.changed).toBe(false);
    expect(result.failed).toBe(true);
    expect(result.message).toMatch(/could not be taken exclusively/);
    expect(result.message).toMatch(/another ShieldCortex update\/install is running/);
    // The copy is exactly where it was, and no `backups/` was even created.
    expect(fs.existsSync(path.join(backupShaped, 'plugin.yaml'))).toBe(true);
    expect(fs.existsSync(path.join(hermes, 'backups'))).toBe(false);
    expect(fs.readFileSync(updateLockPath(hermes), 'utf-8')).toBe(FOREIGN);
  });

  it('repairs, and hands the lock back, when nothing else holds it', () => {
    const hermes = path.join(home, '.hermes');
    const plugins = path.join(hermes, 'plugins');
    makePlugin(plugins, 'shieldcortex');
    const backupShaped = makePlugin(plugins, 'shieldcortex.bak-pre510');

    const result = fixHermesPluginShadowing(home, FROZEN);

    expect(result.moved.map((m) => m.from)).toEqual([backupShaped]);
    expect(result.failed).toBe(false);
    expect(fs.existsSync(backupShaped)).toBe(false);
    // Nothing is left holding the root it just wrote in.
    expect(fs.existsSync(updateLockPath(hermes))).toBe(false);
  });

  it('refuses, moving nothing, when the re-plan reaches a root it did not lock (#574 r5 review)', () => {
    // The reviewer's interleaving: the survey sees a shadow only in the default
    // root; while doctor holds that root's lock, a shadow appears in a profile
    // whose lock another writer holds. The re-plan must not move it.
    const hermes = path.join(home, '.hermes');
    const plugins = path.join(hermes, 'plugins');
    makePlugin(plugins, 'shieldcortex');
    const defaultShadow = makePlugin(plugins, 'shieldcortex.bak-pre510');
    const work = path.join(hermes, 'profiles', 'work');
    const workPlugins = path.join(work, 'plugins');
    makePlugin(workPlugins, 'shieldcortex');

    let workShadow = '';
    const result = fixHermesPluginShadowing(home, FROZEN, {}, () => {
      workShadow = makePlugin(workPlugins, 'shieldcortex.bak-pre510');
      fs.writeFileSync(updateLockPath(work), FOREIGN);
    });

    expect(result.moved).toEqual([]);
    expect(result.changed).toBe(false);
    expect(result.failed).toBe(true);
    expect(result.message).toMatch(/layout changed while doctor was taking its locks/);
    // Both shadows exactly where they were; the foreign lock untouched; ours released.
    expect(fs.existsSync(path.join(defaultShadow, 'plugin.yaml'))).toBe(true);
    expect(fs.existsSync(path.join(workShadow, 'plugin.yaml'))).toBe(true);
    expect(fs.readFileSync(updateLockPath(work), 'utf-8')).toBe(FOREIGN);
    expect(fs.existsSync(updateLockPath(hermes))).toBe(false);
  });
});
