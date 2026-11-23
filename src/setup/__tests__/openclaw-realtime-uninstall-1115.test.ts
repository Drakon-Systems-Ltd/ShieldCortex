/**
 * #1115 — managed realtime uninstall must not report success, or strip config,
 * while OpenClaw still has a loadable copy. Spawn is injected. Homes are
 * throwaway directories under os.tmpdir() (TMPDIR). No live openclaw, no
 * gateway, no real uninstall.
 */
import fs from 'fs';
import os from 'os';
import path from 'path';
import { afterEach, beforeEach, describe, expect, it, jest } from '@jest/globals';
import { uninstallPlugin } from '../openclaw.js';
import { PLUGINS_UNINSTALL_ARGV, PLUGINS_UNINSTALL_STDIN, PLUGINS_UNINSTALL_TIMEOUT_MS } from '../openclaw-realtime-uninstall.js';
import { runDeepClean, scanForResidue, cleanResidue } from '../deep-clean.js';
import { updateLockPath } from '../host-swap.js';

const PKG = '@drakon-systems/shieldcortex-realtime';
const ID = 'shieldcortex-realtime';

let home: string;
let otherHome: string;
let prev: Record<string, string | undefined>;
let homedirSpy: jest.SpiedFunction<typeof os.homedir>;
let logSpy: jest.SpiedFunction<typeof console.log>;
let errorSpy: jest.SpiedFunction<typeof console.error>;
let prevExit: typeof process.exitCode;

const TARGETING = [
  'OPENCLAW_HOME',
  'OPENCLAW_STATE_DIR',
  'CLAWDBOT_STATE_DIR',
  'OPENCLAW_CONFIG_PATH',
  'CLAWDBOT_CONFIG_PATH',
  'OPENCLAW_PROFILE',
  'SUDO_USER',
] as const;

function writeManaged(dirName: string): string {
  const installPath = path.join(
    home, '.openclaw', 'npm', 'projects', dirName,
    'node_modules', '@drakon-systems', ID,
  );
  fs.mkdirSync(installPath, { recursive: true });
  fs.writeFileSync(path.join(installPath, 'package.json'), JSON.stringify({ name: PKG, version: '5.22.1' }));
  fs.writeFileSync(path.join(installPath, 'openclaw.plugin.json'), JSON.stringify({ id: ID, version: '5.22.1' }));
  fs.writeFileSync(path.join(installPath, 'index.js'), 'export default {};\n');
  return installPath;
}

function writeInstalls(installPath: string): void {
  const pluginsDir = path.join(home, '.openclaw', 'plugins');
  fs.mkdirSync(pluginsDir, { recursive: true });
  fs.writeFileSync(path.join(pluginsDir, 'installs.json'), JSON.stringify({
    installRecords: { [ID]: { source: 'npm', version: '5.22.1', installPath } },
  }));
}

function writeConfig(): string {
  const file = path.join(home, '.openclaw', 'openclaw.json');
  fs.mkdirSync(path.dirname(file), { recursive: true });
  const raw = JSON.stringify({
    plugins: {
      allow: [ID, 'other-plugin'],
      entries: { [ID]: { enabled: true }, other: { enabled: true } },
    },
    hooks: { internal: { installs: { [ID]: { version: '5.22.1' } } } },
  }, null, 2) + '\n';
  fs.writeFileSync(file, raw);
  return raw;
}

type SpawnCall = {
  command: string;
  args: readonly string[];
  options: { env?: NodeJS.ProcessEnv; input?: string; timeout?: number; shell?: unknown };
};

function okSpawn(mutate?: () => void): { spawn: (c: string, a: readonly string[], o: SpawnCall['options']) => { status: number; signal: null; stdout: string; stderr: string }; calls: SpawnCall[] } {
  const calls: SpawnCall[] = [];
  return {
    calls,
    spawn: (command, args, options) => {
      calls.push({ command, args, options });
      mutate?.();
      return { status: 0, signal: null, stdout: '', stderr: '' };
    },
  };
}

beforeEach(() => {
  home = fs.mkdtempSync(path.join(os.tmpdir(), 'sc-1115-'));
  otherHome = fs.mkdtempSync(path.join(os.tmpdir(), 'sc-1115-other-'));
  prev = {};
  for (const key of TARGETING) {
    prev[key] = process.env[key];
    delete process.env[key];
  }
  process.env.OPENCLAW_HOME = home;
  prevExit = process.exitCode;
  process.exitCode = undefined;
  homedirSpy = jest.spyOn(os, 'homedir').mockReturnValue(otherHome);
  logSpy = jest.spyOn(console, 'log').mockImplementation(() => {});
  errorSpy = jest.spyOn(console, 'error').mockImplementation(() => {});
});

afterEach(() => {
  homedirSpy.mockRestore();
  logSpy.mockRestore();
  errorSpy.mockRestore();
  for (const key of TARGETING) {
    if (prev[key] === undefined) delete process.env[key];
    else process.env[key] = prev[key];
  }
  process.exitCode = prevExit;
  fs.rmSync(home, { recursive: true, force: true });
  fs.rmSync(otherHome, { recursive: true, force: true });
});

describe('#1115 managed realtime uninstall', () => {
  it('spawns plugins uninstall for a managed install and does not create extensions/ or rm the project', () => {
    const installPath = writeManaged('drakon-systems-shieldcortex-realtime-abc123');
    writeInstalls(installPath);
    const configBefore = writeConfig();
    const { spawn, calls } = okSpawn(() => {
      fs.writeFileSync(path.join(home, '.openclaw', 'plugins', 'installs.json'), JSON.stringify({ installRecords: {} }));
    });

    const result = uninstallPlugin({ resolveBinary: () => '/fake/bin/openclaw', spawn });

    expect(result.status).toBe('removed');
    expect(calls).toHaveLength(1);
    expect(calls[0].command).toBe('/fake/bin/openclaw');
    expect(calls[0].args).toEqual([...PLUGINS_UNINSTALL_ARGV]);
    expect(calls[0].options.input).toBe(PLUGINS_UNINSTALL_STDIN);
    expect(calls[0].options.timeout).toBe(PLUGINS_UNINSTALL_TIMEOUT_MS);
    expect(calls[0].options.shell).toBe(false);
    expect(calls[0].options.env?.HOME).toBe(home);
    expect(calls[0].options.env?.OPENCLAW_HOME).toBe(home);
    expect(fs.existsSync(path.join(home, '.openclaw', 'extensions'))).toBe(false);
    expect(fs.existsSync(installPath)).toBe(true);
    expect(fs.existsSync(path.join(otherHome, '.openclaw'))).toBe(false);
    const config = JSON.parse(fs.readFileSync(path.join(home, '.openclaw', 'openclaw.json'), 'utf-8'));
    expect(config.plugins.allow).toEqual(['other-plugin']);
    expect(config.plugins.entries[ID]).toBeUndefined();
    expect(config.plugins.entries.other).toEqual({ enabled: true });
    expect(config.hooks.internal.installs[ID]).toBeUndefined();
    expect(fs.readFileSync(path.join(home, '.openclaw', 'plugins', 'installs.json'), 'utf-8')).not.toBe(configBefore);
    expect(result.detail).toMatch(/Left in place/);
    expect(result.leftovers).toContain(installPath);
  });

  it('prints a second generation dir as leftover and leaves it on disk', () => {
    const live = writeManaged('drakon-systems-shieldcortex-realtime-gen1');
    const leftover = writeManaged('drakon-systems-shieldcortex-realtime-gen2');
    writeInstalls(live);
    const { spawn } = okSpawn(() => {
      fs.writeFileSync(path.join(home, '.openclaw', 'plugins', 'installs.json'), JSON.stringify({ installRecords: {} }));
    });

    const result = uninstallPlugin({ resolveBinary: () => '/fake/bin/openclaw', spawn });

    expect(result.status).toBe('removed');
    expect(fs.existsSync(live)).toBe(true);
    expect(fs.existsSync(leftover)).toBe(true);
    expect(result.leftovers).toEqual(expect.arrayContaining([live, leftover]));
    expect(result.detail).toMatch(/Left in place \(not an install, not removed\)/);
  });

  it('exit 0 with the record still naming a copy does not strip config or delete the project', () => {
    const installPath = writeManaged('drakon-systems-shieldcortex-realtime-abc123');
    writeInstalls(installPath);
    const configBefore = writeConfig();
    const { spawn, calls } = okSpawn();

    const result = uninstallPlugin({ resolveBinary: () => '/fake/bin/openclaw', spawn });

    expect(result.status).toBe('failed');
    expect(calls).toHaveLength(1);
    expect(fs.readFileSync(path.join(home, '.openclaw', 'openclaw.json'), 'utf-8')).toBe(configBefore);
    expect(fs.existsSync(installPath)).toBe(true);
    expect(result.detail).not.toMatch(/Uninstall complete/);
  });

  it('a non-zero CLI exit strips nothing', () => {
    const installPath = writeManaged('drakon-systems-shieldcortex-realtime-abc123');
    writeInstalls(installPath);
    const configBefore = writeConfig();

    const result = uninstallPlugin({
      resolveBinary: () => '/fake/bin/openclaw',
      spawn: () => ({ status: 1, signal: null, stdout: '', stderr: 'nope' }),
    });

    expect(result.status).toBe('failed');
    expect(result.detail).toMatch(/exited 1/);
    expect(result.detail).toMatch(/nope/);
    expect(fs.readFileSync(path.join(home, '.openclaw', 'openclaw.json'), 'utf-8')).toBe(configBefore);
    expect(fs.existsSync(installPath)).toBe(true);
  });

  it('a timeout strips nothing', () => {
    const installPath = writeManaged('drakon-systems-shieldcortex-realtime-abc123');
    writeInstalls(installPath);
    const configBefore = writeConfig();
    const error = Object.assign(new Error('timed out'), { code: 'ETIMEDOUT' });

    const result = uninstallPlugin({
      resolveBinary: () => '/fake/bin/openclaw',
      spawn: () => ({ status: null, signal: 'SIGTERM', stdout: '', stderr: '', error }),
    });

    expect(result.status).toBe('failed');
    expect(result.detail).toMatch(/timed out/);
    expect(fs.readFileSync(path.join(home, '.openclaw', 'openclaw.json'), 'utf-8')).toBe(configBefore);
    expect(fs.existsSync(installPath)).toBe(true);
  });

  it('a missing openclaw binary prints the command and deletes nothing', () => {
    const installPath = writeManaged('drakon-systems-shieldcortex-realtime-abc123');
    writeInstalls(installPath);
    const configBefore = writeConfig();
    let spawned = false;

    const result = uninstallPlugin({
      resolveBinary: () => null,
      spawn: () => { spawned = true; return { status: 0, signal: null, stdout: '', stderr: '' }; },
    });

    expect(result.status).toBe('failed');
    expect(spawned).toBe(false);
    expect(result.detail).toContain(`openclaw plugins uninstall ${ID}`);
    expect(result.detail).toContain(home);
    expect(fs.readFileSync(path.join(home, '.openclaw', 'openclaw.json'), 'utf-8')).toBe(configBefore);
    expect(fs.existsSync(installPath)).toBe(true);
    expect(fs.existsSync(updateLockPath(path.join(home, '.openclaw')))).toBe(false);
  });

  it('a linked install is not spawned and not removed', () => {
    const checkout = path.join(home, 'src', 'plugin');
    fs.mkdirSync(checkout, { recursive: true });
    fs.writeFileSync(path.join(checkout, 'package.json'), JSON.stringify({ name: PKG, version: '5.22.1' }));
    fs.mkdirSync(path.join(home, '.openclaw'), { recursive: true });
    fs.writeFileSync(path.join(home, '.openclaw', 'openclaw.json'), JSON.stringify({
      plugins: { load: { paths: [checkout] } },
    }));
    let spawned = false;

    const result = uninstallPlugin({
      resolveBinary: () => '/fake/bin/openclaw',
      spawn: () => { spawned = true; return { status: 0, signal: null, stdout: '', stderr: '' }; },
    });

    expect(result.status).toBe('refused');
    expect(spawned).toBe(false);
    expect(result.detail).toContain(checkout);
    expect(fs.existsSync(checkout)).toBe(true);
  });

  it('an unreadable index is not treated as absent', () => {
    fs.mkdirSync(path.join(home, '.openclaw', 'state'), { recursive: true });
    fs.writeFileSync(path.join(home, '.openclaw', 'state', 'openclaw.sqlite'), 'not a database');
    let spawned = false;

    const result = uninstallPlugin({
      resolveBinary: () => '/fake/bin/openclaw',
      spawn: () => { spawned = true; return { status: 0, signal: null, stdout: '', stderr: '' }; },
    });

    expect(result.status).toBe('refused');
    expect(spawned).toBe(false);
    expect(result.detail).toMatch(/index/i);
    expect(fs.readFileSync(path.join(home, '.openclaw', 'state', 'openclaw.sqlite'), 'utf-8')).toBe('not a database');
  });

  it('JSON5 openclaw.json is not rewritten', () => {
    const installPath = writeManaged('drakon-systems-shieldcortex-realtime-abc123');
    writeInstalls(installPath);
    const file = path.join(home, '.openclaw', 'openclaw.json');
    fs.writeFileSync(file, '{ json5: true, }\n');
    let spawned = false;

    const result = uninstallPlugin({
      resolveBinary: () => '/fake/bin/openclaw',
      spawn: () => { spawned = true; return { status: 0, signal: null, stdout: '', stderr: '' }; },
    });

    expect(result.status).toBe('refused');
    expect(spawned).toBe(false);
    expect(fs.readFileSync(file, 'utf-8')).toBe('{ json5: true, }\n');
    expect(fs.existsSync(installPath)).toBe(true);
  });

  it('a symlink at the extensions path is left alone', () => {
    const target = path.join(home, 'checkout');
    fs.mkdirSync(target, { recursive: true });
    fs.writeFileSync(path.join(target, 'package.json'), JSON.stringify({ name: PKG, version: '5.22.1' }));
    fs.writeFileSync(path.join(target, 'marker'), 'keep');
    const extensions = path.join(home, '.openclaw', 'extensions');
    fs.mkdirSync(extensions, { recursive: true });
    fs.symlinkSync(target, path.join(extensions, ID));
    let spawned = false;

    const result = uninstallPlugin({
      resolveBinary: () => '/fake/bin/openclaw',
      spawn: () => { spawned = true; return { status: 0, signal: null, stdout: '', stderr: '' }; },
    });

    expect(result.status).toBe('refused');
    expect(spawned).toBe(false);
    expect(fs.lstatSync(path.join(extensions, ID)).isSymbolicLink()).toBe(true);
    expect(fs.readFileSync(path.join(target, 'marker'), 'utf-8')).toBe('keep');
  });

  it('a legacy extensions copy with a matching manifest is removed, and findExtensionsDir is not required', () => {
    const dir = path.join(home, '.openclaw', 'extensions', ID);
    fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(path.join(dir, 'package.json'), JSON.stringify({ name: PKG, version: '5.22.1' }));
    fs.writeFileSync(path.join(dir, 'openclaw.plugin.json'), JSON.stringify({ id: ID, version: '5.22.1' }));
    fs.writeFileSync(path.join(dir, 'index.js'), 'export default {};\n');
    const configBefore = writeConfig();
    let spawned = false;

    const result = uninstallPlugin({
      resolveBinary: () => '/fake/bin/openclaw',
      spawn: () => { spawned = true; return { status: 0, signal: null, stdout: '', stderr: '' }; },
    });

    expect(result.status).toBe('removed');
    expect(spawned).toBe(false);
    expect(fs.existsSync(dir)).toBe(false);
    expect(fs.existsSync(path.dirname(dir))).toBe(true);
    const config = JSON.parse(fs.readFileSync(path.join(home, '.openclaw', 'openclaw.json'), 'utf-8'));
    expect(config.plugins.allow).toEqual(['other-plugin']);
    expect(configBefore).not.toBe(fs.readFileSync(path.join(home, '.openclaw', 'openclaw.json'), 'utf-8'));
  });

  it('a directory that only shares the name is not removed', () => {
    const dir = path.join(home, '.openclaw', 'extensions', ID);
    fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(path.join(dir, 'package.json'), JSON.stringify({ name: 'someone-elses-plugin', version: '1.0.0' }));
    fs.writeFileSync(path.join(dir, 'marker'), 'keep');

    const result = uninstallPlugin({
      resolveBinary: () => '/fake/bin/openclaw',
      spawn: () => ({ status: 0, signal: null, stdout: '', stderr: '' }),
    });

    expect(result.status).toBe('absent');
    expect(fs.readFileSync(path.join(dir, 'marker'), 'utf-8')).toBe('keep');
  });

  it('a busy update lock is not stolen and nothing is spawned', () => {
    const installPath = writeManaged('drakon-systems-shieldcortex-realtime-abc123');
    writeInstalls(installPath);
    const configBefore = writeConfig();
    const lock = updateLockPath(path.join(home, '.openclaw'));
    fs.writeFileSync(lock, 'shieldcortex-update 1 2026-01-01T00:00:00.000Z other-token\n');
    let spawned = false;

    const result = uninstallPlugin({
      resolveBinary: () => '/fake/bin/openclaw',
      spawn: () => { spawned = true; return { status: 0, signal: null, stdout: '', stderr: '' }; },
    });

    expect(result.status).toBe('failed');
    expect(spawned).toBe(false);
    expect(fs.readFileSync(lock, 'utf-8')).toContain('other-token');
    expect(fs.readFileSync(path.join(home, '.openclaw', 'openclaw.json'), 'utf-8')).toBe(configBefore);
    expect(fs.existsSync(installPath)).toBe(true);
  });

  it('OPENCLAW_HOME points the uninstall at that tree, not os.homedir()', () => {
    const installPath = writeManaged('drakon-systems-shieldcortex-realtime-abc123');
    writeInstalls(installPath);
    fs.mkdirSync(path.join(otherHome, '.openclaw'), { recursive: true });
    const marker = path.join(otherHome, '.openclaw', 'do-not-touch');
    fs.writeFileSync(marker, 'real');
    const { spawn, calls } = okSpawn(() => {
      fs.writeFileSync(path.join(home, '.openclaw', 'plugins', 'installs.json'), JSON.stringify({ installRecords: {} }));
    });

    const result = uninstallPlugin({ resolveBinary: () => '/fake/bin/openclaw', spawn });

    expect(result.status).toBe('removed');
    expect(calls[0].options.env?.HOME).toBe(home);
    expect(calls[0].options.env?.OPENCLAW_HOME).toBe(home);
    expect(fs.readFileSync(marker, 'utf-8')).toBe('real');
    expect(fs.existsSync(path.join(otherHome, '.openclaw', 'extensions'))).toBe(false);
  });

  it('a relative OPENCLAW_HOME is not resolved against cwd', () => {
    const relative = 'sc-1115-relative-home';
    const cwdCopy = path.join(process.cwd(), relative);
    fs.rmSync(cwdCopy, { recursive: true, force: true });
    const planted = path.join(cwdCopy, '.openclaw', 'npm', 'projects', 'drakon-systems-shieldcortex-realtime-cwd', 'node_modules', '@drakon-systems', ID);
    fs.mkdirSync(planted, { recursive: true });
    fs.writeFileSync(path.join(planted, 'package.json'), JSON.stringify({ name: PKG, version: '5.22.1' }));
    fs.writeFileSync(path.join(planted, 'marker'), 'keep');
    fs.mkdirSync(path.join(cwdCopy, '.openclaw', 'plugins'), { recursive: true });
    fs.writeFileSync(path.join(cwdCopy, '.openclaw', 'plugins', 'installs.json'), JSON.stringify({
      installRecords: { [ID]: { source: 'npm', version: '5.22.1', installPath: planted } },
    }));
    process.env.OPENCLAW_HOME = relative;
    let spawned = false;
    try {
      const result = uninstallPlugin({
        resolveBinary: () => '/fake/bin/openclaw',
        spawn: () => { spawned = true; return { status: 0, signal: null, stdout: '', stderr: '' }; },
      });
      expect(spawned).toBe(false);
      expect(fs.readFileSync(path.join(planted, 'marker'), 'utf-8')).toBe('keep');
      expect(result.detail).not.toContain(cwdCopy);
      expect(path.resolve(relative)).toBe(cwdCopy);
    } finally {
      fs.rmSync(cwdCopy, { recursive: true, force: true });
    }
  });

  it('OPENCLAW_STATE_DIR pointing at another tree does not declare this home clean', () => {
    const installPath = writeManaged('drakon-systems-shieldcortex-realtime-abc123');
    writeInstalls(installPath);
    const elsewhere = fs.mkdtempSync(path.join(os.tmpdir(), 'sc-1115-state-'));
    process.env.OPENCLAW_STATE_DIR = elsewhere;
    let spawned = false;
    try {
      const result = uninstallPlugin({
        resolveBinary: () => '/fake/bin/openclaw',
        spawn: () => { spawned = true; return { status: 0, signal: null, stdout: '', stderr: '' }; },
      });
      expect(result.status).toBe('refused');
      expect(spawned).toBe(false);
      expect(result.detail).toContain(elsewhere);
      expect(result.status).not.toBe('removed');
      expect(fs.existsSync(installPath)).toBe(true);
    } finally {
      fs.rmSync(elsewhere, { recursive: true, force: true });
    }
  });

  it('an unresolvable OPENCLAW_STATE_DIR does not spawn', () => {
    writeInstalls(writeManaged('drakon-systems-shieldcortex-realtime-abc123'));
    process.env.OPENCLAW_STATE_DIR = 'relative/state';
    let spawned = false;

    const result = uninstallPlugin({
      resolveBinary: () => '/fake/bin/openclaw',
      spawn: () => { spawned = true; return { status: 0, signal: null, stdout: '', stderr: '' }; },
    });

    expect(result.status).toBe('refused');
    expect(spawned).toBe(false);
    expect(result.detail).toMatch(/unresolvable/);
  });

  it('OPENCLAW_PROFILE is refused rather than guessed', () => {
    writeInstalls(writeManaged('drakon-systems-shieldcortex-realtime-abc123'));
    process.env.OPENCLAW_PROFILE = 'work';
    let spawned = false;

    const result = uninstallPlugin({
      resolveBinary: () => '/fake/bin/openclaw',
      spawn: () => { spawned = true; return { status: 0, signal: null, stdout: '', stderr: '' }; },
    });

    expect(result.status).toBe('refused');
    expect(spawned).toBe(false);
    expect(result.detail).toContain('OPENCLAW_PROFILE');
  });

  it('returns without spawning on a managed fixture only if the test is wrong — the manifest function must spawn', () => {
    writeInstalls(writeManaged('drakon-systems-shieldcortex-realtime-abc123'));
    const { spawn, calls } = okSpawn();
    uninstallPlugin({ resolveBinary: () => '/fake/bin/openclaw', spawn });
    expect(calls.length).toBeGreaterThan(0);
    expect(calls[0].args).toEqual(['plugins', 'uninstall', ID]);
  });
});

describe('#1115 deep-clean does not delete a managed project or restart over a failed removal', () => {
  it('lists the managed project and cleanResidue does not delete it', () => {
    const installPath = writeManaged('drakon-systems-shieldcortex-realtime-abc123');
    writeInstalls(installPath);
    const report = scanForResidue();
    const listed = report.paths.filter((p) => p.category === 'managed-project-reported');
    expect(listed.map((p) => p.description)).toContain(installPath);
    expect(listed.every((p) => p.removal.kind === 'report-only')).toBe(true);
    const cleaned = cleanResidue(report);
    expect(fs.existsSync(installPath)).toBe(true);
    expect(cleaned.removed).not.toContain(installPath);
  });

  it('does not strip plugin config or restart when removal is unverified', async () => {
    const installPath = writeManaged('drakon-systems-shieldcortex-realtime-abc123');
    writeInstalls(installPath);
    const configBefore = writeConfig();
    const restart = jest.fn(async () => ({ attempted: true, restarted: true, method: 'test' as const }));

    const { result, gateway } = await runDeepClean({
      restartGateway: true,
      pluginRemoval: { status: 'failed', detail: 'still registered' },
      restart: restart as never,
    });

    expect(restart).not.toHaveBeenCalled();
    expect(gateway).toBeUndefined();
    expect(fs.readFileSync(path.join(home, '.openclaw', 'openclaw.json'), 'utf-8')).toBe(configBefore);
    expect(fs.existsSync(installPath)).toBe(true);
    expect(result.removed.join('\n')).not.toMatch(/plugins\.entries/);
  });
});

describe('#1115 repair shares the spawn primitive, not the postcondition', () => {
  it('repair calls spawnOpenClawPluginsUninstall and does not build a second argv', () => {
    const src = fs.readFileSync(path.join(path.dirname(new URL(import.meta.url).pathname), '..', 'openclaw.ts'), 'utf-8');
    const start = src.indexOf('export async function repairOpenClawPlugin');
    const end = src.indexOf('export function __setRealtimePublishCheckForTest', start);
    const body = src.slice(start, end);
    expect(body).toContain('spawnOpenClawPluginsUninstall(');
    expect(body).not.toContain("['plugins', 'uninstall'");
    expect(body).toContain('resolveOpenClawBinary(home)');
    expect(body).not.toContain('which openclaw');
    const uninstallStart = src.indexOf('export function uninstallPlugin');
    const uninstallEnd = src.indexOf('function pluginStatus', uninstallStart);
    expect(src.slice(uninstallStart, uninstallEnd)).not.toContain('findExtensionsDir');
  });
});
