import fs from 'fs';
import os from 'os';
import path from 'path';
import { afterEach, beforeEach, describe, expect, it, jest } from '@jest/globals';
import {
  installOpenClawHook,
  openClawConfigPath,
  snapshotOpenClawConfig,
  __setNativePluginInstallForTest,
} from '../openclaw.js';

/**
 * #583 — remaining OpenClaw installer write paths were not audited for linked
 * destinations. #582 covered hooks and the plugin/hook refresh; this covers
 * the extensions copy and the openclaw.json pre-install snapshot.
 *
 * Isolation: os.homedir spy + DOCKER=false + a seeded plugin source. The live
 * operator tree is never read or written.
 */
const PLUGIN = 'shieldcortex-realtime';

let tempHome: string;
let tempPluginSource: string;
let external: string;
let previousDocker: string | undefined;
let previousPluginSource: string | undefined;
let previousExitCode: string | number | undefined;
let warnings: string[];

function configPath(): string {
  return path.join(tempHome, '.openclaw', 'openclaw.json');
}

function writeConfig(cfg: Record<string, unknown>): void {
  fs.mkdirSync(path.dirname(configPath()), { recursive: true });
  fs.writeFileSync(configPath(), JSON.stringify(cfg, null, 2) + '\n');
}

function seedPluginSource(): string {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'sc-583-plugin-'));
  for (const file of ['index.js', 'interceptor.js', 'intercept-ingest.js', 'openclaw.plugin.json']) {
    const body = file === 'openclaw.plugin.json'
      ? JSON.stringify({ id: PLUGIN, name: PLUGIN, version: '0.0.0-test' }, null, 2) + '\n'
      : `// test stub ${file}\n`;
    fs.writeFileSync(path.join(root, file), body);
  }
  return root;
}

function plantKeep(root: string, name: string): void {
  fs.mkdirSync(root, { recursive: true });
  fs.writeFileSync(path.join(root, name), 'not yours\n');
}

function expectKeep(root: string, name: string): void {
  expect(fs.readFileSync(path.join(root, name), 'utf-8')).toBe('not yours\n');
}

beforeEach(() => {
  tempHome = fs.mkdtempSync(path.join(os.tmpdir(), 'sc-583-home-'));
  tempPluginSource = seedPluginSource();
  external = fs.mkdtempSync(path.join(os.tmpdir(), 'sc-583-external-'));
  previousDocker = process.env.DOCKER;
  previousPluginSource = process.env.SHIELDCORTEX_PLUGIN_SOURCE;
  process.env.DOCKER = 'false';
  process.env.SHIELDCORTEX_PLUGIN_SOURCE = tempPluginSource;
  previousExitCode = process.exitCode;
  process.exitCode = undefined;
  warnings = [];
  jest.spyOn(console, 'log').mockImplementation(() => {});
  jest.spyOn(console, 'warn').mockImplementation((...args: unknown[]) => {
    warnings.push(args.map(String).join(' '));
  });
  jest.spyOn(console, 'error').mockImplementation(() => {});
  jest.spyOn(os, 'homedir').mockReturnValue(tempHome);
  const resolved = openClawConfigPath();
  if (!resolved.startsWith(tempHome + path.sep)) {
    throw new Error(`REFUSING TO RUN: home redirect failed (${resolved})`);
  }
  fs.mkdirSync(path.join(tempHome, '.openclaw'), { recursive: true });
  writeConfig({ plugins: { allow: [], entries: {} } });
  __setNativePluginInstallForTest(() => null);
});

afterEach(() => {
  __setNativePluginInstallForTest(null);
  if (previousDocker === undefined) delete process.env.DOCKER;
  else process.env.DOCKER = previousDocker;
  if (previousPluginSource === undefined) delete process.env.SHIELDCORTEX_PLUGIN_SOURCE;
  else process.env.SHIELDCORTEX_PLUGIN_SOURCE = previousPluginSource;
  process.exitCode = previousExitCode;
  jest.restoreAllMocks();
  fs.rmSync(tempHome, { recursive: true, force: true });
  fs.rmSync(tempPluginSource, { recursive: true, force: true });
  fs.rmSync(external, { recursive: true, force: true });
});

describe('#583 snapshot refuses a linked openclaw.json or planted bak dest', () => {
  it('writes nothing when openclaw.json itself is a symlink', () => {
    const real = path.join(external, 'openclaw.json');
    plantKeep(external, 'openclaw.json');
    const oc = path.join(tempHome, '.openclaw');
    fs.rmSync(configPath());
    fs.symlinkSync(real, configPath());

    const result = snapshotOpenClawConfig(tempHome);

    expect(result).toBeNull();
    expectKeep(external, 'openclaw.json');
    const leftovers = fs.readdirSync(oc).filter((n) => n.includes('sc-preinstall.bak'));
    expect(leftovers).toEqual([]);
    expect(warnings.join('\n')).toMatch(/is a symlink; nothing written/);
  });

  it('writes nothing through a planted snapshot destination symlink', () => {
    const frozen = new Date('2026-09-28T07:00:00.000Z');
    jest.useFakeTimers();
    jest.setSystemTime(frozen);
    try {
      const destName = `openclaw.json.sc-preinstall.bak-${frozen.toISOString().replace(/[:.]/g, '-')}`;
      const dest = path.join(tempHome, '.openclaw', destName);
      plantKeep(external, 'captured.json');
      fs.symlinkSync(path.join(external, 'captured.json'), dest);

      const result = snapshotOpenClawConfig(tempHome);

      expect(result).toBeNull();
      expectKeep(external, 'captured.json');
      expect(fs.lstatSync(dest).isSymbolicLink()).toBe(true);
      expect(warnings.join('\n')).toMatch(/is a symlink; nothing written/);
    } finally {
      jest.useRealTimers();
    }
  });

  it('still snapshots an ordinary file', () => {
    writeConfig({ plugins: { allow: ['codex'] } });
    const before = fs.readFileSync(configPath(), 'utf-8');
    const dest = snapshotOpenClawConfig(tempHome);
    expect(dest).not.toBeNull();
    expect(fs.readFileSync(dest!, 'utf-8')).toBe(before);
  });
});

describe('#583 extensions copy refuses a linked destination at each level', () => {
  it('writes nothing through a linked extensions directory', async () => {
    plantKeep(external, 'keep.txt');
    fs.symlinkSync(external, path.join(tempHome, '.openclaw', 'extensions'));

    await installOpenClawHook({ noHooks: true, restartGateway: false });

    expectKeep(external, 'keep.txt');
    expect(fs.existsSync(path.join(external, PLUGIN))).toBe(false);
    expect(fs.lstatSync(path.join(tempHome, '.openclaw', 'extensions')).isSymbolicLink()).toBe(true);
    expect(warnings.join('\n')).toMatch(/is a symlink; nothing written/);
    expect(process.exitCode).toBe(1);
  });

  it('writes nothing through a linked plugin directory under a real extensions dir', async () => {
    const extensions = path.join(tempHome, '.openclaw', 'extensions');
    fs.mkdirSync(extensions, { recursive: true });
    plantKeep(external, 'keep.txt');
    fs.symlinkSync(external, path.join(extensions, PLUGIN));

    await installOpenClawHook({ noHooks: true, restartGateway: false });

    expectKeep(external, 'keep.txt');
    expect(fs.existsSync(path.join(external, 'index.js'))).toBe(false);
    expect(fs.lstatSync(path.join(extensions, PLUGIN)).isSymbolicLink()).toBe(true);
    expect(warnings.join('\n')).toMatch(/is a symlink; nothing written/);
    expect(process.exitCode).toBe(1);
  });

  it('writes nothing through a linked leaf inside a real plugin directory', async () => {
    const destDir = path.join(tempHome, '.openclaw', 'extensions', PLUGIN);
    fs.mkdirSync(destDir, { recursive: true });
    plantKeep(external, 'index.js');
    fs.symlinkSync(path.join(external, 'index.js'), path.join(destDir, 'index.js'));

    await installOpenClawHook({ noHooks: true, restartGateway: false });

    expectKeep(external, 'index.js');
    expect(fs.lstatSync(path.join(destDir, 'index.js')).isSymbolicLink()).toBe(true);
    expect(warnings.join('\n')).toMatch(/is a symlink; nothing written/);
    expect(process.exitCode).toBe(1);
  });
});
