/**
 * #1110 — the direct `shieldcortex openclaw install` path on a host whose
 * install record is openclaw.json `plugins.installs` (OpenClaw <= 2026.4.24)
 * and whose copy is the npm package in ~/.openclaw/extensions
 * (`dist/index.js`, no root index.js).
 *
 * Before the fix the selected-copy reader answered "none" on that layout, so
 * the forced install ran with no version comparison, and a correct install
 * read as unverified.
 *
 * Hermetic: a temp home, JSON files only, a recorded spawn. No install-index
 * database is written; the fixture host simply has none.
 */
import fs from 'fs';
import os from 'os';
import path from 'path';
import { afterEach, beforeEach, describe, expect, it, jest } from '@jest/globals';
import {
  installOpenClawHook,
  openClawConfigPath,
  __setNativePluginInstallForTest,
  __setNativeSpawnForTest,
  __clearLastNativePluginInstallRefusalForTest,
} from '../openclaw.js';

const PLUGIN = 'shieldcortex-realtime';
const PKG = '@drakon-systems/shieldcortex-realtime';

let tempHome: string;
let tempPluginSource: string;
let saved: { docker?: string; source?: string; exitCode: typeof process.exitCode };
let warnLines: string[];
let logLines: string[];
let calls: string[][];

const selfVersion = (): string => JSON.parse(
  fs.readFileSync(path.join(path.dirname(new URL(import.meta.url).pathname), '..', '..', '..', 'package.json'), 'utf-8'),
).version;
const ext = (): string => path.join(tempHome, '.openclaw', 'extensions', PLUGIN);
/** The published package layout: package.json + manifest + dist/index.js, NO root index.js. */
const nativeCopy = (version: string): string => {
  fs.mkdirSync(path.join(ext(), 'dist'), { recursive: true });
  fs.writeFileSync(path.join(ext(), 'dist', 'index.js'), '');
  fs.writeFileSync(path.join(ext(), 'package.json'), JSON.stringify({ name: PKG, version, main: './dist/index.js' }));
  fs.writeFileSync(path.join(ext(), 'openclaw.plugin.json'), JSON.stringify({ id: PLUGIN, version }));
  return ext();
};
const writeConfig = (installs?: Record<string, unknown>): void => {
  fs.mkdirSync(path.join(tempHome, '.openclaw'), { recursive: true });
  fs.writeFileSync(path.join(tempHome, '.openclaw', 'openclaw.json'),
    JSON.stringify({ plugins: { allow: [], entries: {}, ...(installs ? { installs: { [PLUGIN]: installs } } : {}) } }, null, 2) + '\n');
};
const installCalls = (): string[][] => calls.filter((a) => a[1] === 'install');

beforeEach(() => {
  tempHome = fs.mkdtempSync(path.join(os.tmpdir(), 'sc-1110-home-'));
  tempPluginSource = fs.mkdtempSync(path.join(os.tmpdir(), 'sc-1110-plugin-'));
  for (const file of ['index.js', 'interceptor.js', 'intercept-ingest.js', 'openclaw.plugin.json']) {
    fs.writeFileSync(path.join(tempPluginSource, file), file.endsWith('.json')
      ? JSON.stringify({ id: PLUGIN, name: PLUGIN, version: '0.0.0-test' }) : `// test stub ${file}\n`);
  }
  saved = { docker: process.env.DOCKER, source: process.env.SHIELDCORTEX_PLUGIN_SOURCE, exitCode: process.exitCode };
  process.env.DOCKER = 'false';
  process.env.SHIELDCORTEX_PLUGIN_SOURCE = tempPluginSource;
  process.exitCode = undefined;
  warnLines = [];
  logLines = [];
  calls = [];
  jest.spyOn(console, 'log').mockImplementation((...args: unknown[]) => { logLines.push(args.map(String).join(' ')); });
  jest.spyOn(console, 'warn').mockImplementation((...args: unknown[]) => { warnLines.push(args.map(String).join(' ')); });
  jest.spyOn(console, 'error').mockImplementation(() => {});
  jest.spyOn(os, 'homedir').mockReturnValue(tempHome);
  const resolved = openClawConfigPath();
  if (!resolved.startsWith(tempHome + path.sep)) throw new Error(`REFUSING TO RUN: home redirect failed (${resolved})`);
  __clearLastNativePluginInstallRefusalForTest();
  __setNativePluginInstallForTest(null);
});

afterEach(() => {
  __setNativePluginInstallForTest(null);
  __setNativeSpawnForTest(null);
  __clearLastNativePluginInstallRefusalForTest();
  if (saved.docker === undefined) delete process.env.DOCKER; else process.env.DOCKER = saved.docker;
  if (saved.source === undefined) delete process.env.SHIELDCORTEX_PLUGIN_SOURCE; else process.env.SHIELDCORTEX_PLUGIN_SOURCE = saved.source;
  process.exitCode = saved.exitCode;
  jest.restoreAllMocks();
  fs.rmSync(tempHome, { recursive: true, force: true });
  fs.rmSync(tempPluginSource, { recursive: true, force: true });
});

describe('#1110 — direct install on a native openclaw.json plugins.installs host', () => {
  it('a NEWER native copy is kept: the installer is not invoked, the copy is untouched', async () => {
    const dir = nativeCopy('999.0.0');
    writeConfig({ source: 'npm', spec: PKG, installPath: dir, version: '999.0.0' });
    __setNativeSpawnForTest((_cmd, args) => { calls.push([...args]); return { status: 0, stdout: '', stderr: '' }; });

    await installOpenClawHook({ noHooks: true, restartGateway: false });

    expect(installCalls()).toEqual([]);
    expect(warnLines.join('\n')).toContain(`Real-time plugin not installed: the plugin is on v999.0.0, newer than this CLI (v${selfVersion()})`);
    expect(JSON.parse(fs.readFileSync(path.join(dir, 'package.json'), 'utf-8')).version).toBe('999.0.0');
    expect(process.exitCode).toBe(1);
  });

  it('a newer extension copy NO record or reader selects is still kept (deletion evidence)', async () => {
    // Only a package.json: no record, no dist/index.js, no root index.js.
    fs.mkdirSync(ext(), { recursive: true });
    fs.writeFileSync(path.join(ext(), 'package.json'), JSON.stringify({ name: PKG, version: '999.0.0' }));
    writeConfig();
    __setNativeSpawnForTest((_cmd, args) => { calls.push([...args]); return { status: 0, stdout: '', stderr: '' }; });

    await installOpenClawHook({ noHooks: true, restartGateway: false });

    expect(installCalls()).toEqual([]);
    expect(warnLines.join('\n')).toContain(`holds v999.0.0, newer than this CLI (v${selfVersion()})`);
    expect(process.exitCode).toBe(1);
  });

  it('an OLDER native copy is replaced, and the exact-pin copy that lands is verified', async () => {
    const dir = nativeCopy('5.17.3');
    writeConfig({ source: 'npm', installPath: dir, version: '5.17.3' });
    __setNativeSpawnForTest((_cmd, args) => {
      calls.push([...args]);
      if (args[1] === 'install') {
        nativeCopy(selfVersion());
        writeConfig({ source: 'npm', installPath: dir, version: selfVersion() });
      }
      return { status: 0, stdout: '', stderr: '' };
    });

    await installOpenClawHook({ noHooks: true, restartGateway: false });

    expect(installCalls()).toHaveLength(1);
    expect(logLines.join('\n')).toContain(`Installed real-time plugin v${selfVersion()} via OpenClaw package install.`);
    expect(warnLines.join('\n')).not.toMatch(/Real-time plugin installed by OpenClaw .*but/);
    expect(process.exitCode).not.toBe(1);
  });

  it('round 2: a pin-version record copy does NOT claim "already at" while an older plugins.load.paths copy is configured', async () => {
    nativeCopy(selfVersion());
    // A linked checkout at an older version: OpenClaw ranks it above the record copy.
    const checkout = path.join(tempHome, 'src', 'ShieldCortex', 'plugins', 'openclaw');
    fs.mkdirSync(checkout, { recursive: true });
    fs.writeFileSync(path.join(checkout, 'package.json'), JSON.stringify({ name: PKG, version: '5.17.3' }));
    fs.writeFileSync(path.join(checkout, 'openclaw.plugin.json'), JSON.stringify({ id: PLUGIN, version: '5.17.3' }));
    fs.mkdirSync(path.join(tempHome, '.openclaw'), { recursive: true });
    fs.writeFileSync(path.join(tempHome, '.openclaw', 'openclaw.json'), JSON.stringify({
      plugins: { allow: [], entries: {}, load: { paths: [checkout] }, installs: { [PLUGIN]: { source: 'npm', version: selfVersion() } } },
    }, null, 2) + '\n');
    __setNativeSpawnForTest((_cmd, args) => { calls.push([...args]); return { status: 0, stdout: '', stderr: '' }; });

    await installOpenClawHook({ noHooks: true, restartGateway: false });

    expect(installCalls()).toEqual([]);
    expect(logLines.join('\n')).not.toContain('Real-time plugin already at');
    expect(warnLines.join('\n')).toContain('Real-time plugin not installed:');
    expect(process.exitCode).toBe(1);
  });
});
