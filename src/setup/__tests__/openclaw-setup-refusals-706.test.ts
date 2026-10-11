import fs from 'fs';
import os from 'os';
import path from 'path';
import { afterEach, beforeEach, describe, expect, it, jest } from '@jest/globals';
import {
  __clearLastNativePluginInstallRefusalForTest,
  __setNativePluginInstallForTest,
  __setNativeSpawnForTest,
  classifyNativePluginInstallFailure,
  getLastNativePluginInstallRefusal,
  getNativePluginInstallRefusals,
  installOpenClawHook,
  openClawConfigPath,
} from '../openclaw.js';

let home: string;
let packageSource: string;
let warnings: string[];
let previous: Record<string, string | undefined>;
let previousExitCode: string | number | null | undefined;
const envNames = [
  'DOCKER', 'SHIELDCORTEX_PLUGIN_SOURCE', 'SHIELDCORTEX_PLUGIN_PACKAGE_SOURCE',
  'SHIELDCORTEX_SOURCE_CHECKOUT',
];

beforeEach(() => {
  home = fs.mkdtempSync(path.join(os.tmpdir(), 'sc-706-home-'));
  packageSource = fs.mkdtempSync(path.join(os.tmpdir(), 'sc-706-package-'));
  previous = Object.fromEntries(envNames.map((name) => [name, process.env[name]]));
  previousExitCode = process.exitCode;
  process.exitCode = undefined;
  process.env.DOCKER = 'false';
  process.env.SHIELDCORTEX_PLUGIN_SOURCE = path.join(home, 'missing-local-copy');
  process.env.SHIELDCORTEX_PLUGIN_PACKAGE_SOURCE = packageSource;
  process.env.SHIELDCORTEX_SOURCE_CHECKOUT = '0';
  fs.mkdirSync(path.join(home, '.openclaw'), { recursive: true });
  fs.writeFileSync(path.join(home, '.openclaw', 'openclaw.json'), JSON.stringify({ plugins: { allow: [], entries: {} } }));
  jest.spyOn(os, 'homedir').mockReturnValue(home);
  warnings = [];
  jest.spyOn(console, 'warn').mockImplementation((...args: unknown[]) => { warnings.push(args.map(String).join(' ')); });
  jest.spyOn(console, 'log').mockImplementation(() => {});
  jest.spyOn(console, 'error').mockImplementation(() => {});
  __clearLastNativePluginInstallRefusalForTest();
  __setNativePluginInstallForTest(null);
  expect(openClawConfigPath()).toBe(path.join(home, '.openclaw', 'openclaw.json'));
});

afterEach(() => {
  __setNativeSpawnForTest(null);
  __setNativePluginInstallForTest(null);
  __clearLastNativePluginInstallRefusalForTest();
  for (const name of envNames) {
    if (previous[name] === undefined) delete process.env[name];
    else process.env[name] = previous[name];
  }
  process.exitCode = previousExitCode;
  jest.restoreAllMocks();
  fs.rmSync(home, { recursive: true, force: true });
  fs.rmSync(packageSource, { recursive: true, force: true });
});

describe('OpenClaw native refusals (#706)', () => {
  it('reports both attempts in order and keeps the package refusal primary', async () => {
    __setNativeSpawnForTest((_command, args) => ({
      status: 1,
      stderr: args.includes('--link') ? 'Plugin path not found: /plugin\n' : 'Network request failed: registry unavailable\n',
    }));
    await installOpenClawHook({ noHooks: true, restartGateway: false });
    const refusals = getNativePluginInstallRefusals();
    expect(refusals).toHaveLength(2);
    expect(refusals.map((r) => r.label)).toEqual(['package install', 'linked install']);
    expect(getLastNativePluginInstallRefusal()).toEqual(refusals[0]);
    const output = warnings.join('\n');
    expect(output).toMatch(/Network request failed/);
    expect(output).toMatch(/Plugin path not found/);
    expect(output.indexOf('Network request failed')).toBeLessThan(output.indexOf('Plugin path not found'));
  });

  it('classifies missing config, prints its remedy once, and hard fails', async () => {
    fs.unlinkSync(openClawConfigPath());
    expect(fs.existsSync(openClawConfigPath())).toBe(false);
    __setNativeSpawnForTest((_command, args) => ({
      status: 1,
      stderr: args.includes('--link') ? 'Plugin path not found: /plugin\n' : 'Error: config not found: ~/.openclaw/openclaw.json\n',
    }));
    await installOpenClawHook({ noHooks: true, restartGateway: false });
    expect(getLastNativePluginInstallRefusal()?.configMissing).toBe(true);
    expect(getNativePluginInstallRefusals()).toHaveLength(2);
    const output = warnings.join('\n');
    expect(output).toMatch(/No OpenClaw config was found/);
    expect(output).toContain(openClawConfigPath());
    expect(output).toMatch(/run it once.*shieldcortex openclaw install/);
    expect(output.match(/No OpenClaw config was found/g)).toHaveLength(1);
    expect(process.exitCode).toBe(1);
  });

  // Review of 2d250a45 (B1): the local fallback creates openclaw.json, so the
  // summary must not repeat the historical refusal as "still missing".
  it('does not call a config the fallback created "still missing"', async () => {
    const localSource = fs.mkdtempSync(path.join(os.tmpdir(), 'sc-706-local-'));
    try {
      fs.writeFileSync(path.join(localSource, 'index.js'), 'export default {};\n');
      fs.writeFileSync(path.join(localSource, 'interceptor.js'), 'export {};\n');
      fs.writeFileSync(path.join(localSource, 'intercept-ingest.js'), 'export {};\n');
      fs.writeFileSync(path.join(localSource, 'openclaw.plugin.json'), JSON.stringify({ id: 'shieldcortex-realtime' }));
      process.env.SHIELDCORTEX_PLUGIN_SOURCE = localSource;
      fs.unlinkSync(openClawConfigPath());
      const logs: string[] = [];
      jest.spyOn(console, 'log').mockImplementation((...args: unknown[]) => { logs.push(args.map(String).join(' ')); });
      __setNativeSpawnForTest((_command, args) => ({
        status: 1,
        stderr: args.includes('--link') ? 'Plugin path not found: /plugin\n' : 'Error: config not found: ~/.openclaw/openclaw.json\n',
      }));
      await installOpenClawHook({ noHooks: true, restartGateway: false });
      expect(getNativePluginInstallRefusals()).toHaveLength(2);
      expect(getLastNativePluginInstallRefusal()?.configMissing).toBe(true);
      expect(fs.existsSync(openClawConfigPath())).toBe(true);
      const config = JSON.parse(fs.readFileSync(openClawConfigPath(), 'utf-8'));
      expect(config.plugins.allow).toContain('shieldcortex-realtime');
      const output = [...logs, ...warnings].join('\n');
      expect(output).not.toMatch(/still missing/);
      expect(output).toMatch(/OpenClaw config was missing when the native install ran/);
      expect(output).toContain(`the local fallback created ${openClawConfigPath()}`);
      expect(process.exitCode).toBe(1);
    } finally {
      fs.rmSync(localSource, { recursive: true, force: true });
    }
  });

  it('skips the linked attempt when its source is absent', async () => {
    process.env.SHIELDCORTEX_PLUGIN_PACKAGE_SOURCE = path.join(home, 'absent-package');
    const calls: string[][] = [];
    __setNativeSpawnForTest((_command, args) => {
      calls.push([...args]);
      return { status: 1, stderr: 'Network request failed\n' };
    });
    await installOpenClawHook({ noHooks: true, restartGateway: false });
    expect(calls).toHaveLength(1);
    expect(calls[0]).not.toContain('--link');
    expect(getNativePluginInstallRefusals()).toHaveLength(1);
  });

  it.each([['packaged', '0', false], ['source checkout', '1', true]] as const)(
    '%s install gives an appropriate missing-copy remedy',
    async (_kind, sourceFlag, expectBuildHint) => {
      process.env.SHIELDCORTEX_SOURCE_CHECKOUT = sourceFlag;
      process.env.SHIELDCORTEX_PLUGIN_PACKAGE_SOURCE = path.join(home, 'absent-package');
      __setNativeSpawnForTest(() => ({ status: 1, stderr: 'Network request failed\n' }));
      await installOpenClawHook({ noHooks: true, restartGateway: false });
      const output = warnings.join('\n');
      expect(output.includes('npm run build')).toBe(expectBuildHint);
      if (!expectBuildHint) {
        expect(output).toMatch(/no local plugin copy ships with the npm package/i);
        expect(output).toMatch(/openclaw plugins install @drakon-systems\/shieldcortex-realtime/);
      }
      expect(process.exitCode).toBe(1);
    },
  );

  // ~5-8 ms locally for 100 KB; a quadratic regex takes seconds. 300 ms
  // leaves room for slow CI runners under the full parallel suite.
  it.each([
    ['repeated config tokens', 'config '.repeat(14_285) + 'no config', true],
    ['one long line of config', 'config'.repeat(17_000), false],
    ['repeated ENOENT', 'ENOENT '.repeat(14_000), false],
  ] as const)('classifies adversarial output (%s) within 300 ms', (_name, output, missing) => {
    // Config absent, so the text signal alone decides the result.
    const configPath = path.join(home, 'absent', 'openclaw.json');
    let best = Infinity;
    let refusal = classifyNativePluginInstallFailure('', output, 1, { configPath });
    for (let i = 0; i < 3; i++) {
      const start = performance.now();
      refusal = classifyNativePluginInstallFailure('', output, 1, { configPath });
      best = Math.min(best, performance.now() - start);
    }
    expect(best).toBeLessThan(300);
    expect(refusal.configMissing).toBe(missing);
  });

  it('does not treat a linked-path or duplicate refusal as missing config', () => {
    const configPath = path.join(home, 'absent', 'openclaw.json');
    expect(classifyNativePluginInstallFailure('', 'Plugin path not found: /p\n', 1, { configPath }).configMissing).toBe(false);
    expect(classifyNativePluginInstallFailure('', 'plugin already exists\n', 1, { configPath }).configMissing).toBe(false);
    expect(classifyNativePluginInstallFailure('', 'ENOENT: open /h/.openclaw/openclaw.json\n', 1, { configPath }).configMissing).toBe(true);
  });

  // Review of 562364bc: these lines match the text signal, but the real cause
  // is elsewhere. With openclaw.json present they must never read as missing.
  it.each([
    'Using config /home/u/.openclaw/openclaw.json; package @drakon-systems/shieldcortex-realtime not found',
    'Error: plugin manifest configSchema not found in package',
    'Wrote openclaw.json backup; plugin entry does not exist in registry',
    'Error: npm install failed; no config changes were made',
    'Error: config not found: ~/.openclaw/openclaw.json',
  ])('never reports a present config as missing: %s', (line) => {
    expect(fs.existsSync(openClawConfigPath())).toBe(true);
    const refusal = classifyNativePluginInstallFailure('', `${line}\n`, 1);
    expect(refusal.configMissing).toBe(false);
  });

  it('a present config with a misleading line keeps the package refusal non-fatal-for-config', async () => {
    __setNativeSpawnForTest((_command, args) => ({
      status: 1,
      stderr: args.includes('--link')
        ? 'Plugin path not found: /plugin\n'
        : 'Using config /home/u/.openclaw/openclaw.json; package @drakon-systems/shieldcortex-realtime not found\n',
    }));
    await installOpenClawHook({ noHooks: true, restartGateway: false });
    expect(getLastNativePluginInstallRefusal()?.configMissing).toBe(false);
    const output = warnings.join('\n');
    expect(output).not.toMatch(/No OpenClaw config was found/);
    expect(output).toMatch(/shieldcortex-realtime not found/);
  });

  it('anchors the bare "no config" alternative on word boundaries', () => {
    const configPath = path.join(home, 'absent', 'openclaw.json');
    expect(classifyNativePluginInstallFailure('', 'Error: no config\n', 1, { configPath }).configMissing).toBe(true);
    expect(classifyNativePluginInstallFailure('', 'Error: casino config loaded\n', 1, { configPath }).configMissing).toBe(false);
  });
});
