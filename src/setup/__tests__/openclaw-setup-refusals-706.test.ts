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

  it('classifies adversarial missing-config output within 50 ms', () => {
    const output = 'config '.repeat(14_285) + 'no config';
    const start = performance.now();
    const refusal = classifyNativePluginInstallFailure('', output, 1);
    expect(performance.now() - start).toBeLessThan(50);
    expect(refusal.configMissing).toBe(true);
  });
});
