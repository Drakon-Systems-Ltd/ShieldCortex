/**
 * #251 — install/repair must not swallow OpenClaw's config-invalid refusal.
 *
 * Before this fix, tryNativeOpenClawPluginInstall discarded every line of a
 * failed `openclaw plugins install` and returned bare null. installPlugin then
 * fell through to the local-copy path and printed plain success — so operators
 * following doctor's `shieldcortex repair` advice never saw that OpenClaw had
 * refused registration because the config was invalid.
 */

import fs from 'fs';
import os from 'os';
import path from 'path';
import { afterEach, beforeEach, describe, expect, it, jest } from '@jest/globals';

import {
  classifyNativePluginInstallFailure,
  installOpenClawHook,
  openClawConfigPath,
  getLastNativePluginInstallRefusal,
  __setNativePluginInstallForTest,
  __setLastNativePluginInstallRefusalForTest,
  __clearLastNativePluginInstallRefusalForTest,
} from '../openclaw.js';

const PLUGIN = 'shieldcortex-realtime';

let tempHome: string;
let tempPluginSource: string;
let previousDocker: string | undefined;
let previousPluginSource: string | undefined;
let previousExitCode: string | number | undefined;
let warnLines: string[];
let logLines: string[];

function configPath(): string {
  return path.join(tempHome, '.openclaw', 'openclaw.json');
}

function writeConfig(cfg: Record<string, unknown>): void {
  fs.mkdirSync(path.dirname(configPath()), { recursive: true });
  fs.writeFileSync(configPath(), JSON.stringify(cfg, null, 2) + '\n');
}

/** Minimal plugin source tree so the local-copy fallback can run. */
function seedPluginSource(): string {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'sc-251-plugin-'));
  for (const file of ['index.js', 'interceptor.js', 'intercept-ingest.js', 'openclaw.plugin.json']) {
    const body = file === 'openclaw.plugin.json'
      ? JSON.stringify({ id: PLUGIN, name: PLUGIN, version: '0.0.0-test' }, null, 2) + '\n'
      : `// test stub ${file}\n`;
    fs.writeFileSync(path.join(root, file), body);
  }
  return root;
}

beforeEach(() => {
  tempHome = fs.mkdtempSync(path.join(os.tmpdir(), 'sc-251-home-'));
  tempPluginSource = seedPluginSource();
  previousDocker = process.env.DOCKER;
  previousPluginSource = process.env.SHIELDCORTEX_PLUGIN_SOURCE;
  process.env.DOCKER = 'false';
  process.env.SHIELDCORTEX_PLUGIN_SOURCE = tempPluginSource;
  previousExitCode = process.exitCode;
  process.exitCode = undefined;
  warnLines = [];
  logLines = [];
  jest.spyOn(console, 'log').mockImplementation((...args: unknown[]) => {
    logLines.push(args.map(String).join(' '));
  });
  jest.spyOn(console, 'warn').mockImplementation((...args: unknown[]) => {
    warnLines.push(args.map(String).join(' '));
  });
  jest.spyOn(console, 'error').mockImplementation(() => {});
  jest.spyOn(os, 'homedir').mockReturnValue(tempHome);
  const resolved = openClawConfigPath();
  if (!resolved.startsWith(tempHome + path.sep)) {
    throw new Error(`REFUSING TO RUN: home redirect failed (${resolved})`);
  }
  __clearLastNativePluginInstallRefusalForTest();
});

afterEach(() => {
  __setNativePluginInstallForTest(null);
  __clearLastNativePluginInstallRefusalForTest();
  if (previousDocker === undefined) delete process.env.DOCKER;
  else process.env.DOCKER = previousDocker;
  if (previousPluginSource === undefined) delete process.env.SHIELDCORTEX_PLUGIN_SOURCE;
  else process.env.SHIELDCORTEX_PLUGIN_SOURCE = previousPluginSource;
  process.exitCode = previousExitCode;
  jest.restoreAllMocks();
  fs.rmSync(tempHome, { recursive: true, force: true });
  fs.rmSync(tempPluginSource, { recursive: true, force: true });
});

describe('classifyNativePluginInstallFailure (#251)', () => {
  it('surfaces config-invalid as the reason and flags it', () => {
    const refusal = classifyNativePluginInstallFailure(
      'Audit, status, health, logs, tasks list/audit, and doctor commands still run with invalid config.\n',
      'OpenClaw config is invalid\nFile: ~/.openclaw/openclaw.json\nProblem:\n  - plugins.entries.bogus-dangler: Invalid input\nFix: openclaw doctor --fix\n',
      1,
      { label: 'package install', home: tempHome },
    );
    expect(refusal.configInvalid).toBe(true);
    expect(refusal.reason).toMatch(/config is invalid/i);
    // Must not prefer the reassuring last line over the diagnosis.
    expect(refusal.reason).not.toMatch(/still run with invalid config/i);
    expect(refusal.label).toBe('package install');
    // Operator-facing detail should still mention the offending key when present.
    expect(refusal.detail.join('\n')).toMatch(/bogus-dangler|Invalid input|config is invalid/i);
  });

  it('does not mark a generic failure as config-invalid', () => {
    const refusal = classifyNativePluginInstallFailure(
      '',
      'Error: plugin already exists\n',
      1,
      { label: 'linked install' },
    );
    expect(refusal.configInvalid).toBe(false);
    expect(refusal.reason).toMatch(/already exists|Error/i);
  });

  it('falls back to exit status when there is no usable output', () => {
    const refusal = classifyNativePluginInstallFailure('', '', 1, { label: 'package install' });
    expect(refusal.configInvalid).toBe(false);
    expect(refusal.reason).toMatch(/exited 1|no usable output/i);
  });
});

describe('install/repair surfaces native refusal (#251)', () => {
  it('warns with openclaw config validate when native install is refused for invalid config, even if local copy succeeds', async () => {
    writeConfig({
      plugins: {
        allow: ['codex'],
        entries: { codex: { enabled: true } },
      },
    });

    __setLastNativePluginInstallRefusalForTest({
      reason: 'OpenClaw config is invalid',
      detail: [
        'OpenClaw config is invalid',
        'plugins.entries.bogus-dangler: Invalid input',
      ],
      configInvalid: true,
      truncated: false,
      label: 'package install',
    });
    __setNativePluginInstallForTest(() => null);

    await installOpenClawHook({ noHooks: true, restartGateway: false });

    const warnings = warnLines.join('\n');
    expect(warnings).toMatch(/native plugin install refused/i);
    expect(warnings).toMatch(/OpenClaw config is invalid/i);
    expect(warnings).toMatch(/openclaw config validate/);
    // Local fallback must not read as a plain native success.
    expect(warnings).toMatch(/local fallback|not a native registration/i);

    const summary = logLines.join('\n');
    // Must not claim native package/link install after a refusal.
    expect(summary).not.toMatch(/Installed through native OpenClaw package records/);
    expect(summary).not.toMatch(/Installed through native OpenClaw linked plugin records/);
  });

  it('does not report plain skip when native was refused and plugin source is missing', async () => {
    // Remove the seeded plugin source so fallback cannot copy.
    fs.rmSync(tempPluginSource, { recursive: true, force: true });
    process.env.SHIELDCORTEX_PLUGIN_SOURCE = path.join(tempHome, 'missing-plugin-source');

    writeConfig({ plugins: { allow: [], entries: {} } });
    __setLastNativePluginInstallRefusalForTest({
      reason: 'OpenClaw config is invalid',
      detail: ['OpenClaw config is invalid'],
      configInvalid: true,
      truncated: false,
      label: 'package install',
    });
    __setNativePluginInstallForTest(() => null);

    await installOpenClawHook({ noHooks: true, restartGateway: false });

    const warnings = warnLines.join('\n');
    expect(warnings).toMatch(/native plugin install refused/i);
    expect(warnings).toMatch(/cannot fall back|Nothing was installed/i);

    const summary = logLines.join('\n');
    expect(summary).toMatch(/skipped after native install refused/i);
    expect(summary).not.toMatch(/Installed through native OpenClaw/);
  });

  it('clears the refusal state when native install succeeds', async () => {
    writeConfig({
      plugins: {
        allow: [PLUGIN],
        entries: { [PLUGIN]: { enabled: true } },
      },
    });
    __setLastNativePluginInstallRefusalForTest({
      reason: 'stale',
      detail: ['stale'],
      configInvalid: true,
      truncated: false,
      label: 'package install',
    });
    __setNativePluginInstallForTest(() => 'native-package');

    await installOpenClawHook({ noHooks: true, restartGateway: false });

    expect(getLastNativePluginInstallRefusal()).toBeNull();
    const summary = logLines.join('\n');
    expect(summary).toMatch(/native OpenClaw package records/);
    expect(warnLines.join('\n')).not.toMatch(/native plugin install refused/i);
  });
});

describe('#251 source contract — tryNativeOpenClawPluginInstall keeps child output', () => {
  it('classifies spawn output instead of bare-null discard', () => {
    const src = fs.readFileSync(
      path.join(path.dirname(new URL(import.meta.url).pathname), '..', 'openclaw.ts'),
      'utf-8',
    );
    const start = src.indexOf('function tryNativeOpenClawPluginInstall');
    const end = src.indexOf('function findExtensionsDir');
    expect(start).toBeGreaterThan(0);
    expect(end).toBeGreaterThan(start);
    const fn = src.slice(start, end);
    expect(fn).toMatch(/classifyNativePluginInstallFailure/);
    expect(fn).toMatch(/lastNativePluginInstallRefusal/);
    expect(fn).toMatch(/summariseCommandOutput|classifyNativePluginInstallFailure/);
    // Must still not delete the extensions copy before spawn (#214).
    const rmAt = fn.indexOf('rmSync');
    const spawnAt = fn.indexOf('spawnSync');
    expect(spawnAt).toBeGreaterThan(0);
    if (rmAt >= 0) expect(rmAt).toBeGreaterThan(spawnAt);
  });
});
