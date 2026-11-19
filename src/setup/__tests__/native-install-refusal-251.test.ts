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
  handleOpenClawCommand,
  installOpenClawHook,
  openClawConfigPath,
  getLastNativePluginInstallRefusal,
  __setNativePluginInstallForTest,
  __setNativeSpawnForTest,
  __setLastNativePluginInstallRefusalForTest,
  __clearLastNativePluginInstallRefusalForTest,
} from '../openclaw.js';

const PLUGIN = 'shieldcortex-realtime';

let tempHome: string;
let tempPluginSource: string;
let previousDocker: string | undefined;
let previousPluginSource: string | undefined;
let previousExitCode: string | number | null | undefined;
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
  __setNativeSpawnForTest(null);
  __clearLastNativePluginInstallRefusalForTest();
  if (previousDocker === undefined) delete process.env.DOCKER;
  else process.env.DOCKER = previousDocker;
  if (previousPluginSource === undefined) delete process.env.SHIELDCORTEX_PLUGIN_SOURCE;
  else process.env.SHIELDCORTEX_PLUGIN_SOURCE = previousPluginSource;
  process.exitCode = previousExitCode ?? undefined;
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
  it('warns with openclaw config validate when native install is refused for invalid config — and makes NO local copy (#1109 round 2)', async () => {
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
    // #1109 round 2: the local copy is the offline/development exception — it
    // is not a way around a refusal, so nothing is copied.
    expect(warnings).toMatch(/Nothing was installed: the local plugin copy is only used when the npm package cannot be installed here/);
    expect(fs.existsSync(path.join(tempHome, '.openclaw', 'extensions', PLUGIN))).toBe(false);

    const summary = logLines.join('\n');
    // Must not claim native package/link install after a refusal.
    expect(summary).not.toMatch(/Installed through native OpenClaw package records/);
    expect(summary).not.toMatch(/Installed through native OpenClaw linked plugin records/);
    expect(process.exitCode).toBe(1);
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
    // #251: nothing installed after refusal is a hard failure, not exit-0 quiet.
    expect(process.exitCode).toBe(1);
  });

  it('does not claim native-link success when load.paths already has the plugin but THIS run refused config-invalid', async () => {
    writeConfig({
      plugins: {
        allow: [PLUGIN],
        load: { paths: [path.join(tempHome, '.openclaw', 'extensions', PLUGIN)] },
        entries: { [PLUGIN]: { enabled: true } },
      },
    });
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
    expect(warnings).toMatch(/Not claiming native success|config is invalid/i);
    const summary = logLines.join('\n');
    expect(summary).not.toMatch(/Installed through native OpenClaw linked plugin records/);
    // Mode is skipped (not native-link); summary must say refused.
    expect(summary).toMatch(/skipped after native install refused/i);
    expect(process.exitCode).toBe(1);
  });

  it('keeps native-link when load.paths pre-exists and refusal is non-config-invalid (already exists)', async () => {
    writeConfig({
      plugins: {
        allow: [PLUGIN],
        load: { paths: [path.join(tempHome, '.openclaw', 'extensions', PLUGIN)] },
        entries: { [PLUGIN]: { enabled: true } },
      },
    });
    __setLastNativePluginInstallRefusalForTest({
      reason: 'Error: plugin already exists',
      detail: ['Error: plugin already exists'],
      configInvalid: false,
      truncated: false,
      label: 'package install',
    });
    __setNativePluginInstallForTest(() => null);

    await installOpenClawHook({ noHooks: true, restartGateway: false });

    const summary = logLines.join('\n');
    expect(summary).toMatch(/Installed through native OpenClaw linked plugin records/);
    expect(summary).not.toMatch(/skipped after native install refused/);
    // Soft warning only — pre-existing registration is still valid.
    expect(process.exitCode).not.toBe(1);
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

describe('tryNativeOpenClawPluginInstall real spawn wiring (#251)', () => {
  it('classifies failed spawnSync output into lastNativePluginInstallRefusal without pre-seeding', async () => {
    writeConfig({ plugins: { allow: [], entries: {} } });
    // Do NOT seed refusal state. Drive the real tryNative path via spawn seam.
    __setNativePluginInstallForTest(null);
    __setNativeSpawnForTest((_cmd, _args) => ({
      status: 1,
      stdout: 'Audit, status, health, logs, tasks list/audit, and doctor commands still run with invalid config.\n',
      stderr:
        'OpenClaw config is invalid\n' +
        'File: ~/.openclaw/openclaw.json\n' +
        'Problem:\n' +
        '  - plugins.entries.bogus-dangler: Invalid input\n' +
        'Fix: openclaw doctor --fix\n',
    }));

    await installOpenClawHook({ noHooks: true, restartGateway: false });

    const refusal = getLastNativePluginInstallRefusal();
    expect(refusal).not.toBeNull();
    expect(refusal!.configInvalid).toBe(true);
    expect(refusal!.reason).toMatch(/config is invalid/i);
    expect(refusal!.reason).not.toMatch(/still run with invalid config/i);

    const warnings = warnLines.join('\n');
    expect(warnings).toMatch(/native plugin install refused/i);
    expect(warnings).toMatch(/openclaw config validate/);
    // #1109 round 2: no local fallback after a real config refusal.
    expect(warnings).toMatch(/Nothing was installed/);
    expect(fs.existsSync(path.join(tempHome, '.openclaw', 'extensions', PLUGIN))).toBe(false);
    expect(logLines.join('\n')).not.toMatch(/Installed through native OpenClaw package records/);
    expect(process.exitCode).toBe(1);
  });

  it('accepts Buffer stdout/stderr from spawn (does not wipe diagnosis)', async () => {
    writeConfig({ plugins: { allow: [], entries: {} } });
    __setNativePluginInstallForTest(null);
    __setNativeSpawnForTest(() => ({
      status: 1,
      stdout: Buffer.from('still run with invalid config\n'),
      stderr: Buffer.from('OpenClaw config is invalid\n  × plugins.entries.bogus: bad\n'),
    }));

    await installOpenClawHook({ noHooks: true, restartGateway: false });

    const refusal = getLastNativePluginInstallRefusal();
    expect(refusal?.configInvalid).toBe(true);
    expect(refusal?.reason).toMatch(/config is invalid/i);
  });

  it('a config-invalid package refusal is the diagnosis, and the development --link is NOT tried after it (#1109 round 2)', async () => {
    writeConfig({ plugins: { allow: [], entries: {} } });
    __setNativePluginInstallForTest(null);
    let calls = 0;
    __setNativeSpawnForTest((_cmd, args) => {
      calls += 1;
      const joined = args.join(' ');
      if (joined.includes('--link')) {
        return { status: 1, stderr: 'Error: plugin already exists\n', stdout: '' };
      }
      return {
        status: 1,
        stderr: 'OpenClaw config is invalid\n  × plugins.entries.bogus: Invalid input\n',
        stdout: '',
      };
    });

    await installOpenClawHook({ noHooks: true, restartGateway: false });

    expect(calls).toBe(1);
    const refusal = getLastNativePluginInstallRefusal();
    expect(refusal?.configInvalid).toBe(true);
    expect(refusal?.reason).toMatch(/config is invalid/i);
    expect(process.exitCode).toBe(1);
  });

  it('hard-fails when extensions dir is unavailable after native refusal', async () => {
    // Valid ~/.openclaw, but `extensions` is a FILE so mkdir/open fails and
    // findExtensionsDir returns null — without tripping the earlier
    // "OpenClaw not installed" hard exit.
    const openclawDir = path.join(tempHome, '.openclaw');
    fs.rmSync(openclawDir, { recursive: true, force: true });
    fs.mkdirSync(openclawDir, { recursive: true });
    fs.writeFileSync(path.join(openclawDir, 'extensions'), 'not-a-directory\n');
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
    expect(warnings).toMatch(/extensions directory unavailable|cannot fall back|Nothing was installed/i);
    expect(process.exitCode).toBe(1);
    expect(logLines.join('\n')).toMatch(/skipped after native install refused/i);
    expect(logLines.join('\n')).not.toMatch(/Installed through native OpenClaw/);
  });
});

describe('native package install — npm: source, exact pin (OpenClaw 2026.11.5 ClawHub default)', () => {
  const selfVersion = (): string => JSON.parse(
    fs.readFileSync(path.join(path.dirname(new URL(import.meta.url).pathname), '..', '..', '..', 'package.json'), 'utf-8'),
  ).version;
  const NPM = (): string[] => ['plugins', 'install', '--force', `npm:@drakon-systems/shieldcortex-realtime@${selfVersion()}`];
  const BARE = (): string[] => ['plugins', 'install', '--force', `@drakon-systems/shieldcortex-realtime@${selfVersion()}`];
  const isPackageAttempt = (args: readonly string[]) => !args.includes('--link');

  it('first attempt is `plugins install --force npm:…@<this CLI version>`', async () => {
    writeConfig({ plugins: { allow: [], entries: {} } });
    __setNativePluginInstallForTest(null);
    const calls: string[][] = [];
    __setNativeSpawnForTest((_cmd, args) => { calls.push([...args]); return { status: 0, stdout: '', stderr: '' }; });

    await installOpenClawHook({ noHooks: true, restartGateway: false });

    expect(calls[0]).toEqual(NPM());
    expect(calls.flat().join(' ')).not.toMatch(/@latest|clawhub:/);
  });

  it('retries ONCE with the bare exact spec when OpenClaw predates `npm:`', async () => {
    writeConfig({ plugins: { allow: [], entries: {} } });
    __setNativePluginInstallForTest(null);
    const calls: string[][] = [];
    __setNativeSpawnForTest((_cmd, args) => {
      calls.push([...args]);
      return args.some((a) => a.startsWith('npm:'))
        ? { status: 1, stdout: '', stderr: 'unsupported npm spec: protocol specs are not allowed\n' }
        : { status: 0, stdout: '', stderr: '' };
    });

    await installOpenClawHook({ noHooks: true, restartGateway: false });

    expect(calls.slice(0, 2)).toEqual([NPM(), BARE()]);
    expect(calls.filter(isPackageAttempt)).toHaveLength(2);
    expect(getLastNativePluginInstallRefusal()).toBeNull();
  });

  it.each([
    ['consent', 'Install cancelled; rerun with --force after reviewing the source.\n'],
    ['integrity', 'npm error code EINTEGRITY\n'],
    ['network', 'npm error code ENOTFOUND\n'],
  ])('does NOT retry the package install on a %s failure', async (_label, stderr) => {
    writeConfig({ plugins: { allow: [], entries: {} } });
    __setNativePluginInstallForTest(null);
    const calls: string[][] = [];
    __setNativeSpawnForTest((_cmd, args) => { calls.push([...args]); return { status: 1, stdout: '', stderr }; });

    await installOpenClawHook({ noHooks: true, restartGateway: false });

    expect(calls.filter(isPackageAttempt)).toEqual([NPM()]);
  });
});

describe('native package install — verified against the pin, never clobbering a linked or newer install (#1109 review)', () => {
  const selfVersion = (): string => JSON.parse(
    fs.readFileSync(path.join(path.dirname(new URL(import.meta.url).pathname), '..', '..', '..', 'package.json'), 'utf-8'),
  ).version;
  /** What `openclaw plugins install` leaves on disk: an npm project holding the plugin at `version`. */
  const land = (version: string, project = 'drakon-systems-shieldcortex-realtime-abc', record = true): string => {
    const dir = path.join(tempHome, '.openclaw', 'npm', 'projects', project,
      'node_modules', '@drakon-systems', 'shieldcortex-realtime');
    fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(path.join(dir, 'package.json'), JSON.stringify({ name: '@drakon-systems/shieldcortex-realtime', version }));
    // OpenClaw's install record for it (no SQLite index on this fixture host).
    if (record) {
      fs.mkdirSync(path.join(tempHome, '.openclaw', 'plugins'), { recursive: true });
      fs.writeFileSync(path.join(tempHome, '.openclaw', 'plugins', 'installs.json'),
        JSON.stringify({ installRecords: { [PLUGIN]: { source: 'npm', installPath: dir } } }));
    }
    return dir;
  };
  const extensionCopy = (): string => path.join(tempHome, '.openclaw', 'extensions', PLUGIN);

  it('exit 0 and the pinned build on disk: installed, no failure exit', async () => {
    writeConfig({ plugins: { allow: [], entries: {} } });
    __setNativePluginInstallForTest(null);
    __setNativeSpawnForTest((_cmd, args) => { if (args.some((a) => a.startsWith('npm:'))) land(selfVersion()); return { status: 0, stdout: '', stderr: '' }; });

    await installOpenClawHook({ noHooks: true, restartGateway: false });

    expect(logLines.join('\n')).toContain(`Installed real-time plugin v${selfVersion()} via OpenClaw package install.`);
    expect(process.exitCode).not.toBe(1);
  });

  it('exit 0 but a stale (ClawHub) build on disk: reported with the npm: command, exit 1, and no second copied install', async () => {
    writeConfig({ plugins: { allow: [], entries: {} } });
    __setNativePluginInstallForTest(null);
    __setNativeSpawnForTest((_cmd, args) => { if (args.some((a) => a.startsWith('npm:'))) land('5.17.3'); return { status: 0, stdout: '', stderr: '' }; });

    await installOpenClawHook({ noHooks: true, restartGateway: false });

    const warned = warnLines.join('\n');
    expect(warned).toContain(`the plugin is on v5.17.3, CLI is v${selfVersion()}`);
    expect(warned).toContain(`openclaw plugins install --force npm:@drakon-systems/shieldcortex-realtime@${selfVersion()}`);
    expect(warned).not.toMatch(/FAILED|unprotected/i);
    expect(process.exitCode).toBe(1);
    expect(fs.existsSync(extensionCopy())).toBe(false);
  });

  it('a NEWER install is kept: no package install runs, the command is printed', async () => {
    writeConfig({ plugins: { allow: [], entries: {} } });
    land('999.0.0');
    __setNativePluginInstallForTest(null);
    const calls: string[][] = [];
    __setNativeSpawnForTest((_cmd, args) => { calls.push([...args]); return { status: 0, stdout: '', stderr: '' }; });

    await installOpenClawHook({ noHooks: true, restartGateway: false });

    expect(calls.filter((a) => a[1] === 'install')).toEqual([]);
    // #1109 round 3: kept is not installed — reported, with the command, exit 1.
    expect(warnLines.join('\n')).toContain(`Real-time plugin not installed: the plugin is on v999.0.0, newer than this CLI (v${selfVersion()})`);
    expect(warnLines.join('\n')).toContain(`openclaw plugins install --force npm:@drakon-systems/shieldcortex-realtime@${selfVersion()}`);
    expect(process.exitCode).toBe(1);
  });

  it('a linked install (plugins.load.paths → a checkout\'s plugins/openclaw) is kept: no forced package install replaces it', async () => {
    const checkout = path.join(tempHome, 'src', 'ShieldCortex', 'plugins', 'openclaw');
    fs.mkdirSync(checkout, { recursive: true });
    fs.writeFileSync(path.join(checkout, 'package.json'), JSON.stringify({ name: '@drakon-systems/shieldcortex-realtime', version: '5.0.0' }));
    writeConfig({ plugins: { allow: [], entries: {}, load: { paths: [checkout] } } });
    __setNativePluginInstallForTest(null);
    const calls: string[][] = [];
    __setNativeSpawnForTest((_cmd, args) => { calls.push([...args]); return { status: 0, stdout: '', stderr: '' }; });

    await installOpenClawHook({ noHooks: true, restartGateway: false });

    expect(calls.filter((a) => a.includes('--force'))).toEqual([]);
    expect(warnLines.join('\n')).toMatch(/Real-time plugin not installed: the plugin is a linked install \(v5\.0\.0\)/);
    expect(process.exitCode).toBe(1);
  });
});

describe('#1109 round 3 — a kept install is not an install (through `shieldcortex openclaw install`)', () => {
  const selfVersion = (): string => JSON.parse(
    fs.readFileSync(path.join(path.dirname(new URL(import.meta.url).pathname), '..', '..', '..', 'package.json'), 'utf-8'),
  ).version;
  const linkedCheckout = (version: string): string => {
    const checkout = path.join(tempHome, 'src', 'ShieldCortex', 'plugins', 'openclaw');
    fs.mkdirSync(checkout, { recursive: true });
    fs.writeFileSync(path.join(checkout, 'package.json'), JSON.stringify({ name: '@drakon-systems/shieldcortex-realtime', version }));
    return checkout;
  };
  const record = (calls: string[][]) => (_cmd: string, args: readonly string[]) => {
    calls.push([...args]);
    return { status: 0, stdout: '', stderr: '' };
  };
  const all = (): string => [...logLines, ...warnLines].join('\n');

  it.each([
    ['--no-gateway-restart', ['--no-hooks', '--no-gateway-restart']],
    ['default restart flags', ['--no-hooks']],
  ])('a kept linked copy that is NOT the pin: no "Installed through native …" line, exit 1 (%s)', async (_label, argv) => {
    writeConfig({ plugins: { allow: [], entries: {}, load: { paths: [linkedCheckout('5.0.0')] } } });
    __setNativePluginInstallForTest(null);
    const calls: string[][] = [];
    __setNativeSpawnForTest(record(calls));
    const prevSkip = process.env.SHIELDCORTEX_SKIP_GATEWAY_RESTART;
    process.env.SHIELDCORTEX_SKIP_GATEWAY_RESTART = '1';
    try {
      await handleOpenClawCommand('install', argv);
    } finally {
      if (prevSkip === undefined) delete process.env.SHIELDCORTEX_SKIP_GATEWAY_RESTART;
      else process.env.SHIELDCORTEX_SKIP_GATEWAY_RESTART = prevSkip;
    }

    expect(calls.filter((a) => a[1] === 'install')).toEqual([]);
    expect(all()).not.toMatch(/Installed through native OpenClaw/);
    expect(all()).not.toMatch(/Installed real-time plugin/);
    expect(warnLines.join('\n')).toContain('Real-time plugin not installed: the plugin is a linked install (v5.0.0)');
    expect(warnLines.join('\n')).toContain(`To replace it with v${selfVersion()}: openclaw plugins install --force npm:@drakon-systems/shieldcortex-realtime@${selfVersion()}`);
    expect(warnLines.join('\n')).toMatch(/Not installed — the existing install was kept/);
    expect(process.exitCode).toBe(1);
  });

  it('a kept linked copy AT the pin is fine: said plainly, no install claimed, no failure exit', async () => {
    writeConfig({ plugins: { allow: [], entries: {}, load: { paths: [linkedCheckout(selfVersion())] } } });
    __setNativePluginInstallForTest(null);
    const calls: string[][] = [];
    __setNativeSpawnForTest(record(calls));

    await handleOpenClawCommand('install', ['--no-hooks', '--no-gateway-restart']);

    expect(calls.filter((a) => a[1] === 'install')).toEqual([]);
    expect(logLines.join('\n')).toContain(`Real-time plugin already at v${selfVersion()}`);
    expect(logLines.join('\n')).toMatch(/Existing install kept — it is already this CLI's version; nothing was installed/);
    expect(all()).not.toMatch(/Installed through native OpenClaw/);
    expect(process.exitCode).not.toBe(1);
  });

  it('a stale npm project does not hide a NEWER selected extension copy: no forced install, exit 1', async () => {
    writeConfig({ plugins: { allow: [], entries: {} } });
    const stale = path.join(tempHome, '.openclaw', 'npm', 'projects', 'drakon-systems-shieldcortex-realtime-old', 'node_modules', '@drakon-systems', 'shieldcortex-realtime');
    fs.mkdirSync(stale, { recursive: true });
    fs.writeFileSync(path.join(stale, 'package.json'), JSON.stringify({ name: '@drakon-systems/shieldcortex-realtime', version: '5.0.0' }));
    const ext = path.join(tempHome, '.openclaw', 'extensions', PLUGIN);
    fs.mkdirSync(ext, { recursive: true });
    fs.writeFileSync(path.join(ext, 'index.js'), 'export default {};\n');
    fs.writeFileSync(path.join(ext, 'openclaw.plugin.json'), JSON.stringify({ id: PLUGIN, version: '999.0.0' }));
    __setNativePluginInstallForTest(null);
    const calls: string[][] = [];
    __setNativeSpawnForTest(record(calls));

    await handleOpenClawCommand('install', ['--no-hooks', '--no-gateway-restart']);

    expect(calls.filter((a) => a.includes('--force'))).toEqual([]);
    expect(warnLines.join('\n')).toContain(`the plugin is on v999.0.0, newer than this CLI (v${selfVersion()})`);
    expect(JSON.parse(fs.readFileSync(path.join(ext, 'openclaw.plugin.json'), 'utf-8')).version).toBe('999.0.0');
    expect(process.exitCode).toBe(1);
  });
});

describe('#1109 round 2 — the development installs (--link, local copy) are an exception, not a way around a refusal', () => {
  const selfVersion = (): string => JSON.parse(
    fs.readFileSync(path.join(path.dirname(new URL(import.meta.url).pathname), '..', '..', '..', 'package.json'), 'utf-8'),
  ).version;
  const extensionCopy = (): string => path.join(tempHome, '.openclaw', 'extensions', PLUGIN);
  const linkCalls = (calls: string[][]) => calls.filter((a) => a.includes('--link'));

  it.each([
    ['integrity', 'npm error code EINTEGRITY\nnpm error sha512 integrity checksum failed\n'],
    ['trust', 'plugin trust provenance-invalid: refusing to install\n'],
    ['policy', 'Plugin install blocked by security.installPolicy: package not allowed\n'],
    ['consent', 'Install cancelled; rerun with --force after reviewing the source.\n'],
    ['unknown', 'something nobody has seen before\n'],
  ])('after a %s failure: no --link, no local copy, exit 1', async (_label, stderr) => {
    writeConfig({ plugins: { allow: [], entries: {} } });
    __setNativePluginInstallForTest(null);
    const calls: string[][] = [];
    __setNativeSpawnForTest((_cmd, args) => { calls.push([...args]); return { status: 1, stdout: '', stderr }; });

    await installOpenClawHook({ noHooks: true, restartGateway: false });

    expect(linkCalls(calls)).toEqual([]);
    expect(fs.existsSync(extensionCopy())).toBe(false);
    expect(warnLines.join('\n')).toMatch(/Nothing was installed/);
    expect(process.exitCode).toBe(1);
  });

  it('a timed-out package install is not "unavailable": no --link, no copy', async () => {
    writeConfig({ plugins: { allow: [], entries: {} } });
    __setNativePluginInstallForTest(null);
    const calls: string[][] = [];
    __setNativeSpawnForTest((_cmd, args) => {
      calls.push([...args]);
      return { status: null, stdout: '', stderr: '', signal: 'SIGTERM', error: Object.assign(new Error('spawnSync openclaw ETIMEDOUT'), { code: 'ETIMEDOUT' }) };
    });

    await installOpenClawHook({ noHooks: true, restartGateway: false });

    expect(linkCalls(calls)).toEqual([]);
    expect(fs.existsSync(extensionCopy())).toBe(false);
    expect(process.exitCode).toBe(1);
  });

  it('offline (npm unavailable here): the --link development install runs, and is VERIFIED against the pin', async () => {
    writeConfig({ plugins: { allow: [], entries: {} } });
    __setNativePluginInstallForTest(null);
    const calls: string[][] = [];
    __setNativeSpawnForTest((_cmd, args) => {
      calls.push([...args]);
      return args.includes('--link')
        ? { status: 0, stdout: '', stderr: '' } // linked, but OpenClaw recorded nothing we can read
        : { status: 1, stdout: '', stderr: 'npm error code ENOTFOUND\nnpm error network request to https://registry.npmjs.org failed\n' };
    });

    await installOpenClawHook({ noHooks: true, restartGateway: false });

    expect(linkCalls(calls)).toHaveLength(1);
    const warned = warnLines.join('\n');
    expect(warned).toMatch(/installed by OpenClaw \(linked install\), but no install record names the copy OpenClaw loads/);
    expect(warned).toContain(`openclaw plugins install --force npm:@drakon-systems/shieldcortex-realtime@${selfVersion()}`);
    expect(process.exitCode).toBe(1);
  });

  it('offline: a --link that OpenClaw records at the pin is success', async () => {
    writeConfig({ plugins: { allow: [], entries: {} } });
    __setNativePluginInstallForTest(null);
    __setNativeSpawnForTest((_cmd, args) => {
      if (!args.includes('--link')) return { status: 1, stdout: '', stderr: 'npm error code E404\nnpm error 404 Not Found\n' };
      const linked = args[args.length - 1];
      fs.mkdirSync(path.join(tempHome, '.openclaw', 'plugins'), { recursive: true });
      fs.writeFileSync(path.join(tempHome, '.openclaw', 'plugins', 'installs.json'),
        JSON.stringify({ installRecords: { [PLUGIN]: { source: 'path', sourcePath: linked, installPath: linked } } }));
      return { status: 0, stdout: '', stderr: '' };
    });
    const linkedPkg = path.join(tempHome, 'checkout', 'plugins', 'openclaw');
    fs.mkdirSync(linkedPkg, { recursive: true });
    fs.writeFileSync(path.join(linkedPkg, 'package.json'), JSON.stringify({ name: '@drakon-systems/shieldcortex-realtime', version: selfVersion() }));
    const prev = process.env.SHIELDCORTEX_PLUGIN_PACKAGE_SOURCE;
    process.env.SHIELDCORTEX_PLUGIN_PACKAGE_SOURCE = linkedPkg;
    try {
      await installOpenClawHook({ noHooks: true, restartGateway: false });
    } finally {
      if (prev === undefined) delete process.env.SHIELDCORTEX_PLUGIN_PACKAGE_SOURCE;
      else process.env.SHIELDCORTEX_PLUGIN_PACKAGE_SOURCE = prev;
    }

    expect(logLines.join('\n')).toContain(`Installed real-time plugin v${selfVersion()} via OpenClaw linked install.`);
    expect(process.exitCode).not.toBe(1);
  });

  it('offline and the --link also fails: the local copy runs, and is verified (lands at the pin ⇒ no failure exit)', async () => {
    writeConfig({ plugins: { allow: [], entries: {} } });
    __setNativePluginInstallForTest(null);
    __setNativeSpawnForTest((_cmd, args) => (args.includes('--link')
      ? { status: 1, stdout: '', stderr: 'Error: getaddrinfo EAI_AGAIN registry.npmjs.org\n' }
      : { status: 1, stdout: '', stderr: 'npm error code EAI_AGAIN\nnpm error network request failed\n' }));

    await installOpenClawHook({ noHooks: true, restartGateway: false });

    expect(fs.existsSync(path.join(extensionCopy(), 'openclaw.plugin.json'))).toBe(true);
    expect(JSON.parse(fs.readFileSync(path.join(extensionCopy(), 'openclaw.plugin.json'), 'utf-8')).version).toBe(selfVersion());
    expect(warnLines.join('\n')).not.toMatch(/Local plugin copy written, but/);
  });

  it.each([
    ['refused (policy)', { status: 1, stdout: '', stderr: 'Error: install blocked by plugin install policy\n' }],
    ['timed out', { status: null, stdout: '', stderr: '', error: Object.assign(new Error('spawnSync openclaw ETIMEDOUT'), { code: 'ETIMEDOUT' }) }],
    ['killed', { status: null, stdout: '', stderr: '', signal: 'SIGKILL' }],
  ])('#1109 round 3: offline, then the --link attempt itself is %s: NO local copy, exit 1', async (_label, linkResult) => {
    writeConfig({ plugins: { allow: [], entries: {} } });
    __setNativePluginInstallForTest(null);
    __setNativeSpawnForTest((_cmd, args) => (args.includes('--link')
      ? linkResult as never
      : { status: 1, stdout: '', stderr: 'npm error code EAI_AGAIN\nnpm error network request failed\n' }));

    await installOpenClawHook({ noHooks: true, restartGateway: false });

    expect(fs.existsSync(extensionCopy())).toBe(false);
    expect(warnLines.join('\n')).toMatch(/Nothing was installed/);
    expect(process.exitCode).toBe(1);
  });

  it('the local copy is verified: an OpenClaw record that still selects an older copy makes it exit 1', async () => {
    writeConfig({ plugins: { allow: [], entries: {} } });
    // OpenClaw still records (and loads) an old npm copy.
    const old = path.join(tempHome, '.openclaw', 'npm', 'projects', 'p', 'node_modules', '@drakon-systems', 'shieldcortex-realtime');
    fs.mkdirSync(old, { recursive: true });
    fs.writeFileSync(path.join(old, 'package.json'), JSON.stringify({ name: '@drakon-systems/shieldcortex-realtime', version: '5.0.0' }));
    fs.mkdirSync(path.join(tempHome, '.openclaw', 'plugins'), { recursive: true });
    fs.writeFileSync(path.join(tempHome, '.openclaw', 'plugins', 'installs.json'),
      JSON.stringify({ installRecords: { [PLUGIN]: { source: 'npm', installPath: old } } }));
    __setNativePluginInstallForTest(null);
    __setNativeSpawnForTest((_cmd, args) => (args.includes('--link')
      ? { status: 1, stdout: '', stderr: 'Error: network unreachable\n' }
      : { status: 1, stdout: '', stderr: 'npm error code ENOTFOUND\n' }));

    await installOpenClawHook({ noHooks: true, restartGateway: false });

    expect(warnLines.join('\n')).toMatch(/Local plugin copy written, but the plugin is on v5\.0\.0, CLI is v/);
    expect(process.exitCode).toBe(1);
  });

  it('no exact CLI version: no package install, no --link, no local copy', async () => {
    writeConfig({ plugins: { allow: [], entries: {} } });
    const rootPkg = path.resolve(path.dirname(new URL(import.meta.url).pathname), '..', '..', '..', 'package.json');
    const realRead = fs.readFileSync;
    jest.spyOn(fs, 'readFileSync').mockImplementation(((p: fs.PathOrFileDescriptor, ...rest: unknown[]) => {
      if (typeof p === 'string' && path.resolve(p) === rootPkg) return JSON.stringify({ name: 'shieldcortex', version: 'not-a-version' });
      return (realRead as (...a: unknown[]) => unknown)(p, ...rest);
    }) as typeof fs.readFileSync);
    __setNativePluginInstallForTest(null);
    const calls: string[][] = [];
    __setNativeSpawnForTest((_cmd, args) => { calls.push([...args]); return { status: 0, stdout: '', stderr: '' }; });

    await installOpenClawHook({ noHooks: true, restartGateway: false });

    expect(calls.filter((a) => a[1] === 'install')).toEqual([]);
    expect(fs.existsSync(extensionCopy())).toBe(false);
    expect(warnLines.join('\n')).toMatch(/Nothing was installed/);
    expect(process.exitCode).toBe(1);
  });

  it('two installs: a leftover at the pin + the SELECTED older copy after exit 0 is not success', async () => {
    writeConfig({ plugins: { allow: [], entries: {} } });
    __setNativePluginInstallForTest(null);
    __setNativeSpawnForTest((_cmd, args) => {
      if (args.some((a) => a.startsWith('npm:'))) {
        // The pinned build lands in a new project dir, but OpenClaw's record still names the old one.
        const leftover = path.join(tempHome, '.openclaw', 'npm', 'projects', 'new', 'node_modules', '@drakon-systems', 'shieldcortex-realtime');
        fs.mkdirSync(leftover, { recursive: true });
        fs.writeFileSync(path.join(leftover, 'package.json'), JSON.stringify({ name: '@drakon-systems/shieldcortex-realtime', version: selfVersion() }));
        const old = path.join(tempHome, '.openclaw', 'npm', 'projects', 'old', 'node_modules', '@drakon-systems', 'shieldcortex-realtime');
        fs.mkdirSync(old, { recursive: true });
        fs.writeFileSync(path.join(old, 'package.json'), JSON.stringify({ name: '@drakon-systems/shieldcortex-realtime', version: '5.17.3' }));
        fs.mkdirSync(path.join(tempHome, '.openclaw', 'plugins'), { recursive: true });
        fs.writeFileSync(path.join(tempHome, '.openclaw', 'plugins', 'installs.json'),
          JSON.stringify({ installRecords: { [PLUGIN]: { source: 'npm', installPath: old } } }));
      }
      return { status: 0, stdout: '', stderr: '' };
    });

    await installOpenClawHook({ noHooks: true, restartGateway: false });

    expect(warnLines.join('\n')).toContain(`the plugin is on v5.17.3, CLI is v${selfVersion()}`);
    expect(process.exitCode).toBe(1);
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
    expect(fn).toMatch(/spawnResultText/);
    // Must still not delete the extensions copy before spawn (#214).
    const rmAt = fn.indexOf('rmSync');
    const spawnAt = fn.indexOf('spawn(') >= 0 ? fn.indexOf('spawn(') : fn.indexOf('spawnSync');
    expect(spawnAt).toBeGreaterThan(0);
    if (rmAt >= 0) expect(rmAt).toBeGreaterThan(spawnAt);
  });
});
