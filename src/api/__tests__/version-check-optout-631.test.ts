/**
 * #631 — operator opt-out for the dashboard's automatic npm registry lookup.
 *
 * With `dashboardUpdateCheck: false` (or SHIELDCORTEX_SKIP_UPDATE_CHECK=1) every
 * path through checkForUpdates — normal, warm cache, forceRefresh — must spawn
 * nothing and report `checkStatus: 'disabled'`, never a cached or empty answer
 * that reads as "up to date". The default stays on.
 *
 * child_process is mocked: no npm, pgrep or kill ever runs. Config lives in a
 * per-suite directory, never the operator's ~/.shieldcortex.
 */

import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, jest } from '@jest/globals';
import { existsSync, mkdirSync, mkdtempSync, readFileSync, rmSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';

const execFileSyncMock = jest.fn();
const execFileMock = jest.fn();
const execSyncMock = jest.fn();
const execMock = jest.fn();
const spawnMock = jest.fn();
const spawnSyncMock = jest.fn();

jest.unstable_mockModule('child_process', () => {
  const api = {
    execFileSync: execFileSyncMock,
    execFile: execFileMock,
    execSync: execSyncMock,
    exec: execMock,
    spawn: spawnMock,
    spawnSync: spawnSyncMock,
  };
  return { ...api, default: api };
});

const SCRATCH_ROOT = existsSync('/home/ubuntu/.hermes/cache/scratch')
  ? '/home/ubuntu/.hermes/cache/scratch'
  : tmpdir();
mkdirSync(SCRATCH_ROOT, { recursive: true });
const suiteDir = mkdtempSync(join(SCRATCH_ROOT, 'sc631-version-optout-'));
const originalConfigDir = process.env.SHIELDCORTEX_CONFIG_DIR;
const originalSkipEnv = process.env.SHIELDCORTEX_SKIP_UPDATE_CHECK;

const version = await import('../version.js');
const config = await import('../../cloud/config.js');
const cli = await import('../../cloud/cli.js');

function configFile(): string {
  return join(suiteDir, 'config.json');
}

function npmViewCalls(): unknown[][] {
  return execFileSyncMock.mock.calls.filter(
    ([cmd, args]) => cmd === 'npm' && Array.isArray(args) && args[0] === 'view',
  );
}

function anySpawn(): number {
  return (
    execFileSyncMock.mock.calls.length
    + execFileMock.mock.calls.length
    + execSyncMock.mock.calls.length
    + execMock.mock.calls.length
    + spawnMock.mock.calls.length
    + spawnSyncMock.mock.calls.length
  );
}

beforeAll(() => {
  process.env.SHIELDCORTEX_CONFIG_DIR = suiteDir;
});

beforeEach(async () => {
  process.env.SHIELDCORTEX_CONFIG_DIR = suiteDir;
  delete process.env.SHIELDCORTEX_SKIP_UPDATE_CHECK;
  rmSync(configFile(), { force: true });
  config.clearCloudConfigCache();
  // Drain any registry answer cached by a previous test with a disabled call,
  // which drops the module-level cache (#631).
  config.setDashboardUpdateCheck(false);
  await version.checkForUpdates();
  rmSync(configFile(), { force: true });
  config.clearCloudConfigCache();

  for (const m of [execFileSyncMock, execFileMock, execSyncMock, execMock, spawnMock, spawnSyncMock]) m.mockReset();
  execFileSyncMock.mockReturnValue('99.0.0\n');
});

afterEach(() => {
  jest.restoreAllMocks();
});

afterAll(() => {
  if (originalConfigDir === undefined) delete process.env.SHIELDCORTEX_CONFIG_DIR;
  else process.env.SHIELDCORTEX_CONFIG_DIR = originalConfigDir;
  if (originalSkipEnv === undefined) delete process.env.SHIELDCORTEX_SKIP_UPDATE_CHECK;
  else process.env.SHIELDCORTEX_SKIP_UPDATE_CHECK = originalSkipEnv;
  if (suiteDir.includes('sc631-version-optout-')) rmSync(suiteDir, { recursive: true, force: true });
});

describe('default behaviour is unchanged (#631)', () => {
  it('queries the registry once when nothing is configured and reports ok', async () => {
    const info = await version.checkForUpdates();

    expect(npmViewCalls()).toHaveLength(1);
    const [cmd, args] = npmViewCalls()[0] as [string, string[]];
    expect(cmd).toBe('npm');
    expect(args).toEqual(['view', 'shieldcortex', 'version']);
    expect(info.checkStatus).toBe('ok');
    expect(info.checkDisabledBy).toBeUndefined();
    expect(info.latestVersion).toBe('99.0.0');
    expect(info.updateAvailable).toBe(true);
    expect(info.cacheHit).toBe(false);
    expect(typeof info.checkedAt).toBe('string');
  });

  it('serves the second call from cache with checkStatus ok', async () => {
    await version.checkForUpdates();
    const cached = await version.checkForUpdates();

    expect(npmViewCalls()).toHaveLength(1);
    expect(cached.cacheHit).toBe(true);
    expect(cached.checkStatus).toBe('ok');
    expect(cached.latestVersion).toBe('99.0.0');
  });

  it('an explicit dashboardUpdateCheck: true keeps the check on', async () => {
    config.setDashboardUpdateCheck(true);
    const info = await version.checkForUpdates(true);
    expect(npmViewCalls()).toHaveLength(1);
    expect(info.checkStatus).toBe('ok');
  });

  it('turns off npm\'s own update notifier for the lookup, without touching global npm config', async () => {
    await version.checkForUpdates();
    const opts = npmViewCalls()[0][2] as { env?: Record<string, string>; shell?: unknown };
    expect(opts.env?.npm_config_update_notifier).toBe('false');
    expect(opts.shell).toBeUndefined();
    // A copy for the child only: the API process's own environment is untouched.
    expect(opts.env).not.toBe(process.env);
  });

  it('reports a registry failure as failed, not as up to date', async () => {
    execFileSyncMock.mockImplementation(() => {
      throw new Error('ENOTFOUND registry.npmjs.org');
    });
    const info = await version.checkForUpdates(true);
    expect(info.checkStatus).toBe('failed');
    expect(info.latestVersion).toBeNull();
    expect(info.updateAvailable).toBe(false);
  });
});

describe('disabled via config (#631)', () => {
  beforeEach(() => {
    config.setDashboardUpdateCheck(false);
  });

  it('normal request: no subprocess, reported as disabled', async () => {
    const info = await version.checkForUpdates();

    expect(anySpawn()).toBe(0);
    expect(info).toMatchObject({
      latestVersion: null,
      updateAvailable: false,
      checkedAt: null,
      cacheHit: false,
      checkStatus: 'disabled',
      checkDisabledBy: 'config',
    });
  });

  it('forceRefresh: still no subprocess', async () => {
    const info = await version.checkForUpdates(true);
    expect(anySpawn()).toBe(0);
    expect(info.checkStatus).toBe('disabled');
  });

  it('keeps installed/running/stale facts available without a lookup', async () => {
    const info = await version.checkForUpdates();
    expect(info.currentVersion).toBe(version.getCurrentVersion());
    expect(info.runningVersion).toBe(version.getRunningVersion());
    expect(info.stale).toBe(version.getRunningVersion() !== version.getCurrentVersion());
    expect(info.currentVersion).not.toBe('unknown');
    expect(anySpawn()).toBe(0);
  });

  it('does not disable the explicit update action (mocked)', async () => {
    execFileMock.mockImplementation((...call: unknown[]) => {
      const cb = call[call.length - 1] as (e: Error | null, stdout: string, stderr: string) => void;
      cb(new Error('mocked'), '', 'mocked failure');
    });
    const result = await version.performUpdate();
    expect(execFileMock).toHaveBeenCalledTimes(1);
    expect((execFileMock.mock.calls[0] as unknown[])[1]).toEqual(['update', '-g', 'shieldcortex']);
    expect(result.success).toBe(false);
  });
});

describe('warm cache, then disabled (#631)', () => {
  it('never replays the cached registry answer once disabled, and re-enabling queries fresh', async () => {
    const before = await version.checkForUpdates();
    expect(before.updateAvailable).toBe(true);
    expect(npmViewCalls()).toHaveLength(1);

    config.setDashboardUpdateCheck(false);
    const normal = await version.checkForUpdates();
    const forced = await version.checkForUpdates(true);

    for (const info of [normal, forced]) {
      expect(info.checkStatus).toBe('disabled');
      expect(info.cacheHit).toBe(false);
      expect(info.latestVersion).toBeNull();
      expect(info.updateAvailable).toBe(false);
      expect(info.checkedAt).toBeNull();
    }
    expect(npmViewCalls()).toHaveLength(1);

    config.setDashboardUpdateCheck(true);
    const after = await version.checkForUpdates();
    expect(after.cacheHit).toBe(false);
    expect(after.checkStatus).toBe('ok');
    expect(npmViewCalls()).toHaveLength(2);
  });
});

describe('SHIELDCORTEX_SKIP_UPDATE_CHECK (#631)', () => {
  it('=1 disables the check with no config, on every path', async () => {
    process.env.SHIELDCORTEX_SKIP_UPDATE_CHECK = '1';
    const normal = await version.checkForUpdates();
    const forced = await version.checkForUpdates(true);
    expect(anySpawn()).toBe(0);
    expect(normal).toMatchObject({ checkStatus: 'disabled', checkDisabledBy: 'env' });
    expect(forced).toMatchObject({ checkStatus: 'disabled', checkDisabledBy: 'env' });
  });

  it('only "1" opts out; other values leave the default on', async () => {
    process.env.SHIELDCORTEX_SKIP_UPDATE_CHECK = '0';
    const info = await version.checkForUpdates();
    expect(info.checkStatus).toBe('ok');
    expect(npmViewCalls()).toHaveLength(1);
  });

  it('cannot re-enable a check the config turned off', async () => {
    config.setDashboardUpdateCheck(false);
    process.env.SHIELDCORTEX_SKIP_UPDATE_CHECK = '0';
    const info = await version.checkForUpdates(true);
    expect(info.checkStatus).toBe('disabled');
    expect(anySpawn()).toBe(0);
  });
});

describe('getDashboardUpdateCheckSetting / config persistence (#631)', () => {
  it('truth table over raw config and env', () => {
    const get = config.getDashboardUpdateCheckSetting;
    expect(get({}, {})).toEqual({ enabled: true });
    expect(get({ dashboardUpdateCheck: true }, {})).toEqual({ enabled: true });
    expect(get({ dashboardUpdateCheck: false }, {})).toEqual({ enabled: false, disabledBy: 'config' });
    // Strict boolean, like the other config switches: a string is not `false`.
    expect(get({ dashboardUpdateCheck: 'false' }, {})).toEqual({ enabled: true });
    expect(get({ dashboardUpdateCheck: 0 }, {})).toEqual({ enabled: true });
    expect(get({}, { SHIELDCORTEX_SKIP_UPDATE_CHECK: '1' })).toEqual({ enabled: false, disabledBy: 'env' });
    expect(get({ dashboardUpdateCheck: true }, { SHIELDCORTEX_SKIP_UPDATE_CHECK: '1' })).toEqual({ enabled: false, disabledBy: 'env' });
    expect(get({}, { SHIELDCORTEX_SKIP_UPDATE_CHECK: 'true' })).toEqual({ enabled: true });
  });

  it('setDashboardUpdateCheck persists to config.json in the configured dir and reloads', () => {
    config.setDashboardUpdateCheck(false);
    const onDisk = JSON.parse(readFileSync(configFile(), 'utf-8'));
    expect(onDisk.dashboardUpdateCheck).toBe(false);
    expect(config.getDashboardUpdateCheckSetting(undefined, {})).toEqual({ enabled: false, disabledBy: 'config' });

    config.setDashboardUpdateCheck(true);
    expect(JSON.parse(readFileSync(configFile(), 'utf-8')).dashboardUpdateCheck).toBe(true);
    expect(config.getDashboardUpdateCheckSetting(undefined, {})).toEqual({ enabled: true });
  });

  it('preserves unrelated keys when writing', () => {
    config.setSelfHeal(false);
    config.setDashboardUpdateCheck(false);
    const onDisk = JSON.parse(readFileSync(configFile(), 'utf-8'));
    expect(onDisk.selfHeal).toBe(false);
    expect(onDisk.dashboardUpdateCheck).toBe(false);
  });
});

describe('shieldcortex config --dashboard-update-check (#631)', () => {
  function captureLog(): string[] {
    const lines: string[] = [];
    jest.spyOn(console, 'log').mockImplementation((...a: unknown[]) => { lines.push(a.join(' ')); });
    return lines;
  }

  it('false persists the opt-out and says it is not an offline mode', () => {
    const lines = captureLog();
    cli.handleCloudConfig(['--dashboard-update-check', 'false']);
    expect(JSON.parse(readFileSync(configFile(), 'utf-8')).dashboardUpdateCheck).toBe(false);
    const out = lines.join('\n');
    expect(out).toMatch(/Dashboard update check disabled/);
    expect(out).toMatch(/stops only that lookup/);
    expect(out).not.toMatch(/offline mode|no outbound|zero outbound/i);
  });

  it('true re-enables it', () => {
    captureLog();
    config.setDashboardUpdateCheck(false);
    cli.handleCloudConfig(['--dashboard-update-check', 'TRUE']);
    expect(JSON.parse(readFileSync(configFile(), 'utf-8')).dashboardUpdateCheck).toBe(true);
  });

  it('rejects a missing or invalid value without writing', () => {
    captureLog();
    jest.spyOn(console, 'error').mockImplementation(() => {});
    const exit = jest.spyOn(process, 'exit').mockImplementation(((code?: number) => {
      throw new Error(`exit ${code}`);
    }) as never);

    expect(() => cli.handleCloudConfig(['--dashboard-update-check'])).toThrow('exit 1');
    expect(() => cli.handleCloudConfig(['--dashboard-update-check', 'off'])).toThrow('exit 1');
    expect(exit).toHaveBeenCalledWith(1);
    expect(existsSync(configFile())).toBe(false);
  });

  it('help lists the flag with its scope', () => {
    const lines = captureLog();
    cli.handleCloudConfig([]);
    const out = lines.join('\n');
    expect(out).toMatch(/--dashboard-update-check <true\|false>/);
    expect(out).toMatch(/SHIELDCORTEX_SKIP_UPDATE_CHECK=1 also opts out/);
    expect(out).toMatch(/not an offline mode/);
  });
});

describe('GET /api/version/check route (#631)', () => {
  async function getCheck(query: Record<string, string>): Promise<{ statusCode: number; body: any }> {
    const { registerSystemRoutes } = await import('../routes/system.js');
    const gets = new Map<string, (req: any, res: any) => unknown>();
    const app = {
      get: (route: string, ...handlers: Array<(req: any, res: any) => unknown>) => { gets.set(route, handlers[handlers.length - 1]); },
      post: () => {},
      patch: () => {},
      delete: () => {},
    };
    registerSystemRoutes(app as never, {
      broadcast: () => {},
      clients: new Set(),
      requireIronDomeAction: () => (_req: unknown, _res: unknown, next: () => void) => next(),
    } as never);
    const res = {
      statusCode: 200,
      body: undefined as unknown,
      status(code: number) { this.statusCode = code; return this; },
      json(payload: unknown) { this.body = payload; return this; },
    };
    await gets.get('/api/version/check')!({ query, params: {}, body: {} }, res);
    return res as { statusCode: number; body: any };
  }

  it('disabled: normal and force=true requests spawn nothing and say disabled', async () => {
    config.setDashboardUpdateCheck(false);
    for (const query of [{}, { force: 'true' }]) {
      const res = await getCheck(query);
      expect(res.statusCode).toBe(200);
      expect(res.body).toMatchObject({ checkStatus: 'disabled', checkDisabledBy: 'config', latestVersion: null, updateAvailable: false });
    }
    expect(anySpawn()).toBe(0);
  });

  it('default: force=true reaches the registry lookup', async () => {
    const res = await getCheck({ force: 'true' });
    expect(res.body).toMatchObject({ checkStatus: 'ok', latestVersion: '99.0.0' });
    expect(npmViewCalls()).toHaveLength(1);
  });
});
