import fs from 'fs';
import os from 'os';
import path from 'path';
import { afterEach, beforeEach, describe, expect, it, jest } from '@jest/globals';

/**
 * `getent passwd` is how `SUDO_USER` is resolved (#429: argv array, never a
 * shell string). A PATH stub cannot be used here — jest's sandboxed
 * `process.env` does not reach a spawned child's environment, so the child
 * would find the real `/usr/bin/getent` and answer for the real box. Mocking
 * the module is the same seam `openclaw-resolve-home-shell-free.test.ts` uses.
 */
const execFileSyncMock = jest.fn();
jest.unstable_mockModule('child_process', () => ({
  execFileSync: execFileSyncMock,
  execSync: jest.fn(),
  spawnSync: jest.fn(),
  spawn: jest.fn(),
  execFile: jest.fn(),
  exec: jest.fn(),
  default: {
    execFileSync: execFileSyncMock,
    execSync: jest.fn(),
    spawnSync: jest.fn(),
    spawn: jest.fn(),
    execFile: jest.fn(),
    exec: jest.fn(),
  },
}));

const { stepHermesPlugin, stepOpenClawHook } = await import('../update.js');
const { defaultHookDestDir, openClawUserHome } = await import('../../setup/openclaw.js');
const { hermesUserHome } = await import('../../setup/user-home.js');

/**
 * #574 / #576 round 2, blocker 3 — `runUpdate` resolved `os.homedir()` and
 * passed it explicitly into the two host-refresh steps, which defeated the
 * override- and sudo-aware resolver those steps would otherwise have used.
 * With `HOME=A` and `OPENCLAW_HOME=B` the update refreshed A and left B stale,
 * while `defaultHookDestDir()` — and therefore doctor — kept pointing at B.
 * Under sudo the same argument skipped `SUDO_USER` and refreshed root's tree.
 *
 * Both steps now take NO positional home: `runUpdate` calls
 * `stepOpenClawHook()` / `stepHermesPlugin()` with nothing, so the resolver is
 * the only path in, and a caller cannot reintroduce the bug by passing a home.
 * `deps.home` remains as the fixture seam for the reporting tests.
 *
 * Every case injects `deps.refresh` and asserts the HOME the step handed it.
 * That is deliberate: with the fix reverted the step would resolve
 * `os.homedir()`, and a refresh that actually ran would write into the real
 * `$HOME` of whoever runs this suite.
 */
let tmp: string;
const saved: Record<string, string | undefined> = {};
const KEYS = ['OPENCLAW_HOME', 'SUDO_USER', 'HOME', 'HERMES_HOME'] as const;

/** Swallow the step renderer's own output. */
async function quietly<T>(fn: () => Promise<T>): Promise<T> {
  const spy = jest.spyOn(process.stdout, 'write').mockImplementation(() => true);
  try {
    return await fn();
  } finally {
    spy.mockRestore();
  }
}

const NOTHING_INSTALLED = {
  installed: [] as string[],
  refreshed: [] as string[],
  current: [] as string[],
  failed: [] as Array<{ dir: string; error: string }>,
  backups: [] as Array<{ dir: string; backup: string }>,
  sourceAvailable: true,
};

beforeEach(() => {
  for (const key of KEYS) saved[key] = process.env[key];
  tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'sc-update-home-'));
  execFileSyncMock.mockReset();
  delete process.env.OPENCLAW_HOME;
  delete process.env.SUDO_USER;
  delete process.env.HERMES_HOME;
});

afterEach(() => {
  jest.restoreAllMocks();
  for (const key of KEYS) {
    if (saved[key] === undefined) delete process.env[key];
    else process.env[key] = saved[key] as string;
  }
  fs.rmSync(tmp, { recursive: true, force: true });
});

/** `sudo -u <user>` on a box whose passwd database puts them at `homeDir`. */
function underSudo(user: string, homeDir: string): void {
  execFileSyncMock.mockImplementation((file: unknown, args: unknown) => {
    expect(file).toBe('getent');
    expect(args).toEqual(['passwd', user]);
    return `${user}:x:1000:1000::${homeDir}:/bin/sh\n`;
  });
  process.env.SUDO_USER = user;
}

describe('the OpenClaw hook step resolves the OpenClaw home (#574 r2 blocker 3)', () => {
  it('follows OPENCLAW_HOME, not the process home', async () => {
    const isolated = path.join(tmp, 'oc-home');
    fs.mkdirSync(path.join(isolated, '.openclaw', 'hooks', 'cortex-memory'), { recursive: true });
    process.env.OPENCLAW_HOME = isolated;
    const seen: string[] = [];

    await quietly(() => stepOpenClawHook({
      refresh: (home) => { seen.push(home); return NOTHING_INSTALLED; },
    }));

    expect(seen).toEqual([isolated]);
    expect(seen[0]).not.toBe(os.homedir());
    // The same home doctor's row resolves — they cannot disagree about a host.
    expect(defaultHookDestDir().startsWith(isolated)).toBe(true);
    expect(openClawUserHome()).toBe(isolated);
  });

  it('follows SUDO_USER rather than refreshing root\'s tree', async () => {
    const operator = path.join(tmp, 'operator');
    fs.mkdirSync(path.join(operator, '.openclaw', 'hooks', 'cortex-memory'), { recursive: true });
    underSudo('scfake', operator);
    const seen: string[] = [];

    await quietly(() => stepOpenClawHook({
      refresh: (home) => { seen.push(home); return NOTHING_INSTALLED; },
    }));

    expect(seen).toEqual([operator]);
    expect(seen[0]).not.toBe(os.homedir());
  });

  it('keeps the explicit test seam working', async () => {
    const explicit = path.join(tmp, 'explicit');
    process.env.OPENCLAW_HOME = path.join(tmp, 'oc-home');
    const seen: string[] = [];

    await quietly(() => stepOpenClawHook({
      home: explicit,
      refresh: (home) => { seen.push(home); return NOTHING_INSTALLED; },
    }));

    expect(seen).toEqual([explicit]);
  });
});

describe('the Hermes step resolves the operator home (#576 r2 blocker 3)', () => {
  const HERMES_NOTHING = { status: 'not-installed' as const, summary: 'x', detail: [], refreshed: [] };

  it('follows SUDO_USER rather than scanning root\'s Hermes', async () => {
    const operator = path.join(tmp, 'operator');
    fs.mkdirSync(path.join(operator, '.hermes', 'plugins'), { recursive: true });
    underSudo('scfake', operator);
    const seen: string[] = [];

    await quietly(() => stepHermesPlugin({
      refresh: (home) => { seen.push(home); return HERMES_NOTHING; },
    }));

    expect(seen).toEqual([operator]);
    expect(seen[0]).not.toBe(os.homedir());
    expect(hermesUserHome()).toBe(operator);
  });

  it('does NOT read OPENCLAW_HOME — that variable is not Hermes\'s', async () => {
    const openclawOnly = path.join(tmp, 'oc-home');
    fs.mkdirSync(openclawOnly, { recursive: true });
    process.env.OPENCLAW_HOME = openclawOnly;
    const seen: string[] = [];

    await quietly(() => stepHermesPlugin({
      refresh: (home) => { seen.push(home); return HERMES_NOTHING; },
    }));

    expect(seen).toEqual([os.homedir()]);
  });

  it('leaves HERMES_HOME to Hermes, unexpanded (#569 r5)', async () => {
    const operator = path.join(tmp, 'operator');
    fs.mkdirSync(path.join(operator, '.hermes'), { recursive: true });
    underSudo('scfake', operator);
    process.env.HERMES_HOME = '$SOMETHING/profiles/work';
    const seen: string[] = [];

    await quietly(() => stepHermesPlugin({
      refresh: (home) => { seen.push(home); return HERMES_NOTHING; },
    }));

    // The step hands over the OPERATOR home; Hermes' own resolution of
    // HERMES_HOME happens in the probe, against the value as the shell set it.
    expect(seen).toEqual([operator]);
    expect(process.env.HERMES_HOME).toBe('$SOMETHING/profiles/work');
  });
});
