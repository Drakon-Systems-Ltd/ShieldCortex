import fs from 'fs';
import os from 'os';
import path from 'path';
import { afterEach, beforeEach, describe, expect, it, jest } from '@jest/globals';
import {
  stepHermesPlugin,
  stepOpenClawHook,
  stepOpenClawPlugin,
  updateVerdict,
} from '../update.js';
import { installHermes } from '../../setup/hermes.js';
import { HOOK_FILES } from '../../setup/openclaw.js';
import { updateLockPath } from '../../setup/host-swap.js';

/**
 * #574 / #576 round 4 nit 1 — a run that refreshed nothing exited 0.
 *
 * `update` classified every host-integration problem as "attention" and then
 * set `exitCode = 0` unless npm or the protection self-check had failed. So a
 * busy integration root, a copy that could not be published, a copy that
 * vanished mid-swap and a durability the device refused all printed a warning
 * and told a script the upgrade was clean. `hermes install` refused a busy
 * root and returned 0 as well, and `openclaw install` exited non-zero only
 * when EVERY root was unavailable.
 *
 * The chain here is the real one: a real temp-home state, the real step that
 * reads it, the flag it sets, and the real decision `runUpdate` exits with.
 */
let home: string;
let stdout: string[];
const FOREIGN = 'shieldcortex-update 4194304 2026-09-24T11:00:00.000Z foreign\n';
const savedHermesHome = process.env.HERMES_HOME;
let savedExitCode: number | string | undefined;

beforeEach(() => {
  home = fs.mkdtempSync(path.join(os.tmpdir(), 'sc-unfinished-exit-'));
  savedExitCode = process.exitCode;
  delete process.env.HERMES_HOME;
  stdout = [];
  jest.spyOn(process.stdout, 'write').mockImplementation(((chunk: string | Uint8Array) => {
    stdout.push(String(chunk));
    return true;
  }) as typeof process.stdout.write);
  jest.spyOn(console, 'error').mockImplementation(() => {});
  jest.spyOn(console, 'log').mockImplementation(() => {});
});

afterEach(() => {
  jest.restoreAllMocks();
  process.exitCode = savedExitCode;
  fs.rmSync(home, { recursive: true, force: true });
  if (savedHermesHome === undefined) delete process.env.HERMES_HOME;
  else process.env.HERMES_HOME = savedHermesHome;
});

describe("update exits non-zero on work it did not finish (#574/#576 r4 nit 1)", () => {
  it('is INCOMPLETE and non-zero when a step did not finish, and OK when none did', () => {
    // The two lines `runUpdate` actually exits with, driven directly. npm
    // failing stays FAILED; an unfinished refresh is its own verdict.
    expect(updateVerdict({ failed: false, attention: true, unfinished: true }))
      .toEqual({ exitCode: 1, verdict: 'INCOMPLETE' });
    expect(updateVerdict({ failed: true, attention: true, unfinished: true }))
      .toEqual({ exitCode: 1, verdict: 'FAILED' });
    expect(updateVerdict({ failed: false, attention: true, unfinished: false }))
      .toEqual({ exitCode: 0, verdict: 'NEEDS ATTENTION' });
    expect(updateVerdict({ failed: false, attention: false, unfinished: false }))
      .toEqual({ exitCode: 0, verdict: 'OK' });
  });

  it('flags the OpenClaw hook step as unfinished when the root is locked', async () => {
    const configRoot = path.join(home, '.openclaw');
    const hookDir = path.join(configRoot, 'hooks', 'cortex-memory');
    fs.mkdirSync(hookDir, { recursive: true });
    for (const file of HOOK_FILES) fs.writeFileSync(path.join(hookDir, file), `old ${file}\n`);
    fs.writeFileSync(updateLockPath(configRoot), FOREIGN);

    const result = await stepOpenClawHook({ home });

    expect(result.status).toBe('warn');
    expect(result.unfinished).toBe(true);
    expect(updateVerdict({ failed: false, attention: true, unfinished: result.unfinished === true }).exitCode).toBe(1);
  });

  it('flags the OpenClaw plugin step as unfinished when the root is locked', async () => {
    const configRoot = path.join(home, '.openclaw');
    fs.mkdirSync(path.join(configRoot, 'extensions', 'shieldcortex-realtime'), { recursive: true });
    fs.writeFileSync(updateLockPath(configRoot), FOREIGN);

    const result = await stepOpenClawPlugin(home, {
      run: (async () => { throw new Error('the runner must not be reached'); }) as never,
    });

    expect(result.status).toBe('warn');
    expect(result.unfinished).toBe(true);
  });

  it('flags the Hermes step as unfinished on any refusal', async () => {
    const result = await stepHermesPlugin({
      home,
      refresh: () => ({
        status: 'warn' as const,
        summary: 'could not refresh 1 copy',
        detail: ['locked'],
        refreshed: [],
      }),
    });

    expect(result.status).toBe('warn');
    expect(result.unfinished).toBe(true);
  });

  it('leaves a clean refresh at zero', async () => {
    const result = await stepHermesPlugin({
      home,
      refresh: () => ({ status: 'refreshed' as const, summary: 'refreshed 1 copy', detail: [], refreshed: [] }),
    });

    expect(result.unfinished).toBeUndefined();
    expect(updateVerdict({ failed: false, attention: false, unfinished: false }).exitCode).toBe(0);
  });
});

describe('`hermes install` exits non-zero when the root is busy (#576 r4 nit 1)', () => {
  it('writes nothing and sets a failing exit code', async () => {
    const hermes = path.join(home, '.hermes');
    fs.mkdirSync(hermes, { recursive: true });
    fs.writeFileSync(updateLockPath(hermes), FOREIGN);
    process.exitCode = 0;

    await installHermes(home);

    expect(process.exitCode).toBe(1);
    expect(fs.existsSync(path.join(hermes, 'plugins'))).toBe(false);
    expect(fs.readFileSync(updateLockPath(hermes), 'utf-8')).toBe(FOREIGN);
  });
});
