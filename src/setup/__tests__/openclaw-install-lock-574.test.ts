import fs from 'fs';
import os from 'os';
import path from 'path';
import { afterEach, beforeEach, describe, expect, it, jest } from '@jest/globals';
import { installOpenClawHook } from '../openclaw.js';
import { updateLockPath } from '../host-swap.js';

/**
 * #574 round 3 blocker 6 (and the installer half of blocker 4) — the OpenClaw
 * installer wrote before it checked the lock, and kept writing after it was
 * refused one.
 *
 * Round 3 acquired the lock INSIDE the hook-copy loop. Everything ahead of it
 * ran unlocked — `findAllHooksDirs` creating `hooks/`, `cleanupLegacyPlugin`
 * rewriting `openclaw.json` — and everything after it ran outside it: the
 * plugin install, the registration rewrite, the gateway restart. The reviewer
 * held `.openclaw/.shieldcortex-update.lock`, ran the installer with
 * `noPlugins`, and watched it create the hooks directory and rewrite the
 * config anyway.
 *
 * `OPENCLAW_HOME` is the isolation seam: every path below is under a temp dir,
 * and the real `~/.openclaw` / `~/.claude` are never read or written.
 */
let home: string;
let openclawRoot: string;
let claudeRoot: string;
let warnings: string[];
const saved: Record<string, string | undefined> = {};
const KEYS = ['OPENCLAW_HOME', 'HOME', 'SUDO_USER'] as const;
const FOREIGN = 'shieldcortex-update 4194304 2026-09-24T11:00:00.000Z foreign\n';
/** The legacy `plugins.allow` entry `cleanupLegacyPlugin` rewrites away. */
const LEGACY_CONFIG = `${JSON.stringify(
  { plugins: { allow: ['/opt/somewhere/shieldcortex-realtime/index.js'] } },
  null,
  2,
)}\n`;
let savedExitCode: number | string | undefined;

beforeEach(() => {
  for (const key of KEYS) saved[key] = process.env[key];
  savedExitCode = process.exitCode;
  home = fs.mkdtempSync(path.join(os.tmpdir(), 'sc-oc-install-lock-'));
  openclawRoot = path.join(home, '.openclaw');
  claudeRoot = path.join(home, '.claude');
  process.env.OPENCLAW_HOME = home;
  process.env.HOME = home;
  delete process.env.SUDO_USER;
  warnings = [];
  jest.spyOn(console, 'warn').mockImplementation((...a: unknown[]) => { warnings.push(a.join(' ')); });
  jest.spyOn(console, 'log').mockImplementation(() => {});
  jest.spyOn(console, 'error').mockImplementation((...a: unknown[]) => { warnings.push(a.join(' ')); });
});

afterEach(() => {
  jest.restoreAllMocks();
  for (const key of KEYS) {
    if (saved[key] === undefined) delete process.env[key];
    else process.env[key] = saved[key];
  }
  process.exitCode = savedExitCode;
  fs.rmSync(home, { recursive: true, force: true });
});

describe('a busy config root gets no writes at all (#574 r3 blocker 6)', () => {
  it('creates no hooks/ and rewrites no openclaw.json while the lock is held', async () => {
    fs.mkdirSync(openclawRoot, { recursive: true });
    fs.writeFileSync(path.join(openclawRoot, 'openclaw.json'), LEGACY_CONFIG);
    fs.writeFileSync(updateLockPath(openclawRoot), FOREIGN);

    await installOpenClawHook({ noPlugins: true, restartGateway: false });

    // The two mutations the reviewer drove with the lock held.
    expect(fs.existsSync(path.join(openclawRoot, 'hooks'))).toBe(false);
    expect(fs.readFileSync(path.join(openclawRoot, 'openclaw.json'), 'utf-8')).toBe(LEGACY_CONFIG);
    // And the foreign lock is still the foreign lock.
    expect(fs.readFileSync(updateLockPath(openclawRoot), 'utf-8')).toBe(FOREIGN);
    expect(warnings.join('\n')).toMatch(/another ShieldCortex update\/install is running/);
  });

  it('still installs into the config root it DID get the lock for', async () => {
    fs.mkdirSync(openclawRoot, { recursive: true });
    fs.writeFileSync(path.join(openclawRoot, 'openclaw.json'), LEGACY_CONFIG);
    fs.writeFileSync(updateLockPath(openclawRoot), FOREIGN);
    fs.mkdirSync(claudeRoot, { recursive: true });

    await installOpenClawHook({ noPlugins: true, restartGateway: false });

    expect(fs.existsSync(path.join(claudeRoot, 'hooks', 'cortex-memory', 'HOOK.md'))).toBe(true);
    expect(fs.existsSync(path.join(openclawRoot, 'hooks'))).toBe(false);
    expect(fs.readFileSync(path.join(openclawRoot, 'openclaw.json'), 'utf-8')).toBe(LEGACY_CONFIG);
  });

  it('releases the locks it took, so the next install is not blocked by itself', async () => {
    fs.mkdirSync(claudeRoot, { recursive: true });

    await installOpenClawHook({ noHooks: true, noPlugins: true, restartGateway: false });

    expect(fs.existsSync(updateLockPath(claudeRoot))).toBe(false);
  });
});

describe('a symlinked config root is refused before anything is written (#574 r3 blocker 4)', () => {
  it('does not follow the link, delete the lock inside it, or copy through it', async () => {
    const external = fs.mkdtempSync(path.join(os.tmpdir(), 'sc-oc-external-'));
    try {
      // The reviewer's layout: `~/.openclaw` is a link to a tree that already
      // holds somebody else's lock and a stale hook.
      fs.mkdirSync(path.join(external, 'hooks', 'cortex-memory'), { recursive: true });
      fs.writeFileSync(path.join(external, 'hooks', 'cortex-memory', 'HOOK.md'), 'old\n');
      fs.writeFileSync(updateLockPath(external), FOREIGN);
      fs.symlinkSync(external, openclawRoot);

      await installOpenClawHook({ noPlugins: true, restartGateway: false });

      expect(fs.readFileSync(updateLockPath(external), 'utf-8')).toBe(FOREIGN);
      expect(fs.readFileSync(path.join(external, 'hooks', 'cortex-memory', 'HOOK.md'), 'utf-8')).toBe('old\n');
      expect(fs.lstatSync(openclawRoot).isSymbolicLink()).toBe(true);
      expect(warnings.join('\n')).toMatch(/is a symlink; nothing written/);
    } finally {
      fs.rmSync(external, { recursive: true, force: true });
    }
  });
});
