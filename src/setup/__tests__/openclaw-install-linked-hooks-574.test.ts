import fs from 'fs';
import os from 'os';
import path from 'path';
import { afterEach, beforeEach, describe, expect, it, jest } from '@jest/globals';
import { installOpenClawHook } from '../openclaw.js';

/**
 * #574 round 4 blocker 1 — the OpenClaw installer wrote and DELETED through a
 * linked hook directory.
 *
 * Round 3 added leaf checks: `copyHookFiles` lstats the directory it overlays
 * and each file inside it. But the installer reaches those leaves through
 * `hooks/` and `hooks/internal/`, which it `mkdir -p`s, and it removes the
 * legacy layouts `hooks/shieldcortex/` and `hooks/internal/cortex-memory/`
 * with `rm -rf` before copying anything. None of those looked. The reviewer
 * pointed `~/.openclaw/hooks` at an external directory holding
 * `cortex-memory/handler.ts` and `shieldcortex/keep.txt`: the external handler
 * was overwritten, the external `shieldcortex/` was DELETED, and the install
 * reported success.
 *
 * Every component from the config root down to each destination and each
 * legacy-removal path is now lstat'd before the first write in that root, and
 * a link refuses the root whole — nothing written, nothing deleted, non-zero.
 *
 * `OPENCLAW_HOME` is the isolation seam; the real `~/.openclaw` and
 * `~/.claude` are never read or written.
 */
let home: string;
let openclawRoot: string;
let external: string;
let warnings: string[];
const saved: Record<string, string | undefined> = {};
const KEYS = ['OPENCLAW_HOME', 'HOME', 'SUDO_USER'] as const;
let savedExitCode: number | string | undefined;

beforeEach(() => {
  for (const key of KEYS) saved[key] = process.env[key];
  savedExitCode = process.exitCode;
  home = fs.mkdtempSync(path.join(os.tmpdir(), 'sc-oc-linked-hooks-'));
  external = fs.mkdtempSync(path.join(os.tmpdir(), 'sc-oc-external-hooks-'));
  openclawRoot = path.join(home, '.openclaw');
  fs.mkdirSync(openclawRoot, { recursive: true });
  process.env.OPENCLAW_HOME = home;
  process.env.HOME = home;
  delete process.env.SUDO_USER;
  warnings = [];
  jest.spyOn(console, 'warn').mockImplementation((...a: unknown[]) => { warnings.push(a.join(' ')); });
  jest.spyOn(console, 'error').mockImplementation((...a: unknown[]) => { warnings.push(a.join(' ')); });
  jest.spyOn(console, 'log').mockImplementation(() => {});
});

afterEach(() => {
  jest.restoreAllMocks();
  for (const key of KEYS) {
    if (saved[key] === undefined) delete process.env[key];
    else process.env[key] = saved[key];
  }
  process.exitCode = savedExitCode;
  fs.rmSync(home, { recursive: true, force: true });
  fs.rmSync(external, { recursive: true, force: true });
});

/**
 * The reviewer's tree, out of reach of this command: a hook it would overlay
 * and a legacy directory it would delete.
 */
function plantExternalHookTree(root: string): void {
  fs.mkdirSync(path.join(root, 'cortex-memory'), { recursive: true });
  fs.writeFileSync(path.join(root, 'cortex-memory', 'handler.ts'), 'somebody else\n');
  fs.mkdirSync(path.join(root, 'shieldcortex'), { recursive: true });
  fs.writeFileSync(path.join(root, 'shieldcortex', 'keep.txt'), 'not yours to delete\n');
}

function expectExternalTreeIntact(root: string): void {
  expect(fs.readFileSync(path.join(root, 'cortex-memory', 'handler.ts'), 'utf-8')).toBe('somebody else\n');
  // The legacy-removal path is the one that COSTS more when it is followed.
  expect(fs.existsSync(path.join(root, 'shieldcortex'))).toBe(true);
  expect(fs.readFileSync(path.join(root, 'shieldcortex', 'keep.txt'), 'utf-8')).toBe('not yours to delete\n');
}

describe('the hook installer refuses a linked hook ancestor (#574 r4 blocker 1)', () => {
  it('writes and deletes nothing through a linked hooks/ directory', async () => {
    plantExternalHookTree(external);
    fs.symlinkSync(external, path.join(openclawRoot, 'hooks'));

    await installOpenClawHook({ noPlugins: true, restartGateway: false });

    expectExternalTreeIntact(external);
    // The link itself is left exactly as it was — not replaced by a real dir.
    expect(fs.lstatSync(path.join(openclawRoot, 'hooks')).isSymbolicLink()).toBe(true);
    expect(warnings.join('\n')).toMatch(/is a symlink; nothing written or deleted/);
    expect(process.exitCode).toBe(1);
  });

  it('does not refuse a linked hooks/ when --no-hooks means the hook tree is never touched (r5 nit 3)', async () => {
    plantExternalHookTree(external);
    fs.symlinkSync(external, path.join(openclawRoot, 'hooks'));

    await installOpenClawHook({ noHooks: true, noPlugins: true, restartGateway: false });

    expectExternalTreeIntact(external);
    expect(fs.lstatSync(path.join(openclawRoot, 'hooks')).isSymbolicLink()).toBe(true);
    expect(warnings.join('\n')).not.toMatch(/is a symlink; nothing written or deleted/);
    expect(process.exitCode).not.toBe(1);
  });

  it('writes and deletes nothing through a linked hooks/internal/ directory', async () => {
    // `hooks/` itself is real here, so only the second level is a link — the
    // component the round-3 leaf checks could never see.
    fs.mkdirSync(path.join(openclawRoot, 'hooks'), { recursive: true });
    plantExternalHookTree(external);
    fs.symlinkSync(external, path.join(openclawRoot, 'hooks', 'internal'));

    await installOpenClawHook({ noPlugins: true, restartGateway: false });

    expectExternalTreeIntact(external);
    expect(fs.lstatSync(path.join(openclawRoot, 'hooks', 'internal')).isSymbolicLink()).toBe(true);
    // And the refusal is whole: no hook landed beside the link either.
    expect(fs.existsSync(path.join(openclawRoot, 'hooks', 'cortex-memory'))).toBe(false);
    expect(warnings.join('\n')).toMatch(/is a symlink; nothing written or deleted/);
    expect(process.exitCode).toBe(1);
  });

  it('refuses a linked destination without refusing the hosts that are fine', async () => {
    // `~/.claude` is an ordinary tree; `~/.openclaw/hooks/cortex-memory` is a
    // link. One root is dropped, the other is installed, and the command
    // still exits non-zero because the operator did not get what they asked.
    const claudeRoot = path.join(home, '.claude');
    fs.mkdirSync(claudeRoot, { recursive: true });
    fs.mkdirSync(path.join(openclawRoot, 'hooks'), { recursive: true });
    fs.mkdirSync(path.join(external, 'cortex-memory'), { recursive: true });
    fs.writeFileSync(path.join(external, 'cortex-memory', 'HOOK.md'), 'somebody else\n');
    fs.symlinkSync(path.join(external, 'cortex-memory'), path.join(openclawRoot, 'hooks', 'cortex-memory'));

    await installOpenClawHook({ noPlugins: true, restartGateway: false });

    expect(fs.readFileSync(path.join(external, 'cortex-memory', 'HOOK.md'), 'utf-8')).toBe('somebody else\n');
    expect(fs.existsSync(path.join(claudeRoot, 'hooks', 'cortex-memory', 'HOOK.md'))).toBe(true);
    expect(process.exitCode).toBe(1);
  });
});
