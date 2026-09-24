/**
 * #577 (round-2 nit) — an invalid argument must cost NOTHING, end to end.
 *
 * Round 1 gated `update` inside `handleUpdateCommand`, which is correct but
 * late: `main()` opens with `checkVersionStaleness()`, which shells out to
 * `npm ls -g`. npm's own update-notifier then reaches the registry and writes
 * `~/.npm/_logs` — so `shieldcortex update --bogus` spawned a child process and
 * left files under the operator's HOME on its way to exit 2. The handler-level
 * test could not see that, because the preamble is not in the handler.
 *
 * So this drives the real entry point: the BUILT `dist/index.js`, in a child
 * process, with HOME at an empty temp directory and a fake `npm` first on PATH
 * that leaves a marker if it is ever executed. The assertions are the whole
 * claim — exit 2, no marker, and not one byte written under HOME.
 */
import { afterEach, beforeEach, describe, expect, it } from '@jest/globals';
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..', '..');
const cliEntry = path.join(repoRoot, 'dist', 'index.js');

let tmp = '';
let home = '';
let binDir = '';

/** Every path under `dir`, relative — the proof that nothing was written. */
function walk(dir: string, base = dir): string[] {
  const out: string[] = [];
  for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, e.name);
    out.push(path.relative(base, full));
    if (e.isDirectory()) out.push(...walk(full, base));
  }
  return out;
}

function runCli(args: string[]): { status: number | null; stdout: string; stderr: string } {
  // A copy of the environment with HOME moved and every inherited
  // SHIELDCORTEX_* variable dropped, so the child cannot reach this box's
  // state tree. The fake npm goes first on PATH.
  const env: Record<string, string> = {};
  for (const [k, v] of Object.entries(process.env)) {
    if (v === undefined) continue;
    if (k.startsWith('SHIELDCORTEX_') || k === 'CLAUDE_MEMORY_DB') continue;
    env[k] = v;
  }
  env.HOME = home;
  env.USERPROFILE = home;
  env.npm_config_cache = path.join(home, '.npm');
  env.PATH = `${binDir}${path.delimiter}${env.PATH ?? ''}`;
  const r = spawnSync(process.execPath, [cliEntry, ...args], {
    env,
    encoding: 'utf-8',
    timeout: 60_000,
  });
  return { status: r.status, stdout: r.stdout ?? '', stderr: r.stderr ?? '' };
}

beforeEach(() => {
  tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'sc577-entry-'));
  home = path.join(tmp, 'home');
  binDir = path.join(tmp, 'bin');
  fs.mkdirSync(home);
  fs.mkdirSync(binDir);
  // Marker lands OUTSIDE HOME, so the "HOME is empty" assertion and the "npm
  // never ran" assertion are independent of each other.
  const marker = path.join(tmp, 'npm-was-executed');
  fs.writeFileSync(
    path.join(binDir, 'npm'),
    `#!/bin/sh\necho "$@" >> ${JSON.stringify(marker)}\nmkdir -p "$HOME/.npm/_logs"\ntouch "$HOME/.npm/_logs/debug.log"\nexit 0\n`,
    { mode: 0o755 },
  );
});

afterEach(() => {
  if (tmp) fs.rmSync(tmp, { recursive: true, force: true });
  tmp = '';
});

describe('#577 — `shieldcortex update --bogus` at the real entry point', () => {
  it('has the built CLI to drive', () => {
    expect(fs.existsSync(cliEntry)).toBe(true);
  });

  it('exits 2, spawns no npm, and writes nothing under HOME', () => {
    const r = runCli(['update', '--bogus']);
    expect(r.status).toBe(2);
    expect(r.stderr).toContain('Unknown argument: --bogus');
    expect(r.stderr).toContain('Usage: shieldcortex update');
    expect(r.stdout).toBe('');
    expect(fs.existsSync(path.join(tmp, 'npm-was-executed'))).toBe(false);
    expect(walk(home)).toEqual([]);
  });

  it('`update --help` is free too — exit 0, usage on stdout, HOME untouched', () => {
    const r = runCli(['update', '--help']);
    expect(r.status).toBe(0);
    expect(r.stdout).toContain('Usage: shieldcortex update');
    expect(r.stdout).toContain('--allow-conversation-access');
    expect(fs.existsSync(path.join(tmp, 'npm-was-executed'))).toBe(false);
    expect(walk(home)).toEqual([]);
  });

  it('`update --allow-conversation-access --help` prints usage, not an argument error', () => {
    const r = runCli(['update', '--allow-conversation-access', '--help']);
    expect(r.status).toBe(0);
    expect(r.stderr).toBe('');
    expect(r.stdout).toContain('Usage: shieldcortex update');
    expect(walk(home)).toEqual([]);
  });

  it('the other strict commands reject a bad argument just as cheaply', () => {
    for (const cmd of ['repair', 'migrate', 'uninstall', 'vacuum']) {
      const r = runCli([cmd, '--bogus']);
      expect({ cmd, status: r.status }).toEqual({ cmd, status: 2 });
      expect(r.stderr).toContain('Unknown argument: --bogus');
      expect(fs.existsSync(path.join(tmp, 'npm-was-executed'))).toBe(false);
      expect({ cmd, under: walk(home) }).toEqual({ cmd, under: [] });
    }
  });
});
