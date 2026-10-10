/**
 * #707 — `install --help` / `doctor --help` at the real entry point.
 *
 * On 5.5.0 `shieldcortex install --help` wrote the Claude Code config and hooks
 * and `doctor --help` ran the diagnostics. The in-process half
 * (setup-doctor-help-707.test.ts) proves the dispatchers call no handler; this
 * half drives the built `dist/index.js` in a child process, because what a help
 * request must not do — load an installer, spawn a host CLI, write a file —
 * can also happen in `main()`'s preamble, which no handler test reaches.
 *
 * Sandbox (entry-point-harness-577.ts): HOME is an empty temp dir; the config,
 * audit, OpenClaw, Hermes, Claude and Codex state dirs are separate empty dirs
 * beside it; `npm` and every host CLI an installer shells out to are fakes that
 * leave a marker outside HOME; and a canary file outside all of them must keep
 * its bytes and mtime.
 */
import { afterEach, beforeEach, describe, expect, it } from '@jest/globals';
import fs from 'node:fs';
import path from 'node:path';
import { cliEntry, makeEntryPointSandbox, type EntryPointSandbox } from './entry-point-harness-577.js';

const FAKE_COMMANDS = ['openclaw', 'claude', 'hermes', 'codex', 'code', 'cursor', 'git', 'systemctl', 'launchctl'] as const;
const STATE_DIRS = {
  SHIELDCORTEX_CONFIG_DIR: 'config',
  SHIELDCORTEX_AUDIT_DIR: 'audit',
  OPENCLAW_HOME: 'openclaw',
  HERMES_HOME: 'hermes',
  CLAUDE_CONFIG_DIR: 'claude',
  CODEX_HOME: 'codex',
} as const;

let sandbox: EntryPointSandbox;
let env: Record<string, string>;
let canary: string;
let canaryMtime: number;

beforeEach(() => {
  sandbox = makeEntryPointSandbox('sc707-help-entry-', { fakeCommands: FAKE_COMMANDS });
  env = {};
  for (const [key, dir] of Object.entries(STATE_DIRS)) {
    const full = path.join(sandbox.tmp, 'state', dir);
    fs.mkdirSync(full, { recursive: true });
    env[key] = full;
  }
  canary = path.join(sandbox.tmp, 'outside-canary.txt');
  fs.writeFileSync(canary, 'canary-707\n');
  canaryMtime = fs.statSync(canary).mtimeMs;
});
afterEach(() => { sandbox.cleanup(); });

/** Every path under each state dir, relative to `state/`. */
function underStateDirs(): string[] {
  const root = path.join(sandbox.tmp, 'state');
  const out: string[] = [];
  const walk = (dir: string) => {
    for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
      const full = path.join(dir, e.name);
      out.push(path.relative(root, full));
      if (e.isDirectory()) walk(full);
    }
  };
  for (const dir of Object.values(STATE_DIRS)) walk(path.join(root, dir));
  return out;
}

function expectNoSideEffects(argv: string[]): void {
  expect({ argv, npm: sandbox.npmRan() }).toEqual({ argv, npm: false });
  expect({ argv, spawned: sandbox.spawnedCommands() }).toEqual({ argv, spawned: [] });
  expect({ argv, home: sandbox.underHome() }).toEqual({ argv, home: [] });
  expect({ argv, state: underStateDirs() }).toEqual({ argv, state: [] });
  expect({ argv, canary: fs.readFileSync(canary, 'utf-8') }).toEqual({ argv, canary: 'canary-707\n' });
  expect({ argv, canaryMtime: fs.statSync(canary).mtimeMs }).toEqual({ argv, canaryMtime });
}

describe('#707 — setup / install / doctor help costs nothing at the entry point', () => {
  it('has the built CLI to drive', () => {
    expect(fs.existsSync(cliEntry)).toBe(true);
  });

  it.each([
    [['install', '--help']],
    [['install', '-h']],
    [['install', '--with-stop-hook', '--help']],
    [['install', '--help', '--with-stop-hook', '--with-session-end']],
    [['setup', '--help']],
    [['setup', '-h']],
    [['setup', '--with-stop-hook', '-h']],
    [['setup', '-h', '--with-session-end']],
    [['setup', 'uninstall', '--help']],
  ])('%j prints setup usage, exits 0, touches nothing', (argv) => {
    const r = sandbox.run(argv, env);
    expect({ argv, status: r.status }).toEqual({ argv, status: 0 });
    expect(r.stdout).toContain('Usage: shieldcortex setup');
    expect(r.stdout).toContain('shieldcortex install');
    expect(r.stdout).toContain('--with-stop-hook');
    // None of the installer's own progress lines.
    expect(r.stdout).not.toContain('Setting up ShieldCortex');
    expectNoSideEffects(argv);
  });

  it.each([
    [['doctor', '--help']],
    [['doctor', '-h']],
    [['doctor', '--json', '--help']],
    [['doctor', '--strict', '-h']],
  ])('%j prints doctor usage, exits 0, runs no checks', (argv) => {
    const r = sandbox.run(argv, env);
    expect({ argv, status: r.status }).toEqual({ argv, status: 0 });
    expect(r.stdout).toContain('Usage: shieldcortex doctor');
    expect(r.stdout).toContain('--strict');
    // `--json` with help is usage, not the JSON report.
    expect(r.stdout).not.toContain('"results"');
    expectNoSideEffects(argv);
  });

  it('non-help control: an unknown setup target still reaches the quickstart handler', () => {
    // Proves the gate did not swallow real dispatch: the handler's own usage
    // error (stderr, exit 1) is only reachable past the help gate. Side effects
    // are not asserted here — this path is the handler's, not the gate's.
    const r = sandbox.run(['setup', 'not-a-target'], env);
    expect(r.status).toBe(1);
    expect(r.stderr).toContain('Usage: shieldcortex setup [claude|openclaw|hermes|copilot|codex|security|--yes|--install-detected]');
    expect(r.stdout).not.toContain('-h, --help');
  });
});
