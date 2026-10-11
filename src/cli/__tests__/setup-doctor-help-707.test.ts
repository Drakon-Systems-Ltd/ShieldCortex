/**
 * #707 — `install --help` must print usage, not install.
 *
 * Reported against 5.5.0: `shieldcortex install --help` wrote the Claude Code
 * config and hooks, because `main()` routed `install` (and any `setup` with a
 * `--with-*` / `--no-*` flag) straight into `setupClaudeMd()`. `doctor --help`
 * ignored the flag and ran every check. `setup --help` printed a usage ERROR
 * (exit 1) after scanning the host table.
 *
 * These tests drive the real dispatchers `main()` calls, with every handler
 * injected as a recorder, so a regression fails an assertion instead of
 * installing into the box running the suite. The built-CLI half of the contract
 * (no files, no child processes, exit 0) is setup-doctor-help-entry-point-707.
 */
import { afterEach, beforeEach, describe, expect, it } from '@jest/globals';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  DOCTOR_HELP,
  SETUP_HELP,
  dispatchDoctorCommand,
  dispatchSetupCommand,
} from '../setup-dispatch.js';
import { argvWantsHelp } from '../wants-help.js';
import { parseHookOptInFlags } from '../../setup/settings-hooks.js';

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..', '..');

type Call = [string, unknown];

/** A dispatch with every handler recording instead of acting. */
async function setup(command: 'setup' | 'install', args: string[]) {
  const calls: Call[] = [];
  const out: string[] = [];
  await dispatchSetupCommand(command, args, {
    log: (m) => out.push(m),
    uninstallSetup: async () => { calls.push(['uninstallSetup', undefined]); },
    setupClaudeMd: async (opts) => { calls.push(['setupClaudeMd', opts]); },
    handleQuickstartCommand: async (target) => { calls.push(['handleQuickstartCommand', target]); },
  });
  return { calls, out: out.join('\n') };
}

async function doctor(args: string[]) {
  const calls: Call[] = [];
  const out: string[] = [];
  await dispatchDoctorCommand(args, {
    log: (m) => out.push(m),
    runDoctor: async (a) => { calls.push(['runDoctor', a]); },
  });
  return { calls, out: out.join('\n') };
}

let savedExitCode: typeof process.exitCode;
beforeEach(() => { savedExitCode = process.exitCode; process.exitCode = undefined; });
afterEach(() => { process.exitCode = savedExitCode; });

describe('#707 — setup / install help prints usage and calls no installer', () => {
  const helpLines: Array<['setup' | 'install', string[]]> = [
    ['install', ['--help']],
    ['install', ['-h']],
    ['setup', ['--help']],
    ['setup', ['-h']],
    ['setup', ['help']],
    ['install', ['help']],
    // Hook-flag routing, help flag on either side of the hook flags.
    ['install', ['--with-stop-hook', '--help']],
    ['install', ['--help', '--with-stop-hook']],
    ['install', ['--with-stop-hook', '--with-session-end', '-h']],
    ['install', ['-h', '--with-session-end', '--with-stop-hook']],
    ['install', ['--without-stop-hook', '--help']],
    ['setup', ['--with-stop-hook', '--help']],
    ['setup', ['--help', '--with-stop-hook']],
    ['setup', ['--with-session-end', '-h']],
    ['setup', ['-h', '--with-session-end']],
    ['setup', ['--no-stop-hook', '--help']],
    ['setup', ['--help', '--no-stop-hook']],
    // Every other route the dispatcher has, too.
    ['setup', ['uninstall', '--help']],
    ['setup', ['claude', '-h']],
    ['setup', ['--yes', '--help']],
  ];

  it.each(helpLines)('%s %j', async (command, args) => {
    const r = await setup(command, args);
    expect(r.calls).toEqual([]);
    expect(r.out).toBe(SETUP_HELP);
    expect(process.exitCode).toBeUndefined();
  });

  it('the usage is meaningful: it names install, the hook flags and the no-op promise', () => {
    expect(SETUP_HELP).toContain('Usage: shieldcortex setup');
    expect(SETUP_HELP).toContain('shieldcortex install');
    for (const f of ['--with-stop-hook', '--with-session-end', '--without-stop-hook', '--without-session-end']) {
      expect(SETUP_HELP).toContain(f);
    }
    expect(SETUP_HELP).toMatch(/-h, --help\s+Show this help and exit \(installs and changes nothing\)/);
  });

  it('every hook flag the usage names is one the installer actually honours', () => {
    const named = [...SETUP_HELP.matchAll(/--with(?:out)?-[a-z-]+/g)].map((m) => m[0]);
    expect(named.length).toBeGreaterThanOrEqual(4);
    for (const flag of named) {
      const parsed = parseHookOptInFlags([flag]);
      expect({ flag, honoured: Object.values(parsed).some((v) => v !== undefined) })
        .toEqual({ flag, honoured: true });
    }
  });
});

describe('#707 — non-help setup / install routing is unchanged', () => {
  it('install → the Claude Code install with no opt-in fields', async () => {
    expect((await setup('install', [])).calls).toEqual([['setupClaudeMd', {}]]);
  });

  it('install with hook flags passes them through, in either order', async () => {
    const both = { stopHook: true, sessionEnd: true };
    expect((await setup('install', ['--with-stop-hook', '--with-session-end'])).calls)
      .toEqual([['setupClaudeMd', both]]);
    expect((await setup('install', ['--with-session-end', '--with-stop-hook'])).calls)
      .toEqual([['setupClaudeMd', both]]);
    expect((await setup('install', ['--without-stop-hook'])).calls)
      .toEqual([['setupClaudeMd', { stopHook: false }]]);
  });

  it('setup with a --with-* or --no-* flag is the Claude Code install, in either order', async () => {
    expect((await setup('setup', ['--with-stop-hook'])).calls)
      .toEqual([['setupClaudeMd', { stopHook: true }]]);
    expect((await setup('setup', ['--with-session-end', '--with-stop-hook'])).calls)
      .toEqual([['setupClaudeMd', { stopHook: true, sessionEnd: true }]]);
    expect((await setup('setup', ['--no-color'])).calls).toEqual([['setupClaudeMd', {}]]);
  });

  it('setup with no flags is the host-table wizard; a target is passed through', async () => {
    expect((await setup('setup', [])).calls).toEqual([['handleQuickstartCommand', undefined]]);
    expect((await setup('setup', ['claude'])).calls).toEqual([['handleQuickstartCommand', 'claude']]);
    expect((await setup('setup', ['--yes'])).calls).toEqual([['handleQuickstartCommand', '--yes']]);
    // A target this dispatcher does not know is still the quickstart handler's
    // to reject — the gate takes no view on data it does not own.
    expect((await setup('setup', ['bogus'])).calls).toEqual([['handleQuickstartCommand', 'bogus']]);
  });

  it('setup uninstall / install uninstall reach the uninstaller', async () => {
    expect((await setup('setup', ['uninstall'])).calls).toEqual([['uninstallSetup', undefined]]);
    expect((await setup('install', ['uninstall'])).calls).toEqual([['uninstallSetup', undefined]]);
  });

  it('`help` as a later positional is not the verb', async () => {
    expect((await setup('setup', ['hermes', 'help'])).calls).toEqual([['handleQuickstartCommand', 'hermes']]);
  });
});

describe('#707 — doctor help prints usage and runs no checks', () => {
  it.each([
    [['--help']],
    [['-h']],
    [['help']],
    [['--json', '--help']],
    [['--help', '--json']],
    [['--strict', '-h']],
    [['--fix-project-keys', '--help']],
    [['--repair', '--agent', '-h']],
  ])('doctor %j', async (args) => {
    const r = await doctor(args);
    expect(r.calls).toEqual([]);
    expect(r.out).toBe(DOCTOR_HELP);
    expect(process.exitCode).toBeUndefined();
  });

  it('non-help doctor arguments reach runDoctor verbatim', async () => {
    expect((await doctor([])).calls).toEqual([['runDoctor', []]]);
    expect((await doctor(['--json', '--strict'])).calls).toEqual([['runDoctor', ['--json', '--strict']]]);
    expect((await doctor(['--verbose'])).calls).toEqual([['runDoctor', ['--verbose']]]);
  });

  it('the usage lists exactly the flags runDoctor reads', () => {
    // Truthful usage, checked against the handler rather than by inspection:
    // every `args.includes('--x')` in doctor.ts is named, and nothing else is.
    const src = fs.readFileSync(path.join(repoRoot, 'src', 'cli', 'doctor.ts'), 'utf-8');
    const read = new Set([...src.matchAll(/args\.includes\('(--[a-z-]+)'\)/g)].map((m) => m[1]));
    const listed = new Set(
      [...DOCTOR_HELP.matchAll(/(?<![\w-])(--[a-z][a-z-]*)/g)].map((m) => m[1]).filter((f) => f !== '--help'),
    );
    expect(read.size).toBeGreaterThan(5);
    expect([...listed].sort()).toEqual([...read].sort());
    expect(DOCTOR_HELP).toContain('Usage: shieldcortex doctor');
    expect(DOCTOR_HELP).toMatch(/-h, --help\s+Show this help and exit \(runs no checks\)/);
  });
});

describe('#707 — the dispatch gate and the global preamble gate agree', () => {
  // The staleness preamble and stats banner in main() skip themselves on
  // argvWantsHelp(argv). If the dispatcher disagreed, a help request could
  // still spawn `npm ls -g` (preamble says "run") or a real run could skip it.
  const shapes: string[][] = [
    [], ['--help'], ['-h'], ['help'], ['--with-stop-hook'], ['--with-stop-hook', '--help'],
    ['--help', '--with-session-end'], ['uninstall'], ['uninstall', '-h'], ['claude'], ['claude', 'help'],
    ['--', '--help'], ['--'], ['--json'], ['--json', '-h'], ['--yes'],
  ];

  it.each(['setup', 'install', 'doctor'] as const)('%s', async (command) => {
    const disagreements: string[] = [];
    for (const args of shapes) {
      const ran = command === 'doctor'
        ? (await doctor(args)).calls.length > 0
        : (await setup(command, args)).calls.length > 0;
      if (argvWantsHelp([command, ...args]) === ran) disagreements.push(args.join(' '));
    }
    expect(disagreements).toEqual([]);
  });
});

describe('#707 — main() dispatches through the gated dispatchers', () => {
  const indexSrc = fs.readFileSync(path.join(repoRoot, 'src', 'index.ts'), 'utf-8');

  it('setup / install and doctor go through setup-dispatch, not the handlers directly', () => {
    expect(indexSrc).toContain('dispatchSetupCommand(');
    expect(indexSrc).toContain('dispatchDoctorCommand(process.argv.slice(3))');
    expect(indexSrc).not.toMatch(/\bsetupClaudeMd\(/);
    expect(indexSrc).not.toMatch(/\brunDoctor\(/);
    expect(indexSrc).not.toMatch(/import\('\.\/cli\/doctor\.js'\)/);
    expect(indexSrc).not.toMatch(/import\('\.\/setup\/claude-md\.js'\)/);
  });
});
