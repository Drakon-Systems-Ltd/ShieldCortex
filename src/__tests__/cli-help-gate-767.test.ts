/**
 * #767 — `--help` is a real gate for every command `main()` dispatches.
 *
 * Observed on 5.10.0: `shieldcortex consolidate --help` ran memory maintenance
 * and created the database; `api --help` started the API server; `stats`,
 * `deny`, `lease`, `protect`, `scan-skill` and `graph backfill` ignored the flag
 * and did the thing; `quickstart --help` fell through to a usage ERROR. A help
 * flag is the operator's one chance to read what a command does before it does
 * it — and the obvious thing for an agent to run when discovering a tool — so an
 * ungated help flag turns discovery into a write.
 *
 * The fix is one gate in front of the dispatcher (`dispatchHelp` in
 * src/cli/dispatch-help.ts), reading the shared registry in
 * src/cli/wants-help.ts and called first in `main()`, so a help request prints
 * usage and exits 0 before any handler module is imported.
 *
 * The command list is DERIVED from src/index.ts rather than written down here,
 * so a command added to the dispatcher without a gate fails this suite instead
 * of shipping. Every command is driven through the BUILT CLI under a fresh,
 * empty HOME, and the assertion is not just "usage was printed" but "and nothing
 * under HOME exists afterwards": the database, config, audit, log and npm planes
 * all live there. The free-text controls run against the gate function directly
 * — a real `remember` would write the memory it is proving it does not write.
 */
import { spawnSync } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { afterEach, beforeAll, describe, expect, it } from '@jest/globals';
import { requireFreshBuiltArtefacts } from './built-artefact-freshness.js';
import {
  DISPATCH_HELP,
  FREEZE_HELP,
  HOOK_HELP,
  UNFREEZE_HELP,
  dispatchHelp,
  isDispatchGated,
} from '../cli/dispatch-help.js';
import { argvWantsHelp, commandWantsHelp } from '../cli/wants-help.js';
import { BUILT_IN_HOOKS } from '../setup/hooks.js';
import { SCOPE_KEYWORDS } from '../defence/iron-dome/session-lease.js';

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..');
const DIST_ENTRY = path.join(repoRoot, 'dist', 'index.js');
const indexSrc = fs.readFileSync(path.join(repoRoot, 'src', 'index.ts'), 'utf-8');

/**
 * Commands whose HANDLER owns the gate: `--help` is answered inside the handler
 * module, before any side effect (#577 strict preflight and handler gates, #707
 * setup/doctor, and the rest). They are driven exactly like the dispatcher-gated
 * commands below; the split only records WHERE each gate is, so that a new
 * command has to be classified before this suite goes green.
 */
const HANDLER_GATED: readonly string[] = [
  'update', 'repair', 'migrate', 'uninstall', 'vacuum', 'compact', 'logs',        // #577: strict preflight
  'audit', 'allowlist', 'sessions', 'memories', 'openclaw', 'clawdbot', 'hermes', // #577: handler gates
  'doctor', 'setup', 'install',                                                   // #707
  'maintain', 'policy-evidence', 'import-jsonl', 'ledger', 'mcp',
];

/**
 * Commands this suite does NOT drive with `--help`, each with the reason. A
 * command here is a command whose help flag is unproven: keep it empty.
 */
const EXEMPT: ReadonlyArray<{ command: string; reason: string }> = [];

/** The verb-taking commands the issue named, for the `-h` and bare `help` forms. */
const VERB_FORMS = ['consolidate', 'api', 'stats', 'lease', 'deny', 'quickstart'] as const;

/**
 * Every command word `main()` dispatches on, read out of src/index.ts: each
 * `process.argv[2] === '<word>'` branch, plus the three server modes that
 * `parseArgs()` selects by `args[0]`. The top-level flags and the bare `help`
 * word are the top-level help, not commands.
 */
function dispatchedCommands(): string[] {
  const words = new Set<string>(['api', 'dashboard', 'worker']);
  for (const m of indexSrc.matchAll(/process\.argv\[2\] === '([^']+)'/g)) {
    const word = m[1];
    if (word.startsWith('-') || word === 'help') continue;
    words.add(word);
  }
  return [...words].sort();
}

const DISPATCHED = dispatchedCommands();
const DRIVEN = DISPATCHED.filter((c) => !EXEMPT.some((e) => e.command === c));

function freshHome(): string {
  return fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'sc767-help-')));
}

/** Every entry under `dir`, files and directories alike, relative to it. */
function entriesUnder(dir: string): string[] {
  const out: string[] = [];
  const visit = (d: string) => {
    for (const e of fs.readdirSync(d, { withFileTypes: true })) {
      const p = path.join(d, e.name);
      out.push(path.relative(dir, p));
      if (e.isDirectory()) visit(p);
    }
  };
  visit(dir);
  return out.sort();
}

interface CliRun {
  status: number | null;
  signal: NodeJS.Signals | null;
  stdout: string;
  stderr: string;
}

function runCli(home: string, args: string[], timeout = 20_000): CliRun {
  const env: NodeJS.ProcessEnv = {
    ...process.env,
    HOME: home,
    USERPROFILE: home,
    SHIELDCORTEX_CONFIG_DIR: path.join(home, '.shieldcortex'),
    NO_COLOR: '1',
    COLUMNS: '200',
  };
  // A path override inherited from the parent would let a write land outside
  // the HOME the walk below inspects.
  delete env.CLAUDE_MEMORY_DB;
  delete env.SHIELDCORTEX_AUDIT_DIR;
  const r = spawnSync(process.execPath, [DIST_ENTRY, ...args], {
    env, cwd: home, encoding: 'utf8', input: '', timeout,
  });
  return { status: r.status, signal: r.signal, stdout: r.stdout ?? '', stderr: r.stderr ?? '' };
}

const homes: string[] = [];
afterEach(() => {
  for (const h of homes.splice(0)) fs.rmSync(h, { recursive: true, force: true });
});

/**
 * Drive the built CLI with `args` under a fresh HOME: exit 0, no signal (a
 * server that never exits is killed by the timeout and shows up here), usage on
 * stdout, and not one entry under HOME afterwards.
 */
function expectUsageAndNoWrites(args: string[], usage: string): CliRun {
  const home = freshHome();
  homes.push(home);
  const r = runCli(home, args);
  const left = entriesUnder(home);
  expect({ args, status: r.status, signal: r.signal, left, stderr: r.stderr.slice(0, 400) })
    .toEqual({ args, status: 0, signal: null, left: [], stderr: expect.any(String) });
  expect(r.stdout).toContain(usage);
  return r;
}

describe('#767 — every dispatched command is classified, and the gate runs first', () => {
  it('derives the command list from src/index.ts', () => {
    expect(DISPATCHED.length).toBeGreaterThan(40);
    for (const w of ['consolidate', 'api', 'dashboard', 'worker', 'stats', 'lease', 'deny', 'quickstart', 'hook', 'update', 'doctor']) {
      expect(DISPATCHED).toContain(w);
    }
  });

  it('each command is dispatcher-gated, handler-gated or exempt — and only one of those', () => {
    const classes = DISPATCHED.map((command) => ({
      command,
      dispatcher: isDispatchGated(command),
      handler: HANDLER_GATED.includes(command),
      exempt: EXEMPT.some((e) => e.command === command),
    }));
    const unclassified = classes.filter((k) => !k.dispatcher && !k.handler && !k.exempt).map((k) => k.command);
    const twice = classes.filter((k) => [k.dispatcher, k.handler, k.exempt].filter(Boolean).length > 1).map((k) => k.command);
    expect({ unclassified, twice }).toEqual({ unclassified: [], twice: [] });
    // …and nothing is classified that the dispatcher does not know.
    const phantom = [...Object.keys(DISPATCH_HELP), ...HANDLER_GATED, ...EXEMPT.map((e) => e.command)]
      .filter((c) => !DISPATCHED.includes(c));
    expect(phantom).toEqual([]);
  });

  it('main() consults dispatchHelp before the hook branch and before any lazy import', () => {
    const mainAt = indexSrc.indexOf('async function main()');
    expect(mainAt).toBeGreaterThan(-1);
    const gateAt = indexSrc.indexOf('if (dispatchHelp(process.argv.slice(2))) return;', mainAt);
    expect(gateAt).toBeGreaterThan(mainAt);
    expect(gateAt).toBeLessThan(indexSrc.indexOf("process.argv[2] === 'hook'", mainAt));
    expect(gateAt).toBeLessThan(indexSrc.indexOf('await import(', mainAt));
  });

  it('every dispatcher usage names its own command', () => {
    for (const [command, text] of Object.entries(DISPATCH_HELP)) {
      const name = command === 'licence' ? 'license' : command;
      expect({ command, named: text.includes(`shieldcortex ${name}`) }).toEqual({ command, named: true });
    }
  });

  it('HOOK_HELP lists exactly the built-in hooks', () => {
    const m = /Built-in hooks: (.+)/.exec(HOOK_HELP);
    expect(m).not.toBeNull();
    expect((m as RegExpExecArray)[1].split(', ').sort()).toEqual(Object.keys(BUILT_IN_HOOKS).sort());
  });

  it('FREEZE_HELP and UNFREEZE_HELP list exactly the lease scopes', () => {
    const scopes = Object.keys(SCOPE_KEYWORDS).sort();
    for (const text of [FREEZE_HELP, UNFREEZE_HELP]) {
      const m = /<([a-z-]+(?:\|[a-z-]+)+)>/.exec(text);
      expect(m).not.toBeNull();
      expect((m as RegExpExecArray)[1].split('|').sort()).toEqual(scopes);
    }
  });
});

describe('#767 — `<command> --help` prints usage, exits 0 and writes nothing under HOME', () => {
  beforeAll(() => {
    requireFreshBuiltArtefacts({
      repoRoot,
      sources: ['src/index.ts', 'src/cli/dispatch-help.ts', 'src/cli/wants-help.ts'].map((p) => path.join(repoRoot, p)),
      artefacts: ['dist/index.js', 'dist/cli/dispatch-help.js', 'dist/cli/wants-help.js'].map((p) => path.join(repoRoot, p)),
    });
  });

  it.each(DRIVEN)('%s --help', (command) => {
    const r = expectUsageAndNoWrites([command, '--help'], 'Usage');
    if (isDispatchGated(command)) {
      // The dispatcher's gate prints the table entry and nothing else: no
      // banner, no staleness preamble, no handler output.
      expect(r.stdout).toBe(`${DISPATCH_HELP[command]}\n`);
      expect(r.stderr).toBe('');
    }
  }, 30_000);

  it.each(VERB_FORMS)('%s -h and bare help are the same request', (command) => {
    for (const form of ['-h', 'help']) {
      const r = expectUsageAndNoWrites([command, form], 'Usage');
      expect(r.stdout).toBe(`${DISPATCH_HELP[command]}\n`);
      expect(r.stderr).toBe('');
    }
  }, 30_000);

  it.each([
    '--mode api --help',
    '--mode worker -h',
    '--dashboard --help',
  ])('a help flag behind a global option (%s) prints the top-level help and starts no server', (line) => {
    const r = expectUsageAndNoWrites(line.split(' '), 'USAGE');
    expect(r.stdout).toContain('shieldcortex <subcommand> [options]');
  }, 30_000);

  it('positive control: a non-help invocation still reaches its handler', () => {
    // `inspect <unknown>` is answered by the inspect handler — its own usage
    // error on stderr, usage on stdout, exit 2 — so the dispatcher's gate did
    // not intercept an ordinary argument. This path runs the staleness
    // preamble and the stats banner, so HOME is not asserted empty here.
    const home = freshHome();
    homes.push(home);
    const r = runCli(home, ['inspect', 'no-such-subcommand'], 60_000);
    expect({ status: r.status, signal: r.signal }).toEqual({ status: 2, signal: null });
    expect(r.stderr).toContain('Unknown subcommand: inspect no-such-subcommand');
    expect(r.stdout).toContain('Usage: shieldcortex inspect');
  }, 90_000);
});

describe('#767 — free text and forwarded arguments are never a help request', () => {
  function gate(argv: string[]): { hit: boolean; out: string[] } {
    const out: string[] = [];
    return { hit: dispatchHelp(argv, (m) => out.push(m)), out };
  }

  it('remember: the title and every option value are data', () => {
    for (const argv of [
      ['remember', 'x', '--content', 'how to use --help'],
      ['remember', 'help'],
      ['remember', 'help', '--content', 'x'],
      ['remember', 'x', '--content', 'help', '--tags', 'help', '--project', 'help'],
    ]) {
      expect({ argv, ...gate(argv) }).toEqual({ argv, hit: false, out: [] });
      expect(argvWantsHelp(argv)).toBe(false);
    }
  });

  it('scan: everything after `--` is the text to scan, and the text may be "help"', () => {
    for (const argv of [
      ['scan', '--', '--help'],
      ['scan', '--', '-h'],
      ['scan', '--', 'help'],
      ['scan', 'help'],
      ['scan', 'tell', 'me', 'help'],
      ['scan', '--source', 'help', 'help'],
    ]) {
      expect({ argv, ...gate(argv) }).toEqual({ argv, hit: false, out: [] });
      expect(commandWantsHelp('scan', argv.slice(1))).toBe(false);
      expect(argvWantsHelp(argv)).toBe(false);
    }
  });

  it('freeze: every token after --reason is the reason', () => {
    const argv = ['freeze', 'npm-publish', '--reason', 'until', '--help', 'prints', 'usage'];
    expect(gate(argv)).toEqual({ hit: false, out: [] });
    expect(argvWantsHelp(argv)).toBe(false);
  });

  it('a first positional that is data, or an option value, may be spelled help', () => {
    for (const argv of [
      ['scan-skill', 'help'],
      ['xray', 'help'],
      ['config', '--mode', 'help'],
      ['protect', '--config', 'help'],
      ['guard', 'readiness', '--surface', 'help'],
      ['hook', 'pre-tool'],
    ]) {
      expect({ argv, ...gate(argv) }).toEqual({ argv, hit: false, out: [] });
    }
  });

  it('…while an explicit flag wins, and `--` is dropped exactly where the handler drops it', () => {
    for (const argv of [
      ['remember', 'x', '--help'],
      ['remember', 'x', '--content', 'y', '-h'],
      ['scan', '--help', '--', 'not help'],
      ['deny', '--', '--help'],
      ['deny', '--', 'help'],
      ['approve', 'abc123', '--', '-h'],
      ['consolidate', 'help'],
      ['quickstart', 'help'],
    ]) {
      const { hit, out } = gate(argv);
      expect({ argv, hit, out }).toEqual({ argv, hit: true, out: [DISPATCH_HELP[argv[0] as keyof typeof DISPATCH_HELP]] });
    }
  });

  it('commands the dispatcher does not gate, and unknown words, fall through untouched', () => {
    for (const argv of [['doctor', '--help'], ['update', '--help'], ['maintain', '-h'], ['no-such-command', '--help'], ['--help'], []]) {
      expect({ argv, ...gate(argv) }).toEqual({ argv, hit: false, out: [] });
    }
  });
});
