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
 * The command list is DERIVED from src/index.ts rather than written down here:
 * every `process.argv[2] === '<word>'` branch, plus the three server modes
 * `parseArgs()` selects. A command added in that shape without a gate fails this
 * suite instead of shipping. That is the whole guarantee — a command dispatched
 * another way (a switch, a membership test, a reversed or double-quoted
 * comparison) is invisible to the regex and has to be seeded by hand in
 * `dispatchedCommands`, so the derivation is a tripwire for the dispatch shape
 * `main()` uses today, not a proof over every shape it could use.
 * Every command is driven through the BUILT CLI under a fresh,
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
import {
  COMMAND_HELP_SPECS,
  GLOBAL_VALUE_FLAGS,
  argvWantsHelp,
  commandWantsHelp,
  consumesAsValue,
  wantsHelp,
  type GatedCommand,
  type ValueRule,
} from '../cli/wants-help.js';
import { parseProtectArgs } from '../cli/protect.js';
import { parseScanArgs } from '../cli/scan-command.js';
import { parseEmbedBackfillLimit, parseEmbedBackfillProject } from '../cli/embed-backfill.js';
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
 * word are the top-level help, not commands. Only that one comparison shape is
 * recognised (see the header): a dispatch written any other way must be added
 * to the seed set here, or it is not driven.
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

  /** The same argv at all three gates: dispatcher, the command's own, the whole-argv one. */
  function everyGate(argv: string[]): { dispatch: boolean; command: boolean; global: boolean } {
    return {
      dispatch: gate(argv).hit,
      command: commandWantsHelp(argv[0] as GatedCommand, argv.slice(1)),
      global: argvWantsHelp(argv),
    };
  }

  it('r2 B1: an option VALUE spelled --help or -h is that value, at every gate', () => {
    // Each handler reads the token after the option unconditionally
    // (remember/memory `parseFlag`, guard `argv[surfaceAt + 1]`, and Cortex's
    // generic parser, which consumes the token after EVERY `--key`). Before
    // round 2 the gate scanned the whole argv for the flag first, so these
    // printed usage and silently did not remember / downvote / check / capture.
    for (const argv of [
      ['remember', 'x', '--content', '--help'],
      ['remember', 'x', '--content', '-h'],
      ['remember', 'x', '--content', '--help', '--json'],
      ['remember', 'x', '--content', 'y', '--tags', '--help'],
      ['memory', 'downvote', 'x', '--reason', '--help'],
      ['guard', 'readiness', '--surface', '--help'],
      ['cortex', 'capture', '--what', '--help', '--category', 'code', '--why', 'x', '--rule', 'y'],
      ['cortex', 'capture', '--what', '-h'],
      ['cortex', 'capture', '--category', 'code', '--what', 'x', '--why', '--help', '--rule', 'y'],
    ]) {
      expect({ argv, ...everyGate(argv), out: gate(argv).out })
        .toEqual({ argv, dispatch: false, command: false, global: false, out: [] });
    }
  });

  it('r2 B1: …and a help flag at an option position, after a completed value, still counts', () => {
    for (const argv of [
      ['remember', 'x', '--content', 'y', '--help'],
      ['remember', 'x', '--content', '--help', '-h'],      // the value is "--help"; the -h is the flag
      ['memory', 'downvote', 'x', '--reason', 'y', '-h'],
      ['guard', 'readiness', '--surface', 'claude-code', '--help'],
      ['cortex', 'capture', '--what', 'y', '--help'],
      ['cortex', 'capture', '--help', '--what', 'y'],
      ['cortex', '-h'],
    ]) {
      expect({ argv, ...everyGate(argv), out: gate(argv).out })
        .toEqual({ argv, dispatch: true, command: true, global: true, out: [DISPATCH_HELP[argv[0] as keyof typeof DISPATCH_HELP]] });
    }
    // The primitive itself: a value position is a value only when the caller
    // says the option takes one — without the list, `--help` anywhere counts,
    // which is what the handler-gated commands with all-boolean options rely on.
    expect(wantsHelp(['--content', '--help'], { values: { '--content': 'always' } })).toBe(false);
    expect(wantsHelp(['--content', '--help'])).toBe(true);
    expect(wantsHelp(['verb', 'arg', '--help'], { values: { '--content': 'always' } })).toBe(true);
  });

  it('r2 B2: `hook <name>` — the first argument is a hook name, so `hook help` runs the hook named help', () => {
    // src/setup/hooks.ts looks the first argument up in BUILT_IN_HOOKS and then
    // in config.json's customHooks, without reserving "help": a custom hook may
    // be named that, and was runnable before #767. Only the flags ask for usage.
    expect({ argv: ['hook', 'help'], ...everyGate(['hook', 'help']), out: gate(['hook', 'help']).out })
      .toEqual({ argv: ['hook', 'help'], dispatch: false, command: false, global: false, out: [] });
    for (const argv of [['hook', '--help'], ['hook', '-h']]) {
      expect({ argv, ...everyGate(argv), out: gate(argv).out })
        .toEqual({ argv, dispatch: true, command: true, global: true, out: [HOOK_HELP] });
    }
  });

  it('commands the dispatcher does not gate, and unknown words, fall through untouched', () => {
    for (const argv of [['doctor', '--help'], ['update', '--help'], ['maintain', '-h'], ['no-such-command', '--help'], ['--help'], []]) {
      expect({ argv, ...gate(argv) }).toEqual({ argv, hit: false, out: [] });
    }
  });
});

/**
 * #767 round 3 — the gate steps over a token exactly when the command's OWN
 * parser would read it as the option's value (B3), and an inline/server row
 * declares only the options `parseArgs()` reads (B4).
 *
 * B3, reproduced on the built CLI by the round-2 review: `sessions prune --days
 * --help` printed no usage, ran a dry-run prune and created the database. The
 * sessions handler's `flagValue` returns "no value" for a token starting with
 * `--` and leaves it unread — so `--help` was a help flag to the handler — while
 * the round-2 gate stepped over the token after EVERY declared value flag. Each
 * option now carries its parser's rule, and the gate applies that rule.
 */
describe('#767 round 3 — each option is read the way its own parser reads it', () => {
  /**
   * The command's gate and the whole-argv gate, and the dispatcher's where it
   * answers for the command (the #577 handler-gated commands are not in its
   * table). All of them read the same row, so they must all agree.
   */
  function verdicts(argv: string[]): Record<string, boolean> {
    const v: Record<string, boolean> = {
      command: commandWantsHelp(argv[0] as GatedCommand, argv.slice(1)),
      global: argvWantsHelp(argv),
    };
    if (isDispatchGated(argv[0])) v.dispatch = dispatchHelp(argv, () => {});
    return v;
  }

  function expectHelp(argv: string[], help: boolean): void {
    const v = verdicts(argv);
    const want = Object.fromEntries(Object.keys(v).map((k) => [k, help]));
    expect({ argv, ...v }).toEqual({ argv, ...want });
  }

  it('B3: an option whose parser leaves a `--`-leading token UNREAD is followed by a help flag', () => {
    for (const argv of [
      ['sessions', 'prune', '--days', '--help'],             // src/cli/sessions.ts flagValue — the reproduction
      ['audit', '--deps-path', '--help'],                    // src/cli/audit.ts parseAuditArgs
      ['protect', '--config', '--help'],                     // src/cli/protect.ts parseProtectArgs
      ['memories', 'prune', '--project', '--help'],          // src/cli/migrate-legacy.ts flagValue
      ['memories', 'prune', '--salience-lte', '--help'],
      ['memories', 'prune', '--older-than', '--help'],
      ['memories', 'dedupe', '--limit', '--help'],
      ['memories', 'repair-project-keys', '--db', '--help'],
      ['memories', 'repair-project-keys', '--scan-paths', '--help'],
      ['memories', 'recalc', '--backup-dir', '--help'],
      ['memories', 'purge', '--malformed', '--backup-dir', '--help'],
      ['config', '--memory-plane', '--help'],                // src/cloud/cli.ts: "Missing value" without reading it
      ['config', '--memory-inject-contract', '--help'],
      ['config', '--memory-host-posture', '--help'],
      ['config', '--memory-host-runtime', '--help'],
      ['config', '--auto-memory-sampling', '--help'],
      ['config', '--action-guard-notify-webhook', '--help'],
    ]) expectHelp(argv, true);
  });

  it('B3: an option whose parser refuses ANY `-`-leading token is followed by a help flag, `-h` included', () => {
    for (const argv of [
      ['allowlist', 'scan', '--glob', '--help'],             // src/cli/allowlist-scan.ts runAllowlistScan
      ['allowlist', 'scan', '--openclaw-cron-db', '-h'],
      ['allowlist', 'add', './x.sh', '--note', '--help'],    // src/cli/allowlist.ts add
      ['allowlist', 'add', './x.sh', '--note', '-h'],
      ['openclaw', 'skill', 'install', '--agent', '--help'], // src/setup/openclaw.ts skill install
      ['openclaw', 'skill', 'install', '--agent', '-h'],
      ['clawdbot', 'skill', 'update', '--agent', '--help'],
      ['scan', 'text', '--source', '--help'],                // src/cli/scan-command.ts takeFlagValue
      ['scan', 'text', '--identifier', '-h'],
      ['memories', 'import-native', 'notes.md', '--host-id', '--help'], // src/cli/import-native.ts
      ['memories', 'import-native', 'notes.md', '--agent-id', '-h'],
      ['memories', 'import-native', 'notes.md', '--project', '-h'],
      ['memories', 'embed-backfill', '--project', '--help'], // src/cli/embed-backfill.ts parseEmbedBackfillProject
      ['memories', 'reclassify', '--project', '-h'],         // src/cli/reclassify.ts
    ]) expectHelp(argv, true);
  });

  it('B3: `-h` after a parser that checks only for `--` is the value "-h", as that parser reads it', () => {
    // sessions' and migrate-legacy's `flagValue`, audit's `--deps-path` and
    // protect's `--config` test the next token for a `--` prefix and nothing
    // else: "-h" is a (soon rejected) number, path or project key to them and a
    // help request to nobody. The gate says what the parser says — the real one:
    expect(parseProtectArgs(['--config', '-h']).sourceConfig).toBe('-h');
    expect(parseProtectArgs(['--config', '--help']).sourceConfig).toBeUndefined();
    for (const argv of [
      ['sessions', 'prune', '--days', '-h'],
      ['protect', '--config', '-h'],
      ['memories', 'prune', '--project', '-h'],
      ['audit', '--deps-path', '-h'],
    ]) expectHelp(argv, false);
  });

  it('B3 controls (B1 preserved): a value read unconditionally may be spelled --help or -h', () => {
    for (const argv of [
      ['remember', 'x', '--content', '--help'],
      ['memory', 'downvote', 'x', '--reason', '--help'],
      ['guard', 'readiness', '--surface', '--help'],
      ['cortex', 'capture', '--what', '--help', '--category', 'code'],
      ['api', '--db', '--help'],                              // the database path really is "--help"
      ['protect', '--agent-uid', '--help'],                   // kept as the malformed uid "--help", refused by name
      ['memories', 'migrate-legacy', '--source', '--help'],   // args[sourceIdx + 1], whenever truthy
      ['memories', 'embed-backfill', '--limit', '--help'],    // readFlag reads it; refused as a non-integer
      ['memories', 'repair-project-keys', '--map', '--help'], // args[i + 1], whenever truthy; refused as not k=v
      ['config', '--mode', '--help'],                          // "Invalid mode: --help"
      ['config', '--ranker', '-h'],
      ['review-copilot', 'annotate', '--id', '-h'],
      ['approve', 'abc123', '--ttl', '--help'],
      ['iron-dome', 'scan', '--text', '--help'],
      ['inspect', 'last-recall', '--history', '-h'],
      ['scan-skills', '--dir', '--help'],                      // the directory really is "--help"
    ]) expectHelp(argv, false);
    // …and a help flag after a completed value still counts, for every kind of option.
    for (const argv of [
      ['sessions', 'prune', '--days', '7', '--help'],
      ['memories', 'embed-backfill', '--limit', '5', '-h'],
      ['memories', 'import-native', 'notes.md', '--project', 'acme', '--help'],
      ['protect', '--config', '/etc/x.json', '-h'],
      ['scan-skills', '--dir', '/tmp', '--help'],
    ]) expectHelp(argv, true);
  });

  it('B3: a verb row applies only behind its verb, and import-native honours `--` like its parser', () => {
    // src/cli/import-native.ts: after a bare `--` every token is a path.
    expectHelp(['memories', 'import-native', '--', '--help'], false);
    expectHelp(['memories', 'import-native', '--help', '--', 'x'], true);
    // The other memories verbs have no `--` handling; their `--help` is a flag anywhere.
    expectHelp(['memories', 'prune', '--', '--help'], true);
    // `memories prune help` is an argument to prune, as before; the verb slot is `memories`' own.
    expectHelp(['memories', 'prune', 'help'], false);
    expectHelp(['memories', 'help'], true);
    expectHelp(['memories', 'no-such-verb', '--help'], true);
    expectHelp(['memories', '--project', 'help'], true);      // not a verb → usage from the handler too
  });

  it('B3: the real parsers read the token exactly as the rule says, for the parsers that are cheap to call', () => {
    const probes = ['--help', '-h', 'help', 'x'];
    for (const token of probes) {
      // protect --config: unless-double-dash; --agent-uid: always.
      expect({ token, consumed: parseProtectArgs(['--config', token]).sourceConfig === token })
        .toEqual({ token, consumed: consumesAsValue(COMMAND_HELP_SPECS.protect.values['--config'], token) });
      expect({ token, consumed: parseProtectArgs(['--agent-uid', token]).agentUid === token })
        .toEqual({ token, consumed: consumesAsValue(COMMAND_HELP_SPECS.protect.values['--agent-uid'], token) });
      // scan --identifier: unless-dash (every probe is a well-formed identifier when read).
      const scanned = parseScanArgs(['text', '--source', 'document', '--identifier', token]);
      expect({ token, consumed: scanned.ok && scanned.source.identifier === token })
        .toEqual({ token, consumed: consumesAsValue(COMMAND_HELP_SPECS.scan.values['--identifier'], token) });
      // embed-backfill --project: unless-dash.
      const project = parseEmbedBackfillProject(['--project', token]);
      expect({ token, consumed: project.ok && project.project === token })
        .toEqual({ token, consumed: consumesAsValue(COMMAND_HELP_SPECS.memories.verbs!['embed-backfill'].values['--project'], token) });
    }
    // embed-backfill --limit: always — read whatever it is, then refused as a non-integer.
    expect(parseEmbedBackfillLimit(['--limit', '--help'])).toEqual({ ok: false, error: expect.stringContaining('positive integer') });
    expect(parseEmbedBackfillLimit(['--limit', '5'])).toEqual({ ok: true, limit: 5 });
    expect(COMMAND_HELP_SPECS.memories.verbs!['embed-backfill'].values['--limit']).toBe('always');
  });

  it('B4: `--dir` is scan-skills\' option; on every other inline/server command `--dir --help` is a help flag', () => {
    for (const argv of [
      ['api', '--dir', '--help'],
      ['dashboard', '--dir', '--help'],
      ['worker', '--dir', '-h'],
      ['graph', '--dir', '--help'],
      ['threat-graph', '--dir', '-h'],
      ['env', '--dir', '--help'],
      ['consolidate', '--dir', '--help'],
      ['scan-skill', '--dir', '--help'],
    ]) expectHelp(argv, true);
    // `parseArgs()` in src/index.ts reads the token after --db / --mode whenever
    // it is truthy: those values really are "--help", on every command line.
    for (const argv of [
      ['api', '--db', '--help'],
      ['dashboard', '--mode', '--help'],
      ['worker', '--db', '-h'],
    ]) expectHelp(argv, false);
    // The flag-only command line: parseArgs() does not read --dir there either.
    expect(argvWantsHelp(['--dir', '--help'])).toBe(true);
    expect(argvWantsHelp(['--db', '--help'])).toBe(false);
    expect(argvWantsHelp(['--mode', 'api', '--dir', '-h'])).toBe(true);
    expect(GLOBAL_VALUE_FLAGS).toEqual(['--db', '--mode']);
    expect([...COMMAND_HELP_SPECS['scan-skills'].valueFlags].sort()).toEqual(['--db', '--dir', '--mode']);
    expect(COMMAND_HELP_SPECS.api.valueFlags).not.toContain('--dir');
  });

  it('the audited rule of every value-taking option — the round-3 review table, pinned', () => {
    // One line per (command [verb] flag) → how that option's parser reads the
    // token after it. Read out of each parser by hand (file:line in the row
    // comments of src/cli/wants-help.ts); a change here is a change to a parser
    // or to the audit, and has to be deliberate either way.
    const table: Record<string, ValueRule> = {};
    for (const command of Object.keys(COMMAND_HELP_SPECS).sort() as GatedCommand[]) {
      const row = COMMAND_HELP_SPECS[command];
      for (const [flag, rule] of Object.entries(row.values)) table[`${command} ${flag}`] = rule;
      for (const [verb, verbRow] of Object.entries(row.verbs ?? {})) {
        for (const [flag, rule] of Object.entries(verbRow.values)) table[`${command} ${verb} ${flag}`] = rule;
      }
    }
    const global: Record<string, ValueRule> = { '--db': 'always', '--mode': 'always' };
    const prefixed = (command: string, rules: Record<string, ValueRule>) =>
      Object.fromEntries(Object.entries(rules).map(([f, r]) => [`${command} ${f}`, r]));
    expect(table).toEqual({
      ...prefixed('allowlist', {
        '--glob': 'unless-dash', '--hermes-cron': 'unless-dash', '--openclaw-cron': 'unless-dash',
        '--openclaw-cron-db': 'unless-dash', '--note': 'unless-dash',
      }),
      ...prefixed('api', global),
      ...prefixed('approve', { '--ttl': 'always', '--attempt': 'always' }),
      ...prefixed('audit', { '--deps-path': 'unless-double-dash' }),
      ...prefixed('clawdbot', { '--agent': 'unless-dash' }),
      ...prefixed('config', {
        '--mode': 'always', '--cloud-api-key': 'always', '--cloud-url': 'always', '--verify-mode': 'always',
        '--verify-timeout': 'always', '--openclaw-auto-memory': 'always', '--ranker': 'always',
        '--proactive-recall': 'always', '--self-heal': 'always',
        '--action-guard-notify-webhook': 'unless-double-dash', '--memory-inject-contract': 'unless-double-dash',
        '--memory-plane': 'unless-double-dash', '--memory-host-posture': 'unless-double-dash',
        '--memory-host-runtime': 'unless-double-dash', '--auto-memory-sampling': 'unless-double-dash',
      }),
      ...prefixed('consolidate', global),
      ...prefixed('dashboard', global),
      ...prefixed('deny', { '--attempt': 'always' }),
      ...prefixed('env', global),
      ...prefixed('graph', global),
      ...prefixed('guard', { '--surface': 'always' }),
      ...prefixed('inspect', { '--history': 'always' }),
      ...prefixed('iron-dome', { '--profile': 'always', '--text': 'always', '--file': 'always', '--search': 'always' }),
      ...prefixed('memories migrate-legacy', { '--source': 'always' }),
      ...prefixed('memories prune', {
        '--salience-lte': 'unless-double-dash', '--older-than': 'unless-double-dash', '--project': 'unless-double-dash',
      }),
      ...prefixed('memories dedupe', { '--project': 'unless-double-dash', '--limit': 'unless-double-dash' }),
      ...prefixed('memories repair-project-keys', {
        '--map': 'always', '--scan-paths': 'unless-double-dash', '--project': 'unless-double-dash', '--db': 'unless-double-dash',
      }),
      ...prefixed('memories purge', { '--backup-dir': 'unless-double-dash' }),
      ...prefixed('memories recalc', { '--backup-dir': 'unless-double-dash', '--db': 'unless-double-dash' }),
      ...prefixed('memories import-native', { '--host-id': 'unless-dash', '--agent-id': 'unless-dash', '--project': 'unless-dash' }),
      ...prefixed('memories embed-backfill', { '--limit': 'always', '--project': 'unless-dash' }),
      ...prefixed('memories reclassify', { '--project': 'unless-dash' }),
      ...prefixed('memory', { '--reason': 'always', '--purpose': 'always', '--category': 'always', '--limit': 'always' }),
      ...prefixed('openclaw', { '--agent': 'unless-dash' }),
      ...prefixed('protect', { '--config': 'unless-double-dash', '--agent-uid': 'always' }),
      ...prefixed('remember', {
        '--content': 'always', '--category': 'always', '--importance': 'always', '--tags': 'always', '--project': 'always',
      }),
      ...prefixed('review-copilot', { '--id': 'always', '--limit': 'always' }),
      ...prefixed('scan', { '--source': 'unless-dash', '--identifier': 'unless-dash' }),
      ...prefixed('scan-skill', global),
      ...prefixed('scan-skills', { ...global, '--dir': 'always' }),
      ...prefixed('sessions', { '--days': 'unless-double-dash' }),
      ...prefixed('threat-graph', global),
      ...prefixed('worker', global),
    });
  });
});

describe('#767 round 3 — built CLI, isolated HOME', () => {
  beforeAll(() => {
    requireFreshBuiltArtefacts({
      repoRoot,
      sources: ['src/index.ts', 'src/cli/dispatch-help.ts', 'src/cli/wants-help.ts', 'src/cli/sessions.ts'].map((p) => path.join(repoRoot, p)),
      artefacts: ['dist/index.js', 'dist/cli/dispatch-help.js', 'dist/cli/wants-help.js', 'dist/cli/sessions.js'].map((p) => path.join(repoRoot, p)),
    });
  });

  it('B3: `sessions prune --days --help` prints usage, exits 0 and creates nothing under HOME', () => {
    // The round-2 reproduction: this ran a dry-run prune and created
    // ~/.shieldcortex/memories.db. Usage on stdout, no prune banner, empty HOME.
    const r = expectUsageAndNoWrites(['sessions', 'prune', '--days', '--help'], 'Usage: shieldcortex sessions');
    expect(r.stdout).not.toContain('DRY RUN');
    expect(r.stdout).not.toContain('Matched:');
  }, 30_000);

  it('B4: `api --dir --help`, `dashboard --dir --help` and `worker --dir -h` print the server usage and start nothing', () => {
    for (const [argv, usage] of [
      [['api', '--dir', '--help'], DISPATCH_HELP.api],
      [['dashboard', '--dir', '--help'], DISPATCH_HELP.dashboard],
      [['worker', '--dir', '-h'], DISPATCH_HELP.worker],
    ] as const) {
      const r = expectUsageAndNoWrites([...argv], 'Usage');
      expect(r.stdout).toBe(`${usage}\n`);
      expect(r.stderr).toBe('');
    }
  }, 90_000);
});
