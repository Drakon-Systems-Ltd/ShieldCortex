/**
 * #577 round 3, blocker 1 — the global help gate must not be able to disagree
 * with the command it is gating for.
 *
 * `shieldcortex audit --deps-path node_modules help` is a help request: audit's
 * own gate skips `--deps-path`'s value and finds `help` in the verb slot. The
 * whole-argv gates in `src/index.ts` carried a different table (a flat
 * `GLOBAL_VALUE_FLAGS` and `verbDepth: 2`), counted `node_modules` as the verb,
 * answered "not a help request", and ran the `npm ls -g` staleness preamble —
 * which lets npm's own update-notifier reach the registry and write
 * `~/.npm/_logs` — before audit printed its usage.
 *
 * Two tables is the defect; the fix is one table. `COMMAND_HELP_SPECS` holds it,
 * `argvWantsHelp` (global) and `commandWantsHelp` (per command) both read it, and
 * this suite generates the argv shapes where they used to differ and asserts one
 * verdict across both. The entry-point regression for the exact reported
 * invocation is in help-entry-point-577.test.ts.
 */
import { describe, expect, it } from '@jest/globals';
import {
  COMMAND_HELP_SPECS,
  GLOBAL_VALUE_FLAGS,
  argvWantsHelp,
  commandWantsHelp,
  isGatedCommand,
  type GatedCommand,
} from '../wants-help.js';
import { AUDIT_VALUE_FLAGS } from '../audit.js';
import { ALLOWLIST_VALUE_FLAGS, runAllowlist } from '../allowlist.js';
import { SESSIONS_VALUE_FLAGS } from '../sessions.js';
import { MEMORIES_VALUE_FLAGS } from '../migrate-legacy.js';
import { OPENCLAW_VALUE_FLAGS } from '../../setup/openclaw.js';

const COMMANDS = Object.keys(COMMAND_HELP_SPECS) as GatedCommand[];

/**
 * Every argv shape that has ever told the two gates apart, for one command:
 * `help` after each value flag, `help` in the verb slot, `--help`/`-h` anywhere,
 * and the same lines behind a global `--db <path>` prefix (the one thing the
 * global gate legitimately knows about and the command does not).
 */
function argvShapes(command: GatedCommand): string[][] {
  const flags = COMMAND_HELP_SPECS[command].valueFlags;
  const shapes: string[][] = [
    [command],
    [command, 'help'],
    [command, '--help'],
    [command, '-h'],
    [command, 'verb', 'help'],
    [command, 'verb', '--help'],
    [command, 'verb', 'sub', '-h'],
    [command, '--force', 'help'],
  ];
  for (const f of flags) {
    shapes.push(
      [command, f, 'help'],                    // the value IS the first positional
      [command, f, 'help', 'help'],            // …and the verb comes after it
      [command, 'verb', f, 'help'],            // a value behind a real verb
      [command, f, 'node_modules', 'help'],    // the reported audit shape
      [command, f, 'help', '--help'],          // an explicit flag still wins
      [command, f, 'help', '-h'],
      [command, `${f}=help`],                  // one token: never a positional
      [command, f],                            // a dangling value flag
    );
  }
  // The same shapes with a global prefix the command never sees.
  return [...shapes, ...shapes.map((s) => ['--db', '/tmp/sc577.db', ...s])];
}

/** The command's own argv: everything after the command word. */
function handlerArgs(argv: string[]): { command: string; args: string[] } {
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if ((GLOBAL_VALUE_FLAGS as readonly string[]).includes(a)) { i++; continue; }
    if (a.startsWith('-') && a !== '-') continue;
    return { command: a, args: argv.slice(i + 1) };
  }
  return { command: '', args: [] };
}

describe('#577 — one value-flag table, read by every gate', () => {
  it('covers every command that owns a help gate', () => {
    // Keep the registry honest about its own scope: these are the command words
    // `src/index.ts` dispatches to a handler with a gate (plus the two aliases).
    expect(COMMANDS.sort()).toEqual([
      'allowlist', 'audit', 'clawdbot', 'compact', 'hermes', 'memories',
      'migrate', 'openclaw', 'repair', 'sessions', 'uninstall', 'update', 'vacuum',
    ]);
  });

  it('each command module reads its row, not a private copy', () => {
    // Identity, not equality: an equal-but-separate array is a second place to
    // edit, which is how the two gates diverged in the first place.
    expect(AUDIT_VALUE_FLAGS).toBe(COMMAND_HELP_SPECS.audit.valueFlags);
    expect(ALLOWLIST_VALUE_FLAGS).toBe(COMMAND_HELP_SPECS.allowlist.valueFlags);
    expect(SESSIONS_VALUE_FLAGS).toBe(COMMAND_HELP_SPECS.sessions.valueFlags);
    expect(MEMORIES_VALUE_FLAGS).toBe(COMMAND_HELP_SPECS.memories.valueFlags);
    expect(OPENCLAW_VALUE_FLAGS).toBe(COMMAND_HELP_SPECS.openclaw.valueFlags);
  });

  it('the documented aliases share their target\'s row object', () => {
    expect(COMMAND_HELP_SPECS.compact).toBe(COMMAND_HELP_SPECS.vacuum);
    expect(COMMAND_HELP_SPECS.clawdbot).toBe(COMMAND_HELP_SPECS.openclaw);
  });

  it('global gate and handler gate reach the same verdict for every generated shape', () => {
    const disagreements: Array<{ argv: string; global: boolean; handler: boolean }> = [];
    let checked = 0;
    for (const command of COMMANDS) {
      for (const argv of argvShapes(command)) {
        const { command: word, args } = handlerArgs(argv);
        expect(isGatedCommand(word)).toBe(true);
        const globalVerdict = argvWantsHelp(argv);
        const handlerVerdict = commandWantsHelp(word as GatedCommand, args);
        checked += 1;
        if (globalVerdict !== handlerVerdict) {
          disagreements.push({ argv: argv.join(' '), global: globalVerdict, handler: handlerVerdict });
        }
      }
    }
    expect(disagreements).toEqual([]);
    // A parity assertion over an empty set proves nothing — the shapes have to
    // exist, and both answers have to occur among them.
    expect(checked).toBeGreaterThan(200);
  });

  it('the generated shapes really do contain both verdicts', () => {
    const verdicts = new Set(COMMANDS.flatMap((c) => argvShapes(c)).map((a) => argvWantsHelp(a)));
    expect([...verdicts].sort()).toEqual([false, true]);
  });

  it('the reported invocation is a help request at both levels', () => {
    const argv = ['audit', '--deps-path', 'node_modules', 'help'];
    expect(argvWantsHelp(argv)).toBe(true);
    expect(commandWantsHelp('audit', argv.slice(1))).toBe(true);
    // The sibling shapes the fix must not break: a real audit run stays a run.
    expect(argvWantsHelp(['audit', '--deps-path', 'node_modules'])).toBe(false);
    expect(argvWantsHelp(['audit', '--deps-path', 'help'])).toBe(false);
    expect(commandWantsHelp('audit', ['--deps-path', 'help'])).toBe(false);
  });

  it('an unregistered command keeps the conservative reading', () => {
    // `doctor` and friends print no usage for a bare `help`, and a false positive
    // here only skips a staleness warning — but a `help` verb must still count.
    expect(isGatedCommand('doctor')).toBe(false);
    expect(argvWantsHelp(['doctor', 'help'])).toBe(true);
    expect(argvWantsHelp(['doctor', '--help'])).toBe(true);
    expect(argvWantsHelp(['doctor', '--json'])).toBe(false);
    expect(argvWantsHelp(['scan', 'tell', 'me', 'help'])).toBe(false);
  });

  it('a flag-only command line is not a help request', () => {
    expect(argvWantsHelp([])).toBe(false);
    expect(argvWantsHelp(['--db', '/tmp/x.db'])).toBe(false);
    expect(argvWantsHelp(['--mode', 'mcp'])).toBe(false);
    // …not even when a global value happens to spell it (MCP stdio, no banner).
    expect(argvWantsHelp(['--db', 'help'])).toBe(false);
    expect(argvWantsHelp(['--mode', 'help'])).toBe(false);
  });

  it('allowlist: the gate normalises `--` exactly as the handler does (round-3 review)', () => {
    // runAllowlist drops every bare `--` before its own gate and parser. The
    // global gate sees raw argv, so parity only holds if the shared gate applies
    // the same normalisation. Drive the REAL handler, not a copied predicate.
    const argv = ['--note', '--', 'reviewed', 'help'];
    const out: string[] = [];
    const reads: number[] = [];
    const code = runAllowlist(argv, {
      log: (m: string) => out.push(m),
      error: (m: string) => out.push(m),
      readEntries: () => { reads.push(1); return []; },
      writeEntries: () => { throw new Error('help must not write'); },
    });
    const handlerHelp = code === 0 && out.join('\n').includes('Usage: shieldcortex allowlist') && reads.length === 0;
    expect(handlerHelp).toBe(true);
    expect(argvWantsHelp(['allowlist', ...argv])).toBe(handlerHelp);
    expect(commandWantsHelp('allowlist', argv)).toBe(handlerHelp);
    // Normal paths unchanged: a `--` before a real note value is still not help.
    expect(argvWantsHelp(['allowlist', 'add', './x.sh', '--note', '--', 'help'])).toBe(false);
    expect(commandWantsHelp('allowlist', ['add', './x.sh', '--note', '--', 'help'])).toBe(false);
  });
});
