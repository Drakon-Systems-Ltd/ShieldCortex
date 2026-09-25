/**
 * #577 round 2 — the help gate must not eat real work, and a rejected argument
 * must cost nothing.
 *
 * Round 1 put a strict parser in front of every host-mutating subcommand. The
 * review found the two ways that over-reached:
 *
 *  1. `--allow-conversation-access` (#226) is read by the plugin reconcile, several
 *     modules below `update` and `repair`. Neither parser knew about it, so
 *     `shieldcortex update --allow-conversation-access` — a documented, working
 *     invocation — exited 2 without running. A strict allow-list is only as
 *     honest as its inventory of the WHOLE call graph's argv readers.
 *
 *  2. `wantsHelp` answered "is the word `help` anywhere in argv?", so the VALUE
 *     of a value-taking option was read as a help request:
 *     `openclaw skill install --agent help`, `memories prune --project help`
 *     and `memories migrate-legacy --source help` all printed usage and
 *     returned 0 having done nothing at all.
 *
 * Every test here fails if its fix is reverted — the two gates are the subject,
 * not the scaffolding.
 */
import { describe, expect, it, jest } from '@jest/globals';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { wantsHelp, GLOBAL_VALUE_FLAGS } from '../wants-help.js';
import { helpGate } from '../help-gate.js';
import {
  UPDATE_FLAGS,
  UPDATE_HELP,
  handleUpdateCommand,
  parseUpdateOptions,
  reexecUpdatedCli,
  stepVerifyProtection,
  type UpdateOptions,
} from '../update.js';
import {
  REPAIR_FLAGS,
  REPAIR_HELP,
  parseRepairOptions,
  runRepair,
  type RepairOptions,
} from '../repair.js';
import { OPENCLAW_VALUE_FLAGS, handleOpenClawCommand } from '../../setup/openclaw.js';
import { MEMORIES_VALUE_FLAGS, handleMemoriesCommand } from '../migrate-legacy.js';
import { SESSIONS_VALUE_FLAGS } from '../sessions.js';
import { preflightStrictArgs } from '../strict-args-preflight.js';
import { closeDatabase } from '../../database/init.js';

/** Source of a repo file, with comment lines removed — prose about a defect
 *  must not be mistaken for the defect. */
function codeOf(relative: string): string {
  const text = fs.readFileSync(new URL(relative, import.meta.url).pathname, 'utf-8');
  return text
    .split('\n')
    .filter((l) => !/^\s*(\/\/|\*|\/\*)/.test(l))
    .join('\n');
}

/** Capture console + stream writes; restore process.exitCode so Jest does not exit 2. */
async function withConsole(fn: () => Promise<void>): Promise<{ out: string[]; err: string[]; exitCode: number }> {
  const out: string[] = [];
  const err: string[] = [];
  const prevExit = process.exitCode;
  const origLog = console.log;
  const origError = console.error;
  const origOut = process.stdout.write.bind(process.stdout);
  const origErr = process.stderr.write.bind(process.stderr);
  const origExit = process.exit;
  process.exit = ((code?: number) => { throw new Error(`process.exit(${code})`); }) as typeof process.exit;
  console.log = ((...a: unknown[]) => { out.push(a.map(String).join(' ')); }) as typeof console.log;
  console.error = ((...a: unknown[]) => { err.push(a.map(String).join(' ')); }) as typeof console.error;
  process.stdout.write = ((c: string | Uint8Array) => { out.push(String(c)); return true; }) as typeof process.stdout.write;
  process.stderr.write = ((c: string | Uint8Array) => { err.push(String(c)); return true; }) as typeof process.stderr.write;
  process.exitCode = 0;
  try {
    await fn();
    return { out, err, exitCode: typeof process.exitCode === 'number' ? process.exitCode : 0 };
  } finally {
    console.log = origLog;
    console.error = origError;
    process.stdout.write = origOut;
    process.stderr.write = origErr;
    process.exit = origExit;
    process.exitCode = prevExit;
  }
}

// ── Blocker 1: --allow-conversation-access is a flag both commands honour ────

describe('#577 — update accepts and threads --allow-conversation-access', () => {
  const sink = () => {
    const out: string[] = [];
    const err: string[] = [];
    return { out, err, log: (m: string) => out.push(m), error: (m: string) => err.push(m) };
  };

  it('the normal path reaches runUpdate with consent=true instead of exiting 2', async () => {
    const seen: UpdateOptions[] = [];
    const run = jest.fn(async (o: UpdateOptions) => { seen.push(o); });
    const s = sink();
    const { exitCode } = await withConsole(async () => {
      await handleUpdateCommand(['--allow-conversation-access'], { run, env: {}, log: s.log, error: s.error });
    });
    expect(s.err).toEqual([]);
    expect(exitCode).toBe(0);
    expect(seen).toEqual([{ force: false, verbose: false, allowConversationAccess: true }]);
  });

  it('the env twin resolves at the same single parse point', () => {
    expect(parseUpdateOptions([], { SHIELDCORTEX_ALLOW_CONVERSATION_ACCESS: '1' }).allowConversationAccess).toBe(true);
    expect(parseUpdateOptions([], {}).allowConversationAccess).toBe(false);
  });

  it('the flag and its env twin are documented in the usage', () => {
    expect(UPDATE_FLAGS).toContain('--allow-conversation-access');
    expect(UPDATE_HELP).toContain('--allow-conversation-access');
    expect(UPDATE_HELP).toContain('SHIELDCORTEX_ALLOW_CONVERSATION_ACCESS');
  });

  it('consent reaches the reconcile as a parameter, not a deep process.argv read', async () => {
    // stepVerifyProtection owns the reconcile call. Reading the plugin registry
    // out of an empty temp HOME returns "not registered", so point it at a home
    // that IS registered and watch the option arrive.
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'sc577-consent-'));
    try {
      const openclaw = path.join(tmp, '.openclaw');
      fs.mkdirSync(openclaw, { recursive: true });
      fs.writeFileSync(
        path.join(openclaw, 'openclaw.json'),
        JSON.stringify({ plugins: { entries: { 'shieldcortex-realtime': { enabled: true } } } }),
      );
      const prevArgv = process.argv;
      // The old code read consent from process.argv here. Leave the flag OUT of
      // argv so only the threaded parameter can produce `true`.
      process.argv = [process.argv[0], process.argv[1], 'update'];
      try {
        await withConsole(async () => {
          await stepVerifyProtection(tmp, { verbose: false, allowConversationAccess: true });
        });
      } finally {
        process.argv = prevArgv;
      }
      // The reconcile is dynamically imported and reads the host; what matters
      // is that the option is declared on the call it makes.
      const code = codeOf('../update.ts');
      const at = code.indexOf('export async function stepVerifyProtection');
      const body = code.slice(at, code.indexOf('\n}', at));
      expect(body).toContain('grantConversationAccess: options.allowConversationAccess');
      expect(body).not.toContain('process.argv');
    } finally {
      fs.rmSync(tmp, { recursive: true, force: true });
    }
  });

  it('the re-exec argv round-trips the flag through the new parser', async () => {
    let launched: string[] = [];
    await reexecUpdatedCli('5.1.0', {
      readVersion: () => '5.2.0',
      env: {},
      argv: ['update', '--allow-conversation-access'],
      launch: async (_bin: string, args: string[]) => { launched = args; return 0; },
    });
    expect(launched.slice(1)).toEqual(['update', '--allow-conversation-access']);
    const run = jest.fn(async () => {});
    const s = sink();
    await withConsole(async () => {
      await handleUpdateCommand(launched.slice(2), { run, env: {}, log: s.log, error: s.error });
    });
    expect(s.err).toEqual([]);
    expect(run).toHaveBeenCalledWith({ force: false, verbose: false, allowConversationAccess: true });
  });
});

describe('#577 — repair accepts and threads --allow-conversation-access', () => {
  it('the normal path reaches the repair run with consent=true instead of exiting 2', async () => {
    const seen: RepairOptions[] = [];
    const run = jest.fn(async (o: RepairOptions) => { seen.push(o); });
    const { err, exitCode } = await withConsole(async () => {
      await runRepair(['--allow-conversation-access'], { run, env: {} });
    });
    expect(err).toEqual([]);
    expect(exitCode).toBe(0);
    expect(seen).toEqual([{ allowConversationAccess: true }]);
  });

  it('a bare repair still runs, with consent off', async () => {
    const seen: RepairOptions[] = [];
    const run = jest.fn(async (o: RepairOptions) => { seen.push(o); });
    await withConsole(async () => { await runRepair([], { run, env: {} }); });
    expect(seen).toEqual([{ allowConversationAccess: false }]);
  });

  it('the env twin resolves at the same single parse point', () => {
    expect(parseRepairOptions([], { SHIELDCORTEX_ALLOW_CONVERSATION_ACCESS: '1' })).toEqual({ allowConversationAccess: true });
    expect(parseRepairOptions([], {})).toEqual({ allowConversationAccess: false });
  });

  it('the flag and its env twin are documented in the usage', () => {
    expect(REPAIR_FLAGS).toContain('--allow-conversation-access');
    expect(REPAIR_HELP).toContain('--allow-conversation-access');
    expect(REPAIR_HELP).toContain('SHIELDCORTEX_ALLOW_CONVERSATION_ACCESS');
  });

  it('the reconcile pass takes the consent as a parameter, not from process.argv', () => {
    const code = codeOf('../repair.ts');
    expect(code).toContain('grantConversationAccess: options.allowConversationAccess');
    expect(code).not.toContain('process.argv');
  });

  it('the reconciler no longer reads process.argv when the caller supplied consent', () => {
    const code = codeOf('../../setup/openclaw-reconcile.ts');
    const at = code.indexOf('async function defaultRestoreRegistration');
    const body = code.slice(at, code.indexOf('\n}', at));
    expect(body).not.toContain('process.argv');
    expect(body).toContain('grantConversationAccess');
  });
});

// ── Blocker 2: a value spelled "help" is a value ─────────────────────────────

describe('#577 — wantsHelp distinguishes the help verb from an option value', () => {
  it('--help / -h still count anywhere, including a non-first position', () => {
    expect(wantsHelp(['--help'])).toBe(true);
    expect(wantsHelp(['-h'])).toBe(true);
    expect(wantsHelp(['skill', 'install', '--help'])).toBe(true);
    expect(wantsHelp(['prune', '--project', 'acme', '--help'], { valueFlags: ['--project'] })).toBe(true);
    expect(wantsHelp(['--force', '-h'])).toBe(true);
  });

  it('a bare `help` counts only in the verb position', () => {
    expect(wantsHelp(['help'])).toBe(true);
    expect(wantsHelp(['--verbose', 'help'])).toBe(true);
    // Already past the verb: `help` here is an argument to `prune`.
    expect(wantsHelp(['prune', 'help'])).toBe(false);
    expect(wantsHelp(['add', '/tmp/help.sh'])).toBe(false);
  });

  it('the value of a value-taking option is never the verb', () => {
    expect(wantsHelp(['--agent', 'help'], { valueFlags: ['--agent'] })).toBe(false);
    expect(wantsHelp(['--source', 'help'], { valueFlags: ['--source'] })).toBe(false);
    // …and without the list it would be, which is why each gate passes its own.
    expect(wantsHelp(['--agent', 'help'])).toBe(true);
  });

  it('helpGate forwards the value-flag list', () => {
    // The reported invocation is fixed by the verb-position rule alone…
    expect(helpGate(['skill', 'install', '--agent', 'help'], 'USAGE', { valueFlags: OPENCLAW_VALUE_FLAGS })).toBeNull();
    // …and the list is what stops a value BEING the first positional.
    expect(helpGate(['--agent', 'help'], 'USAGE', { valueFlags: OPENCLAW_VALUE_FLAGS })).toBeNull();
    expect(helpGate(['--agent', 'help'], 'USAGE')).toBe(0);
  });

  it('the dispatcher sees one verb slot deeper than the command does', () => {
    // src/index.ts is handed the whole command line, so a subcommand's own verb
    // sits in the SECOND positional. Both gates must reach the same verdict the
    // command will, or `audit help` prints usage under a stats banner.
    expect(wantsHelp(['audit', 'help'], { verbDepth: 2 })).toBe(true);
    expect(wantsHelp(['audit', 'help'])).toBe(false);   // audit's own gate sees ['help']
    expect(wantsHelp(['help'], { verbDepth: 2 })).toBe(true);
    // Still not a help request at either depth — this is the reported defect.
    expect(wantsHelp(['memories', 'prune', '--project', 'help'], {
      verbDepth: 2,
      valueFlags: MEMORIES_VALUE_FLAGS,
    })).toBe(false);
    expect(wantsHelp(['openclaw', 'skill', 'install', '--agent', 'help'], {
      verbDepth: 2,
      valueFlags: OPENCLAW_VALUE_FLAGS,
    })).toBe(false);
  });

  it('the index.ts gates agree with the gate the command itself applies', () => {
    const cases: Array<[string[], boolean]> = [
      [['audit', 'help'], true],
      [['audit', '--help'], true],
      [['memories', 'prune', '--project', 'help'], false],
      [['memories', 'migrate-legacy', '--source', 'help'], false],
      [['openclaw', 'skill', 'install', '--agent', 'help'], false],
      [['update', '--allow-conversation-access'], false],
    ];
    for (const [argv, expected] of cases) {
      expect({ argv, help: wantsHelp(argv, { verbDepth: 2, valueFlags: MEMORIES_VALUE_FLAGS }) })
        .toEqual({ argv, help: expected });
    }
  });

  it('each gated surface declares the options that take a value', () => {
    expect(OPENCLAW_VALUE_FLAGS).toContain('--agent');
    expect(MEMORIES_VALUE_FLAGS).toEqual(expect.arrayContaining(['--project', '--source', '--db', '--limit']));
    expect(SESSIONS_VALUE_FLAGS).toContain('--days');
    expect(GLOBAL_VALUE_FLAGS).toContain('--db');
  });
});

describe('#577 — `openclaw skill install --agent help` installs for the agent "help"', () => {
  it('reaches the skill installer with the agent id instead of printing usage', async () => {
    const skillInstall = jest.fn(async (_home: string, _agent?: string) => true);
    const install = jest.fn(async () => {});
    const { out } = await withConsole(async () => {
      await handleOpenClawCommand('skill', ['install', '--agent', 'help'], { install, skillInstall });
    });
    expect(skillInstall).toHaveBeenCalledTimes(1);
    expect(skillInstall.mock.calls[0][1]).toBe('help');
    expect(install).not.toHaveBeenCalled();
    expect(out.join('\n')).not.toContain('Usage: shieldcortex openclaw');
  });

  it('`openclaw skill install --help` still prints usage and installs nothing', async () => {
    const skillInstall = jest.fn(async () => true);
    const { out, exitCode } = await withConsole(async () => {
      await handleOpenClawCommand('skill', ['install', '--help'], { skillInstall });
    });
    expect(skillInstall).not.toHaveBeenCalled();
    expect(exitCode).toBe(0);
    expect(out.join('\n')).toContain('Usage: shieldcortex openclaw');
  });
});

describe('#577 — `memories … help` values reach the real handler', () => {
  it('`memories prune --project help` prunes project "help" instead of printing usage', async () => {
    const tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'sc577-prune-'));
    const prevDb = process.env.CLAUDE_MEMORY_DB;
    const prevHome = process.env.HOME;
    process.env.CLAUDE_MEMORY_DB = path.join(tmp, 'memories.db');
    process.env.HOME = tmp;
    try {
      const { out } = await withConsole(async () => {
        await handleMemoriesCommand(['prune', '--project', 'help']);
      });
      const text = out.join('\n');
      expect(text).not.toContain('Usage: shieldcortex memories');
      expect(text).toContain('[DRY RUN] Prune memories where salience');
      expect(text).toContain('Project: help');
    } finally {
      closeDatabase();
      if (prevDb === undefined) delete process.env.CLAUDE_MEMORY_DB;
      else process.env.CLAUDE_MEMORY_DB = prevDb;
      if (prevHome === undefined) delete process.env.HOME;
      else process.env.HOME = prevHome;
      fs.rmSync(tmp, { recursive: true, force: true });
    }
  });

  it('`memories migrate-legacy --source help` imports from the path "help"', async () => {
    // The importer is injected: `migrateLegacy` resolves its target DB from
    // os.homedir(), which a Jest process cannot move — so executing it for
    // real would open the operator's own memories.db. What the gate broke, and
    // what this proves, is that the VALUE reaches the migrator at all.
    const seen: Array<{ sources?: string[]; dryRun?: boolean }> = [];
    const migrateLegacy = jest.fn((o: { sources?: string[]; dryRun?: boolean }) => {
      seen.push(o);
      return { target: '/tmp/t.db', dryRun: !!o.dryRun, sources: [], totalMemories: 0, totalLinks: 0 };
    });
    const { out } = await withConsole(async () => {
      await handleMemoriesCommand(
        ['migrate-legacy', '--source', 'help'],
        { migrateLegacy: migrateLegacy as never },
      );
    });
    expect(out.join('\n')).not.toContain('Usage: shieldcortex memories');
    expect(seen).toEqual([{ sources: ['help'], dryRun: false }]);
  });

  it('`memories migrate-legacy --help` still prints usage and imports nothing', async () => {
    const migrateLegacy = jest.fn();
    const { out } = await withConsole(async () => {
      await handleMemoriesCommand(['migrate-legacy', '--help'], { migrateLegacy: migrateLegacy as never });
    });
    expect(migrateLegacy).not.toHaveBeenCalled();
    expect(out.join('\n')).toContain('Usage: shieldcortex memories');
  });

});

// ── Nit: a rejected argument spawns no child process ─────────────────────────

describe('#577 — strict arguments are validated before the npm staleness preamble', () => {
  it('rejects `update --bogus` with exit 2 and the usage on stderr', async () => {
    const out: string[] = [];
    const err: string[] = [];
    expect(await preflightStrictArgs(['update', '--bogus'], { log: (m) => out.push(m), error: (m) => err.push(m) })).toBe(2);
    expect(out).toEqual([]);
    expect(err.join('\n')).toContain('Unknown argument: --bogus');
    expect(err.join('\n')).toContain('Usage: shieldcortex update');
  });

  it('covers every strict-parser command, including the compact alias', async () => {
    for (const cmd of ['update', 'repair', 'migrate', 'uninstall', 'vacuum', 'compact']) {
      expect(await preflightStrictArgs([cmd, '--bogus'], { log: () => {}, error: () => {} })).toBe(2);
      expect(await preflightStrictArgs([cmd, '--help'], { log: () => {}, error: () => {} })).toBe(0);
    }
  });

  it('lets valid arguments and every other command through untouched', async () => {
    expect(await preflightStrictArgs(['update', '--force'], { log: () => {}, error: () => {} })).toBeNull();
    expect(await preflightStrictArgs(['update', '--allow-conversation-access'], { log: () => {}, error: () => {} })).toBeNull();
    expect(await preflightStrictArgs(['repair', '--allow-conversation-access'], { log: () => {}, error: () => {} })).toBeNull();
    expect(await preflightStrictArgs(['doctor', '--bogus'], { log: () => {}, error: () => {} })).toBeNull();
    expect(await preflightStrictArgs([], { log: () => {}, error: () => {} })).toBeNull();
  });

  it('main() runs the preflight before checkVersionStaleness()', () => {
    const body = codeOf('../../index.ts');
    const main = body.slice(body.indexOf('async function main()'));
    expect(main.indexOf('preflightStrictArgs(')).toBeGreaterThan(-1);
    expect(main.indexOf('preflightStrictArgs(')).toBeLessThan(main.indexOf('checkVersionStaleness();'));
  });
});
