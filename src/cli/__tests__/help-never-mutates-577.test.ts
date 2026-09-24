/**
 * #577 — a help flag must never mutate the host.
 *
 * Observed on 5.1.0: `shieldcortex update --help` performed the whole upgrade
 * (npm global install, re-exec, hook rewrites, plugin reinstall) and printed no
 * usage at all — `src/index.ts` dispatched `argv[2] === 'update'` straight into
 * `runUpdate()`, which only ever looked for `--force` / `-f` / `--verbose` deep
 * inside itself. So `--help`, `-h` and every typo were silently "run the
 * upgrade", which is exactly the operator's one chance to READ what the command
 * will do before it does it.
 *
 * The same shape sat on the other host-mutating subcommands: `repair`,
 * `migrate`, `uninstall`, `hermes install`, `openclaw install`,
 * `memories migrate-legacy`, `memories prune`, `sessions prune`, `vacuum`.
 * Every one of them now goes through the shared `helpGate` (src/cli/help-gate.ts)
 * BEFORE it touches the network or the filesystem.
 *
 * These tests inject the mutating dependency (`deps.run` / `deps.install`) the
 * way src/cli/__tests__/update-reexec-501.test.ts injects `launch`, so a
 * regression here fails the assertion instead of upgrading the box running the
 * suite.
 */
import { describe, expect, it, afterEach, jest } from '@jest/globals';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { fileURLToPath } from 'url';
import { helpGate } from '../help-gate.js';
import {
  UPDATE_HELP,
  handleUpdateCommand,
  parseUpdateOptions,
  reexecUpdatedCli,
  type UpdateOptions,
} from '../update.js';
import { REPAIR_HELP, runRepair } from '../repair.js';
import { MIGRATE_HELP, handleMigrateCommand } from '../../setup/migrate.js';
import { UNINSTALL_HELP, handleUninstallCommand } from '../../setup/uninstall.js';
import { HERMES_HELP, handleHermesCommand } from '../../setup/hermes.js';
import { OPENCLAW_HELP, handleOpenClawCommand } from '../../setup/openclaw.js';
import { handleMemoriesCommand } from '../migrate-legacy.js';
import { handleSessionsCommand } from '../sessions.js';
import { VACUUM_HELP, vacuumHelpRequested } from '../vacuum.js';
import { closeDatabase } from '../../database/init.js';

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..', '..', '..');
const indexSrc = fs.readFileSync(path.join(repoRoot, 'src', 'index.ts'), 'utf-8');
const updateSrc = fs.readFileSync(path.join(repoRoot, 'src', 'cli', 'update.ts'), 'utf-8');

/** Collected stdout/stderr for the commands that write straight to the console. */
interface Captured {
  out: string[];
  err: string[];
}

/**
 * The gated commands set `process.exitCode` (2 on a bad argument) rather than
 * calling process.exit, so the suite has to put it back or Jest itself exits 2.
 */
async function withConsole(fn: () => Promise<void>): Promise<Captured & { exitCode: number }> {
  const captured: Captured = { out: [], err: [] };
  const prevExit = process.exitCode;
  const origLog = console.log;
  const origError = console.error;
  const origOut = process.stdout.write.bind(process.stdout);
  const origErr = process.stderr.write.bind(process.stderr);
  const origExit = process.exit;
  process.exit = ((code?: number) => { throw new Error(`process.exit(${code})`); }) as typeof process.exit;
  console.log = ((...args: unknown[]) => { captured.out.push(args.map(String).join(' ')); }) as typeof console.log;
  console.error = ((...args: unknown[]) => { captured.err.push(args.map(String).join(' ')); }) as typeof console.error;
  process.stdout.write = ((chunk: string | Uint8Array) => { captured.out.push(String(chunk)); return true; }) as typeof process.stdout.write;
  process.stderr.write = ((chunk: string | Uint8Array) => { captured.err.push(String(chunk)); return true; }) as typeof process.stderr.write;
  process.exitCode = 0;
  try {
    await fn();
    return { ...captured, exitCode: typeof process.exitCode === 'number' ? process.exitCode : 0 };
  } finally {
    console.log = origLog;
    console.error = origError;
    process.stdout.write = origOut;
    process.stderr.write = origErr;
    process.exit = origExit;
    process.exitCode = prevExit;
  }
}

describe('#577 — helpGate is the shared, side-effect-free parser', () => {
  it('stops on --help / -h / help and prints the usage it was given', () => {
    for (const args of [['--help'], ['-h'], ['help'], ['--force', '--help']]) {
      const out: string[] = [];
      expect(helpGate(args, 'USAGE', { log: (m) => out.push(m) })).toBe(0);
      expect(out).toEqual(['USAGE']);
    }
  });

  it('lets the honoured flags through', () => {
    expect(helpGate([], 'USAGE', { known: [] })).toBeNull();
    expect(helpGate(['--force'], 'USAGE', { known: ['--force'] })).toBeNull();
  });

  it('rejects unknown flags and extra positionals with the usage on stderr', () => {
    const err: string[] = [];
    const out: string[] = [];
    expect(helpGate(['--bogus'], 'USAGE', { known: ['--force'], log: (m) => out.push(m), error: (m) => err.push(m) })).toBe(2);
    expect(out).toEqual([]);
    expect(err.join('\n')).toContain('Unknown argument: --bogus');
    expect(err.join('\n')).toContain('USAGE');

    const err2: string[] = [];
    expect(helpGate(['5.3.0', '--nope'], 'USAGE', { known: [], error: (m) => err2.push(m) })).toBe(2);
    expect(err2.join('\n')).toContain('Unknown arguments: 5.3.0 --nope');
  });
});

describe('#577 — shieldcortex update --help never upgrades', () => {
  const sink = () => {
    const out: string[] = [];
    const err: string[] = [];
    return { out, err, log: (m: string) => out.push(m), error: (m: string) => err.push(m) };
  };

  for (const flag of ['--help', '-h']) {
    it(`${flag} prints usage, exits 0, and calls no install/launch/fetch dependency`, async () => {
      const run = jest.fn(async () => {});
      const s = sink();
      const { exitCode } = await withConsole(async () => {
        await handleUpdateCommand([flag], { run, env: {}, log: s.log, error: s.error });
      });
      expect(run).not.toHaveBeenCalled();
      expect(exitCode).toBe(0);
      expect(s.err).toEqual([]);
      expect(s.out.join('\n')).toBe(UPDATE_HELP);
      expect(s.out.join('\n')).toContain('Usage: shieldcortex update');
    });
  }

  it('the usage lists every flag and env switch update actually honours', () => {
    for (const token of ['--force', '-f', '--verbose', '--help', '-h', 'SHIELDCORTEX_VERBOSE', 'SHIELDCORTEX_UPDATE_REEXEC', 'SHIELDCORTEX_UPDATE_FROM_VERSION']) {
      expect(UPDATE_HELP).toContain(token);
    }
  });

  it('an unknown flag exits 2 with the error plus usage on stderr and upgrades nothing', async () => {
    const run = jest.fn(async () => {});
    const s = sink();
    const { exitCode } = await withConsole(async () => {
      await handleUpdateCommand(['--bogus'], { run, env: {}, log: s.log, error: s.error });
    });
    expect(run).not.toHaveBeenCalled();
    expect(exitCode).toBe(2);
    expect(s.out).toEqual([]);
    expect(s.err.join('\n')).toContain('Unknown argument: --bogus');
    expect(s.err.join('\n')).toContain('Usage: shieldcortex update');
  });

  it('an extra positional arg exits 2 — `update 5.3.0` is not a version selector', async () => {
    const run = jest.fn(async () => {});
    const s = sink();
    const { exitCode } = await withConsole(async () => {
      await handleUpdateCommand(['5.3.0'], { run, env: {}, log: s.log, error: s.error });
    });
    expect(run).not.toHaveBeenCalled();
    expect(exitCode).toBe(2);
    expect(s.err.join('\n')).toContain('Unknown argument: 5.3.0');
  });

  it('the honoured flags reach runUpdate as parsed options', async () => {
    const seen: UpdateOptions[] = [];
    const run = jest.fn(async (options: UpdateOptions) => { seen.push(options); });
    const s = sink();
    await withConsole(async () => {
      await handleUpdateCommand([], { run, env: {}, log: s.log, error: s.error });
      await handleUpdateCommand(['--force'], { run, env: {}, log: s.log, error: s.error });
      await handleUpdateCommand(['-f', '--verbose'], { run, env: {}, log: s.log, error: s.error });
    });
    expect(seen).toEqual([
      { force: false, verbose: false },
      { force: true, verbose: false },
      { force: true, verbose: true },
    ]);
  });

  it('SHIELDCORTEX_VERBOSE=1 is resolved at the one parse point', () => {
    expect(parseUpdateOptions([], { SHIELDCORTEX_VERBOSE: '1' })).toEqual({ force: false, verbose: true });
    expect(parseUpdateOptions([], {})).toEqual({ force: false, verbose: false });
  });

  it('runUpdate reads no flags out of process.argv any more', () => {
    expect(updateSrc).not.toMatch(/process\.argv\.includes\(/);
    const body = updateSrc.slice(updateSrc.indexOf('export async function runUpdate'));
    expect(body).toMatch(/options\.force/);
  });

  it('the argv update re-launches itself with is still accepted by the new parser', async () => {
    let launched: string[] = [];
    await reexecUpdatedCli('5.1.0', {
      readVersion: () => '5.2.0',
      env: {},
      argv: ['update', '--force', '--verbose'],
      launch: async (_bin: string, args: string[]) => { launched = args; return 0; },
    });
    // [dist/index.js, 'update', ...flags] — the child re-enters the dispatcher,
    // which hands argv.slice(3) to the parser.
    expect(launched[1]).toBe('update');
    const run = jest.fn(async () => {});
    const s = sink();
    await withConsole(async () => {
      await handleUpdateCommand(launched.slice(2), { run, env: {}, log: s.log, error: s.error });
    });
    expect(s.err).toEqual([]);
    expect(run).toHaveBeenCalledWith({ force: true, verbose: true });
  });

  it('index.ts parses once at the entry point instead of calling runUpdate bare', () => {
    expect(indexSrc).toContain('handleUpdateCommand(process.argv.slice(3))');
    expect(indexSrc).not.toMatch(/await runUpdate\(\)/);
  });
});

describe('#577 — shieldcortex repair --help never touches the install', () => {
  it('--help prints usage and never reaches the engine check', async () => {
    const run = jest.fn(async () => {});
    const { out, err, exitCode } = await withConsole(async () => {
      await runRepair(['--help'], { run });
    });
    expect(run).not.toHaveBeenCalled();
    expect(exitCode).toBe(0);
    expect(err).toEqual([]);
    expect(out.join('')).toContain('Usage: shieldcortex repair');
    expect(out.join('')).not.toContain('Checking the native database engine');
  });

  it('an unknown argument exits 2 and repairs nothing', async () => {
    const run = jest.fn(async () => {});
    const { out, err, exitCode } = await withConsole(async () => {
      await runRepair(['--bogus'], { run });
    });
    expect(run).not.toHaveBeenCalled();
    expect(exitCode).toBe(2);
    expect(err.join('')).toContain('Unknown argument: --bogus');
    expect(out.join('')).not.toContain('Checking the native database engine');
  });

  it('no arguments still repairs', async () => {
    const run = jest.fn(async () => {});
    await withConsole(async () => { await runRepair([], { run }); });
    expect(run).toHaveBeenCalledTimes(1);
    expect(REPAIR_HELP).toContain('Usage: shieldcortex repair');
  });
});

describe('#577 — shieldcortex migrate --help never migrates', () => {
  it('--help prints usage and rewrites no settings, database or CLAUDE.md', async () => {
    const run = jest.fn(async () => {});
    const { out, exitCode } = await withConsole(async () => {
      await handleMigrateCommand(['--help'], { run });
    });
    expect(run).not.toHaveBeenCalled();
    expect(exitCode).toBe(0);
    expect(out.join('\n')).toContain('Usage: shieldcortex migrate');
    expect(out.join('\n')).not.toContain('Migrating from Claude Cortex');
    expect(MIGRATE_HELP).toContain('-h, --help');
  });

  it('an unknown argument exits 2 and migrates nothing', async () => {
    const run = jest.fn(async () => {});
    const { err, exitCode } = await withConsole(async () => {
      await handleMigrateCommand(['--bogus'], { run });
    });
    expect(run).not.toHaveBeenCalled();
    expect(exitCode).toBe(2);
    expect(err.join('\n')).toContain('Unknown argument: --bogus');
  });

  it('no arguments still migrates', async () => {
    const run = jest.fn(async () => {});
    await withConsole(async () => { await handleMigrateCommand([], { run }); });
    expect(run).toHaveBeenCalledTimes(1);
  });
});

describe('#577 — shieldcortex uninstall --help removes nothing', () => {
  it('--help prints usage listing every honoured flag, and never uninstalls', async () => {
    const run = jest.fn(async () => {});
    const out: string[] = [];
    const err: string[] = [];
    const { exitCode } = await withConsole(async () => {
      await handleUninstallCommand(['--help'], { run, log: (m) => out.push(m), error: (m) => err.push(m) });
    });
    expect(run).not.toHaveBeenCalled();
    expect(exitCode).toBe(0);
    expect(err).toEqual([]);
    expect(out.join('\n')).toBe(UNINSTALL_HELP);
    for (const token of ['--confirm', '--keep-logs', '--deep', '--no-gateway-restart', '-h, --help']) {
      expect(UNINSTALL_HELP).toContain(token);
    }
  });

  it('an unknown argument exits 2 and removes nothing', async () => {
    const run = jest.fn(async () => {});
    const err: string[] = [];
    const { exitCode } = await withConsole(async () => {
      await handleUninstallCommand(['--bogus'], { run, log: () => {}, error: (m) => err.push(m) });
    });
    expect(run).not.toHaveBeenCalled();
    expect(exitCode).toBe(2);
    expect(err.join('\n')).toContain('Unknown argument: --bogus');
  });

  it('the honoured flags still reach uninstallAll', async () => {
    const run = jest.fn(async () => {});
    await withConsole(async () => {
      await handleUninstallCommand(['--deep', '--keep-logs', '--no-gateway-restart', '--confirm'], { run });
    });
    expect(run).toHaveBeenCalledWith({ keepLogs: true, deep: true, restartGateway: false });
  });
});

describe('#577 — shieldcortex hermes install --help installs nothing', () => {
  it('a help flag after the verb prints usage and never copies the plugin', async () => {
    const install = jest.fn(async () => {});
    const { out, exitCode } = await withConsole(async () => {
      await handleHermesCommand('install', ['--help'], { install });
    });
    expect(install).not.toHaveBeenCalled();
    expect(exitCode).toBe(0);
    expect(out.join('\n')).toContain('Usage: shieldcortex hermes');
    expect(HERMES_HELP).toContain('-h, --help');
  });

  it('`hermes --help` prints usage and exits 0 rather than the old usage+exit 1', async () => {
    const install = jest.fn(async () => {});
    const { out, exitCode } = await withConsole(async () => {
      await handleHermesCommand('--help', [], { install });
    });
    expect(install).not.toHaveBeenCalled();
    expect(exitCode).toBe(0);
    expect(out.join('\n')).toContain('Usage: shieldcortex hermes');
  });

  it('the bare verb still installs', async () => {
    const install = jest.fn(async () => {});
    await withConsole(async () => { await handleHermesCommand('install', [], { install }); });
    expect(install).toHaveBeenCalledTimes(1);
  });

  it('index.ts forwards the extra args so the gate can see them', () => {
    expect(indexSrc).toContain("handleHermesCommand(process.argv[3] || '', process.argv.slice(4))");
  });
});

describe('#577 — shieldcortex openclaw install --help installs nothing', () => {
  it('a help flag after the verb prints usage and never installs the hook or plugin', async () => {
    const install = jest.fn(async () => {});
    const { out, exitCode } = await withConsole(async () => {
      await handleOpenClawCommand('install', ['--help'], { install });
    });
    expect(install).not.toHaveBeenCalled();
    expect(exitCode).toBe(0);
    expect(out.join('\n')).toContain('Usage: shieldcortex openclaw');
    expect(OPENCLAW_HELP).toContain('--no-gateway-restart');
  });

  it('the real install flags still dispatch', async () => {
    const install = jest.fn(async () => {});
    await withConsole(async () => {
      await handleOpenClawCommand('install', ['--no-hooks'], { install });
    });
    expect(install).toHaveBeenCalledTimes(1);
  });
});

describe('#577 — the DB-opening prune/compact commands print usage instead', () => {
  let tmp: string | null = null;
  const prevDb = process.env.CLAUDE_MEMORY_DB;

  afterEach(() => {
    closeDatabase();
    if (prevDb === undefined) delete process.env.CLAUDE_MEMORY_DB;
    else process.env.CLAUDE_MEMORY_DB = prevDb;
    if (tmp) {
      try { fs.rmSync(tmp, { recursive: true, force: true }); } catch { /* ignore */ }
      tmp = null;
    }
  });

  function tempDb(): string {
    tmp = fs.mkdtempSync(path.join(os.tmpdir(), 'sc577-db-'));
    const dbPath = path.join(tmp, 'memories.db');
    process.env.CLAUDE_MEMORY_DB = dbPath;
    return dbPath;
  }

  it('`memories prune --help` prints usage and never creates or opens the database', async () => {
    const dbPath = tempDb();
    const { out } = await withConsole(async () => {
      await handleMemoriesCommand(['prune', '--help']);
    });
    expect(out.join('\n')).toContain('Usage: shieldcortex memories');
    expect(out.join('\n')).not.toContain('Prune memories where salience');
    expect(fs.existsSync(dbPath)).toBe(false);
  });

  it('`memories migrate-legacy --help` prints usage and imports nothing', async () => {
    const dbPath = tempDb();
    const { out } = await withConsole(async () => {
      await handleMemoriesCommand(['migrate-legacy', '--help']);
    });
    expect(out.join('\n')).toContain('Usage: shieldcortex memories');
    expect(fs.existsSync(dbPath)).toBe(false);
  });

  it('`sessions prune --help` prints usage and never creates or opens the database', async () => {
    const dbPath = tempDb();
    const { out } = await withConsole(async () => {
      await handleSessionsCommand(['prune', '--help']);
    });
    expect(out.join('\n')).toContain('Usage: shieldcortex sessions');
    expect(out.join('\n')).not.toContain('Prune session_events older than');
    expect(fs.existsSync(dbPath)).toBe(false);
  });

  it('the shared staleness preamble runs no npm child process on a help request', () => {
    // It fires before every subcommand, and `npm ls -g` lets npm's own
    // update-notifier reach the registry and write ~/.npm/_logs — so the gate in
    // the update branch alone could not make `update --help` side-effect free.
    const at = indexSrc.indexOf('function checkVersionStaleness');
    expect(at).toBeGreaterThan(-1);
    const body = indexSrc.slice(at, indexSrc.indexOf('\n}', at));
    expect(body).toMatch(/wantsHelp\(/);
    expect(body.indexOf('wantsHelp(')).toBeLessThan(body.indexOf('execSync('));
  });

  it('`vacuum --help` stops the caller and prints usage', () => {
    for (const args of [['--help'], ['-h']]) {
      const out: string[] = [];
      const err: string[] = [];
      const prevExit = process.exitCode;
      try {
        expect(vacuumHelpRequested(args, { log: (m) => out.push(m), error: (m) => err.push(m) })).toBe(true);
        expect(process.exitCode).toBe(0);
      } finally {
        process.exitCode = prevExit;
      }
      expect(err).toEqual([]);
      expect(out.join('\n')).toBe(VACUUM_HELP);
      expect(out.join('\n')).toContain('Usage: shieldcortex vacuum');
    }
  });

  it('`vacuum --bogus` stops the caller with exit 2, and a bare `vacuum` proceeds', () => {
    const err: string[] = [];
    const prevExit = process.exitCode;
    try {
      expect(vacuumHelpRequested(['--bogus'], { log: () => {}, error: (m) => err.push(m) })).toBe(true);
      expect(process.exitCode).toBe(2);
      expect(vacuumHelpRequested([], { log: () => {}, error: (m) => err.push(m) })).toBe(false);
    } finally {
      process.exitCode = prevExit;
    }
    expect(err.join('\n')).toContain('Unknown argument: --bogus');
  });

  it('the vacuum branch consults the gate before it opens or compacts the database', () => {
    const at = indexSrc.indexOf("process.argv[2] === 'vacuum'");
    expect(at).toBeGreaterThan(-1);
    const branch = indexSrc.slice(at, indexSrc.indexOf('\n  }', at));
    expect(branch).toContain('vacuumHelpRequested(process.argv.slice(3))');
    expect(branch.indexOf('vacuumHelpRequested(')).toBeLessThan(branch.indexOf('initDatabase()'));
  });
});
