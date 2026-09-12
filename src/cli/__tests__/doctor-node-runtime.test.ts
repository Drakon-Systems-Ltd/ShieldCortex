import { spawn } from 'child_process';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { createRequire } from 'module';
import { fileURLToPath } from 'url';
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it } from '@jest/globals';

import {
  NATIVE_ENGINE_AFFECTED_NODE_MAJOR,
  NATIVE_ENGINE_LABEL,
  NATIVE_ENGINE_MAJOR_FLOOR,
  NODE_RUNTIME_LABEL,
  REQUIRED_ENGINE_RANGE,
  SUPPORTED_NODE_RANGE,
  checkNativeEngineCompat,
  checkNodeRuntime,
  doctorExitCode,
  nativeEngineVerdict,
  readInstalledEngineVersion,
} from '../doctor.js';
import { closeDatabase, initDatabase } from '../../database/init.js';

const require = createRequire(import.meta.url);
const __dirname = path.dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = path.resolve(__dirname, '..', '..', '..');
const CLI_PATH = path.join(REPO_ROOT, 'dist', 'index.js');

/**
 * An unsupported Node must be a FAIL from the doctor that actually runs.
 *
 * `src/setup/doctor.ts` carries a `nodeSupportVerdict`, but nothing dispatches
 * `handleDoctorCommand` — `src/index.ts` routes `shieldcortex doctor` to
 * `src/cli/doctor.ts`'s `runDoctor`. A verdict that only exists in the unused
 * implementation is not a gate: on a Node 20 or Node 23 box the live command
 * said nothing about the runtime at all, and on a FRESH install it could not
 * even fail indirectly, because with no database every DB check is correctly
 * `info` and the run exits 0. That is the worst case — the user who has just
 * installed on the wrong Node is exactly the one running `doctor`.
 *
 * Proven against the real dispatched command rather than in-process:
 * `runDoctor()`'s checks resolve against the real `os.homedir()` and do live DB
 * round-trips (see the header of doctor-ai-section.test.ts — no test in this
 * suite calls it in-process for that reason), and the exit STATUS is what CI
 * consumes, which only running the binary can prove. The child's Node version
 * is moved with a `--require` preload, so the report and the exit code below
 * are the genuine article and not a re-implementation of them.
 */

/** Report lines are wrapped and coloured; compare against flattened plain text. */
function plain(text: string): string {
  // eslint-disable-next-line no-control-regex
  return text.replace(/\x1b\[[0-9;]*m/g, '').replace(/\s+/g, ' ');
}

interface DoctorRun {
  stdout: string;
  code: number | null;
  signal: NodeJS.Signals | null;
}

/**
 * Move the CHILD's `process.version` before the CLI module graph loads.
 * `process.versions.modules` is deliberately left alone: this pins the
 * doctor's own runtime verdict, not any ABI-derived behaviour.
 */
function writePreload(home: string, version: string): string {
  const preload = path.join(home, 'force-node-version.cjs');
  fs.writeFileSync(
    preload,
    `Object.defineProperty(process, 'version', { value: ${JSON.stringify(version)}, configurable: true });\n`,
    { mode: 0o600 },
  );
  return preload;
}

/** Written by the stand-in engine below the instant anything REQUIRES it. */
const ENGINE_LOAD_MARKER = 'engine-was-loaded';

interface FakeEngine {
  /** `--require` preload that points better-sqlite3 resolution at the layout. */
  preload: string;
  /** Exists iff some check actually loaded the package. */
  marker: string;
}

/**
 * A disposable INSTALLED-package layout that reports itself as `version`.
 *
 * The doctor's preflight reads the version off the manifest of the package this
 * process would really load, so making the built CLI believe it is on a stale
 * 12.x is a module-RESOLUTION question, not an env-var one — and deliberately
 * so: a production switch that could be set to fake an engine version would be
 * a way to switch the gate off, which is the opposite of what it is for.
 *
 * `node_modules` is never touched. The layout lives in the caller's sandbox and
 * dies with it, and the preload that points at it is passed only to the child.
 *
 * The stand-in DELEGATES to the real installed engine rather than throwing, so
 * the only thing that differs from a normal run is the version string — a run
 * that gets past the preflight behaves exactly as it would have. It writes
 * `marker` first, which turns "the run short-circuited" into a filesystem fact:
 * no marker means no check below the preflight ever loaded the engine.
 */
function installFakeEngine(home: string, version: string): FakeEngine {
  const root = path.join(home, 'stale-engine');
  const pkgDir = path.join(root, 'better-sqlite3');
  fs.mkdirSync(pkgDir, { recursive: true });
  const marker = path.join(root, ENGINE_LOAD_MARKER);
  const realEntry = require.resolve('better-sqlite3');

  fs.writeFileSync(
    path.join(pkgDir, 'package.json'),
    `${JSON.stringify({ name: 'better-sqlite3', version, main: 'index.js' }, null, 2)}\n`,
    { mode: 0o600 },
  );
  fs.writeFileSync(
    path.join(pkgDir, 'index.js'),
    `require('fs').writeFileSync(${JSON.stringify(marker)}, 'loaded');\n` +
      `module.exports = require(${JSON.stringify(realEntry)});\n`,
    { mode: 0o600 },
  );

  const preload = path.join(root, 'resolve-stale-engine.cjs');
  fs.writeFileSync(
    preload,
    // `Module._resolveFilename` is the single funnel every `require` and
    // `require.resolve` goes through, including the ones `createRequire` hands
    // out inside the compiled ESM bundle. Absolute paths and every other
    // specifier fall through untouched.
    `const Module = require('module');\n` +
      `const path = require('path');\n` +
      `const PKG_DIR = ${JSON.stringify(pkgDir)};\n` +
      `const original = Module._resolveFilename;\n` +
      `Module._resolveFilename = function (request, ...rest) {\n` +
      `  if (request === 'better-sqlite3') return path.join(PKG_DIR, 'index.js');\n` +
      `  if (request === 'better-sqlite3/package.json') return path.join(PKG_DIR, 'package.json');\n` +
      `  return original.call(this, request, ...rest);\n` +
      `};\n`,
    { mode: 0o600 },
  );
  return { preload, marker };
}

/**
 * A scrubbed environment: HOME points at the caller's sandbox so doctor reads
 * and writes nothing of the host's, and inherited SHIELDCORTEX_* would
 * otherwise change what the checks resolve to (#125).
 */
const runDoctorCli = (
  home: string,
  args: string[] = [],
  opts: { forceVersion?: string; preloads?: string[] } = {},
): Promise<DoctorRun> =>
  new Promise((resolve, reject) => {
    const nodeArgs: string[] = [];
    if (opts.forceVersion) nodeArgs.push('--require', writePreload(home, opts.forceVersion));
    for (const preload of opts.preloads ?? []) nodeArgs.push('--require', preload);
    const child = spawn(process.execPath, [...nodeArgs, CLI_PATH, 'doctor', ...args], {
      stdio: ['ignore', 'pipe', 'pipe'],
      env: { PATH: process.env.PATH ?? '/usr/bin:/bin', HOME: home },
    });
    let stdout = '';
    child.stdout.on('data', (c) => { stdout += c.toString(); });
    child.stderr.on('data', (c) => { stdout += c.toString(); });
    child.on('error', reject);
    // #471: SIGABRT yields code=null, signal=SIGABRT. Mapping null→0 hid the
    // Node 24 better-sqlite3 ObjectWrap abort as a green doctor run.
    child.on('close', (code, signal) => resolve({ stdout, code, signal }));
  });

describe('doctor — Node runtime verdict (live command)', () => {
  let exitCodeBefore: number | string | undefined;

  beforeAll(() => {
    exitCodeBefore = process.exitCode;
  });

  afterAll(() => {
    // The live doctor signals failure by SETTING process.exitCode. Everything
    // exercised here must keep that inside the spawned children — a verdict
    // helper that leaked it would fail the whole jest run for a passing test.
    expect(process.exitCode).toBe(exitCodeBefore);
    process.exitCode = exitCodeBefore;
  });

  it('takes its range from the manifest, so the gate cannot drift from engines.node', () => {
    const pkg = require('../../../package.json');
    expect(SUPPORTED_NODE_RANGE).toBe(pkg.engines.node);
    expect(SUPPORTED_NODE_RANGE).toBe('^22.14.0 || >=24.0.0');
  });

  it.each(['v22.14.0', 'v22.20.1', 'v24.0.0', 'v26.1.0'])('passes on supported Node %s', async (version) => {
    const result = await checkNodeRuntime(version);
    expect(result.label).toBe(NODE_RUNTIME_LABEL);
    expect(result.status).toBe('pass');
  });

  // v22.13.0 is the sub-floor case the caret range excludes; v23 is a whole
  // excluded major, which a naive ">= 22.14" comparison would wave through.
  it.each(['v20.19.0', 'v22.13.0', 'v23.11.0'])('fails on unsupported Node %s', async (version) => {
    const result = await checkNodeRuntime(version);
    expect(result.status).toBe('fail');
    expect(result.message).toContain(version);
    expect(result.message).toContain(SUPPORTED_NODE_RANGE);
    expect(result.fix).toMatch(/Node 22\.14\+ LTS or Node 24\+/);
    // A warn would exit 0 and report a host healthy while nothing on it can
    // open the database — the severity IS the contract here.
    expect(doctorExitCode([result])).toBe(1);
  });

  it('warns rather than crashing on an unparseable version string', async () => {
    const result = await checkNodeRuntime('not-a-version');
    expect(result.status).toBe('warn');
    expect(doctorExitCode([result])).toBe(0);
  });
});

describe('doctor — unsupported Node fails the real CLI with no database present', () => {
  let home: string;

  beforeEach(() => {
    home = fs.mkdtempSync(path.join(os.tmpdir(), 'sc-doctor-node-'));
  });

  afterEach(() => {
    try { fs.rmSync(home, { recursive: true, force: true }); } catch { /* ignore */ }
  });

  it('the check is in the live check list and passes on this supported runtime', async () => {
    // dist is built before tests in CI; assert the invariant so a missing
    // build fails loudly rather than green-skipping the end-to-end proof.
    expect(fs.existsSync(CLI_PATH)).toBe(true);

    // Passes are collapsed into theme codes without --verbose.
    const { stdout, code, signal } = await runDoctorCli(home, ['--verbose']);
    expect(signal).toBeNull();
    expect(code).not.toBe(134);
    expect(plain(stdout)).not.toMatch(/Assertion failed: \(env\) != nullptr/);
    expect(plain(stdout)).toContain(NODE_RUNTIME_LABEL);
    expect(code).toBe(0);
  }, 120_000);

  // The baseline above is what makes the assertions below non-vacuous: the
  // SAME empty sandbox exits 0, so a 1 here is this check and nothing else.
  it.each(['v20.19.0', 'v23.11.0'])('exits 1 with a ❌ on Node %s, database or not', async (version) => {
    expect(fs.existsSync(CLI_PATH)).toBe(true);

    const { stdout, code } = await runDoctorCli(home, [], { forceVersion: version });
    const report = plain(stdout);

    expect(report).toContain(`Node ${version} is an unsupported runtime`);
    expect(report).toContain(SUPPORTED_NODE_RANGE);
    expect(report).toContain('Install Node 22.14+ LTS or Node 24+');
    expect(code).toBe(1);

    // The point of the check: no database exists, so every DB check is the
    // friendly fresh-install `info` and could never have carried this verdict.
    expect(report).toContain('not initialised yet');
    expect(fs.existsSync(path.join(home, '.shieldcortex', 'memories.db'))).toBe(false);
  }, 120_000);
});

/**
 * #471 regression gate: the abort it names is `Database::~Database`, so the
 * run has to have a database to destroy.
 *
 * The sibling suite above deliberately runs in an EMPTY sandbox, where every
 * DB check is the fresh-install `info` and no better-sqlite3 handle is ever
 * constructed — a green run there says nothing about the destructor. Here the
 * child opens a real initialised database (the read-only per-check handles in
 * `runDoctor` are exactly the objects better-sqlite3 12 aborted on when the
 * Node 24 environment was torn down before GC ran their destructor), so a
 * dependency regression that brings the ObjectWrap cleanup back fails this
 * test instead of reading as a healthy host.
 *
 * The fixture is built through the real `initDatabase` rather than by driving
 * another CLI verb: it is the same schema + migrations + WAL state a user's
 * database has, and nothing about the assertion depends on a second command's
 * behaviour.
 */
describe('doctor — an initialised database survives teardown on the real CLI (#471)', () => {
  let home: string;
  let dbPath: string;

  beforeEach(() => {
    home = fs.mkdtempSync(path.join(os.tmpdir(), 'sc-doctor-db-'));
    dbPath = path.join(home, '.shieldcortex', 'memories.db');
  });

  afterEach(() => {
    // `initDatabase` owns a MODULE-GLOBAL handle plus a startup lock file, and
    // this is the only suite in the file that takes them. Release them on every
    // path — including the one where the build itself threw — so neither the
    // handle nor the lock outlives the sandbox we are about to delete.
    try { closeDatabase(); } catch { /* ignore */ }
    try { fs.rmSync(home, { recursive: true, force: true }); } catch { /* ignore */ }
  });

  /**
   * Build the fixture in-process, then close it: the spawned doctor must meet
   * a quiescent file, not this process's open connection.
   *
   * Everything `initDatabase` leaves in the directory is forced owner-only
   * afterwards (files 0600, directories 0700 — a directory chmod'd 0600 loses
   * its execute bit and everything under it becomes unreachable). That is not
   * hygiene theatre — the doctor's State permissions
   * check FAILS the whole run on a single group/world-readable file under
   * `~/.shieldcortex`, and `initDatabase` writes its `.pre-backfill-*` snapshot
   * at the ambient umask. Without the chmod the run exits 1 for a reason that
   * has nothing to do with #471.
   */
  function buildDatabaseFixture(): void {
    try {
      initDatabase(dbPath);
    } finally {
      closeDatabase();
    }
    const ownerOnly = (dir: string): void => {
      fs.chmodSync(dir, 0o700);
      for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
        const child = path.join(dir, entry.name);
        if (entry.isDirectory()) ownerOnly(child);
        else fs.chmodSync(child, 0o600);
      }
    };
    ownerOnly(path.dirname(dbPath));
  }

  it('exits 0 with no signal and no destructor assertion', async () => {
    expect(fs.existsSync(CLI_PATH)).toBe(true);

    buildDatabaseFixture();
    expect(fs.existsSync(dbPath)).toBe(true);
    expect(fs.statSync(dbPath).size).toBeGreaterThan(0);

    const { stdout, code, signal } = await runDoctorCli(home, ['--verbose']);
    const report = plain(stdout);

    // A SIGABRT death is code=null + signal='SIGABRT', which a shell reports as
    // 134. Assert every shape: no single mapping can then hide the abort.
    expect(signal).toBeNull();
    expect(report).not.toMatch(/Assertion failed: \(env\) != nullptr/);
    expect(report).not.toMatch(/SIGABRT/);
    expect(code).not.toBe(134);

    // Non-vacuity: the CHILD really opened the fixture. `not initialised yet`
    // is the empty-sandbox wording the sibling suite asserts, so its absence
    // here proves this run took the database path and not the fresh-install
    // one that constructs no native handle at all.
    expect(report).toContain(NODE_RUNTIME_LABEL);
    expect(report).not.toContain('not initialised yet');
    // The positive half of the same proof: `runDatabaseCheck` emits this pass
    // row only after the child's own read-only handle ran the integrity check
    // — the exact native object whose destructor #471 aborts on. The verbose
    // report puts the `Database` label and its `healthy (<size>)` message on
    // separate wrapped lines; `plain()` collapses them to one space apart.
    expect(report).toMatch(/Database healthy \(/);

    expect(code).toBe(0);
  }, 180_000);
});

/**
 * #471 follow-up — the STALE-INSTALL half.
 *
 * The dependency floor (`better-sqlite3 ^13.0.3`) is the real fix for the Node
 * 24 `Database::~Database` abort, and the suite above proves a correctly
 * installed host survives it. What neither that suite nor package metadata can
 * speak to is the host whose tree does not match its metadata: an upgrade that
 * left 12.x in `node_modules` still satisfies every manifest you can read, and
 * on Node 24 the process then aborts from a handle destructor part-way down the
 * check list — `checkDiskUsage` is where it landed — printing no report at all.
 *
 * So the verdict is taken from the version of the package this process would
 * really load, before anything opens a database, and it stops the run.
 */
describe('doctor — installed-engine preflight verdict (#471, pure)', () => {
  const at = (state: string, version?: string, extra: Record<string, unknown> = {}) =>
    ({ state, version, ...extra } as Parameters<typeof nativeEngineVerdict>[1]);

  it('pins its floors to this package\'s declared dependency, so the gate cannot drift', () => {
    const pkg = require('../../../package.json');
    expect(REQUIRED_ENGINE_RANGE).toBe(pkg.dependencies['better-sqlite3']);
    expect(REQUIRED_ENGINE_RANGE).toBe('^13.0.3');
    // The check's floor is the ABI fact (12 = node::ObjectWrap, 13 = Node-API),
    // not the declared range — but a declared range BELOW it would mean this
    // release ships an engine its own doctor calls incompatible.
    expect(NATIVE_ENGINE_MAJOR_FLOOR).toBe(13);
    expect(NATIVE_ENGINE_AFFECTED_NODE_MAJOR).toBe(24);
    expect(Number(REQUIRED_ENGINE_RANGE.replace(/^\D+/, '').split('.')[0]))
      .toBeGreaterThanOrEqual(NATIVE_ENGINE_MAJOR_FLOOR);
  });

  it.each(['v24.0.0', 'v24.21.0', 'v26.1.0'])(
    'fails and halts the run on %s with an installed 12.x',
    (nodeVersion) => {
      const result = nativeEngineVerdict(
        nodeVersion,
        at('resolved', '12.4.1', { source: '/opt/sc/node_modules/better-sqlite3/package.json' }),
      );

      expect(result.label).toBe(NATIVE_ENGINE_LABEL);
      expect(result.status).toBe('fail');
      expect(doctorExitCode([result])).toBe(1);
      // The halt IS the fix: without it the run walks into the abort it just
      // diagnosed and the operator sees a crash instead of this sentence.
      expect(result.haltsRun).toBe(true);

      // Honest about WHAT is wrong: the installed engine, named, with its version.
      expect(result.message).toContain('better-sqlite3 12.4.1');
      expect(result.message).toContain('/opt/sc/node_modules/better-sqlite3/package.json');
      expect(result.message).toMatch(/incompatible with Node 2[46]\./);
      expect(result.message).toContain('STALE');
      // It names the abort without REPRODUCING its banner. That banner is how a
      // real crash is recognised — by the live-CLI tests below and by anyone
      // grepping their logs — so a clean diagnosis must not forge one.
      expect(result.message).not.toMatch(/Assertion failed/);
      expect(result.message).not.toMatch(/SIGABRT/);

      // Honest about the REMEDY: reinstall to re-resolve the range. Never a
      // rebuild (recompiles the same 12.x), and never the closeDatabase story —
      // doctor does not own the connection that aborts, so a teardown close
      // would have fixed nothing (the claim #465 removed from the CHANGELOG).
      expect(result.fix).toContain('npm install -g shieldcortex@latest');
      expect(result.fix).toMatch(/[Uu]pgrade\/reinstall ShieldCortex/);
      expect(result.fix).toContain(REQUIRED_ENGINE_RANGE);
      expect(result.fix).toContain('Rebuilding does not help');
      expect(result.fix).not.toMatch(/`npm rebuild/);
      expect(`${result.message} ${result.fix}`).not.toMatch(/closeDatabase|close the database/i);
    },
  );

  it.each(['v24.0.0', 'v24.21.0'])('passes on %s with the engine this release declares', (nodeVersion) => {
    const result = nativeEngineVerdict(nodeVersion, at('resolved', '13.0.3'));
    expect(result.status).toBe('pass');
    expect(result.haltsRun).toBeUndefined();
    expect(doctorExitCode([result])).toBe(0);
    expect(result.message).toContain('13.0.3');
  });

  // The floor is a Node 24 fact. Node 22 runs 12.x perfectly well, and doctor
  // does not invent a failure for a host that works.
  it.each(['v22.14.0', 'v22.23.2'])('does not trigger on %s with an installed 12.x', (nodeVersion) => {
    const result = nativeEngineVerdict(nodeVersion, at('resolved', '12.4.1'));
    expect(result.status).toBe('pass');
    expect(result.haltsRun).toBeUndefined();
    expect(doctorExitCode([result], { strict: true })).toBe(0);
    expect(result.message).toContain('does not apply to this runtime');
  });

  it('still catches a 12.x on Node 22 once the runtime is 24 — the gate is the pair, not the engine alone', () => {
    expect(nativeEngineVerdict('v22.23.2', at('resolved', '12.4.1')).status).toBe('pass');
    expect(nativeEngineVerdict('v24.21.0', at('resolved', '12.4.1')).status).toBe('fail');
  });

  /**
   * Not-knowing must READ as not-knowing. A silent `pass` here would be the
   * worst outcome of the three: it would tell an operator on the exact broken
   * install that their engine is fine, in the report printed right before the
   * process aborts. And on Node 24 not-knowing must also STOP the run (#465):
   * a preflight that could not read the version cannot rule the abort out, so
   * continuing gambles the report on exactly what it failed to establish.
   */
  it.each([
    ['unresolvable', at('unresolvable', undefined, { detail: 'Cannot find module \'better-sqlite3\'' })],
    ['unreadable', at('unreadable', undefined, { source: '/opt/sc/node_modules/better-sqlite3/package.json', detail: 'manifest is not valid JSON — Unexpected token' })],
    ['malformed version', at('resolved', 'not-a-version', { source: '/opt/sc/node_modules/better-sqlite3/package.json' })],
    // Coercible junk is still junk: `semver.coerce("13-garbage")` invents
    // 13.0.0, which would wave a version nothing can vouch for past the floor.
    ['coercible-but-not-semver version', at('resolved', '13-garbage', { source: '/opt/sc/node_modules/better-sqlite3/package.json' })],
  ])('warns, halts the run, and claims nothing on a %s engine version under Node 24', (_label, engine) => {
    const result = nativeEngineVerdict('v24.21.0', engine);
    expect(result.label).toBe(NATIVE_ENGINE_LABEL);
    // A warn, not a fail: an unreadable manifest is not evidence of 12.x, so
    // the exit code stays 0 — but the run still halts, and the report says
    // outright which findings the operator is not getting, and why.
    expect(result.status).toBe('warn');
    expect(doctorExitCode([result])).toBe(0);
    expect(result.haltsRun).toBe(true);
    expect(result.message).toContain('cannot determine the installed better-sqlite3 version');
    expect(result.message).toContain('No compatibility is claimed from this row');
    expect(result.message).toContain('floor unproven');
    expect(result.message).toContain('The remaining checks were not run');
    // Unproven is not proven-stale: no incompatibility claim, no forged abort
    // banner, and no rebuild story about a 12.x nothing established is there.
    expect(result.message).not.toContain('incompatible');
    expect(result.message).not.toMatch(/Assertion failed|SIGABRT/);
    expect(result.fix).toContain('npm install -g shieldcortex@latest');
    expect(result.fix).not.toContain('Rebuilding');
  });

  it('says the same not-knowing on Node 22, without importing the Node 24 alarm', () => {
    const result = nativeEngineVerdict('v22.23.2', at('unresolvable', undefined, { detail: 'boom' }));
    expect(result.status).toBe('warn');
    expect(result.message).toContain('cannot determine the installed better-sqlite3 version');
    expect(result.message).toContain('not exposed to the Node 24');
    expect(result.message).not.toContain('floor unproven');
    // Non-halting AND unfixed: this runtime runs 12.x and 13.x alike, so there
    // is no incompatibility finding — the list keeps running and no reinstall
    // is promoted for a fault that was not found.
    expect(result.haltsRun).toBeUndefined();
    expect(result.message).not.toContain('The remaining checks were not run');
    expect(result.fix).toBeUndefined();
  });

  it('warns rather than guessing when the Node version itself is unparseable', () => {
    const result = nativeEngineVerdict('not-a-version', at('resolved', '12.4.1'));
    expect(result.status).toBe('warn');
    expect(result.haltsRun).toBeUndefined();
    expect(result.message).toContain('unrecognised Node version "not-a-version"');
    expect(doctorExitCode([result])).toBe(0);
  });

  it('the live check reads the real installed tree and agrees with the verdict', async () => {
    const engine = readInstalledEngineVersion();
    expect(engine.state).toBe('resolved');
    expect(engine.source).toMatch(/node_modules[/\\]better-sqlite3[/\\]package\.json$/);
    expect(engine.version).toMatch(/^13\./);

    // Same inputs, same answer — the check adds no logic of its own.
    const viaCheck = await checkNativeEngineCompat('v24.21.0');
    expect(viaCheck).toEqual(nativeEngineVerdict('v24.21.0', engine));
    expect(viaCheck.status).toBe('pass');
  });
});

describe('doctor — readInstalledEngineVersion reports what it could not learn', () => {
  it('is unresolvable when neither the manifest nor the entry resolves', () => {
    const result = readInstalledEngineVersion({
      resolve: () => { throw new Error('Cannot find module \'better-sqlite3\''); },
      read: () => { throw new Error('never reached'); },
    });
    expect(result.state).toBe('unresolvable');
    expect(result.detail).toContain('Cannot find module');
    expect(result.version).toBeUndefined();
  });

  it('falls back to the package root when `exports` withholds the manifest', () => {
    const files: Record<string, string> = {
      '/opt/sc/node_modules/better-sqlite3/package.json': JSON.stringify({
        name: 'better-sqlite3', version: '12.4.1',
      }),
    };
    const result = readInstalledEngineVersion({
      resolve: (specifier) => {
        if (specifier === 'better-sqlite3') return '/opt/sc/node_modules/better-sqlite3/lib/index.js';
        throw new Error('ERR_PACKAGE_PATH_NOT_EXPORTED');
      },
      read: (file) => {
        if (file in files) return files[file];
        throw new Error(`ENOENT: ${file}`);
      },
    });
    expect(result).toEqual({
      state: 'resolved',
      version: '12.4.1',
      source: '/opt/sc/node_modules/better-sqlite3/package.json',
    });
  });

  it.each([
    ['unparseable JSON', 'not json at all', /not valid JSON/],
    ['a missing version', JSON.stringify({ name: 'better-sqlite3' }), /no usable "version"/],
    ['a non-string version', JSON.stringify({ version: 12 }), /no usable "version"/],
    ['a version that is not semver at all', JSON.stringify({ version: 'latest' }), /no usable "version"/],
    // The #465 case: `semver.coerce` would salvage 13.0.0 out of this and the
    // preflight would then PASS a manifest it could not actually read. Only a
    // full valid semantic version counts as known.
    ['a coercible-but-invalid version', JSON.stringify({ version: '13-garbage' }), /no usable "version"/],
  ])('is unreadable, with a reason, on %s', (_label, body, reason) => {
    const result = readInstalledEngineVersion({
      resolve: () => '/opt/sc/node_modules/better-sqlite3/package.json',
      read: () => body,
    });
    expect(result.state).toBe('unreadable');
    expect(result.source).toBe('/opt/sc/node_modules/better-sqlite3/package.json');
    expect(result.detail).toMatch(reason);
    expect(result.version).toBeUndefined();
  });
});

/**
 * The live compiled CLI, on a tree it believes is a stale 12.x.
 *
 * In-process assertions cannot settle this one: what is being claimed is that
 * the RUN stops — that no later check opens a database — and only the real
 * dispatched command, with its real check list and its real exit status, can
 * show that.
 */
describe('doctor — a stale installed engine fails early on the real CLI (#471)', () => {
  let home: string;

  beforeEach(() => {
    home = fs.mkdtempSync(path.join(os.tmpdir(), 'sc-doctor-engine-'));
  });

  afterEach(() => {
    try { fs.rmSync(home, { recursive: true, force: true }); } catch { /* ignore */ }
  });

  it('exits 1 with an actionable ❌ and never reaches the database checks on Node 24', async () => {
    expect(fs.existsSync(CLI_PATH)).toBe(true);
    const engine = installFakeEngine(home, '12.4.1');

    const { stdout, code, signal } = await runDoctorCli(home, [], {
      forceVersion: 'v24.21.0',
      preloads: [engine.preload],
    });
    const report = plain(stdout);

    // It FAILED, and it failed by rendering a report — not by dying.
    expect(signal).toBeNull();
    expect(report).not.toMatch(/Assertion failed: \(env\) != nullptr/);
    expect(report).not.toMatch(/SIGABRT/);
    expect(code).not.toBe(134);
    expect(code).toBe(1);

    // The operator can act on it.
    expect(report).toContain(NATIVE_ENGINE_LABEL);
    expect(report).toContain('better-sqlite3 12.4.1');
    expect(report).toContain('incompatible with Node 24.21.0');
    expect(report).toContain('npm install -g shieldcortex@latest');
    expect(report).not.toMatch(/closeDatabase/i);

    // The run short-circuited. Two independent witnesses, because either alone
    // could be satisfied by a coincidence: no check below the preflight printed
    // a row, and nothing ever loaded the engine package.
    expect(report).not.toContain('not initialised yet'); // the Database row
    for (const laterCheck of ['Disk', 'Write path', 'Hooks', 'Lock', 'Schema', 'Memories']) {
      expect(report).not.toContain(laterCheck);
    }
    expect(fs.existsSync(engine.marker)).toBe(false);
    expect(fs.existsSync(path.join(home, '.shieldcortex', 'memories.db'))).toBe(false);
  }, 120_000);

  // Non-vacuity for the two assertions above: the SAME sandbox and the SAME
  // forced Node 24, with the engine this release actually installs, runs the
  // whole list and exits 0. A gate that fired on Node 24 alone would fail here.
  it('passes the preflight and runs the rest of the list on Node 24 with the installed 13.x', async () => {
    expect(fs.existsSync(CLI_PATH)).toBe(true);

    const { stdout, code, signal } = await runDoctorCli(home, ['--verbose'], {
      forceVersion: 'v24.21.0',
    });
    const report = plain(stdout);

    expect(signal).toBeNull();
    expect(code).toBe(0);
    expect(report).toContain(NATIVE_ENGINE_LABEL);
    expect(report).not.toContain('incompatible with Node');
    // Reached the checks the stale run never got to.
    expect(report).toContain('not initialised yet');
    expect(report).toContain('Disk');
  }, 120_000);

  // #465 blocker: unknowable must not fall through into the same abort. A
  // manifest whose version is coercible junk ("13-garbage" → 13.0.0 under
  // `semver.coerce`) used to read as a resolved 13.x and PASS — straight into
  // the handle-opening checks the preflight exists to keep away from a
  // maybe-12.x tree. Same two short-circuit witnesses as the stale-12 proof.
  it('halts before any later check or native load on Node 24 when the version is unknowable', async () => {
    expect(fs.existsSync(CLI_PATH)).toBe(true);
    const engine = installFakeEngine(home, '13-garbage');

    const { stdout, code, signal } = await runDoctorCli(home, [], {
      forceVersion: 'v24.21.0',
      preloads: [engine.preload],
    });
    const report = plain(stdout);

    expect(signal).toBeNull();
    expect(report).not.toMatch(/Assertion failed: \(env\) != nullptr/);
    expect(code).not.toBe(134);

    // Honest severity: nothing was DISproven, so this is a warning and exit 0
    // — but the report says outright why the rest of the list is missing.
    expect(code).toBe(0);
    expect(report).toContain(NATIVE_ENGINE_LABEL);
    expect(report).toContain('cannot determine the installed better-sqlite3 version');
    expect(report).toContain('The remaining checks were not run');
    expect(report).toContain('npm install -g shieldcortex@latest');
    expect(report).not.toContain('incompatible with Node');

    expect(report).not.toContain('not initialised yet'); // the Database row
    for (const laterCheck of ['Disk', 'Write path', 'Hooks', 'Lock', 'Schema', 'Memories']) {
      expect(report).not.toContain(laterCheck);
    }
    expect(fs.existsSync(engine.marker)).toBe(false);
    expect(fs.existsSync(path.join(home, '.shieldcortex', 'memories.db'))).toBe(false);
  }, 120_000);

  // Node 22 is not exposed to the abort, so not-knowing stays an ordinary
  // warning there: the list runs to the end and no reinstall is promoted for
  // an incompatibility that was never found.
  it('keeps an unknowable version non-halting, with no reinstall pitch, on Node 22', async () => {
    expect(fs.existsSync(CLI_PATH)).toBe(true);
    const engine = installFakeEngine(home, '13-garbage');

    const { stdout, code, signal } = await runDoctorCli(home, ['--verbose'], {
      forceVersion: 'v22.14.0',
      preloads: [engine.preload],
    });
    const report = plain(stdout);

    expect(signal).toBeNull();
    expect(report).toContain('cannot determine the installed better-sqlite3 version');
    expect(report).toContain('not an incompatibility finding');
    expect(report).not.toContain('The remaining checks were not run');
    expect(report).not.toContain('npm install -g shieldcortex@latest');
    // The run continued past the preflight.
    expect(report).toContain('not initialised yet');
    expect(report).toContain('Disk');
    expect(code).toBe(0);
  }, 120_000);

  // Node 22 is the runtime the 12.x line was fine on. A host that never
  // upgraded Node must not be handed a new failure by this release.
  it('does not fire on Node 22 with the same 12.x tree', async () => {
    expect(fs.existsSync(CLI_PATH)).toBe(true);
    const engine = installFakeEngine(home, '12.4.1');

    const { stdout, code, signal } = await runDoctorCli(home, ['--verbose'], {
      forceVersion: 'v22.14.0',
      preloads: [engine.preload],
    });
    const report = plain(stdout);

    expect(signal).toBeNull();
    // Rendered as a PASS: collapsed pass rows are truncated, so the section it
    // lands in — not the full prose — is what proves the severity here. The
    // wording itself is pinned on the pure verdict above.
    expect(report).toMatch(/HEALTHY .*Database engine better-sqlite3 12\.4\.1/);
    expect(report).not.toContain('incompatible with Node');
    // The run continued: the preflight neither failed nor halted it.
    expect(report).toContain('not initialised yet');
    expect(report).toContain('Disk');
    expect(code).toBe(0);
  }, 120_000);
});
