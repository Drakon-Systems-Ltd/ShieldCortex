import { spawn } from 'child_process';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { createRequire } from 'module';
import { fileURLToPath } from 'url';
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it } from '@jest/globals';

import {
  NODE_RUNTIME_LABEL,
  SUPPORTED_NODE_RANGE,
  checkNodeRuntime,
  doctorExitCode,
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

/**
 * A scrubbed environment: HOME points at the caller's sandbox so doctor reads
 * and writes nothing of the host's, and inherited SHIELDCORTEX_* would
 * otherwise change what the checks resolve to (#125).
 */
const runDoctorCli = (
  home: string,
  args: string[] = [],
  opts: { forceVersion?: string } = {},
): Promise<DoctorRun> =>
  new Promise((resolve, reject) => {
    const nodeArgs = opts.forceVersion ? ['--require', writePreload(home, opts.forceVersion)] : [];
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
   * afterwards. That is not hygiene theatre — the doctor's State permissions
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
    const dir = path.dirname(dbPath);
    fs.chmodSync(dir, 0o700);
    for (const entry of fs.readdirSync(dir)) {
      fs.chmodSync(path.join(dir, entry), 0o600);
    }
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

    expect(code).toBe(0);
  }, 180_000);
});
