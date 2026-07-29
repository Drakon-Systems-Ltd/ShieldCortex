import { spawn } from 'child_process';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { createRequire } from 'module';
import { fileURLToPath } from 'url';
import { afterEach, beforeEach, describe, expect, it } from '@jest/globals';

import {
  doctorExitCode,
  probePath,
  runDatabaseCheck,
  runHooksCheck,
  runMemoryStatsCheck,
  runSchemaDriftCheck,
  runWritePathProbe,
  checkDiskUsage,
  checkLockFile,
  type CheckResult,
} from '../doctor.js';

const require = createRequire(import.meta.url);
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

/**
 * Permission-denied is not a fresh install (#132).
 *
 * #131 made a missing database an informational "not initialised yet" — right
 * for a genuine first run. It asked `fs.existsSync`, which returns false for
 * "not there" AND for "there but unreadable", so a root-owned `~/.shieldcortex`
 * (the classic artefact of one `sudo shieldcortex …`) started reporting a clean
 * bill of health on a genuinely broken install. Doctor exists for exactly that
 * user; going green on them is its worst possible failure mode.
 *
 * The contract locked in here:
 *   - ENOENT  → ℹ️ "not initialised yet", exit 0 (the #129/#131 behaviour)
 *   - EACCES/EPERM → ❌ naming ownership as the likely cause, exit 1
 *   - any other errno → ❌ with the real error surfaced, never swallowed
 *   - a healthy install is unchanged
 */

const errno = (code: string): NodeJS.ErrnoException => {
  const err = new Error(`${code}: simulated`) as NodeJS.ErrnoException;
  err.code = code;
  return err;
};

const throwing = (code: string) => (): fs.Stats => { throw errno(code); };

// chmod cannot deny root anything, so the filesystem-level tests are
// meaningless when the suite runs as root (containers, some CI images). The
// injected-statSync tests below cover every branch deterministically either
// way; these add the proof that a real EACCES lands in the right branch.
const isRoot = typeof process.getuid === 'function' && process.getuid() === 0;
const describeUnprivileged = isRoot ? describe.skip : describe;

describe('doctor — probePath keeps absent, denied and broken apart', () => {
  it('classifies ENOENT as absent — the only "fresh install" code', () => {
    expect(probePath('/nope', throwing('ENOENT'))).toEqual({ kind: 'absent' });
  });

  it.each(['EACCES', 'EPERM'])('classifies %s as denied, not absent', (code) => {
    const probe = probePath('/root-owned', throwing(code));
    expect(probe.kind).toBe('denied');
    expect(probe).toMatchObject({ code });
  });

  it('classifies any other errno as an error, keeping the code and message', () => {
    const probe = probePath('/flaky', throwing('EIO'));
    expect(probe.kind).toBe('error');
    expect(probe).toMatchObject({ code: 'EIO' });
    if (probe.kind === 'error') expect(probe.message).toMatch(/simulated/);
  });

  it('reports a readable path as present', () => {
    const probe = probePath(__filename);
    expect(probe.kind).toBe('present');
  });
});

describe('doctor — exit code', () => {
  const result = (status: CheckResult['status']): CheckResult =>
    ({ label: 'X', status, message: 'm' });

  it('exits 1 when any check failed', () => {
    expect(doctorExitCode([result('pass'), result('fail')])).toBe(1);
  });

  it('exits 0 for a clean run', () => {
    expect(doctorExitCode([result('pass'), result('pass')])).toBe(0);
  });

  it('exits 0 on a fresh install — info states are not failures', () => {
    expect(doctorExitCode([result('info'), result('info'), result('pass')])).toBe(0);
  });

  it('exits 0 on warnings by default', () => {
    expect(doctorExitCode([result('warn'), result('pass')])).toBe(0);
  });

  it('exits 1 on warnings under --strict', () => {
    expect(doctorExitCode([result('warn')], { strict: true })).toBe(1);
  });

  it('--strict still passes a run with nothing but info/pass', () => {
    expect(doctorExitCode([result('info'), result('pass')], { strict: true })).toBe(0);
  });
});

describeUnprivileged('doctor — an unreadable install is ❌, never "fresh"', () => {
  const claudeEnv = { hasClaude: true, hasOpenClaw: false, hasVSCode: false, hasCodex: false, isHeadless: false };

  let tmpDir: string;
  let scDir: string;
  let dbPath: string;

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'sc-denied-'));
    scDir = path.join(tmpDir, '.shieldcortex');
    dbPath = path.join(scDir, 'memories.db');
    fs.mkdirSync(scDir);
    const Database = require('better-sqlite3');
    const db = new Database(dbPath);
    db.exec('CREATE TABLE memories (id INTEGER PRIMARY KEY)');
    db.close();
  });

  afterEach(() => {
    try { fs.chmodSync(scDir, 0o755); } catch { /* already gone */ }
    try { fs.chmodSync(path.join(tmpDir, '.claude'), 0o755); } catch { /* may not exist */ }
    try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch { /* ignore */ }
  });

  /** Deny traversal the way a root-owned directory does to a normal user. */
  const deny = (): void => { fs.chmodSync(scDir, 0o000); };

  it('Database reports ❌ with an ownership remedy, not "not initialised yet"', () => {
    deny();
    const result = runDatabaseCheck(dbPath, claudeEnv);

    expect(result.status).toBe('fail');
    expect(result.message).toMatch(/permission denied/i);
    expect(result.message).toMatch(/EACCES/);
    expect(result.message).not.toMatch(/not initialised yet/i);
    expect(result.fix).toMatch(/chown -R/);
    expect(result.fix).toMatch(/sudo/i);
  });

  it.each([
    ['Schema', () => runSchemaDriftCheck(dbPath)],
    ['Write path', () => runWritePathProbe(dbPath)],
    ['Memories', () => runMemoryStatsCheck(dbPath)],
  ])('%s reports ❌ and is never collapsed into the fresh-install note', (label, run) => {
    deny();
    const result = run();

    expect(result.label).toBe(label);
    expect(result.status).toBe('fail');
    expect(result.message).toMatch(/permission denied/i);
    // The suppression that hides dependent checks on a fresh box must not
    // hide a permission fault — that is the regression being closed.
    expect(result.skipped).toBeUndefined();
  });

  it('Disk does not report a green 0 B for an unreadable directory', async () => {
    deny();
    const result = await checkDiskUsage(scDir);

    expect(result.status).toBe('fail');
    expect(result.message).toMatch(/permission denied/i);
    expect(result.message).not.toMatch(/not yet created/i);
  });

  it('Lock does not report "clean" for an unreadable directory', async () => {
    deny();
    const result = await checkLockFile(scDir);

    expect(result.status).toBe('fail');
    expect(result.message).toMatch(/permission denied/i);
    expect(result.message).not.toMatch(/clean/i);
  });

  it('Hooks reports ❌ for an unreadable settings.json, not "not configured yet"', () => {
    const claudeDir = path.join(tmpDir, '.claude');
    const settingsPath = path.join(claudeDir, 'settings.json');
    fs.mkdirSync(claudeDir);
    fs.writeFileSync(settingsPath, JSON.stringify({ hooks: {} }));
    fs.chmodSync(claudeDir, 0o000);

    const result = runHooksCheck(settingsPath, claudeEnv);

    expect(result.status).toBe('fail');
    expect(result.message).toMatch(/permission denied/i);
    expect(result.message).not.toMatch(/not configured yet/i);
    expect(result.fix).toMatch(/ownership and permissions/i);
  });

  it('a readable database is still healthy — the check only fires on real denial', () => {
    const result = runDatabaseCheck(dbPath, claudeEnv);
    expect(result.status).toBe('pass');
    expect(result.message).toMatch(/healthy/);
  });

  it('an absent database is still the friendly informational state', () => {
    const result = runDatabaseCheck(path.join(tmpDir, 'nothing-here.db'), claudeEnv);
    expect(result.status).toBe('info');
    expect(result.message).toMatch(/not initialised yet/i);
  });
});

/**
 * End-to-end through the real CLI: the exit code is the part CI consumes, and
 * it can only be proven by running the binary.
 */
describeUnprivileged('doctor — CLI exit status', () => {
  const cliPath = path.resolve(__dirname, '..', '..', '..', 'dist', 'index.js');

  let home: string;

  beforeEach(() => {
    home = fs.mkdtempSync(path.join(os.tmpdir(), 'sc-doctor-home-'));
  });

  afterEach(() => {
    try { fs.chmodSync(path.join(home, '.shieldcortex'), 0o755); } catch { /* may not exist */ }
    try { fs.rmSync(home, { recursive: true, force: true }); } catch { /* ignore */ }
  });

  /**
   * A scrubbed environment: HOME points at the sandbox so doctor reads and
   * writes nothing of the host's, and inherited SHIELDCORTEX_* would otherwise
   * change what the checks resolve to (#125).
   */
  const runDoctorCli = (args: string[] = []): Promise<{ stdout: string; code: number }> =>
    new Promise((resolve, reject) => {
      const child = spawn(process.execPath, [cliPath, 'doctor', ...args], {
        stdio: ['ignore', 'pipe', 'pipe'],
        env: { PATH: process.env.PATH ?? '/usr/bin:/bin', HOME: home },
      });
      let stdout = '';
      child.stdout.on('data', (c) => { stdout += c.toString(); });
      child.stderr.on('data', (c) => { stdout += c.toString(); });
      child.on('error', reject);
      child.on('close', (code) => resolve({ stdout, code: code ?? 0 }));
    });

  it('exits 0 on a fresh box — a first run must not fail a pipeline', async () => {
    // dist is built before tests in CI; assert the invariant so a missing
    // build fails loudly rather than green-skipping the exit-code proof.
    expect(fs.existsSync(cliPath)).toBe(true);

    const { stdout, code } = await runDoctorCli();
    expect(stdout).toMatch(/not initialised yet/);
    expect(stdout).not.toMatch(/failure/);
    expect(code).toBe(0);
  }, 60_000);

  it('exits 1 with a ❌ when ~/.shieldcortex cannot be read', async () => {
    expect(fs.existsSync(cliPath)).toBe(true);

    const scDir = path.join(home, '.shieldcortex');
    fs.mkdirSync(scDir);
    fs.writeFileSync(path.join(scDir, 'memories.db'), '');
    fs.chmodSync(scDir, 0o000);

    const { stdout, code } = await runDoctorCli();
    expect(stdout).toMatch(/permission denied/i);
    expect(stdout).toMatch(/chown -R/);
    expect(stdout).not.toMatch(/not initialised yet/);
    expect(code).toBe(1);
  }, 60_000);
});
