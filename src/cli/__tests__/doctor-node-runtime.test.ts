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
  let preload: string;

  beforeEach(() => {
    home = fs.mkdtempSync(path.join(os.tmpdir(), 'sc-doctor-node-'));
    preload = path.join(home, 'force-node-version.cjs');
  });

  afterEach(() => {
    try { fs.rmSync(home, { recursive: true, force: true }); } catch { /* ignore */ }
  });

  /**
   * Move the CHILD's `process.version` before the CLI module graph loads.
   * `process.versions.modules` is deliberately left alone: this pins the
   * doctor's own runtime verdict, not any ABI-derived behaviour.
   */
  function writePreload(version: string): void {
    fs.writeFileSync(
      preload,
      `Object.defineProperty(process, 'version', { value: ${JSON.stringify(version)}, configurable: true });\n`,
    );
  }

  /**
   * A scrubbed environment: HOME points at the empty sandbox so doctor reads
   * and writes nothing of the host's, and inherited SHIELDCORTEX_* would
   * otherwise change what the checks resolve to (#125).
   */
  const runDoctorCli = (
    args: string[] = [],
    opts: { forceVersion?: string } = {},
  ): Promise<{ stdout: string; code: number }> =>
    new Promise((resolve, reject) => {
      if (opts.forceVersion) writePreload(opts.forceVersion);
      const nodeArgs = opts.forceVersion ? ['--require', preload] : [];
      const child = spawn(process.execPath, [...nodeArgs, CLI_PATH, 'doctor', ...args], {
        stdio: ['ignore', 'pipe', 'pipe'],
        env: { PATH: process.env.PATH ?? '/usr/bin:/bin', HOME: home },
      });
      let stdout = '';
      child.stdout.on('data', (c) => { stdout += c.toString(); });
      child.stderr.on('data', (c) => { stdout += c.toString(); });
      child.on('error', reject);
      child.on('close', (code) => resolve({ stdout, code: code ?? 0 }));
    });

  it('the check is in the live check list and passes on this supported runtime', async () => {
    // dist is built before tests in CI; assert the invariant so a missing
    // build fails loudly rather than green-skipping the end-to-end proof.
    expect(fs.existsSync(CLI_PATH)).toBe(true);

    // Passes are collapsed into theme codes without --verbose.
    const { stdout, code } = await runDoctorCli(['--verbose']);
    expect(plain(stdout)).toContain(NODE_RUNTIME_LABEL);
    expect(code).toBe(0);
  }, 120_000);

  // The baseline above is what makes the assertions below non-vacuous: the
  // SAME empty sandbox exits 0, so a 1 here is this check and nothing else.
  it.each(['v20.19.0', 'v23.11.0'])('exits 1 with a ❌ on Node %s, database or not', async (version) => {
    expect(fs.existsSync(CLI_PATH)).toBe(true);

    const { stdout, code } = await runDoctorCli([], { forceVersion: version });
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
