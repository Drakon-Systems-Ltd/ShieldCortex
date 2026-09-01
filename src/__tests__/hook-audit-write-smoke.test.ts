import { spawn } from 'node:child_process';
import { mkdtempSync, mkdirSync, readdirSync, readFileSync, rmSync, statSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { afterEach, beforeEach, describe, expect, it } from '@jest/globals';

/**
 * PLATFORM SMOKE TEST — does the guard actually write its audit row on THIS OS?
 *
 * Every other test here can pass while the audit trail is silently empty,
 * because they exercise functions rather than the process on a real filesystem.
 * PR #247 showed what that costs: it replaced `appendFileSync` with an
 * `appendFileNoFollow` whose symlink check called `readlinkSync('/dev/fd/N')`.
 * Correct on Linux, where `/proc/self/fd/N` IS a symlink — EINVAL on macOS,
 * where `/dev/fd/N` is not. The failure path returned `false`, the caller was a
 * bare `return`, and the result was an audit file created with ZERO bytes,
 * exit 0, no error printed. On a security product, on the fail-closed hot path,
 * on every Mac in the fleet.
 *
 * Linux-only CI cannot see that class of defect by construction, so the fix is
 * not a better unit test — it is running the real hook as a real process on
 * whichever platform CI is on, and checking a row landed.
 *
 * Deliberately asserts the OUTCOME, not the mechanism: any write strategy is
 * fine so long as the row exists and parses. A zero-byte file is treated as
 * WORSE than a missing one, because it looks like the trail is working.
 *
 * The command below is a string the hook CLASSIFIES; nothing executes it. It is
 * the same catastrophic fixture the sibling hook suites use, chosen because it
 * denies by default with no config at all — so this test needs no fixture setup
 * that could itself drift.
 */

const HOOK_PATH = resolve(dirname(fileURLToPath(import.meta.url)), '..', '..', 'scripts', 'pre-tool-hook.mjs');

const CATASTROPHIC_FIXTURE = 'rm -rf /';

type HookRun = { stdout: string; stderr: string; code: number };

function runHook(home: string): Promise<HookRun> {
  return new Promise((res, reject) => {
    const child = spawn(process.execPath, [HOOK_PATH], {
      stdio: ['pipe', 'pipe', 'pipe'],
      env: {
        ...process.env,
        HOME: home,
        USERPROFILE: home,
        SHIELDCORTEX_CONFIG_DIR: join(home, '.shieldcortex'),
        SHIELDCORTEX_DIST_ROOT: resolve(dirname(fileURLToPath(import.meta.url)), '..', '..', 'dist'),
        SHIELDCORTEX_SESSION_SALT: undefined,
      },
    });
    let stdout = '';
    let stderr = '';
    child.stdout.on('data', (c) => { stdout += c.toString(); });
    child.stderr.on('data', (c) => { stderr += c.toString(); });
    child.on('error', reject);
    child.on('close', (code) => res({ stdout, stderr, code: code ?? 0 }));
    child.stdin.write(JSON.stringify({
      session_id: 'audit-write-smoke',
      cwd: '/tmp',
      permission_mode: 'default',
      tool_name: 'Bash',
      tool_input: { command: CATASTROPHIC_FIXTURE },
    }));
    child.stdin.end();
  });
}

/** Every audit .jsonl written under the sandbox home, with its byte size. */
function auditFiles(home: string): Array<{ name: string; bytes: number; body: string }> {
  const dir = join(home, '.shieldcortex', 'audit');
  let names: string[];
  try {
    names = readdirSync(dir).filter(n => n.endsWith('.jsonl'));
  } catch {
    return [];
  }
  return names.map((name) => {
    const p = join(dir, name);
    return { name, bytes: statSync(p).size, body: readFileSync(p, 'utf-8') };
  });
}

let home: string;

beforeEach(() => {
  home = mkdtempSync(join(tmpdir(), 'sc-audit-smoke-'));
  mkdirSync(join(home, '.shieldcortex'), { recursive: true });
  writeFileSync(
    join(home, '.shieldcortex', 'config.json'),
    JSON.stringify({ actionGuard: { enabled: true, enforce: true } }),
  );
});
afterEach(() => { rmSync(home, { recursive: true, force: true }); });

describe('the action guard writes a real audit row on this platform', () => {
  it('denies the catastrophic fixture AND leaves a non-empty audit row', async () => {
    const run = await runHook(home);

    // Denial travels in the JSON payload, never in the exit code.
    expect(run.code).toBe(0);
    expect(run.stdout).toContain('deny');

    const files = auditFiles(home);
    const nonEmpty = files.filter(f => f.bytes > 0);

    // Report the shape on failure — on a platform regression the useful fact is
    // "the file exists and is 0 bytes", which a bare length assertion hides.
    expect({
      platform: process.platform,
      files: files.map(f => `${f.name}=${f.bytes}b`),
      stderr: run.stderr.slice(0, 300),
    }).toMatchObject({ files: expect.arrayContaining([expect.stringMatching(/\.jsonl=[1-9]/)]) });

    expect(nonEmpty.length).toBeGreaterThan(0);
  });

  it('the row parses as JSON and names the tool', async () => {
    await runHook(home);

    const rows = auditFiles(home)
      .flatMap(f => f.body.split('\n'))
      .filter(line => line.trim().length > 0)
      .map(line => JSON.parse(line) as Record<string, unknown>);

    expect(rows.length).toBeGreaterThan(0);
    expect(JSON.stringify(rows)).toContain('Bash');
  });
});
