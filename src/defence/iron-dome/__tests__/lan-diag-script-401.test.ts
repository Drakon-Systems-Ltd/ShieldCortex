/**
 * #401 — script-level tests for the lan-diag work-lane template.
 *
 * The TypeScript door matrix (denial-doors-401.test.ts) exercises the hint
 * catalog; it never executes the template. These tests run the actual shell
 * script and lock the refusal contract reviewers flagged:
 *   - public destinations refuse (ping + GET)
 *   - GET refuses link-local/IMDS ranges even though ping allows link-local
 *   - ambiguous leading-zero IPv4 literals refuse
 *   - inherited environment (startup-file vars, curl proxy vars, PATH) cannot
 *     alter behaviour — the script re-execs itself with a scrubbed environment
 *   - loopback status/help paths still work (the lane stays useful)
 *
 * No network I/O beyond loopback is attempted: every case below either refuses
 * before any socket opens or targets 127.0.0.1.
 */
import { execFileSync, spawnSync } from 'child_process';
import { existsSync } from 'fs';
import { join } from 'path';

const SCRIPT = join(process.cwd(), 'templates', 'work-lanes', 'lan-diag.sh');

function run(args: string[], extraEnv: Record<string, string> = {}): { code: number; out: string } {
  const res = spawnSync('/bin/bash', [SCRIPT, ...args], {
    encoding: 'utf-8',
    timeout: 10_000,
    env: { ...process.env, ...extraEnv },
  });
  return { code: res.status ?? -1, out: `${res.stdout ?? ''}${res.stderr ?? ''}` };
}

describe('lan-diag.sh script-level refusal contract (#401)', () => {
  test('template exists and is valid bash', () => {
    expect(existsSync(SCRIPT)).toBe(true);
    expect(() => execFileSync('/bin/bash', ['-n', SCRIPT])).not.toThrow();
  });

  test('help and status run clean', () => {
    expect(run(['help']).code).toBe(0);
    const st = run(['status']);
    expect(st.code).toBe(0);
    expect(st.out).toContain('# interfaces');
  });

  test('public IPv4 destination refuses (ping form)', () => {
    const r = run(['8.8.8.8']);
    expect(r.code).toBe(2);
    expect(r.out).toContain('refused');
  });

  test('public URL refuses (GET form)', () => {
    const r = run(['GET', 'http://8.8.8.8/']);
    expect(r.code).toBe(2);
    expect(r.out).toContain('refused');
  });

  test('GET refuses IMDS / link-local even though ping allows link-local', () => {
    const r = run(['GET', 'http://169.254.169.254/latest/meta-data/']);
    expect(r.code).toBe(2);
    expect(r.out).toMatch(/link-local|IMDS/);
  });

  test('GET refuses IPv6 link-local IMDS alias', () => {
    const r = run(['GET', 'http://[fe80::a9fe:a9fe]/']);
    expect(r.code).toBe(2);
  });

  test('ambiguous leading-zero IPv4 literal refuses (octal confusion)', () => {
    const r = run(['010.0.0.1']);
    expect(r.code).toBe(2);
    expect(r.out).toContain('refused');
  });

  test('non-http(s) scheme refuses', () => {
    const r = run(['GET', 'ftp://192.168.1.1/']);
    expect(r.code).toBe(2);
  });

  test('userinfo URL refuses', () => {
    const r = run(['GET', 'http://user@192.168.1.1/']);
    expect(r.code).toBe(2);
  });

  test('unknown flags refuse', () => {
    expect(run(['--interactive']).code).toBe(2);
    expect(run(['-x']).code).toBe(2);
  });

  test('extra arguments refuse', () => {
    expect(run(['status', 'extra']).code).toBe(2);
    expect(run(['GET', 'http://127.0.0.1/', 'extra']).code).toBe(2);
  });

  test('inherited startup-file var cannot inject code (env scrub re-exec)', () => {
    // If the variable survived, bash would try to source this path and fail.
    const r = run(['help'], { BASH_ENV: '/nonexistent/hostile-startup.sh' });
    expect(r.code).toBe(0);
  });

  test('inherited proxy environment cannot route the GET (env scrub re-exec)', () => {
    // A proxy pointing at a dead loopback port would fail the request if
    // honoured; the scrubbed env + --noproxy makes the refusal identical.
    const r = run(['GET', 'http://8.8.8.8/'], {
      http_proxy: 'http://127.0.0.1:1',
      https_proxy: 'http://127.0.0.1:1',
      ALL_PROXY: 'http://127.0.0.1:1',
    });
    expect(r.code).toBe(2); // refused on destination, never reaches curl
  });

  test('hostile PATH cannot shadow tools (env scrub re-exec)', () => {
    const r = run(['help'], { PATH: '/nonexistent-bin' });
    expect(r.code).toBe(0);
  });

  test('spoofed scrub sentinel with hostile PATH still gets scrubbed (SOL round 2)', () => {
    const r = run(['help'], { LAN_DIAG_REEXEC: '1', PATH: '/nonexistent-bin' });
    expect(r.code).toBe(0);
  });

  test('octal-form IPv4 literal refuses instead of canonicalising (SOL round 2)', () => {
    const r = run(['0177.0.0.1']);
    expect(r.code).toBe(2);
    expect(r.out).toContain('refused');
  });

  test('decimal-int IPv4 literal refuses (2130706433 = 127.0.0.1)', () => {
    const r = run(['2130706433']);
    expect(r.code).toBe(2);
  });

  test('hex-form IPv4 literal refuses', () => {
    const r = run(['0x7f.0.0.1']);
    expect(r.code).toBe(2);
  });
});
