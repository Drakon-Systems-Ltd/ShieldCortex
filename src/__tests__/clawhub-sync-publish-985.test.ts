import { describe, expect, it, beforeEach, afterEach } from '@jest/globals';
import { spawnSync } from 'node:child_process';
import { mkdtempSync, mkdirSync, writeFileSync, readFileSync, rmSync, chmodSync, existsSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

/**
 * Issue #985 — v5.17.2, publish.yml run 41373441568.
 *
 * `clawhub publish` returned HTTP 400 "Version 5.17.2 already exists" on the
 * fourth attempt, because the first attempt's upload had landed server-side
 * but was held for scan/review: not `latest`, not in `/versions`. The script
 * reads the public index, sees `absent`, republishes, and `clawhubPublish()`
 * turns that "already exists" into exit 1 ("the publish did not land") — the
 * opposite of what the server just said.
 *
 * These tests run the REAL script against a fake `clawhub` binary. The script
 * resolves the binary from `npm prefix -g`, which honours `npm_config_prefix`,
 * so the fake lives in `<tmp>/bin/clawhub`. It runs on Linux and macOS, the
 * two CI runners; it is skipped on Windows where that layout does not exist.
 */

const root = resolve(dirname(fileURLToPath(import.meta.url)), '..', '..');
const script = join(root, 'scripts', 'clawhub-sync.mjs');
const version = JSON.parse(readFileSync(join(root, 'package.json'), 'utf8')).version as string;
const previous = '5.17.1';

// The fake CLI. `-V` prints a modern version; `inspect` serves `previous` and
// never lists `version` (a held upload is invisible to the public index);
// `publish` consumes one scripted response per call and appends its argv to a
// log so the test can count attempts.
const fakeClawhub = `#!/usr/bin/env node
const fs = require('node:fs');
const args = process.argv.slice(2);
const log = process.env.FAKE_CLAWHUB_LOG;
if (args[0] === '-V') { process.stdout.write('0.30.0\\n'); process.exit(0); }
if (args[0] === 'inspect') {
  process.stdout.write(JSON.stringify({
    latestVersion: { version: '${previous}' },
    versions: [{ version: '${previous}' }],
  }));
  process.exit(0);
}
if (args[0] === 'publish') {
  const calls = fs.existsSync(log) ? fs.readFileSync(log, 'utf8').split('\\n').filter(Boolean).length : 0;
  fs.appendFileSync(log, JSON.stringify({ at: Date.now(), args }) + '\\n');
  const responses = JSON.parse(process.env.FAKE_CLAWHUB_PUBLISH);
  const r = responses[Math.min(calls, responses.length - 1)];
  if (r.stdout) process.stdout.write(r.stdout);
  if (r.stderr) process.stderr.write(r.stderr);
  process.exit(r.status);
}
process.stderr.write('fake clawhub: unexpected args ' + JSON.stringify(args) + '\\n');
process.exit(99);
`;

type Response = { status: number; stdout?: string; stderr?: string };

let tmp: string;
let log: string;

beforeEach(() => {
  tmp = mkdtempSync('/tmp/sc-985-');
  mkdirSync(join(tmp, 'bin'));
  const bin = join(tmp, 'bin', 'clawhub');
  writeFileSync(bin, fakeClawhub);
  chmodSync(bin, 0o755);
  log = join(tmp, 'publish.log');
});

afterEach(() => {
  rmSync(tmp, { recursive: true, force: true });
});

function runSync(responses: Response[]) {
  const env: NodeJS.ProcessEnv = { ...process.env, npm_config_prefix: tmp, FAKE_CLAWHUB_LOG: log, FAKE_CLAWHUB_PUBLISH: JSON.stringify(responses) };
  delete env.CLAWHUB_TOKEN;
  const res = spawnSync(process.execPath, [script], { cwd: root, env, encoding: 'utf8', timeout: 60_000 });
  const calls = existsSync(log) ? readFileSync(log, 'utf8').split('\n').filter(Boolean).map((l) => JSON.parse(l) as { at: number; args: string[] }) : [];
  return { status: res.status, stdout: res.stdout, stderr: res.stderr, calls };
}

// Verbatim failure lines from the run log, Actions timestamp prefix removed.
const alreadyExists = `Publish (files 1/1): HTTP 400: Version ${version} already exists. Increment the version number and try again.\n`;
const throttled = (s: number) =>
  `Upload ticket (file 1/1): HTTP 400: Too many writes in a short period of time. Please wait a moment and try again. (reset in ${s}s)\n`;

const maybe = process.platform === 'win32' ? describe.skip : describe;

maybe('#985 — "Version X already exists" on publish is a held upload, not a failed one', () => {
  it('maps a non-zero publish whose output says the target already exists to pending (exit 2), not exit 1', () => {
    const r = runSync([{ status: 1, stderr: alreadyExists }]);
    expect(r.status).toBe(2);
    expect(r.calls).toHaveLength(1);
    expect(r.stderr + r.stdout).not.toMatch(/did not land/i);
    expect(r.stderr + r.stdout).not.toMatch(/clawhub publish failed/i);
  });

  it('only counts "already exists" for the target version', () => {
    const r = runSync([{ status: 1, stderr: alreadyExists.replace(version, previous) }]);
    expect(r.status).toBe(1);
    expect(r.stderr).toMatch(/clawhub publish failed/i);
  });

  it('negative control: any other HTTP 400 still exits 1', () => {
    const r = runSync([
      { status: 1, stderr: `Upload ticket (file 1/1): HTTP 400: Bad request: upload ticket could not be issued.\n` },
    ]);
    expect(r.status).toBe(1);
    expect(r.calls).toHaveLength(1);
    expect(r.stderr).toMatch(/clawhub publish failed/i);
  });

  it('negative control: a non-zero exit with no recognised output still exits 1', () => {
    const r = runSync([{ status: 1, stderr: 'Network request failed: the request timed out.\n' }]);
    expect(r.status).toBe(1);
    expect(r.calls).toHaveLength(1);
  });
});

maybe('#985 — one bounded retry on a ClawHub write throttle', () => {
  it('retries once after "Too many writes ... reset in Ns" and takes the second result', () => {
    const r = runSync([{ status: 1, stderr: throttled(1) }, { status: 1, stderr: alreadyExists }]);
    expect(r.calls).toHaveLength(2);
    expect(r.calls[1].at - r.calls[0].at).toBeGreaterThanOrEqual(1000);
    expect(r.status).toBe(2);
  });

  it('does not retry a second time: two throttles in a row still exit 1', () => {
    const r = runSync([{ status: 1, stderr: throttled(1) }, { status: 1, stderr: throttled(1) }, { status: 0, stdout: 'ok\n' }]);
    expect(r.calls).toHaveLength(2);
    expect(r.status).toBe(1);
  });
});
