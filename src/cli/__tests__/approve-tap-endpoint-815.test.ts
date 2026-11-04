/**
 * #815 B — the endpoint process: `shieldcortex guard approve-tap`.
 *
 * Tests run as one non-root user, so the root start and the "agent" /
 * "bridge" users are injected (geteuid, the home lstat, the secret's open).
 * The keyless child is the REAL built `dist/.../approve-tap-child.js`,
 * spawned by the real `spawnTapChild` — only with this test user's own
 * uid/gid, since a non-root test cannot become another user.
 */
import { afterEach, beforeAll, beforeEach, describe, expect, it } from '@jest/globals';
import { spawnSync } from 'node:child_process';
import { existsSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import type { Server } from 'node:http';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

import { inspectorRequested, runApproveTapCommand, spawnTapChild, tokeniseNodeOptions, type TapChildRun } from '../approve-tap.js';
import { computeTapHmac, mintApproveTapNonce, normaliseApproveTapConfig } from '../../defence/iron-dome/approve-tap.js';
import { runTapChild } from '../../defence/iron-dome/approve-tap-child.js';
import { canonicaliseCwd, exactCallDigest, getRetryRow, hashToolCall, recordDenialFingerprint } from '../../defence/iron-dome/retry-control.js';

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..', '..', '..');
const DIST_CHILD = join(repoRoot, 'dist', 'defence', 'iron-dome', 'approve-tap-child.js');
const DIST_CLI = join(repoRoot, 'dist', 'cli', 'approve-tap.js');
const MY_UID = process.geteuid!();
const MY_GID = process.getegid!();
const AGENT = 41001;
const BRIDGE = 41002;
const ACTION = 'act-aaaabbbbccccdddd';
const SECRET = 'd4'.repeat(32);
const HASH = hashToolCall('Bash', { command: 'curl -sS https://api.example.com/v1/report' });
const EXACT = exactCallDigest('Bash', { command: 'curl -sS https://api.example.com/v1/report' });

let home: string;
let cwd: string;
let secretDir: string;
let secretPath: string;

const asAgentHome = () => ({ uid: AGENT, gid: 5000, isDirectory: true, isSymbolicLink: false });
const bridgeStat = () => ({ uid: BRIDGE, mode: 0o100600, isFile: true, isSymbolicLink: false });
const bridgeOpen = () => ({ uid: BRIDGE, mode: 0o100600, isFile: true, bytes: Buffer.from(`${SECRET}\n`) });

function writeTapConfig(extra: Record<string, unknown> = {}): void {
  mkdirSync(join(home, '.shieldcortex'), { recursive: true });
  writeFileSync(join(home, '.shieldcortex', 'config.json'), JSON.stringify({
    actionGuard: { approveTap: { enabled: true, secretPath, approverTelegramUid: '777', ...extra } },
  }));
}

const ARGS = () => ['--home', home, '--agent-uid', String(AGENT), '--bridge-uid', String(BRIDGE)];

beforeAll(() => {
  if (!existsSync(DIST_CHILD)) spawnSync('npm', ['run', 'build:ts'], { cwd: repoRoot, stdio: 'ignore' });
}, 300_000);

beforeEach(() => {
  home = mkdtempSync(join(tmpdir(), 'sc-tap-ep-home-'));
  cwd = canonicaliseCwd(mkdtempSync(join(tmpdir(), 'sc-tap-ep-cwd-')))!;
  secretDir = mkdtempSync(join(tmpdir(), 'sc-tap-ep-key-'));
  secretPath = join(secretDir, 'approve.key');
  writeFileSync(secretPath, `${SECRET}\n`, { mode: 0o600 });
  writeTapConfig();
});

afterEach(() => {
  for (const d of [home, cwd, secretDir]) rmSync(d, { recursive: true, force: true });
});

describe('#815 B — endpoint start-up refusals', () => {
  const quiet = { log: () => {}, error: () => {} };

  it('requires --home, --agent-uid and --bridge-uid on the command line, as two different non-root users', async () => {
    const errors: string[] = [];
    const e = { ...quiet, error: (m: string) => errors.push(m) };
    expect(await runApproveTapCommand(['--agent-uid', '1', '--bridge-uid', '2'], e)).toBe(1);
    expect(await runApproveTapCommand(['--home', home, '--bridge-uid', '2'], e)).toBe(1);
    expect(await runApproveTapCommand(['--home', home, '--agent-uid', '5', '--bridge-uid', '5'], e)).toBe(1);
    expect(await runApproveTapCommand(['--home', home, '--agent-uid', '0', '--bridge-uid', '5'], e)).toBe(1);
    expect(errors.join('\n')).toMatch(/never from config/);
    expect(errors.join('\n')).toMatch(/#501 OS lock/);
  });

  it('refuses a home that is a symlink or is not owned by --agent-uid', async () => {
    expect(await runApproveTapCommand(ARGS(), { ...quiet, lstatHome: () => ({ ...asAgentHome(), isSymbolicLink: true }) })).toBe(1);
    expect(await runApproveTapCommand(ARGS(), { ...quiet, lstatHome: () => ({ ...asAgentHome(), uid: 999 }) })).toBe(1);
  });

  it('refuses to serve unless root, and under any inspector flag', async () => {
    const base = { ...quiet, lstatHome: asAgentHome, armingLstat: bridgeStat, openSecret: bridgeOpen, listen: async () => {} };
    expect(await runApproveTapCommand(ARGS(), { ...base, geteuid: () => AGENT })).toBe(1);
    expect(await runApproveTapCommand(ARGS(), { ...base, geteuid: () => BRIDGE })).toBe(1);
    expect(await runApproveTapCommand(ARGS(), { ...base, geteuid: () => 0, execArgv: ['--inspect=0'] })).toBe(1);
    expect(await runApproveTapCommand(ARGS(), { ...base, geteuid: () => 0, execArgv: [], nodeOptions: '--max-old-space-size=99 --inspect-brk' })).toBe(1);
    expect(inspectorRequested(['--disable-sigusr1'], '')).toBe(false);
    expect(inspectorRequested(['--inspect-port=9229'], undefined)).toBe(true);
  });

  it('reads inspector options the way Node does: quoted NODE_OPTIONS, `_` spellings, every inspect/debug name', () => {
    expect(tokeniseNodeOptions('--a "--inspect=127.0.0.1:0" "--title=a b" x\\y')).toEqual(['--a', '--inspect=127.0.0.1:0', '--title=a b', 'x\\y']);
    expect(tokeniseNodeOptions('"--ti\\"tle"')).toEqual(['--ti"tle']);
    expect(tokeniseNodeOptions('"--inspect')).toBeNull();
    for (const nodeOptions of [
      '"--inspect=127.0.0.1:0"', '--max-old-space-size=99 "--inspect-brk"', '--inspect_brk=0', '--inspect_port=0',
      '--debug_port=9229', '--debug-port=9229', '--inspect-wait', '"--insp"ect', '"--unterminated',
    ]) {
      expect({ nodeOptions, refused: inspectorRequested([], nodeOptions) }).toEqual({ nodeOptions, refused: true });
    }
    for (const execArgv of [['--inspect_brk=0'], ['--inspect_port=0'], ['--inspect-publish-uid=http'], ['--debug-port=1']]) {
      expect(inspectorRequested(execArgv, '')).toBe(true);
    }
    expect(inspectorRequested(['--disable-sigusr1'], '--max-old-space-size=99 "--title=inspect me"')).toBe(false);
  });

  it('an inspector already open in the process is refused before the secret is opened', async () => {
    let opened = 0;
    const errors: string[] = [];
    const out = await runApproveTapCommand(ARGS(), {
      log: () => {}, error: (m) => errors.push(m), geteuid: () => 0, execArgv: [], nodeOptions: '',
      inspectorActive: () => true,
      lstatHome: asAgentHome, armingLstat: bridgeStat,
      openSecret: () => { opened += 1; return bridgeOpen(); },
      listen: async () => {},
    });
    expect(out).toBe(1);
    expect(opened).toBe(0);
    expect(errors.join('\n')).toMatch(/inspector is open/);
  });

  // Real Node processes, so Node's own option parser and inspector decide
  // what is active; the root start and the users are injected as above.
  const INSPECTOR_CHILD = `
const [cliUrl, home, openAtRuntime] = process.argv.slice(1);
const inspector = await import('node:inspector');
if (openAtRuntime === '1') inspector.open(0, '127.0.0.1');
const active = inspector.url() !== undefined;
const mod = await import(cliUrl);
let opened = 0;
const errors = [];
const code = await mod.runApproveTapCommand(['--home', home, '--agent-uid', '41001', '--bridge-uid', '41002'], {
  geteuid: () => 0,
  ...(openAtRuntime === '1' ? { execArgv: [], nodeOptions: '' } : {}),
  lstatHome: () => ({ uid: 41001, gid: 5000, isDirectory: true, isSymbolicLink: false }),
  armingLstat: () => ({ uid: 41002, mode: 0o100600, isFile: true, isSymbolicLink: false }),
  openSecret: () => { opened += 1; return { uid: 41002, mode: 0o100600, isFile: true, bytes: Buffer.from('${SECRET}') }; },
  listen: async () => {}, log: () => {}, error: (m) => errors.push(m),
});
inspector.close();
process.stdout.write(JSON.stringify({ active, code, opened, errors }));
`;
  function runInspectorChild(env: Record<string, string>, nodeArgs: string[] = [], openAtRuntime = false) {
    const res = spawnSync(process.execPath, [...nodeArgs, '--input-type=module', '-e', INSPECTOR_CHILD,
      pathToFileURL(DIST_CLI).href, home, openAtRuntime ? '1' : '0'], {
      env: { PATH: process.env.PATH ?? '/usr/bin:/bin', ...env }, encoding: 'utf8', timeout: 30_000,
    });
    return JSON.parse(res.stdout) as { active: boolean; code: number; opened: number; errors: string[] };
  }

  it('real processes: a quoted NODE_OPTIONS inspector, `_` aliases and a runtime-opened inspector never reach the key', () => {
    expect(existsSync(DIST_CLI)).toBe(true);
    const quoted = runInspectorChild({ NODE_OPTIONS: '"--inspect=127.0.0.1:0"' });
    expect(quoted).toMatchObject({ active: true, code: 1, opened: 0 });
    for (const r of [
      runInspectorChild({ NODE_OPTIONS: '--inspect_port=0' }),
      runInspectorChild({}, ['--inspect_port=0']),
    ]) {
      // Node accepts the `_` spelling; no inspector is open, so only the
      // option parser can see it.
      expect(r).toMatchObject({ active: false, code: 1, opened: 0 });
      expect(r.errors.join('\n')).toMatch(/inspector flag/);
    }
    // Opened after start, with no flag anywhere: only the live check sees it.
    const runtime = runInspectorChild({}, [], true);
    expect(runtime).toMatchObject({ active: true, code: 1, opened: 0 });
    expect(runtime.errors.join('\n')).toMatch(/inspector is open/);
    // Control: the same start with no inspector does load the key.
    expect(runInspectorChild({})).toMatchObject({ active: false, code: 0, opened: 1 });
  }, 60_000);

  it('refuses a secret not owned by --bridge-uid, even if config points at it', async () => {
    const errors: string[] = [];
    const out = await runApproveTapCommand(ARGS(), {
      log: () => {}, error: (m) => errors.push(m), geteuid: () => 0, execArgv: [], nodeOptions: '',
      lstatHome: asAgentHome, armingLstat: bridgeStat,
      // Another user's 0600 file — e.g. a second agent's — is not the bridge's key.
      openSecret: () => ({ ...bridgeOpen(), uid: 41003 }),
      listen: async () => {},
    });
    expect(out).toBe(1);
    expect(errors.join('\n')).toMatch(/not the notify bridge's user/);
    expect(errors.join('\n')).not.toContain(SECRET);
  });

  it('--check reports arming without starting anything', async () => {
    const logs: string[] = [];
    expect(await runApproveTapCommand([...ARGS(), '--check'], { log: (m) => logs.push(m), error: () => {}, lstatHome: asAgentHome, armingLstat: bridgeStat })).toBe(0);
    expect(logs.join('\n')).toMatch(/armed/);
    expect(await runApproveTapCommand([...ARGS(), '--check'], { log: () => {}, error: () => {}, lstatHome: asAgentHome, armingLstat: () => ({ ...bridgeStat(), uid: AGENT }) })).toBe(1);
  });
});

describe('#815 B — a served tap goes through the keyless child', () => {
  it('root checks the HMAC; the child, as the agent, writes the grant; the key never reaches the child', async () => {
    expect(existsSync(DIST_CHILD)).toBe(true);
    expect(recordDenialFingerprint({ hash: HASH, tool: 'Bash', actionId: ACTION, signals: ['external-egress'], cwd, exactDigest: EXACT }, { home }).ok).toBe(true);
    const config = normaliseApproveTapConfig({ enabled: true, secretPath, approverTelegramUid: '777' });
    const m = mintApproveTapNonce({ actionId: ACTION }, { home, config, agentUid: AGENT, lstat: bridgeStat });
    if (!m.ok) throw new Error(m.reason);

    const runs: TapChildRun[] = [];
    let server: Server | undefined;
    const code = await runApproveTapCommand([...ARGS()], {
      log: () => {}, error: () => {}, geteuid: () => 0, execArgv: [], nodeOptions: '',
      lstatHome: asAgentHome, armingLstat: bridgeStat, openSecret: bridgeOpen,
      // The real spawner and the real built child, as THIS user (a test
      // cannot become uid 41001); the ids it is told to expect match.
      runChild: (run) => {
        runs.push(run);
        return spawnTapChild({
          uid: MY_UID, gid: MY_GID, childPath: DIST_CHILD,
          input: { ...run.input, expectUid: MY_UID, expectGid: MY_GID },
        });
      },
      onServer: (s) => { server = s; },
      listen: (s) => new Promise<void>((r) => s.listen(0, '127.0.0.1', () => r())),
    });
    expect(code).toBe(0);
    try {
      const port = (server!.address() as { port: number }).port;
      const post = async (body: unknown) => {
        const r = await fetch(`http://127.0.0.1:${port}/approve-tap`, {
          method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body),
        });
        return { status: r.status, body: (await r.json()) as { ok: boolean; reason?: string } };
      };
      const fields = { actionId: ACTION, argsHash: m.argsHash, nonce: m.nonce, exp: m.exp, approver: 'telegram:777' };
      // Bad MAC: refused in the root parent; no child is ever spawned.
      expect(await post({ ...fields, hmac: '0'.repeat(64) })).toMatchObject({ status: 403, body: { ok: false, reason: 'bad-hmac' } });
      expect(runs).toHaveLength(0);
      // Good tap: one child, which grants.
      const tap = { ...fields, hmac: computeTapHmac(SECRET, fields)! };
      expect(await post(tap)).toMatchObject({ status: 200, body: { ok: true } });
      expect(await post(tap)).toMatchObject({ status: 403, body: { ok: false, reason: 'nonce-used' } });
      expect(runs).toHaveLength(2);
      expect(runs[0]).toMatchObject({ uid: AGENT, gid: 5000, input: { home, expectUid: AGENT, expectGid: 5000 } });
      expect(JSON.stringify(runs)).not.toContain(SECRET);
      expect(getRetryRow({ actionId: ACTION }, { home })?.grant).toMatchObject({ via: 'tap', approver: 'telegram:777' });
    } finally {
      await new Promise<void>((r) => server!.close(() => r()));
    }
  });

  it('the child refuses to act unless it runs as exactly the uid/gid it was told, and never as root', () => {
    const input = (o: Record<string, unknown> = {}) => JSON.stringify({
      request: { actionId: ACTION, argsHash: HASH, nonce: 'a'.repeat(32), exp: Date.now() + 60_000, approver: 'telegram:777', hmac: 'b'.repeat(64) },
      home, expectUid: 1000, expectGid: 1000, ...o,
    });
    const ids = { uid: 1000, euid: 1000, gid: 1000, egid: 1000 };
    expect(runTapChild(input(), { ...ids, euid: 0 })).toMatchObject({ ok: false, reason: 'unwritable' });
    expect(runTapChild(input(), { ...ids, egid: 0 })).toMatchObject({ ok: false, reason: 'unwritable' });
    expect(runTapChild(input({ expectUid: 0 }), { ...ids, uid: 0, euid: 0 })).toMatchObject({ ok: false, reason: 'unwritable' });
    expect(runTapChild('not json', ids)).toMatchObject({ ok: false, reason: 'malformed' });
    // Right ids: reaches the store, which has never heard of this nonce.
    expect(runTapChild(input(), ids)).toMatchObject({ ok: false, reason: 'unknown-nonce' });
  });
});
