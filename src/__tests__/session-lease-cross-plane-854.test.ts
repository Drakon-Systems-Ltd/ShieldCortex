import { spawn } from 'node:child_process';
import { createHmac } from 'node:crypto';
import { mkdtempSync, mkdirSync, writeFileSync, rmSync, readFileSync, readdirSync, realpathSync, existsSync, statSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { afterEach, beforeEach, describe, expect, it } from '@jest/globals';
import { createInterceptor, DEFAULT_CONFIG } from '../../plugins/openclaw/interceptor.js';
import { actionLeaseAdapters } from '../../plugins/openclaw/index.js';
import * as defence from '../defence/index.js';
import { leaseIdentityFor } from '../defence/iron-dome/session-lease-identity.js';
import { releaseToolCallLease } from '../defence/iron-dome/session-lease-store.js';

/**
 * #854 — one session, two enforcement planes, ONE lease identity.
 *
 * The Claude Code PreToolUse hook leased as `sc-` + HMAC(session_id); the
 * OpenClaw interceptor leased as the raw sessionId. A raw id never equals an
 * `sc-…` holder, so the second plane of the SAME session was refused with
 * "<scope> is held by another session (sc-…, pid N)".
 *
 * The hook plane here is the REAL hook, spawned as a process against a
 * sandbox home (the holder it writes is the formula the hook actually runs).
 * The OpenClaw plane is the REAL adapter wiring from plugins/openclaw/index.ts
 * over the real defence module, driven through the real interceptor.
 */

const HOOK_PATH = resolve(dirname(fileURLToPath(import.meta.url)), '..', '..', 'scripts', 'pre-tool-hook.mjs');
const DIST_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..', '..', 'dist');
const SALT = 'ab'.repeat(32);
const COMMAND = 'npm publish';

type HookRun = { stdout: string; stderr: string; code: number };

let home: string;
let stateDir: string;
const savedEnv: Record<string, string | undefined> = {};
const ENV_KEYS = ['SHIELDCORTEX_CONFIG_DIR', 'SHIELDCORTEX_SESSION_SALT'] as const;

beforeEach(() => {
  home = realpathSync(mkdtempSync(join(tmpdir(), 'sc-lease-854-')));
  stateDir = join(home, '.shieldcortex');
  mkdirSync(stateDir, { recursive: true });
  writeFileSync(join(stateDir, 'config.json'), JSON.stringify({ actionGuard: { enabled: true, enforce: true } }));
  // The in-process (OpenClaw) plane resolves its state dir and salt the way
  // production does: from SHIELDCORTEX_CONFIG_DIR and SHIELDCORTEX_SESSION_SALT.
  // Both are pinned to the sandbox. (Setting HOME here would NOT isolate it:
  // os.homedir() reads the worker's real environment, not jest's copy — so
  // in-process code is never left to fall back to a home directory.)
  for (const k of ENV_KEYS) savedEnv[k] = process.env[k];
  process.env.SHIELDCORTEX_CONFIG_DIR = stateDir;
  process.env.SHIELDCORTEX_SESSION_SALT = SALT;
});

afterEach(() => {
  for (const k of ENV_KEYS) {
    if (savedEnv[k] === undefined) delete process.env[k];
    else process.env[k] = savedEnv[k];
  }
  rmSync(home, { recursive: true, force: true });
});

/** The Claude Code plane: the hook sees the bridged tool as `mcp__openclaw__exec`. */
function runHook(sessionId: string, opts: { envSalt?: boolean } = {}): Promise<HookRun> {
  const env: NodeJS.ProcessEnv = {
    ...process.env,
    HOME: home,
    USERPROFILE: home,
    SHIELDCORTEX_CONFIG_DIR: stateDir,
    SHIELDCORTEX_DIST_ROOT: DIST_ROOT,
  };
  if (opts.envSalt === false) delete env.SHIELDCORTEX_SESSION_SALT;
  else env.SHIELDCORTEX_SESSION_SALT = SALT;
  return new Promise((res, reject) => {
    const child = spawn(process.execPath, [HOOK_PATH], { stdio: ['pipe', 'pipe', 'pipe'], env });
    let stdout = '';
    let stderr = '';
    child.stdout.on('data', (c) => { stdout += c.toString(); });
    child.stderr.on('data', (c) => { stderr += c.toString(); });
    child.on('error', reject);
    child.on('close', (code) => res({ stdout, stderr, code: code ?? 0 }));
    child.stdin.end(JSON.stringify({
      session_id: sessionId, cwd: '/tmp', permission_mode: 'default',
      tool_name: 'mcp__openclaw__exec', tool_input: { command: COMMAND },
    }));
  });
}

function hookLeaseRefused(run: HookRun): boolean {
  return run.stderr.includes('SESSION-LEASE refused');
}

function hookDecision(run: HookRun): { permissionDecision?: string; permissionDecisionReason?: string } {
  for (const line of run.stdout.split('\n')) {
    const trimmed = line.trim();
    if (!trimmed.startsWith('{')) continue;
    try {
      const parsed = JSON.parse(trimmed);
      if (parsed?.hookSpecificOutput?.hookEventName === 'PreToolUse') return parsed.hookSpecificOutput;
    } catch { /* not the decision line */ }
  }
  return {};
}

const allowAll = () => ({
  decision: 'allow', severity: 'benign', family: 'exec', action: 'exec', reason: 'allowed', signals: [] as string[],
});
const okPipeline = () => ({
  allowed: true,
  firewall: { result: 'ALLOW' as const, reason: '', threatIndicators: [] as string[], anomalyScore: 0, blockedPatterns: [] as string[] },
  trust: { score: 0.5 }, sensitivity: { level: 'INTERNAL' }, fragmentation: null, auditId: 1,
});

/** The OpenClaw plane: production adapters over the real defence module. */
function openclawPlane() {
  const adapters = actionLeaseAdapters(defence as never);
  const interceptor = createInterceptor(
    { ...DEFAULT_CONFIG, actionGuard: { enabled: true, enforce: true, autoApprove: [] } } as never,
    okPipeline as never,
    { evaluateToolCall: allowAll as never, ...adapters },
  );
  return {
    adapters,
    call: (sessionId: string | undefined) =>
      interceptor.handleToolCall({ toolName: 'exec', arguments: { command: COMMAND }, sessionId }),
  };
}

function leaseRecord(): { holder: string; pid: number } | undefined {
  const file = join(stateDir, 'leases', 'leases.json');
  if (!existsSync(file)) return undefined;
  return JSON.parse(readFileSync(file, 'utf-8')).leases['npm-publish'];
}

/** The formula, written out independently of both implementations. */
function expectedKey(salt: string, id: string): string {
  return `sc-${createHmac('sha256', salt).update(`action-guard-session:${id}`).digest('hex').slice(0, 16)}`;
}

describe('#854 — the issue: one session is never refused by its own lease', () => {
  it('hook plane holds npm-publish → the OpenClaw plane of the SAME session is allowed', async () => {
    const hook = await runHook('session-854');
    expect(hookLeaseRefused(hook)).toBe(false);
    const held = leaseRecord();
    expect(held?.holder).toBe(expectedKey(SALT, 'session-854'));
    expect(held?.pid).toBe(process.pid); // the harness (here: jest) pid, as for the session's `claude`

    await expect(openclawPlane().call('session-854')).resolves.toBeUndefined();
    expect(leaseRecord()?.holder).toBe(expectedKey(SALT, 'session-854'));
  });

  it('reverse order: OpenClaw plane holds → the hook plane of the SAME session is allowed', async () => {
    await expect(openclawPlane().call('session-854')).resolves.toBeUndefined();
    expect(leaseRecord()?.holder).toBe(expectedKey(SALT, 'session-854'));

    const hook = await runHook('session-854');
    expect(hookLeaseRefused(hook)).toBe(false);
    expect(hookDecision(hook).permissionDecisionReason ?? '').not.toContain('held by another session');
  });
});

describe('#854 — a genuinely different session is still refused', () => {
  it('hook holds for session-a → OpenClaw session-b is held', async () => {
    await runHook('session-a');
    await expect(openclawPlane().call('session-b')).rejects.toThrow(/held by another session \(sc-[a-f0-9]{16}/);
  });

  it('OpenClaw holds for session-b → hook session-a is denied', async () => {
    await expect(openclawPlane().call('session-b')).resolves.toBeUndefined();
    const hook = await runHook('session-a');
    expect(hookLeaseRefused(hook)).toBe(true);
    expect(hookDecision(hook).permissionDecision).toBe('deny');
  });
});

describe('#854 — a blank identity never re-enters a blank-derived holder', () => {
  it('blank and whitespace ids derive no shared session key', () => {
    expect(leaseIdentityFor('', { salt: SALT })).toBe('');
    expect(leaseIdentityFor('   ', { salt: SALT })).toBe('');
    expect(leaseIdentityFor(undefined, { salt: SALT })).toBe('');
    expect(leaseIdentityFor(null, { salt: SALT })).toBe('');
  });

  it.each(['', '   '])('hook holds with session_id %j → OpenClaw blank/whitespace is held', async (blank) => {
    await runHook(blank);
    expect(leaseRecord()?.holder).toMatch(/^ppid:\d+$/);
    await expect(openclawPlane().call(blank)).rejects.toThrow(/held by another session/);
    await expect(openclawPlane().call(undefined)).rejects.toThrow(/held by another session/);
  });

  it.each(['', '   '])('OpenClaw holds with sessionId %j → hook blank/whitespace is denied', async (blank) => {
    await expect(openclawPlane().call(blank)).resolves.toBeUndefined();
    expect(leaseRecord()?.holder).toMatch(/^anon-pid-\d+$/);
    const hook = await runHook(blank);
    expect(hookLeaseRefused(hook)).toBe(true);
  });
});

describe('#854 — a freeze still outranks the shared identity', () => {
  it('a frozen scope refuses both planes of one session', async () => {
    writeFileSync(join(stateDir, 'DECISIONS.md'), '| FROZEN | nobody publishes to npm until the review completes |\n');
    const hook = await runHook('session-854');
    expect(hookDecision(hook).permissionDecision).toBe('deny');
    expect(hookDecision(hook).permissionDecisionReason ?? '').toContain('FROZEN');
    await expect(openclawPlane().call('session-854')).rejects.toThrow(/FROZEN/);
    expect(leaseRecord()).toBeUndefined();
  });
});

describe('#854 — release from the other plane of the same session frees the slot', () => {
  it('hook acquires; the OpenClaw release for the same session frees it', async () => {
    await runHook('session-854');
    expect(leaseRecord()).toBeDefined();
    openclawPlane().adapters.releaseActionLease!('exec', { command: COMMAND }, 'session-854');
    expect(leaseRecord()).toBeUndefined();
    await expect(openclawPlane().call('session-other')).resolves.toBeUndefined();
  });

  it('a different session\'s OpenClaw release does NOT free the hook\'s hold', async () => {
    await runHook('session-854');
    openclawPlane().adapters.releaseActionLease!('exec', { command: COMMAND }, 'session-other');
    expect(leaseRecord()?.holder).toBe(expectedKey(SALT, 'session-854'));
  });

  it('OpenClaw acquires; a release as the hook identity for the same session frees it', async () => {
    await expect(openclawPlane().call('session-854')).resolves.toBeUndefined();
    // The hook releases as its leaseSelf, which the parity tests pin to this.
    releaseToolCallLease('mcp__openclaw__exec', { command: COMMAND }, { self: expectedKey(SALT, 'session-854') });
    expect(leaseRecord()).toBeUndefined();
  });
});

describe('#854 — the hook .mjs formula and the TS helper agree byte for byte', () => {
  it('env salt: same key', async () => {
    await runHook('parity-env');
    expect(leaseRecord()?.holder).toBe(leaseIdentityFor('parity-env', { salt: SALT }));
  });

  it('salt FILE minted by the hook: the TS helper reads the same salt', async () => {
    // Env salt wins over any file; unset it so both sides read the sandbox file.
    // In-process calls below always pin `home`, so nothing falls back to a real one.
    delete process.env.SHIELDCORTEX_SESSION_SALT;
    await runHook('parity-file', { envSalt: false });
    const salt = readFileSync(join(stateDir, 'action-guard-session-salt'), 'utf-8').trim();
    expect(leaseRecord()?.holder).toBe(expectedKey(salt, 'parity-file'));
    expect(leaseIdentityFor('parity-file', { home })).toBe(leaseRecord()?.holder);
  });

  it('corrupt primary salt: both planes fall through to the same .recovered salt', async () => {
    delete process.env.SHIELDCORTEX_SESSION_SALT;
    const recovered = 'cd'.repeat(32);
    writeFileSync(join(stateDir, 'action-guard-session-salt'), 'not-a-salt\n');
    writeFileSync(join(stateDir, 'action-guard-session-salt.recovered'), `${recovered}\n`);
    await runHook('parity-recovered', { envSalt: false });
    expect(leaseRecord()?.holder).toBe(expectedKey(recovered, 'parity-recovered'));
    expect(leaseIdentityFor('parity-recovered', { home })).toBe(leaseRecord()?.holder);
  });
});

/**
 * #854 round 2 — a nonblank session whose identity cannot be derived (no usable
 * salt) is refused for scoped calls. It never becomes '', a raw id or the
 * process's `anon-pid-<pid>` holder, which would merge every named session of
 * one OpenClaw process into one holder.
 *
 * Every in-process salt lookup here is pinned to the sandbox home through a
 * test-owned wrapper around the real `leaseIdentityFor`; lease state lives in
 * a SEPARATE writable dir, so the salt dir listing is exactly the salt files.
 */
describe('#854 r2 — a failed identity derivation refuses; it never merges sessions', () => {
  let leaseDir: string;
  const SALT_FILE = 'action-guard-session-salt';

  beforeEach(() => {
    delete process.env.SHIELDCORTEX_SESSION_SALT;
    leaseDir = join(home, 'lease-state');
    mkdirSync(leaseDir, { recursive: true });
    process.env.SHIELDCORTEX_CONFIG_DIR = leaseDir;
  });

  /** The real adapters over the real defence module, salt lookup pinned to `saltHome`. */
  function pinnedPlane(saltHome: string, evaluateToolCall: (...a: unknown[]) => unknown = allowAll) {
    const mod = {
      ...defence,
      leaseIdentityFor: (id: string | null | undefined) => leaseIdentityFor(id, { home: saltHome }),
    };
    const adapters = actionLeaseAdapters(mod as never);
    const interceptor = createInterceptor(
      { ...DEFAULT_CONFIG, actionGuard: { enabled: true, enforce: true, autoApprove: [] } } as never,
      okPipeline as never,
      { evaluateToolCall: evaluateToolCall as never, ...adapters },
    );
    return {
      adapters,
      call: (sessionId: string | undefined, command = COMMAND) =>
        interceptor.handleToolCall({ toolName: 'exec', arguments: { command }, sessionId }),
    };
  }

  function heldRecord(): { holder: string; pid: number } | undefined {
    const file = join(leaseDir, 'leases', 'leases.json');
    if (!existsSync(file)) return undefined;
    return JSON.parse(readFileSync(file, 'utf-8')).leases['npm-publish'];
  }

  function saltDirSnapshot(dir: string): Array<[string, string]> {
    return readdirSync(dir).sort().map((name) => [name, readFileSync(join(dir, name)).toString('hex')]);
  }

  function corruptPrimary(): void {
    writeFileSync(join(stateDir, SALT_FILE), 'not-a-salt\n');
  }

  it('two different named sessions in one process are each refused; neither takes or re-enters a hold', async () => {
    corruptPrimary();
    const plane = pinnedPlane(home);
    for (const id of ['session-a', 'session-b', 'session-a']) {
      await expect(plane.call(id)).rejects.toThrow(/identity could not be derived/);
      expect(heldRecord()).toBeUndefined();
    }
    // Unscoped calls are not lease calls, so a missing salt does not refuse them.
    await expect(plane.call('session-a', 'ls -la')).resolves.toBeUndefined();
  });

  it('a named session with no derivable identity never re-enters, or releases, this process\'s anonymous hold', async () => {
    corruptPrimary();
    const plane = pinnedPlane(home);
    await expect(plane.call(undefined)).resolves.toBeUndefined();
    expect(heldRecord()?.holder).toBe(`anon-pid-${process.pid}`);

    await expect(plane.call('session-a')).rejects.toThrow(/identity could not be derived/);
    await expect(plane.call('session-b')).rejects.toThrow(/identity could not be derived/);
    plane.adapters.releaseActionLease!('exec', { command: COMMAND }, 'session-b');
    expect(heldRecord()?.holder).toBe(`anon-pid-${process.pid}`);
  });

  it('the refusal is an explicit non-allow decision, not a throw, and names no salt, path or key', () => {
    corruptPrimary();
    const gate = pinnedPlane(home).adapters.checkActionLease!('exec', { command: COMMAND }, 'session-a');
    expect(gate?.scope).toBe('npm-publish');
    expect(gate?.decision.verdict).toBe('unknown');
    expect(gate?.acquired).toBeUndefined();
    expect(gate?.decision.reason).not.toMatch(/salt|sc-[a-f0-9]|\/|anon-pid/);
  });

  it('a failed derivation writes nothing into the salt directory (no .recovered* slot is created)', async () => {
    corruptPrimary();
    const before = saltDirSnapshot(stateDir);
    expect(leaseIdentityFor('session-a', { home })).toBeNull();
    expect(defence.sessionKeySalt(home)).toBeNull();
    await expect(pinnedPlane(home).call('session-a')).rejects.toThrow(/identity could not be derived/);
    expect(saltDirSnapshot(stateDir)).toEqual(before);
  });

  it('absent primary (fresh home): mints the primary exactly once, as before #854, and reuses it', () => {
    const fresh = realpathSync(mkdtempSync(join(tmpdir(), 'sc-lease-854-fresh-')));
    try {
      const first = leaseIdentityFor('session-fresh', { home: fresh });
      const saltDir = join(fresh, '.shieldcortex');
      expect(readdirSync(saltDir)).toEqual([SALT_FILE]);
      const salt = readFileSync(join(saltDir, SALT_FILE), 'utf-8').trim();
      expect(salt).toMatch(/^[a-f0-9]{64}$/);
      expect(statSync(join(saltDir, SALT_FILE)).mode & 0o777).toBe(0o600);
      expect(first).toBe(expectedKey(salt, 'session-fresh'));
      expect(leaseIdentityFor('session-fresh', { home: fresh })).toBe(first);
      expect(readdirSync(saltDir)).toEqual([SALT_FILE]);
    } finally {
      rmSync(fresh, { recursive: true, force: true });
    }
  });

  it('absent primary with a valid .recovered: reads it, like the hook, and mints nothing', () => {
    const recovered = 'cd'.repeat(32);
    writeFileSync(join(stateDir, `${SALT_FILE}.recovered`), `${recovered}\n`);
    const before = saltDirSnapshot(stateDir);
    expect(leaseIdentityFor('session-r', { home })).toBe(expectedKey(recovered, 'session-r'));
    expect(saltDirSnapshot(stateDir)).toEqual(before);
  });

  it('salt lost between acquire and release (guard blocks): release frees exactly the hold acquire took', async () => {
    writeFileSync(join(stateDir, SALT_FILE), `${'ef'.repeat(32)}\n`);
    const blockAfterSaltLoss = () => {
      // Runs between the lease check (acquired) and the interceptor's release.
      expect(heldRecord()?.holder).toBe(expectedKey('ef'.repeat(32), 'session-a'));
      corruptPrimary();
      return { decision: 'block', severity: 'critical', family: 'exec', action: 'exec', reason: 'blocked', signals: [] as string[] };
    };
    await expect(pinnedPlane(home, blockAfterSaltLoss).call('session-a')).rejects.toThrow(/blocked/);
    expect(heldRecord()).toBeUndefined();
  });

  it('release with the acquiring gate reuses its identity; without it, a failed derivation releases nothing', () => {
    writeFileSync(join(stateDir, SALT_FILE), `${'ef'.repeat(32)}\n`);
    const { adapters } = pinnedPlane(home);
    const gate = adapters.checkActionLease!('exec', { command: COMMAND }, 'session-a');
    expect(gate?.acquired).toBe(true);
    corruptPrimary();

    adapters.releaseActionLease!('exec', { command: COMMAND }, 'session-a');
    expect(heldRecord()?.holder).toBe(expectedKey('ef'.repeat(32), 'session-a'));

    adapters.releaseActionLease!('exec', { command: COMMAND }, 'session-b', gate!);
    // The gate, not the passed id, decides who releases: the hold acquire took.
    expect(heldRecord()).toBeUndefined();
  });
});
