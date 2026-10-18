import { spawn, spawnSync } from 'node:child_process';
import { createHmac } from 'node:crypto';
import Database from 'better-sqlite3';
import { appendFileSync, chmodSync, existsSync, linkSync, lstatSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, renameSync, rmSync, symlinkSync, truncateSync, unlinkSync, utimesSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve, dirname } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { afterEach, beforeEach, describe, expect, it } from '@jest/globals';
import { recordActionGuardDegraded, v1Fingerprint } from '../defence/iron-dome/session-guard.js';

const __dirname = dirname(fileURLToPath(import.meta.url));

const REPO = resolve(__dirname, '..', '..');
const STOP_HOOK = join(REPO, 'scripts', 'stop-hook.mjs');
const PRE_TOOL_HOOK = join(REPO, 'scripts', 'pre-tool-hook.mjs');
const AUDIT_READ_FAULT_PRELOAD = join(__dirname, 'fixtures', 'audit-read-fault-preload-654.mjs');
const SESSION_SALT = '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';
const SECRET_SENTINEL = 'PUPIL_OR_SECRET_VALUE_SHOULD_NOT_LEAVE_AUDIT_PREVIEW';

/**
 * Replace `dir` with a symlink to `outside` while a hook is concurrently
 * writing into `dir`. Two races live here, and both are retried until one
 * deadline: the writer can leave the directory non-empty between `rmSync`'s
 * scan and its unlink (ENOTEMPTY / EBUSY), and — the one Node 22.14.0 hit in
 * CI (#586) — it can recreate the directory between `rmSync` returning and
 * `symlinkSync` running, so the symlink fails with EEXIST. Remove and link are
 * therefore ONE retried step, not two.
 */
async function swapDirForSymlink(dir: string, outside: string): Promise<void> {
  const deadline = Date.now() + 2000;
  // eslint-disable-next-line no-constant-condition
  while (true) {
    try {
      rmSync(dir, { recursive: true, force: true });
      symlinkSync(outside, dir);
      return;
    } catch (err: any) {
      if (err?.code !== 'ENOTEMPTY' && err?.code !== 'EBUSY' && err?.code !== 'EEXIST') throw err;
      if (Date.now() > deadline) throw err;
      await new Promise((r) => setTimeout(r, 25));
    }
  }
}

describe('stop hook — Action Guard run summary (#242)', () => {
  let home: string;

  beforeEach(() => {
    home = mkdtempCompat('sc-stop-242-');
    const db = new Database(dbFile());
    db.close();
    mkdirSync(join(home, '.shieldcortex'), { recursive: true });
    writeFileSync(join(home, '.shieldcortex', 'config.json'), JSON.stringify({ actionGuard: { enabled: true, enforce: true } }));
  });

  afterEach(() => {
    rmSync(home, { recursive: true, force: true });
  });

  function sessionKey(id: string, salt = SESSION_SALT): string {
    return `sc-${createHmac('sha256', salt).update(`action-guard-session:${id}`).digest('hex').slice(0, 16)}`;
  }

  function dbFile(): string {
    const dir = join(home, '.shieldcortex');
    mkdirSync(dir, { recursive: true });
    return join(dir, 'memories.db');
  }

  function hookRows(): Array<{ exit_code: number | null; notes: string | null }> {
    const db = new Database(dbFile());
    try {
      return db.prepare('SELECT exit_code, notes FROM hook_invocations ORDER BY id').all() as Array<{ exit_code: number | null; notes: string | null }>;
    } finally {
      db.close();
    }
  }

  function auditFile(): string {
    return auditFileForDate(new Date().toISOString().slice(0, 10));
  }

  function auditFileForDate(date: string): string {
    const dir = join(home, '.shieldcortex', 'audit');
    mkdirSync(dir, { recursive: true });
    return join(dir, `realtime-${date}.jsonl`);
  }

  function runStopHook(payload: Record<string, unknown>, opts: { timeout?: number; env?: Record<string, string>; execArgv?: string[] } = {}) {
    return spawnSync(process.execPath, [...(opts.execArgv ?? []), STOP_HOOK], {
      input: JSON.stringify(payload),
      encoding: 'utf8',
      timeout: opts.timeout,
      env: { ...process.env, ...(opts.env ?? {}), HOME: home, SHIELDCORTEX_CONFIG_DIR: join(home, '.shieldcortex'), SHIELDCORTEX_SESSION_SALT: SESSION_SALT },
    });
  }

  function runStopHookWithoutEnvSalt(payload: Record<string, unknown>, opts: { env?: Record<string, string> } = {}) {
    const env: NodeJS.ProcessEnv = { ...process.env, ...(opts.env ?? {}), HOME: home, SHIELDCORTEX_CONFIG_DIR: join(home, '.shieldcortex') };
    delete env.SHIELDCORTEX_SESSION_SALT;
    return spawnSync(process.execPath, [STOP_HOOK], {
      input: JSON.stringify(payload),
      encoding: 'utf8',
      env,
    });
  }


  function runPreTool(payload: Record<string, unknown>, opts: { env?: Record<string, string> } = {}) {
    return spawnSync(process.execPath, [PRE_TOOL_HOOK], {
      input: JSON.stringify(payload),
      encoding: 'utf8',
      env: { ...process.env, ...(opts.env ?? {}), HOME: home, SHIELDCORTEX_CONFIG_DIR: join(home, '.shieldcortex'), SHIELDCORTEX_SESSION_SALT: SESSION_SALT },
    });
  }

  function runPreToolAsync(payload: Record<string, unknown>, extraEnv: Record<string, string> = {}, timeoutMs = 3000): Promise<{ status: number | null; stderr: string; timedOut: boolean }> {
    return new Promise((resolvePromise) => {
      const child = spawn(process.execPath, [PRE_TOOL_HOOK], {
        env: { ...process.env, ...extraEnv, HOME: home, SHIELDCORTEX_CONFIG_DIR: join(home, '.shieldcortex'), SHIELDCORTEX_SESSION_SALT: SESSION_SALT },
        stdio: ['pipe', 'ignore', 'pipe'],
      });
      let stderr = '';
      let timedOut = false;
      const timer = setTimeout(() => {
        timedOut = true;
        child.kill('SIGKILL');
      }, timeoutMs);
      child.stderr.setEncoding('utf8');
      child.stderr.on('data', (chunk) => { stderr += chunk; });
      child.on('close', (status) => {
        clearTimeout(timer);
        resolvePromise({ status, stderr, timedOut });
      });
      child.stdin.end(JSON.stringify(payload));
    });
  }

  function runPreToolWithoutEnvSalt(payload: Record<string, unknown>, opts: { env?: Record<string, string> } = {}) {
    const env: NodeJS.ProcessEnv = { ...process.env, ...(opts.env ?? {}), HOME: home, SHIELDCORTEX_CONFIG_DIR: join(home, '.shieldcortex') };
    delete env.SHIELDCORTEX_SESSION_SALT;
    return spawnSync(process.execPath, [PRE_TOOL_HOOK], {
      input: JSON.stringify(payload),
      encoding: 'utf8',
      env,
    });
  }

  function runStopHookAsync(payload: Record<string, unknown>, extraEnv: Record<string, string> = {}, timeoutMs = 3000): Promise<{ status: number | null; stderr: string; timedOut: boolean }> {
    return new Promise((resolvePromise) => {
      const child = spawn(process.execPath, [STOP_HOOK], {
        env: { ...process.env, ...extraEnv, HOME: home, SHIELDCORTEX_CONFIG_DIR: join(home, '.shieldcortex'), SHIELDCORTEX_SESSION_SALT: SESSION_SALT },
        stdio: ['pipe', 'ignore', 'pipe'],
      });
      let stderr = '';
      let timedOut = false;
      const timer = setTimeout(() => {
        timedOut = true;
        child.kill('SIGKILL');
      }, timeoutMs);
      child.stderr.setEncoding('utf8');
      child.stderr.on('data', (chunk) => { stderr += chunk; });
      child.on('close', (status) => {
        clearTimeout(timer);
        resolvePromise({ status, stderr, timedOut });
      });
      child.stdin.end(JSON.stringify(payload));
    });
  }


  function runPreToolWithoutEnvSaltAsync(payload: Record<string, unknown>): Promise<{ status: number | null; stderr: string }> {
    return new Promise((resolvePromise) => {
      const env: NodeJS.ProcessEnv = { ...process.env, HOME: home, SHIELDCORTEX_CONFIG_DIR: join(home, '.shieldcortex') };
      delete env.SHIELDCORTEX_SESSION_SALT;
      const child = spawn(process.execPath, [PRE_TOOL_HOOK], {
        env,
        stdio: ['pipe', 'ignore', 'pipe'],
      });
      let stderr = '';
      child.stderr.setEncoding('utf8');
      child.stderr.on('data', (chunk) => { stderr += chunk; });
      child.on('close', (status) => resolvePromise({ status, stderr }));
      child.stdin.end(JSON.stringify(payload));
    });
  }

  function writeGuardRow(session: string, outcome = 'auto_denied', ts = '2026-08-11T10:00:00.000Z', auditEventId?: string) {
    writeFileSync(auditFile(), [guardRowJson(session, outcome, ts, auditEventId), ''].join('\n'));
  }

  function appendGuardRow(session: string, outcome = 'auto_denied', ts = '2026-08-11T10:00:00.000Z', auditEventId?: string) {
    writeFileSync(auditFile(), `${readFileSync(auditFile(), 'utf8').replace(/\n?$/, '\n')}${guardRowJson(session, outcome, ts, auditEventId)}\n`);
  }

  function guardRowJson(session: string, outcome = 'auto_denied', ts = '2026-08-11T10:00:00.000Z', auditEventId?: string) {
    return JSON.stringify({
      type: 'intercept',
      origin: 'claude-code-hook',
      sessionKey: sessionKey(session),
      action: outcome === 'warned' ? 'warn' : 'auto_deny',
      outcome,
      tool: 'Bash',
      threats: ['secret-egress'],
      ...(auditEventId ? { auditEventId } : {}),
      ts,
    });
  }

  function appendIndexGuardRow(session: string, rowJson: string) {
    const dir = join(home, '.shieldcortex', 'audit', 'session-guard');
    mkdirSync(dir, { recursive: true });
    const row = JSON.parse(rowJson);
    writeFileSync(join(dir, `${sessionKey(session)}.jsonl`), `${JSON.stringify({ recordKind: 'guard', ...row })}\n`);
  }


  it('recovers unusable session salt paths while preserving pre-tool to stop-hook correlation', () => {
    for (const [label, setup] of [
      ['empty', (saltPath: string) => writeFileSync(saltPath, '')],
      ['malformed', (saltPath: string) => writeFileSync(saltPath, 'not-a-valid-salt')],
      ['symlink', (saltPath: string) => {
        const target = join(home, '.shieldcortex', 'salt-target');
        writeFileSync(target, 'also-not-a-valid-salt');
        symlinkSync(target, saltPath);
      }],
      ['directory', (saltPath: string) => mkdirSync(saltPath)],
    ] as const) {
      const originalHome = home;
      home = mkdtempCompat(`sc-salt-${label}-`);
      try {
        const dir = join(home, '.shieldcortex');
        mkdirSync(dir, { recursive: true });
        writeFileSync(join(dir, 'config.json'), JSON.stringify({ actionGuard: { enabled: true, enforce: true } }));
        const primary = join(dir, 'action-guard-session-salt');
        setup(primary);
        const db = new Database(dbFile());
        db.close();
        const session = `salt-recovery-${label}`;

        const pre = runPreToolWithoutEnvSalt({
          session_id: session,
          cwd: '/tmp',
          permission_mode: 'bypassPermissions',
          hook_event_name: 'PreToolUse',
          tool_name: 'Bash',
          tool_input: { command: 'sudo systemctl stop nginx' },
        });

        expect(pre.status).toBe(0);
        expect(pre.stdout).toContain('"permissionDecision":"deny"');
        const recoveredSaltPath = [
          primary,
          `${primary}.recovered`,
          `${primary}.recovered2`,
          `${primary}.recovered3`,
        ].find((candidate) => {
          try { return /^[a-f0-9]{64}\n?$/.test(readFileSync(candidate, 'utf8')); }
          catch { return false; }
        });
        expect(recoveredSaltPath).toBeDefined();
        const recoveredSalt = readFileSync(recoveredSaltPath as string, 'utf8').trim();
        const recoveredKey = `sc-${createHmac('sha256', recoveredSalt).update(`action-guard-session:${session}`).digest('hex').slice(0, 16)}`;
        const auditRows = readFileSync(auditFile(), 'utf8').trim().split('\n').map((l) => JSON.parse(l));
        expect(auditRows.some((r) => r.sessionKey === recoveredKey && r.outcome === 'denied_no_prompt_surface')).toBe(true);

        const stop = runStopHookWithoutEnvSalt({ session_id: session });

        expect(stop.status).toBe(0);
        const after = readFileSync(auditFile(), 'utf8').trim().split('\n').map((l) => JSON.parse(l));
        expect(after.some((r) => r.type === 'session_summary' && r.sessionKey === recoveredKey && r.outcome === 'action_guard_degraded')).toBe(true);
      } finally {
        rmSync(home, { recursive: true, force: true });
        home = originalHome;
      }
    }
  });



  it('persists audit rows, session salt, and degraded summary without the removed /dev/fd fallback', () => {
    const session = 'no-dev-fd-cron-1';
    const pre = runPreToolWithoutEnvSalt({
      session_id: session,
      cwd: '/tmp',
      permission_mode: 'bypassPermissions',
      hook_event_name: 'PreToolUse',
      tool_name: 'Bash',
      tool_input: { command: 'sudo systemctl stop nginx' },
    });

    expect(pre.status).toBe(0);
    expect(pre.stdout).toContain('"permissionDecision":"deny"');
    const salt = readFileSync(join(home, '.shieldcortex', 'action-guard-session-salt'), 'utf8').trim();
    expect(salt).toMatch(/^[a-f0-9]{64}$/);
    const key = sessionKey(session, salt);
    let rows = readFileSync(auditFile(), 'utf8').trim().split('\n').map((l) => JSON.parse(l));
    expect(rows.some((r) => r.sessionKey === key && r.outcome === 'denied_no_prompt_surface')).toBe(true);

    const stop = runStopHookWithoutEnvSalt({ session_id: session });

    expect(stop.status).toBe(0);
    rows = readFileSync(auditFile(), 'utf8').trim().split('\n').map((l) => JSON.parse(l));
    expect(rows.some((r) => r.type === 'session_summary' && r.sessionKey === key && r.outcome === 'action_guard_degraded')).toBe(true);
  });

  it('publishes generated session salt atomically so concurrent pre-tool and stop-hook processes stay correlated', async () => {
    const session = 'concurrent-salt-session-1';
    const payload = {
      session_id: session,
      cwd: '/tmp',
      permission_mode: 'bypassPermissions',
      hook_event_name: 'PreToolUse',
      tool_name: 'Bash',
      tool_input: { command: 'sudo systemctl stop nginx' },
    };

    const results = await Promise.all(Array.from({ length: 6 }, () => runPreToolWithoutEnvSaltAsync(payload)));

    expect(results.every((r) => r.status === 0)).toBe(true);
    const saltPath = join(home, '.shieldcortex', 'action-guard-session-salt');
    const salt = readFileSync(saltPath, 'utf8').trim();
    expect(salt).toMatch(/^[a-f0-9]{64}$/);
    for (const suffix of ['.recovered', '.recovered2', '.recovered3']) {
      expect(existsSync(`${saltPath}${suffix}`)).toBe(false);
    }
    const key = sessionKey(session, salt);
    const before = readFileSync(auditFile(), 'utf8').trim().split('\n').map((l) => JSON.parse(l));
    expect(before.filter((r) => r.sessionKey === key && r.outcome === 'denied_no_prompt_surface')).toHaveLength(6);

    const stop = runStopHookWithoutEnvSalt({ session_id: session });

    expect(stop.status).toBe(0);
    const rows = readFileSync(auditFile(), 'utf8').trim().split('\n').map((l) => JSON.parse(l));
    const summary = rows.find((r) => r.type === 'session_summary' && r.sessionKey === key && r.outcome === 'action_guard_degraded');
    expect(summary.guardOutcomeCount).toBe(6);
  });


  it('ignores leading-zero recovered salt aliases and uses the canonical recovered4 slot', () => {
    const scDir = join(home, '.shieldcortex');
    const primary = join(scDir, 'action-guard-session-salt');
    writeFileSync(primary, 'not-a-valid-salt');
    writeFileSync(`${primary}.recovered`, 'also-bad');
    writeFileSync(`${primary}.recovered2`, 'still-bad');
    writeFileSync(`${primary}.recovered3`, 'bad-again');
    const aliasSalt = 'f'.repeat(64);
    writeFileSync(`${primary}.recovered04`, `${aliasSalt}
`);
    writeFileSync(`${primary}.recovered004`, `${aliasSalt}
`);
    writeFileSync(`${primary}.recovered00`, `${aliasSalt}
`);

    const pre = runPreToolWithoutEnvSalt({
      session_id: 'canonical-salt-cron-1',
      cwd: '/tmp',
      permission_mode: 'bypassPermissions',
      hook_event_name: 'PreToolUse',
      tool_name: 'Bash',
      tool_input: { command: 'sudo systemctl stop nginx' },
    });

    expect(pre.status).toBe(0);
    expect(existsSync(`${primary}.recovered4`)).toBe(true);
    const canonicalSalt = readFileSync(`${primary}.recovered4`, 'utf8').trim();
    expect(canonicalSalt).toMatch(/^[a-f0-9]{64}$/);
    expect(canonicalSalt).not.toBe(aliasSalt);
    const auditRows = readFileSync(auditFile(), 'utf8').trim().split('\n').map((l) => JSON.parse(l));
    const guard = auditRows.find((r) => r.outcome === 'denied_no_prompt_surface');
    expect(guard.sessionKey).toBe(`sc-${createHmac('sha256', canonicalSalt).update('action-guard-session:canonical-salt-cron-1').digest('hex').slice(0, 16)}`);

    const stop = runStopHookWithoutEnvSalt({ session_id: 'canonical-salt-cron-1' });

    expect(stop.status).toBe(0);
    const rows = readFileSync(auditFile(), 'utf8').trim().split('\n').map((l) => JSON.parse(l));
    expect(rows.some((r) => r.type === 'session_summary' && r.sessionKey === guard.sessionKey)).toBe(true);
  });

  it('recovers correlation when all fixed session-salt recovery paths are unusable', () => {
    const scDir = join(home, '.shieldcortex');
    const primary = join(scDir, 'action-guard-session-salt');
    writeFileSync(primary, 'not-a-valid-salt');
    writeFileSync(`${primary}.recovered`, 'also-bad');
    mkdirSync(`${primary}.recovered2`);
    const target = join(scDir, 'bad-salt-target');
    writeFileSync(target, 'bad-target');
    symlinkSync(target, `${primary}.recovered3`);

    const pre = runPreToolWithoutEnvSalt({
      session_id: 'exhausted-salt-cron-1',
      cwd: '/tmp',
      permission_mode: 'bypassPermissions',
      hook_event_name: 'PreToolUse',
      tool_name: 'Bash',
      tool_input: { command: 'sudo systemctl stop nginx' },
    });

    expect(pre.status).toBe(0);
    const generatedSalt = readdirSync(scDir).find((name) => /^action-guard-session-salt\.recovered\d+$/.test(name));
    expect(generatedSalt).toBeDefined();
    const auditRows = readFileSync(auditFile(), 'utf8').trim().split('\n').map((l) => JSON.parse(l));
    const guard = auditRows.find((r) => r.outcome === 'denied_no_prompt_surface');
    expect(guard.sessionKey).toMatch(/^sc-[a-f0-9]{16}$/);

    const stop = runStopHookWithoutEnvSalt({ session_id: 'exhausted-salt-cron-1' });

    expect(stop.status).toBe(0);
    const rows = readFileSync(auditFile(), 'utf8').trim().split('\n').map((l) => JSON.parse(l));
    expect(rows.some((r) => r.type === 'session_summary' && r.sessionKey === guard.sessionKey)).toBe(true);
  });

  it('correlates camelCase sessionId from pre-tool denial through stop-hook degraded summary telemetry', () => {
    const session = 'camel-case-session-1';
    const pre = runPreTool({
      sessionId: session,
      cwd: '/tmp',
      permission_mode: 'bypassPermissions',
      hook_event_name: 'PreToolUse',
      tool_name: 'Bash',
      tool_input: { command: 'sudo systemctl stop nginx' },
    });

    expect(pre.status).toBe(0);
    expect(pre.stdout).toContain('"permissionDecision":"deny"');
    const before = readFileSync(auditFile(), 'utf8').trim().split('\n').map((l) => JSON.parse(l));
    expect(before.some((r) => r.sessionKey === sessionKey(session) && r.outcome === 'denied_no_prompt_surface')).toBe(true);

    const stop = runStopHook({ sessionId: session });

    expect(stop.status).toBe(0);
    const rows = readFileSync(auditFile(), 'utf8').trim().split('\n').map((l) => JSON.parse(l));
    expect(rows.some((r) => r.type === 'session_summary' && r.sessionKey === sessionKey(session) && r.outcome === 'action_guard_degraded')).toBe(true);
    expect(hookRows()).toEqual([
      expect.objectContaining({ exit_code: 1, notes: expect.stringContaining('action_guard_degraded') }),
    ]);
  });


  it('rejects symlinked session-index files while primary audit and summaries remain canonical', () => {
    const session = 'symlink-index-session-1';
    const key = sessionKey(session);
    const indexDir = join(home, '.shieldcortex', 'audit', 'session-guard');
    mkdirSync(indexDir, { recursive: true });
    const victim = join(home, 'session-index-victim.jsonl');
    writeFileSync(victim, 'victim-start\n');
    symlinkSync(victim, join(indexDir, `${key}.jsonl`));

    const pre = runPreTool({
      session_id: session,
      cwd: '/tmp',
      permission_mode: 'bypassPermissions',
      hook_event_name: 'PreToolUse',
      tool_name: 'Bash',
      tool_input: { command: 'sudo systemctl stop nginx' },
    });

    expect(pre.status).toBe(0);
    expect(readFileSync(victim, 'utf8')).toBe('victim-start\n');
    const before = readFileSync(auditFile(), 'utf8').trim().split('\n').map((l) => JSON.parse(l));
    expect(before.some((r) => r.sessionKey === key && r.outcome === 'denied_no_prompt_surface')).toBe(true);

    const stop = runStopHook({ session_id: session });

    expect(stop.status).toBe(0);
    expect(readFileSync(victim, 'utf8')).toBe('victim-start\n');
    const rows = readFileSync(auditFile(), 'utf8').trim().split('\n').map((l) => JSON.parse(l));
    expect(rows.some((r) => r.type === 'session_summary' && r.sessionKey === key && r.outcome === 'action_guard_degraded')).toBe(true);
  });


  it('does not write through a symlinked session-guard directory for pre-tool indexes or stop summaries', () => {
    const session = 'symlink-session-guard-dir-1';
    const key = sessionKey(session);
    const auditDir = join(home, '.shieldcortex', 'audit');
    mkdirSync(auditDir, { recursive: true });
    const outside = join(home, 'outside-session-guard');
    mkdirSync(outside, { recursive: true });
    symlinkSync(outside, join(auditDir, 'session-guard'));

    const pre = runPreTool({
      session_id: session,
      cwd: '/tmp',
      permission_mode: 'bypassPermissions',
      hook_event_name: 'PreToolUse',
      tool_name: 'Bash',
      tool_input: { command: 'sudo systemctl stop nginx' },
    });

    expect(pre.status).toBe(0);
    expect(existsSync(join(outside, `${key}.jsonl`))).toBe(false);
    const stop = runStopHook({ session_id: session });
    expect(stop.status).toBe(0);
    expect(existsSync(join(outside, `${key}.jsonl`))).toBe(false);
    const rows = readFileSync(auditFile(), 'utf8').trim().split('\n').map((l) => JSON.parse(l));
    expect(rows.some((r) => r.type === 'session_summary' && r.sessionKey === key)).toBe(true);
  });

  it('refuses a symlinked locks directory without writing lock files outside the audit tree', () => {
    writeGuardRow('symlink-lock-dir-cron-1');
    const auditDir = join(home, '.shieldcortex', 'audit');
    const outside = join(home, 'outside-locks');
    mkdirSync(outside, { recursive: true });
    symlinkSync(outside, join(auditDir, '.locks'));

    const result = runStopHook({ session_id: 'symlink-lock-dir-cron-1' });

    expect(result.status).toBe(0);
    expect(existsSync(join(outside, `${sessionKey('symlink-lock-dir-cron-1')}.lock`))).toBe(false);
    const rows = readFileSync(auditFile(), 'utf8').trim().split('\n').map((l) => JSON.parse(l));
    expect(rows.some((r) => r.sessionKey === sessionKey('symlink-lock-dir-cron-1') && r.outcome === 'auto_denied')).toBe(true);
    expect(rows.some((r) => r.type === 'session_summary' && r.sessionKey === sessionKey('symlink-lock-dir-cron-1'))).toBe(false);
  });



  it('does not write salt, audit, index, locks, or summaries through a symlinked .shieldcortex base directory', () => {
    const scDir = join(home, '.shieldcortex');
    const outside = join(home, 'outside-shieldcortex');
    rmSync(scDir, { recursive: true, force: true });
    mkdirSync(outside, { recursive: true });
    symlinkSync(outside, scDir);

    const pre = runPreTool({
      session_id: 'base-symlink-pre-1',
      cwd: '/tmp',
      permission_mode: 'bypassPermissions',
      hook_event_name: 'PreToolUse',
      tool_name: 'Bash',
      tool_input: { command: 'sudo systemctl stop nginx' },
    });
    const stop = runStopHook({ session_id: 'base-symlink-stop-1' }, { timeout: 1500 });

    expect(pre.status).toBe(0);
    expect(stop.status).toBe(0);
    expect(existsSync(join(outside, 'action-guard-session-salt'))).toBe(false);
    expect(existsSync(join(outside, 'audit', 'session-guard'))).toBe(false);
    expect(existsSync(join(outside, 'audit', '.locks'))).toBe(false);
    expect(existsSync(join(outside, 'audit', `realtime-${new Date().toISOString().slice(0, 10)}.jsonl`))).toBe(false);
  });

  it('rechecks audit directory ancestry after validation so a directory-swap race cannot redirect appends', async () => {
    const auditDir = join(home, '.shieldcortex', 'audit');
    mkdirSync(auditDir, { recursive: true });
    const outside = join(home, 'outside-append-race');
    mkdirSync(outside, { recursive: true });
    const pending = runPreToolAsync({
      session_id: 'append-race-pre-1',
      cwd: '/tmp',
      permission_mode: 'bypassPermissions',
      hook_event_name: 'PreToolUse',
      tool_name: 'Bash',
      tool_input: { command: 'sudo systemctl stop nginx' },
    }, { SHIELDCORTEX_TEST_POST_APPEND_VALIDATION_DELAY_MS: '250' }, 2500);
    await new Promise((resolvePromise) => setTimeout(resolvePromise, 50));
    await swapDirForSymlink(auditDir, outside);

    const result = await pending;

    expect(result.timedOut).toBe(false);
    expect(result.status).toBe(0);
    expect(existsSync(join(outside, `realtime-${new Date().toISOString().slice(0, 10)}.jsonl`))).toBe(false);
  });


  it('rechecks stop summary ancestry after validation so a directory-swap race cannot redirect appends', async () => {
    writeGuardRow('append-race-stop-1');
    const auditDir = join(home, '.shieldcortex', 'audit');
    const outside = join(home, 'outside-stop-append-race');
    mkdirSync(outside, { recursive: true });
    const pending = runStopHookAsync(
      { session_id: 'append-race-stop-1' },
      { SHIELDCORTEX_TEST_POST_APPEND_VALIDATION_DELAY_MS: '250' },
      2500,
    );
    await new Promise((resolvePromise) => setTimeout(resolvePromise, 50));
    await swapDirForSymlink(auditDir, outside);

    const result = await pending;

    expect(result.timedOut).toBe(false);
    expect(result.status).toBe(0);
    expect(existsSync(join(outside, `realtime-${new Date().toISOString().slice(0, 10)}.jsonl`))).toBe(false);
  });

  it('writes primary audit rows and stop summaries as complete JSONL records', () => {
    const pre = runPreTool({
      session_id: 'jsonl-complete-pre-1',
      cwd: '/tmp',
      permission_mode: 'bypassPermissions',
      hook_event_name: 'PreToolUse',
      tool_name: 'Bash',
      tool_input: { command: 'sudo systemctl stop nginx' },
    });

    expect(pre.status).toBe(0);
    let rows = readFileSync(auditFile(), 'utf8').trim().split('\n').map((l) => JSON.parse(l));
    expect(rows.some((r) => r.sessionKey === sessionKey('jsonl-complete-pre-1') && r.outcome === 'denied_no_prompt_surface')).toBe(true);

    writeGuardRow('jsonl-complete-stop-1');
    const stop = runStopHook({ session_id: 'jsonl-complete-stop-1' });

    expect(stop.status).toBe(0);
    rows = readFileSync(auditFile(), 'utf8').trim().split('\n').map((l) => JSON.parse(l));
    const summary = rows.find((r) => r.type === 'session_summary' && r.sessionKey === sessionKey('jsonl-complete-stop-1'));
    expect(summary.guardOutcomeCount).toBe(1);
  });

  it('does not write pre-tool audit rows or stop-hook summaries through a symlinked current primary audit file', () => {
    const auditDir = join(home, '.shieldcortex', 'audit');
    mkdirSync(auditDir, { recursive: true });
    const outside = join(home, 'outside-primary-audit.jsonl');
    writeFileSync(outside, 'outside-start\n');
    symlinkSync(outside, auditFile());

    const pre = runPreTool({
      session_id: 'primary-symlink-pre-1',
      cwd: '/tmp',
      permission_mode: 'bypassPermissions',
      hook_event_name: 'PreToolUse',
      tool_name: 'Bash',
      tool_input: { command: 'sudo systemctl stop nginx' },
    });

    expect(pre.status).toBe(0);
    expect(pre.stderr).toMatch(/audit sink UNWRITABLE/);
    expect(readFileSync(outside, 'utf8')).toBe('outside-start\n');

    const oldFile = auditFileForDate('2026-08-10');
    writeFileSync(oldFile, `${guardRowJson('primary-symlink-stop-1')}\n`);
    const stop = runStopHook({ session_id: 'primary-symlink-stop-1' });

    expect(stop.status).toBe(0);
    expect(stop.stderr).toMatch(/audit sink UNWRITABLE/);
    expect(readFileSync(outside, 'utf8')).toBe('outside-start\n');
    const oldRows = readFileSync(oldFile, 'utf8').trim().split('\n').map((l) => JSON.parse(l));
    expect(oldRows.some((r) => r.outcome === 'auto_denied')).toBe(true);
    expect(oldRows.some((r) => r.type === 'session_summary')).toBe(false);
  });

  it('skips symlinked and FIFO primary audit candidates without blocking recovery', () => {
    const auditDir = join(home, '.shieldcortex', 'audit');
    mkdirSync(auditDir, { recursive: true });
    const outside = join(home, 'outside-recovery-source.jsonl');
    writeFileSync(outside, `${guardRowJson('fifo-skip-cron-1', 'warned', '2099-08-12T10:00:00.000Z')}\n`);
    symlinkSync(outside, join(auditDir, 'realtime-2099-08-13.jsonl'));
    const fifoPath = join(auditDir, 'realtime-2099-08-12.jsonl');
    const fifo = spawnSync('mkfifo', [fifoPath]);
    expect(fifo.status).toBe(0);
    writeFileSync(auditFileForDate('2026-08-11'), `${guardRowJson('fifo-skip-cron-1', 'auto_denied', '2026-08-11T10:00:00.000Z')}\n`);

    const result = runStopHook({ session_id: 'fifo-skip-cron-1' }, { timeout: 1500 });

    expect(result.error).toBeUndefined();
    expect(result.status).toBe(0);
    const rows = readFileSync(auditFile(), 'utf8').trim().split('\n').map((l) => JSON.parse(l));
    const summary = rows.find((r) => r.type === 'session_summary' && r.sessionKey === sessionKey('fifo-skip-cron-1'));
    expect(summary.guardOutcomeCount).toBe(1);
    expect(summary.outcomes).toMatchObject({ auto_denied: 1 });
  });

  it('keeps legacy primary-audit recovery bounded while recovering rows inside the scan budget', () => {
    writeFileSync(auditFile(), `${guardRowJson('bounded-history-cron-1', 'auto_denied', '2026-08-11T10:00:00.000Z')}\n`);
    for (let i = 0; i < 320; i += 1) {
      const year = 2025 - Math.floor(i / (12 * 28));
      const month = String(1 + Math.floor((i % (12 * 28)) / 28)).padStart(2, '0');
      const day = String(1 + (i % 28)).padStart(2, '0');
      const date = `${year}-${month}-${day}`;
      const file = auditFileForDate(date);
      writeFileSync(file, `${JSON.stringify({ type: 'noise', ts: `${date}T00:00:00.000Z`, pad: 'x'.repeat(256 * 1024) })}\n`);
    }

    const result = runStopHook({ session_id: 'bounded-history-cron-1' }, { timeout: 3000 });

    expect(result.error).toBeUndefined();
    expect(result.status).toBe(0);
    const rows = readFileSync(auditFile(), 'utf8').trim().split('\n').map((l) => JSON.parse(l));
    const summary = rows.find((r) => r.type === 'session_summary' && r.sessionKey === sessionKey('bounded-history-cron-1'));
    expect(summary.guardOutcomeCount).toBe(1);
    expect(summary.outcomes).toMatchObject({ auto_denied: 1 });
  });


  it('skips an oversized newest primary audit file and still recovers an older primary-only guard row', () => {
    writeFileSync(auditFile(), `${JSON.stringify({ type: 'noise', pad: 'x'.repeat(64 * 1024 * 1024 + 1024) })}\n`);
    writeFileSync(auditFileForDate('2026-08-10'), `${guardRowJson('oversized-newest-cron-1', 'auto_denied', '2026-08-10T10:00:00.000Z')}\n`);

    const result = runStopHook({ session_id: 'oversized-newest-cron-1' }, { timeout: 3000 });

    expect(result.error).toBeUndefined();
    expect(result.status).toBe(0);
    const tail = readFileSync(auditFile(), 'utf8').slice(-(8 * 1024));
    const summary = tail.split('\n').filter(Boolean).map((l) => {
      try { return JSON.parse(l); } catch { return null; }
    }).find((r) => r?.type === 'session_summary' && r.sessionKey === sessionKey('oversized-newest-cron-1'));
    expect(summary.guardOutcomeCount).toBe(1);
    expect(summary.outcomes).toMatchObject({ auto_denied: 1 });
  });

  it('does not block when an audit candidate is replaced with a FIFO between lstat and open', async () => {
    const file = auditFileForDate('2026-08-09');
    writeFileSync(file, `${guardRowJson('fifo-race-cron-1', 'auto_denied', '2026-08-09T10:00:00.000Z')}\n`);
    const pending = runStopHookAsync({ session_id: 'fifo-race-cron-1' }, { SHIELDCORTEX_TEST_AUDIT_OPEN_DELAY_MS: '250' }, 2000);
    await new Promise((resolvePromise) => setTimeout(resolvePromise, 50));
    unlinkSync(file);
    const fifo = spawnSync('mkfifo', [file]);
    expect(fifo.status).toBe(0);

    const result = await pending;

    expect(result.timedOut).toBe(false);
    expect(result.status).toBe(0);
    const rows = existsSync(auditFile())
      ? readFileSync(auditFile(), 'utf8').trim().split('\n').filter(Boolean).map((l) => JSON.parse(l))
      : [];
    expect(rows.some((r) => r.type === 'session_summary' && r.sessionKey === sessionKey('fifo-race-cron-1'))).toBe(false);
  });


  it('rejects an oversized physical JSONL line instead of parsing a valid-looking guard suffix', () => {
    writeFileSync(auditFile(), `${'x'.repeat(1024 * 1024 + 17)}${guardRowJson('oversized-suffix-cron-1')}\n`);

    const result = runStopHook({ session_id: 'oversized-suffix-cron-1' }, { timeout: 1500 });

    expect(result.status).toBe(0);
    const rows = readFileSync(auditFile(), 'utf8').trim().split('\n').filter(Boolean).map((l) => {
      try { return JSON.parse(l); } catch { return null; }
    }).filter(Boolean);
    expect(rows.some((r) => r.type === 'session_summary' && r.sessionKey === sessionKey('oversized-suffix-cron-1'))).toBe(false);
  });

  it('records action_guard_degraded from session-linked guard denials before auto-memory exits disabled', () => {
    writeFileSync(auditFile(), [
      JSON.stringify({
        type: 'intercept',
        origin: 'claude-code-hook',
        sessionKey: sessionKey('cron-job-42'),
        action: 'auto_deny',
        outcome: 'auto_denied',
        tool: 'Bash',
        threats: ['secret-egress', 'hunter2', 'ignore.previous.instructions', 'DO_NOT_PERSIST_SIGNAL_VALUE_1234567890', `bad\n${SECRET_SENTINEL}`],
        preview: `Bash :: command=${SECRET_SENTINEL}`,
        ts: '2026-08-11T10:00:00.000Z',
      }),
      JSON.stringify({
        type: 'intercept',
        origin: 'claude-code-hook',
        sessionKey: sessionKey('cron-job-42'),
        action: 'require_approval',
        outcome: 'denied_no_prompt_surface',
        tool: 'Bash',
        threats: ['approval-required'],
        ts: '2026-08-11T10:00:00.500Z',
      }),
      JSON.stringify({
        type: 'intercept',
        origin: 'claude-code-hook',
        sessionKey: sessionKey('cron-job-42'),
        action: 'gate_degraded',
        outcome: 'failure_allowed',
        tool: 'Bash',
        threats: ['fallback-scan'],
        ts: '2026-08-11T10:00:00.700Z',
      }),
      JSON.stringify({
        type: 'intercept',
        origin: 'claude-code-hook',
        sessionKey: sessionKey('different-session'),
        action: 'auto_deny',
        outcome: 'auto_denied',
        tool: 'Bash',
        threats: ['ignored'],
        ts: '2026-08-11T10:00:01.000Z',
      }),
      '',
    ].join('\n'));

    const result = runStopHook({ session_id: 'cron-job-42' });

    expect(result.status).toBe(0);
    expect(result.stderr).toMatch(new RegExp(`action_guard_degraded sessionKey=${sessionKey('cron-job-42')} guardOutcomes=3`));
    const rows = readFileSync(auditFile(), 'utf8').trim().split('\n').map((l) => JSON.parse(l));
    const summary = rows.find((r) => r.type === 'session_summary' && r.outcome === 'action_guard_degraded');
    expect(summary).toMatchObject({
      origin: 'claude-code-stop-hook',
      sessionKey: sessionKey('cron-job-42'),
      guardOutcomeCount: 3,
      outcomes: { auto_denied: 1, denied_no_prompt_surface: 1, failure_allowed: 1 },
    });
    expect(summary?.threats).toEqual(expect.arrayContaining(['secret-egress', 'approval-required', 'fallback-scan']));
    expect(JSON.stringify(summary)).not.toContain(SECRET_SENTINEL);
    expect(JSON.stringify(summary)).not.toContain('DO_NOT_PERSIST_SIGNAL_VALUE_1234567890');
    expect(JSON.stringify(summary)).not.toContain('hunter2');
    expect(JSON.stringify(summary)).not.toContain('ignore.previous.instructions');

    const second = runStopHook({ session_id: 'cron-job-42' });
    expect(second.status).toBe(0);
    // The disabled sentinel may suppress the second diagnostic; the canonical
    // degraded telemetry below is the load-bearing assertion.
    expect(second.stderr).not.toContain('action_guard_degraded sessionKey=cron-job-42');
    const afterSecond = readFileSync(auditFile(), 'utf8').trim().split('\n').map((l) => JSON.parse(l));
    const summaries = afterSecond.filter((r) => r.type === 'session_summary' && r.outcome === 'action_guard_degraded');
    expect(summaries).toHaveLength(1);
    expect(hookRows().map((r) => r.exit_code)).toEqual([1, 1]);
    expect(hookRows().every((r) => String(r.notes).includes('action_guard_degraded'))).toBe(true);
  });

  it('scans audit files beyond the newest fortnight for delayed unattended sessions', () => {
    writeFileSync(auditFileForDate('2026-01-01'), [
      JSON.stringify({
        type: 'intercept',
        origin: 'claude-code-hook',
        sessionKey: sessionKey('long-cron-77'),
        action: 'warn',
        outcome: 'warned',
        tool: 'Bash',
        threats: ['secret-egress'],
        ts: '2026-01-01T10:00:00.000Z',
      }),
      '',
    ].join('\n'));
    for (let day = 2; day <= 20; day++) {
      writeFileSync(auditFileForDate(`2026-01-${String(day).padStart(2, '0')}`), '\n');
    }

    const result = runStopHook({ session_id: 'long-cron-77' });

    expect(result.status).toBe(0);
    const rows = readFileSync(auditFile(), 'utf8').trim().split('\n').map((l) => JSON.parse(l));
    expect(rows.some((r) => r.type === 'session_summary' && r.sessionKey === sessionKey('long-cron-77') && r.outcome === 'action_guard_degraded')).toBe(true);
  });

  it('continues the normal enabled stop-hook telemetry path while marking the run degraded', () => {
    writeFileSync(join(home, '.shieldcortex', 'config.json'), JSON.stringify({
      autoMemory: { enableStop: true, stopHookSamplingTurns: 5, stopHookSalienceBypass: false },
    }));
    writeGuardRow('enabled-cron-1');

    const result = runStopHook({ session_id: 'enabled-cron-1' });

    expect(result.status).toBe(0);
    expect(result.stderr).toMatch(/action_guard_degraded/);
    expect(result.stderr).toMatch(/telemetry-only/);
    expect(hookRows()).toEqual([
      expect.objectContaining({ exit_code: 1, notes: expect.stringContaining('action_guard_degraded') }),
    ]);
    expect(hookRows()[0].notes).toContain('off-sample');
  });

  it('does not duplicate the canonical degraded summary under concurrent stop-hook invocations', async () => {
    writeGuardRow('concurrent-cron-1');

    const [a, b] = await Promise.all([
      runStopHookAsync({ session_id: 'concurrent-cron-1' }),
      runStopHookAsync({ session_id: 'concurrent-cron-1' }),
    ]);

    expect(a.status).toBe(0);
    expect(b.status).toBe(0);
    const rows = readFileSync(auditFile(), 'utf8').trim().split('\n').map((l) => JSON.parse(l));
    const summaries = rows.filter((r) => r.type === 'session_summary' && r.outcome === 'action_guard_degraded');
    expect(summaries).toHaveLength(1);
  });


  it('keeps stale recovery-lock reclamation single-writer under concurrent stop-hook invocations', async () => {
    writeGuardRow('concurrent-stale-recovery-cron-1');
    const lockDir = join(home, '.shieldcortex', 'audit', '.locks');
    mkdirSync(lockDir, { recursive: true });
    const key = sessionKey('concurrent-stale-recovery-cron-1');
    writeFileSync(join(lockDir, `${key}.lock`), JSON.stringify({ pid: -1, startedAt: new Date().toISOString() }));
    writeFileSync(join(lockDir, `${key}.recovery.lock`), 'not-json');

    const previousDelay = process.env.SHIELDCORTEX_TEST_RECOVERY_LOCK_RECLAIM_DELAY_MS;
    process.env.SHIELDCORTEX_TEST_RECOVERY_LOCK_RECLAIM_DELAY_MS = '100';
    let a!: { status: number | null; stderr: string };
    let b!: { status: number | null; stderr: string };
    try {
      [a, b] = await Promise.all([
        runStopHookAsync({ session_id: 'concurrent-stale-recovery-cron-1' }),
        runStopHookAsync({ session_id: 'concurrent-stale-recovery-cron-1' }),
      ]);
    } finally {
      if (previousDelay === undefined) delete process.env.SHIELDCORTEX_TEST_RECOVERY_LOCK_RECLAIM_DELAY_MS;
      else process.env.SHIELDCORTEX_TEST_RECOVERY_LOCK_RECLAIM_DELAY_MS = previousDelay;
    }

    expect(a.status).toBe(0);
    expect(b.status).toBe(0);
    const rows = readFileSync(auditFile(), 'utf8').trim().split('\n').map((l) => JSON.parse(l));
    const summaries = rows.filter((r) => r.type === 'session_summary' && r.sessionKey === key && r.outcome === 'action_guard_degraded');
    expect(summaries).toHaveLength(1);
    expect(summaries[0].guardOutcomeCount).toBe(1);
    expect(summaries[0].guardFingerprints).toHaveLength(1);
  });

  it('picks up backdated guard rows appended after an earlier summary instead of using summary timestamp as a watermark', () => {
    writeGuardRow('delayed-cron-1', 'auto_denied', '2026-08-11T10:00:00.000Z');
    expect(runStopHook({ session_id: 'delayed-cron-1' }).status).toBe(0);

    appendGuardRow('delayed-cron-1', 'denied_no_prompt_surface', '2026-08-11T09:59:59.000Z');
    expect(runStopHook({ session_id: 'delayed-cron-1' }).status).toBe(0);

    const rows = readFileSync(auditFile(), 'utf8').trim().split('\n').map((l) => JSON.parse(l));
    const summaries = rows.filter((r) => r.type === 'session_summary' && r.outcome === 'action_guard_degraded');
    expect(summaries).toHaveLength(2);
    expect(summaries.map((r) => r.guardOutcomeCount)).toEqual([1, 1]);
    expect(summaries.flatMap((r) => Object.keys(r.outcomes))).toEqual(expect.arrayContaining(['auto_denied', 'denied_no_prompt_surface']));

    expect(runStopHook({ session_id: 'delayed-cron-1' }).status).toBe(0);
    const after = readFileSync(auditFile(), 'utf8').trim().split('\n').map((l) => JSON.parse(l));
    expect(after.filter((r) => r.type === 'session_summary' && r.outcome === 'action_guard_degraded')).toHaveLength(2);
  });

  it('aggregates distinct same-millisecond guard rows exactly once by audit line identity', () => {
    const row = guardRowJson('same-ms-cron-1', 'auto_denied', '2026-08-11T10:00:00.000Z');
    writeFileSync(auditFile(), [row, row, ''].join('\n'));

    expect(runStopHook({ session_id: 'same-ms-cron-1' }).status).toBe(0);
    expect(runStopHook({ session_id: 'same-ms-cron-1' }).status).toBe(0);

    const rows = readFileSync(auditFile(), 'utf8').trim().split('\n').map((l) => JSON.parse(l));
    const summaries = rows.filter((r) => r.type === 'session_summary' && r.outcome === 'action_guard_degraded');
    expect(summaries).toHaveLength(1);
    expect(summaries[0].guardOutcomeCount).toBe(2);
    expect(summaries[0].guardFingerprints).toHaveLength(2);
    expect(new Set(summaries[0].guardFingerprints).size).toBe(2);
  });

  it('dedupes an event present in both the session index and primary audit, including repeated stop-hook runs', () => {
    const eventId = '11111111111111111111111111111111';
    const row = guardRowJson('indexed-cron-1', 'auto_denied', '2026-08-11T10:00:00.000Z', eventId);
    writeFileSync(auditFile(), [row, ''].join('\n'));
    appendIndexGuardRow('indexed-cron-1', row);

    expect(runStopHook({ session_id: 'indexed-cron-1' }).status).toBe(0);
    expect(runStopHook({ session_id: 'indexed-cron-1' }).status).toBe(0);

    const rows = readFileSync(auditFile(), 'utf8').trim().split('\n').map((l) => JSON.parse(l));
    const summaries = rows.filter((r) => r.type === 'session_summary' && r.outcome === 'action_guard_degraded');
    expect(summaries).toHaveLength(1);
    expect(summaries[0].guardOutcomeCount).toBe(1);
  });

  it('falls back to primary audit rows when the best-effort session index is stale or partial', () => {
    const indexed = guardRowJson('partial-index-cron-1', 'auto_denied', '2026-08-11T10:00:00.000Z', '22222222222222222222222222222222');
    const primaryOnly = guardRowJson('partial-index-cron-1', 'denied_no_prompt_surface', '2026-08-11T10:00:00.500Z', '33333333333333333333333333333333');
    writeFileSync(auditFile(), [indexed, primaryOnly, ''].join('\n'));
    appendIndexGuardRow('partial-index-cron-1', indexed);

    expect(runStopHook({ session_id: 'partial-index-cron-1' }).status).toBe(0);

    const rows = readFileSync(auditFile(), 'utf8').trim().split('\n').map((l) => JSON.parse(l));
    const summary = rows.find((r) => r.type === 'session_summary' && r.outcome === 'action_guard_degraded');
    expect(summary.guardOutcomeCount).toBe(2);
    expect(summary.outcomes).toMatchObject({ auto_denied: 1, denied_no_prompt_surface: 1 });
  });

  it('recovers primary-only guard rows outside the old recent/tail fallback even when a session index exists', () => {
    const oldFile = auditFileForDate('2026-01-01');
    writeFileSync(oldFile, [
      guardRowJson('full-primary-recovery-cron-1', 'warned', '2026-01-01T10:00:00.000Z', '44444444444444444444444444444444'),
      'x'.repeat(1024 * 1024 + 17),
      '',
    ].join('\n'));
    const oldDate = new Date('2026-01-01T00:00:00.000Z');
    utimesSync(oldFile, oldDate, oldDate);
    for (let i = 2; i <= 10; i += 1) {
      const file = auditFileForDate(`2026-01-${String(i).padStart(2, '0')}`);
      writeFileSync(file, `${JSON.stringify({ type: 'noise', ts: `2026-01-${String(i).padStart(2, '0')}T00:00:00.000Z` })}\n`);
      const d = new Date(`2026-01-${String(i).padStart(2, '0')}T00:00:00.000Z`);
      utimesSync(file, d, d);
    }

    const indexed = guardRowJson('full-primary-recovery-cron-1', 'auto_denied', '2026-08-11T10:00:00.000Z', '55555555555555555555555555555555');
    writeFileSync(auditFile(), [indexed, ''].join('\n'));
    appendIndexGuardRow('full-primary-recovery-cron-1', indexed);

    expect(runStopHook({ session_id: 'full-primary-recovery-cron-1' }).status).toBe(0);

    const rows = [oldFile, auditFile()].flatMap((file) => readFileSync(file, 'utf8').trim().split('\n').filter(Boolean).map((l) => {
      try { return JSON.parse(l); } catch { return null; }
    }).filter(Boolean));
    const allRows = readFileSync(auditFile(), 'utf8').trim().split('\n').map((l) => JSON.parse(l));
    const summary = allRows.find((r) => r.type === 'session_summary' && r.outcome === 'action_guard_degraded');
    expect(rows.some((r) => r.outcome === 'warned')).toBe(true);
    expect(summary.guardOutcomeCount).toBe(2);
    expect(summary.outcomes).toMatchObject({ auto_denied: 1, warned: 1 });
  });

  it('does not steal a live summary lock or claim degraded telemetry was recorded without a summary', () => {
    writeFileSync(join(home, '.shieldcortex', 'config.json'), JSON.stringify({
      autoMemory: { enableStop: true, stopHookSamplingTurns: 5, stopHookSalienceBypass: false },
    }));
    writeGuardRow('live-lock-cron-1');
    const lockDir = join(home, '.shieldcortex', 'audit', '.locks');
    mkdirSync(lockDir, { recursive: true });
    const lock = join(lockDir, `${sessionKey('live-lock-cron-1')}.lock`);
    writeFileSync(lock, JSON.stringify({ pid: process.pid, startedAt: new Date().toISOString() }));

    const result = runStopHook({ session_id: 'live-lock-cron-1' });

    expect(result.status).toBe(0);
    const rows = readFileSync(auditFile(), 'utf8').trim().split('\n').map((l) => JSON.parse(l));
    expect(rows.some((r) => r.type === 'session_summary')).toBe(false);
    expect(hookRows()).toEqual([
      expect.objectContaining({ exit_code: 1, notes: expect.stringContaining('action_guard_degraded_pending') }),
    ]);
  });


  it('reclaims dead or malformed inode-claim recovery locks and still records exactly one summary', () => {
    for (const [session, claimBody] of [
      ['dead-claim-cron-1', JSON.stringify({ pid: -1, processStartToken: 'dead' })],
      ['malformed-claim-cron-1', 'not-json'],
      ['reused-claim-cron-1', JSON.stringify({ pid: process.pid, processStartToken: 'not-this-process' })],
    ] as const) {
      writeGuardRow(session);
      const lockDir = join(home, '.shieldcortex', 'audit', '.locks');
      mkdirSync(lockDir, { recursive: true });
      const key = sessionKey(session);
      const primaryLock = join(lockDir, `${key}.lock`);
      const recoveryLock = join(lockDir, `${key}.recovery.lock`);
      writeFileSync(primaryLock, JSON.stringify({ pid: -1, startedAt: new Date().toISOString() }));
      writeFileSync(recoveryLock, 'not-json');
      const observed = lstatSync(recoveryLock);
      writeFileSync(`${recoveryLock}.claim.${observed.dev}.${observed.ino}.lock`, claimBody);

      const result = runStopHook({ session_id: session });

      expect(result.status).toBe(0);
      const rows = readFileSync(auditFile(), 'utf8').trim().split('\n').map((l) => JSON.parse(l));
      const summaries = rows.filter((r) => r.type === 'session_summary' && r.sessionKey === key && r.outcome === 'action_guard_degraded');
      expect(summaries).toHaveLength(1);
      expect(summaries[0].guardOutcomeCount).toBe(1);
    }
  });

  it('does not expose a partial primary lock during atomic publication under concurrent stop hooks', async () => {
    writeGuardRow('lock-publish-race-cron-1');
    const first = runStopHookAsync(
      { session_id: 'lock-publish-race-cron-1' },
      { SHIELDCORTEX_TEST_LOCK_PUBLISH_DELAY_MS: '250' },
      2500,
    );
    await new Promise((resolvePromise) => setTimeout(resolvePromise, 50));
    const second = runStopHookAsync({ session_id: 'lock-publish-race-cron-1' }, {}, 2500);

    const [a, b] = await Promise.all([first, second]);

    expect(a.timedOut).toBe(false);
    expect(b.timedOut).toBe(false);
    expect(a.status).toBe(0);
    expect(b.status).toBe(0);
    const rows = readFileSync(auditFile(), 'utf8').trim().split('\n').map((l) => JSON.parse(l));
    const summaries = rows.filter((r) => r.type === 'session_summary' && r.sessionKey === sessionKey('lock-publish-race-cron-1'));
    expect(summaries).toHaveLength(1);
    expect(summaries[0].guardOutcomeCount).toBe(1);
  });

  it('recovers a dead-owner summary lock and still writes the canonical degraded summary', () => {
    writeGuardRow('dead-lock-cron-1');
    const lockDir = join(home, '.shieldcortex', 'audit', '.locks');
    mkdirSync(lockDir, { recursive: true });
    const lock = join(lockDir, `${sessionKey('dead-lock-cron-1')}.lock`);
    writeFileSync(lock, JSON.stringify({ pid: -1, startedAt: new Date().toISOString() }));

    const result = runStopHook({ session_id: 'dead-lock-cron-1' });

    expect(result.status).toBe(0);
    const rows = readFileSync(auditFile(), 'utf8').trim().split('\n').map((l) => JSON.parse(l));
    expect(rows.some((r) => r.type === 'session_summary' && r.sessionKey === sessionKey('dead-lock-cron-1'))).toBe(true);
    expect(existsSync(lock)).toBe(true);
    expect(existsSync(join(lockDir, `${sessionKey('dead-lock-cron-1')}.recovery.lock`))).toBe(false);
  });

  it('recovers malformed and reused-pid summary locks instead of suppressing canonical degraded summaries', () => {
    for (const [session, lockBody] of [
      ['malformed-lock-cron-1', 'not-json'],
      ['reused-pid-lock-cron-1', JSON.stringify({ pid: process.pid, processStartToken: 'definitely-not-this-process' })],
    ] as const) {
      writeGuardRow(session);
      const lockDir = join(home, '.shieldcortex', 'audit', '.locks');
      mkdirSync(lockDir, { recursive: true });
      const lock = join(lockDir, `${sessionKey(session)}.lock`);
      writeFileSync(lock, lockBody);

      const result = runStopHook({ session_id: session });

      expect(result.status).toBe(0);
      const rows = readFileSync(auditFile(), 'utf8').trim().split('\n').map((l) => JSON.parse(l));
      expect(rows.some((r) => r.type === 'session_summary' && r.sessionKey === sessionKey(session))).toBe(true);
    }
  });


  it('recovers stale recovery locks without permanently suppressing degraded summaries', () => {
    writeGuardRow('stale-recovery-lock-cron-1');
    const lockDir = join(home, '.shieldcortex', 'audit', '.locks');
    mkdirSync(lockDir, { recursive: true });
    const key = sessionKey('stale-recovery-lock-cron-1');
    const primaryLock = join(lockDir, `${key}.lock`);
    const recoveryLock = join(lockDir, `${key}.recovery.lock`);
    const secondRecoveryLock = join(lockDir, `${key}.recovery2.lock`);
    writeFileSync(primaryLock, JSON.stringify({ pid: -1, startedAt: new Date().toISOString() }));
    writeFileSync(recoveryLock, 'not-json');

    const result = runStopHook({ session_id: 'stale-recovery-lock-cron-1' });

    expect(result.status).toBe(0);
    const rows = readFileSync(auditFile(), 'utf8').trim().split('\n').map((l) => JSON.parse(l));
    expect(rows.some((r) => r.type === 'session_summary' && r.sessionKey === key)).toBe(true);
    expect(existsSync(primaryLock)).toBe(true);
    expect(existsSync(recoveryLock)).toBe(true);
    expect(existsSync(secondRecoveryLock)).toBe(false);
  });


  it('reuses exhausted stale recovery lock slots and still records exactly one canonical degraded summary', () => {
    writeGuardRow('exhausted-recovery-lock-cron-1');
    const lockDir = join(home, '.shieldcortex', 'audit', '.locks');
    mkdirSync(lockDir, { recursive: true });
    const key = sessionKey('exhausted-recovery-lock-cron-1');
    const primaryLock = join(lockDir, `${key}.lock`);
    writeFileSync(primaryLock, JSON.stringify({ pid: -1, startedAt: new Date().toISOString() }));
    for (const suffix of ['recovery', 'recovery2', 'recovery3', 'recovery4']) {
      writeFileSync(join(lockDir, `${key}.${suffix}.lock`), suffix === 'recovery2'
        ? JSON.stringify({ pid: -1, processStartToken: 'dead' })
        : 'not-json');
    }

    const result = runStopHook({ session_id: 'exhausted-recovery-lock-cron-1' });

    expect(result.status).toBe(0);
    const rows = readFileSync(auditFile(), 'utf8').trim().split('\n').map((l) => JSON.parse(l));
    const summaries = rows.filter((r) => r.type === 'session_summary' && r.sessionKey === key && r.outcome === 'action_guard_degraded');
    expect(summaries).toHaveLength(1);
    expect(summaries[0].guardOutcomeCount).toBe(1);
    expect(existsSync(primaryLock)).toBe(true);
  });

  it('omits malformed guard timestamps from session summaries instead of persisting hostile suffixes', () => {
    const secret = 'DO_NOT_PERSIST_TS_VALUE_1234567890';
    writeFileSync(auditFile(), [
      guardRowJson('hostile-ts-cron-1', 'auto_denied', `2026-08-11T10:00:00.000Zhttps://example.invalid/${secret}`, '77777777777777777777777777777777'),
      guardRowJson('hostile-ts-cron-1', 'warned', '2026-08-11T10:00:01.000Z', '88888888888888888888888888888888'),
      '',
    ].join('\n'));

    expect(runStopHook({ session_id: 'hostile-ts-cron-1' }).status).toBe(0);

    const rows = readFileSync(auditFile(), 'utf8').trim().split('\n').map((l) => JSON.parse(l));
    const summary = rows.find((r) => r.type === 'session_summary' && r.sessionKey === sessionKey('hostile-ts-cron-1'));
    expect(summary.guardOutcomeCount).toBe(2);
    expect(summary.firstGuardTs).toBe('2026-08-11T10:00:01.000Z');
    expect(summary.lastGuardTs).toBe('2026-08-11T10:00:01.000Z');
    expect(JSON.stringify(summary)).not.toContain(secret);
    expect(JSON.stringify(summary)).not.toContain('https://example.invalid');
  });

  it('does not persist unsafe stop-hook session ids into summaries or stderr', () => {
    const secret = 'DO_NOT_PERSIST_STOPHOOK_VALUE_1234567890';
    writeFileSync(auditFile(), [
      JSON.stringify({
        type: 'intercept',
        origin: 'claude-code-hook',
        sessionKey: sessionKey(`cron-${secret}`),
        action: 'auto_deny',
        outcome: 'auto_denied',
        tool: 'Bash',
        threats: ['secret-egress'],
        ts: '2026-08-11T10:00:00.000Z',
      }),
      '',
    ].join('\n'));

    const result = runStopHook({ session_id: `cron-${secret}` });

    expect(result.status).toBe(0);
    expect(result.stderr).not.toContain(secret);
    const rows = readFileSync(auditFile(), 'utf8').trim().split('\n').map((l) => JSON.parse(l));
    expect(rows.some((r) => r.type === 'session_summary')).toBe(true);
    expect(JSON.stringify(rows)).not.toContain(secret);
  });

  it('summarises an OpenClaw interceptor denial for the same session-key formula (#260)', () => {
    writeFileSync(auditFile(), [
      JSON.stringify({
        type: 'intercept',
        origin: 'openclaw-interceptor',
        sessionKey: sessionKey('openclaw-cron-backup'),
        action: 'require_approval',
        outcome: 'failure_denied',
        tool: 'Bash',
        threats: ['recursive-force-delete'],
        ts: '2026-08-11T01:30:28.897Z',
      }),
      '',
    ].join('\n'));

    const result = runStopHook({ session_id: 'openclaw-cron-backup' });
    expect(result.status).toBe(0);
    const rows = readFileSync(auditFile(), 'utf8').trim().split('\n').map((l) => JSON.parse(l));
    const summary = rows.find((r) => r.type === 'session_summary' && r.outcome === 'action_guard_degraded');
    expect(summary).toMatchObject({
      origin: 'claude-code-stop-hook',
      sessionKey: sessionKey('openclaw-cron-backup'),
      guardOutcomeCount: 1,
      outcomes: { failure_denied: 1 },
    });
  });

  // ==================== #654: receipts list exactly what they counted ====================
  describe('#654 guard-event identity, explicit membership and honest coverage (hook half)', () => {
    const asRoot = typeof process.getuid === 'function' && process.getuid() === 0;
    const itNonRoot = asRoot ? it.skip : it;
    const T = '2026-08-11T10:00:00.000Z';

    const eid = (n: number) => n.toString(16).padStart(32, '0');
    const nonceOf = (n: number) => `${n.toString(16).padStart(31, '0')}b`;
    const auditDir = () => join(home, '.shieldcortex', 'audit');
    const indexPath = (session: string) => join(auditDir(), 'session-guard', `${sessionKey(session)}.jsonl`);

    function row(session: string, over: Record<string, unknown> = {}): Record<string, unknown> {
      return {
        type: 'intercept', origin: 'openclaw-interceptor', sessionKey: sessionKey(session), action: 'require_approval',
        outcome: 'failure_denied', tool: 'Bash', threats: ['secret-egress'], ts: T, ...over,
      };
    }
    function bound(nonce: string): Record<string, unknown> {
      return { plane: 'action_guard', gatewayInstanceId: 'gw-fixture', hookName: 'before_tool_call', pluginId: 'shieldcortex-realtime', nonce, seq: 3, actionKey: 'rm <home>' };
    }
    /** Append one line; returns its lineIndex (every fixture line is newline-terminated). */
    function appendTo(file: string, value: Record<string, unknown> | string): number {
      mkdirSync(dirname(file), { recursive: true });
      const before = existsSync(file) ? readFileSync(file, 'utf8') : '';
      appendFileSync(file, `${typeof value === 'string' ? value : JSON.stringify(value)}\n`);
      return before === '' ? 0 : before.split('\n').length - 1;
    }
    function appendIndex(session: string, value: Record<string, unknown>): number {
      return appendTo(indexPath(session), { recordKind: value.type === 'session_summary' ? 'summary' : 'guard', ...value });
    }
    function legacyReceipt(session: string, fps: string[]): Record<string, unknown> {
      return {
        type: 'session_summary', origin: 'claude-code-stop-hook', sessionKey: sessionKey(session), action: 'session_health',
        outcome: 'action_guard_degraded', guardOutcomeCount: fps.length, guardFingerprints: fps, outcomes: {}, threats: [],
        ts: '2026-08-11T11:00:00.000Z',
      };
    }
    function fingerprintlessSummary(session: string): Record<string, unknown> {
      return {
        type: 'session_summary', origin: 'openclaw-session-end', sessionKey: sessionKey(session), action: 'session_health',
        outcome: 'action_guard_degraded', guardOutcomeCount: 1, outcomes: { failure_denied: 1 }, threats: [],
        firstGuardTs: T, lastGuardTs: T, ts: '2026-08-11T12:00:00.000Z',
      };
    }
    function rowsIn(file: string): Array<Record<string, any>> {
      if (!existsSync(file) || !lstatSync(file).isFile()) return [];
      return readFileSync(file, 'utf8').split('\n').filter(Boolean).flatMap((l) => {
        try { return [JSON.parse(l)]; } catch { return []; }
      });
    }
    function hookReceipts(session: string): Array<Record<string, any>> {
      if (!existsSync(auditDir())) return [];
      return readdirSync(auditDir()).filter((f) => /^realtime-\d{4}-\d{2}-\d{2}\.jsonl$/.test(f)).sort()
        .flatMap((f) => rowsIn(join(auditDir(), f)))
        .filter((r) => r.origin === 'claude-code-stop-hook' && r.sessionKey === sessionKey(session) && r.fingerprintScheme === 2);
    }
    type SpawnResult = ReturnType<typeof runStopHook>;
    function telemetryNotes(): string[] {
      try {
        return hookRows().map((r) => r.notes ?? '');
      } catch {
        return []; // no hook has created the telemetry table yet
      }
    }
    /** Parse the one `coverage=partial` stderr line: gap kinds and counts per pass (complete states are not printed). */
    function gapsFromLine(line: string | undefined): Record<'receipts' | 'guards', Record<string, any>> {
      const out = {
        receipts: { skippedFiles: 0, refusedFiles: 0, failedFiles: 0, droppedLines: 0 } as Record<string, any>,
        guards: { skippedFiles: 0, refusedFiles: 0, failedFiles: 0, droppedLines: 0 } as Record<string, any>,
      };
      for (const token of (line ?? '').split(' ')) {
        const m = /^(receipts|guards):(.+)$/.exec(token);
        if (!m) continue;
        for (const kv of m[2].split(',')) {
          const [k, v] = kv.split('=');
          out[m[1] as 'receipts' | 'guards'][k] = /^\d+$/.test(v) ? Number(v) : v;
        }
      }
      return out;
    }
    /**
     * Run the UNCHANGED hook and reconstruct its result from what it exposes:
     * the receipt it appended (which carries coverage, gaps and
     * pendingRemaining), its stderr lines (mirror failure, sink failure, the
     * one coverage=partial gap line) and the existing telemetry note. There is
     * no test switch in the hook that prints the internal result object, so a
     * shape that writes nothing (existing, pending, nothing found, a failed
     * primary) carries no count here, and a complete pass's `listed`/`absent`
     * states are only visible on a written receipt.
     *
     * HIST1 rides on every run: snapshot after setup, then every pre-existing
     * audit file must keep its bytes as a prefix (EOF appends only).
     * `during` wraps only the spawn (chmod fixtures), so the snapshot and the
     * observation run with normal modes.
     */
    function run(session: string, opts: {
      failRead?: { name: string; open: number };
      during?: (spawn: () => SpawnResult) => SpawnResult;
    } = {}) {
      const receiptsBefore = hookReceipts(session).length;
      const notesBefore = telemetryNotes().length;
      const snap = snapshot();
      const execArgv = opts.failRead
        ? ['--import', `${pathToFileURL(AUDIT_READ_FAULT_PRELOAD).href}?name=${encodeURIComponent(opts.failRead.name)}&open=${opts.failRead.open}&read=2`]
        : [];
      const spawn = () => runStopHook({ session_id: session }, { execArgv });
      const res = opts.during ? opts.during(spawn) : spawn();
      expect(res.status).toBe(0);
      expectAppendOnly(snap);
      const stderr = res.stderr;
      const fresh = hookReceipts(session).slice(receiptsBefore);
      expect(fresh.length).toBeLessThanOrEqual(1);
      const notes = telemetryNotes().slice(notesBefore).join('; ');
      const gapLines = stderr.split('\n').filter((l) => l.includes('action_guard_degraded coverage=partial'));
      expect(gapLines.length).toBeLessThanOrEqual(1);
      const coverage = gapLines.length ? 'partial' : 'bounded-complete';
      const mirrorFailed = stderr.includes('action_guard_degraded index mirror FAILED');
      let result: Record<string, any>;
      if (fresh.length === 1) {
        const r = fresh[0];
        expect(stderr).toContain(`guardOutcomes=${r.guardOutcomeCount}`);
        expect(r.coverage).toBe(coverage);
        result = {
          recorded: true,
          count: r.guardOutcomeCount,
          receipt: mirrorFailed ? 'primary-only' : 'primary+index',
          indexMirror: mirrorFailed ? 'failed' : 'ok',
          coverage: r.coverage,
          coverageGaps: r.coverageGaps,
          ...(r.pendingRemaining !== undefined ? { pendingRemaining: r.pendingRemaining } : {}),
        };
      } else {
        expect(mirrorFailed).toBe(false);
        const base = { coverage, coverageGaps: gapsFromLine(gapLines[0]) };
        if (stderr.includes('audit sink UNWRITABLE')) result = { recorded: false, receipt: 'none', indexMirror: 'not-attempted', ...base };
        else if (notes.includes('action_guard_degraded_existing')) result = { recorded: true, count: 0, existing: true, ...base };
        else if (notes.includes('action_guard_degraded_pending')) result = { recorded: false, pending: true, ...base };
        else {
          expect(notes).not.toContain('action_guard_degraded');
          result = { recorded: false, count: 0, ...base };
        }
      }
      return { stderr, result };
    }
    function withMode(path: string, mode: number, restore: number) {
      return (spawn: () => SpawnResult): SpawnResult => {
        chmodSync(path, mode);
        try {
          return spawn();
        } finally {
          chmodSync(path, restore);
        }
      };
    }
    function expectReceipt(r: Record<string, any>, want: {
      count: number; basis: Record<string, number>; exact: boolean; reasons?: string[]; coverage?: string;
    }): void {
      expect(r.guardOutcomeCount).toBe(want.count);
      expect(r.guardFingerprints).toHaveLength(want.count);
      expect(new Set(r.guardFingerprints).size).toBe(want.count);
      expect(r.identityBasis).toEqual({ eventId: 0, bindingNonce: 0, physicalRow: 0, ...want.basis });
      expect(r.eventCountExact).toBe(want.exact);
      if (want.reasons?.length) {
        expect(r.historicalOverlap).toBe('possible');
        expect([...r.overlapReasons].sort()).toEqual([...want.reasons].sort());
      } else {
        expect(r.historicalOverlap).toBeUndefined();
        expect(r.overlapReasons).toBeUndefined();
      }
      expect(r.coverage).toBe(want.coverage ?? 'bounded-complete');
      expect(r.coverageGaps).toBeDefined();
      // Final write outcomes never land on the row.
      expect(r.receipt).toBeUndefined();
      expect(r.indexMirror).toBeUndefined();
    }
    // HIST1: snapshot after setup; each run may only append.
    function walk(dir: string, out: string[] = []): string[] {
      if (!existsSync(dir)) return out;
      for (const name of readdirSync(dir)) {
        const p = join(dir, name);
        const st = lstatSync(p);
        if (st.isDirectory()) walk(p, out);
        else if (st.isFile() && !name.endsWith('.lock') && name !== 'memories.db') out.push(p);
      }
      return out;
    }
    function snapshot(): Map<string, Buffer> {
      return new Map(walk(auditDir()).map((p) => [p, readFileSync(p)]));
    }
    function expectAppendOnly(snap: Map<string, Buffer>): void {
      for (const [p, before] of snap) {
        const after = readFileSync(p);
        expect(after.subarray(0, before.length).equals(before)).toBe(true);
      }
    }

    it('R3: a bound nonce-only row mirrored in realtime and the index counts once, exactly', () => {
      const r = row('r3-654', bound(nonceOf(1)));
      appendTo(auditFileForDate('2026-08-10'), r);
      appendIndex('r3-654', r);
      const snap = snapshot();
      const { result } = run('r3-654');
      expect(result).toMatchObject({ recorded: true, count: 1, receipt: 'primary+index', indexMirror: 'ok', coverage: 'bounded-complete' });
      expectReceipt(hookReceipts('r3-654')[0], { count: 1, basis: { bindingNonce: 1 }, exact: true });
      expect(run('r3-654').result).toMatchObject({ recorded: true, count: 0, existing: true, coverage: 'bounded-complete' });
      expect(hookReceipts('r3-654')).toHaveLength(1);
      expectAppendOnly(snap);
    });

    it('R6: distinct IDs with identical content and ts, each mirrored, count 2', () => {
      for (const n of [2, 3]) {
        const r = row('r6-654', { auditEventId: eid(n) });
        appendTo(auditFileForDate('2026-08-10'), r);
        appendIndex('r6-654', r);
      }
      expect(run('r6-654').result.count).toBe(2);
      expectReceipt(hookReceipts('r6-654')[0], { count: 2, basis: { eventId: 2 }, exact: true });
    });

    it('R7: a pre-patch receipt with HEAD v1 physical fingerprints for both copies is still honoured', () => {
      const r = row('r7-654', bound(nonceOf(4)));
      const rtFile = auditFileForDate('2026-08-10');
      const rtLine = appendTo(rtFile, r);
      const ixLine = appendIndex('r7-654', r);
      appendTo(rtFile, legacyReceipt('r7-654', [v1Fingerprint(r, `${rtFile}:${rtLine}`), v1Fingerprint(r, `${indexPath('r7-654')}:${ixLine}`)]));
      expect(run('r7-654').result).toMatchObject({ existing: true, count: 0 });
      expect(hookReceipts('r7-654')).toHaveLength(0);
    });

    it('R8a: the index copy\'s alias still covers a nonce row whose realtime file was renamed away', () => {
      const r = row('r8a-654', bound(nonceOf(5)));
      const rtFile = auditFileForDate('2026-08-10');
      const rtLine = appendTo(rtFile, r);
      const ixLine = appendIndex('r8a-654', r);
      appendIndex('r8a-654', legacyReceipt('r8a-654', [v1Fingerprint(r, `${rtFile}:${rtLine}`), v1Fingerprint(r, `${indexPath('r8a-654')}:${ixLine}`)]));
      renameSync(rtFile, join(auditDir(), 'archived-2026-08-10.jsonl'));
      expect(run('r8a-654').result).toMatchObject({ existing: true, count: 0 });
      expect(hookReceipts('r8a-654')).toHaveLength(0);
    });

    it('R8b: a reachable legacy receipt that could only have listed the moved copy → recount, disclosed', () => {
      const r = row('r8b-654', bound(nonceOf(6)));
      const rtFile = auditFileForDate('2026-08-10');
      const rtLine = appendTo(rtFile, r);
      appendIndex('r8b-654', r);
      appendIndex('r8b-654', legacyReceipt('r8b-654', [v1Fingerprint(r, `${rtFile}:${rtLine}`)]));
      renameSync(rtFile, join(auditDir(), 'archived-2026-08-10.jsonl'));
      expect(run('r8b-654').result).toMatchObject({ recorded: true, count: 1, coverage: 'bounded-complete' });
      expectReceipt(hookReceipts('r8b-654')[0], { count: 1, basis: { bindingNonce: 1 }, exact: true, reasons: ['position-dependent-receipt'] });
    });

    it('R9 — undetectable overlap (G2): pins limitation; a receipt only in the renamed file leaves no indicator', () => {
      const r = row('r9-654', bound(nonceOf(7)));
      const rtFile = auditFileForDate('2026-08-10');
      const rtLine = appendTo(rtFile, r);
      appendIndex('r9-654', r);
      appendTo(rtFile, legacyReceipt('r9-654', [v1Fingerprint(r, `${rtFile}:${rtLine}`)]));
      renameSync(rtFile, join(auditDir(), 'archived-2026-08-10.jsonl'));
      expect(run('r9-654').result.count).toBe(1);
      expectReceipt(hookReceipts('r9-654')[0], { count: 1, basis: { bindingNonce: 1 }, exact: true });
    });

    it('L1 (pins G1): one ID-less, nonce-less row mirrored counts 2 and is labelled not exact — never merged by content', () => {
      const r = row('l1-654');
      appendTo(auditFileForDate('2026-08-10'), r);
      appendIndex('l1-654', r);
      expect(run('l1-654').result.count).toBe(2);
      expectReceipt(hookReceipts('l1-654')[0], { count: 2, basis: { physicalRow: 2 }, exact: false });
    });

    it('L3: an identical-content ID-less event primary-only plus one index-only count 2', () => {
      appendTo(auditFileForDate('2026-08-10'), row('l3-654'));
      appendIndex('l3-654', row('l3-654'));
      expect(run('l3-654').result.count).toBe(2);
    });

    it('L4: after the covered realtime file leaves view, a new identical-content row is pending and disclosed', () => {
      const old = auditFileForDate('2026-08-09');
      appendTo(old, row('l4-654'));
      expect(run('l4-654').result.count).toBe(1);
      renameSync(old, join(auditDir(), 'archived-2026-08-09.jsonl'));
      appendTo(auditFileForDate('2026-08-10'), row('l4-654'));
      expect(run('l4-654').result.count).toBe(1);
      expectReceipt(hookReceipts('l4-654')[1], { count: 1, basis: { physicalRow: 1 }, exact: false, reasons: ['position-dependent-receipt'] });
    });

    it('L6: lines prepended before a covered ID-less row (fixture-only) → recount, not suppression', () => {
      const file = auditFileForDate('2026-08-10');
      appendTo(file, row('l6-654'));
      expect(run('l6-654').result.count).toBe(1);
      writeFileSync(file, `${JSON.stringify({ type: 'noise' })}\n${readFileSync(file, 'utf8')}`);
      expect(run('l6-654').result.count).toBe(1);
      expectReceipt(hookReceipts('l6-654')[1], { count: 1, basis: { physicalRow: 1 }, exact: false, reasons: ['position-dependent-receipt'] });
    });

    it('H1: a mirrored fingerprint-less OpenClaw summary never suppresses — late, equal and backdated IDs all count', () => {
      appendTo(auditFileForDate('2026-08-10'), fingerprintlessSummary('h1-654'));
      appendIndex('h1-654', fingerprintlessSummary('h1-654'));
      appendIndex('h1-654', row('h1-654', { auditEventId: eid(10), ts: '2026-08-11T09:59:59.000Z' }));
      appendIndex('h1-654', row('h1-654', { auditEventId: eid(11), ts: T }));
      appendIndex('h1-654', row('h1-654', { auditEventId: eid(12), ts: '2026-08-11T10:00:01.000Z' }));
      expect(run('h1-654').result.count).toBe(3);
      const r = hookReceipts('h1-654')[0];
      expectReceipt(r, { count: 3, basis: { eventId: 3 }, exact: true, reasons: ['fingerprintless-summary'] });
      expect(r.unknownMembershipSummaryRows).toBe(2);
    });

    it('F-2: the hook keeps its own outcome set — OpenClaw card_* and denied rows are not counted here (G7)', () => {
      let n = 20;
      for (const outcome of ['card_denied', 'card_timeout', 'card_cancelled', 'denied']) {
        appendIndex('f2-654', row('f2-654', { outcome, auditEventId: eid(n += 1) }));
      }
      appendIndex('f2-654', row('f2-654', { auditEventId: eid(n += 1) }));
      expect(run('f2-654').result.count).toBe(1);
    });

    it('F-1: notify rows and foreign-sessionKey rows inside the index are ignored and absent from the receipt', () => {
      appendIndex('f1-654', row('f1-654', { action: 'notify', auditEventId: eid(25) }));
      appendIndex('f1-654', row('f1-654', { sessionKey: sessionKey('someone-else-654'), auditEventId: eid(26) }));
      const counted = row('f1-654', { auditEventId: eid(27) });
      appendIndex('f1-654', counted);
      expect(run('f1-654').result).toMatchObject({ recorded: true, count: 1 });
      const r = hookReceipts('f1-654')[0];
      expectReceipt(r, { count: 1, basis: { eventId: 1 }, exact: true });
      // An eventId primary is position-independent, so it is HEAD v1 at any physKey.
      expect(r.guardFingerprints).toEqual([v1Fingerprint(counted, '')]);
    });

    it('L5: two ID-less rows whose raw labels both clean to redacted-signal stay two physical rows', () => {
      const file = auditFileForDate('2026-08-10');
      appendTo(file, row('l5-654', { threats: ['raw-label-one'] }));
      appendTo(file, row('l5-654', { threats: ['raw-label-two'] }));
      expect(run('l5-654').result.count).toBe(2);
      const r = hookReceipts('l5-654')[0];
      expectReceipt(r, { count: 2, basis: { physicalRow: 2 }, exact: false });
      expect(r.threats).toEqual(['redacted-signal']);
      expect(run('l5-654').result).toMatchObject({ existing: true, count: 0 });
    });

    it('W2: a refused (symlinked) index → primary-only receipt, partial coverage, recovered from realtime', () => {
      const key = sessionKey('w2-654');
      const indexDir = join(auditDir(), 'session-guard');
      mkdirSync(indexDir, { recursive: true });
      const victim = join(home, 'w2-victim.jsonl');
      writeFileSync(victim, 'victim-start\n');
      symlinkSync(victim, join(indexDir, `${key}.jsonl`));
      appendTo(auditFileForDate('2026-08-10'), row('w2-654', { auditEventId: eid(30) }));
      const first = run('w2-654').result;
      expect(first).toMatchObject({ recorded: true, count: 1, receipt: 'primary-only', indexMirror: 'failed', coverage: 'partial' });
      expect(first.coverageGaps.receipts.index).toBe('refused');
      expect(first.coverageGaps.guards.index).toBe('refused');
      expect(readFileSync(victim, 'utf8')).toBe('victim-start\n');
      const second = run('w2-654').result;
      expect(second).toMatchObject({ recorded: true, count: 0, existing: true, coverage: 'partial' });
      expect(hookReceipts('w2-654')).toHaveLength(1);
    });

    it('W3: a failed primary is never coverage — no mirror is attempted, and the next run summarises once', () => {
      appendTo(auditFileForDate('2026-08-10'), row('w3-654', { auditEventId: eid(31) }));
      // Today's primary path is occupied by a directory: the append must fail.
      mkdirSync(auditFile(), { recursive: true });
      const first = run('w3-654').result;
      expect(first).toMatchObject({ recorded: false, receipt: 'none', indexMirror: 'not-attempted' });
      expect(rowsIn(indexPath('w3-654')).filter((r) => r.recordKind === 'summary')).toHaveLength(0);
      rmSync(auditFile(), { recursive: true, force: true });
      expect(run('w3-654').result).toMatchObject({ recorded: true, count: 1, receipt: 'primary+index' });
      expect(run('w3-654').result).toMatchObject({ existing: true, count: 0 });
    });

    itNonRoot('W4: both sinks failing is the same as W3 — no mirror without a primary, then one summary', () => {
      appendTo(auditFileForDate('2026-08-10'), row('w4-654', { auditEventId: eid(32) }));
      // Primary: today's path is a directory. Mirror: the index dir exists but
      // cannot be written, so an attempted mirror would print its FAILED line.
      mkdirSync(auditFile(), { recursive: true });
      const indexDir = join(auditDir(), 'session-guard');
      mkdirSync(indexDir, { recursive: true });
      const first = run('w4-654', { during: withMode(indexDir, 0o500, 0o700) });
      expect(first.result).toMatchObject({ recorded: false, receipt: 'none', indexMirror: 'not-attempted' });
      expect(first.stderr).toContain('audit sink UNWRITABLE');
      expect(first.stderr).not.toContain('index mirror FAILED');
      expect(existsSync(indexPath('w4-654'))).toBe(false);
      rmSync(auditFile(), { recursive: true, force: true });
      expect(run('w4-654').result).toMatchObject({ recorded: true, count: 1, receipt: 'primary+index' });
      expect(run('w4-654').result).toMatchObject({ existing: true, count: 0 });
      expect(hookReceipts('w4-654')).toHaveLength(1);
      expectReceipt(hookReceipts('w4-654')[0], { count: 1, basis: { eventId: 1 }, exact: true });
    });

    it('B1: a receipt past the 256-file cap is unseen → recount with receipt-coverage-partial', () => {
      const r = row('b1-654', { auditEventId: eid(40) });
      appendIndex('b1-654', r);
      for (let i = 0; i < 257; i += 1) {
        const date = `2025-${String(1 + Math.floor(i / 28)).padStart(2, '0')}-${String(1 + (i % 28)).padStart(2, '0')}`;
        appendTo(auditFileForDate(date), i === 0 ? legacyReceipt('b1-654', [v1Fingerprint(r, '')]) : { type: 'noise' });
      }
      const { result } = run('b1-654');
      expect(result).toMatchObject({ recorded: true, count: 1, coverage: 'partial' });
      expect(result.coverageGaps.receipts.skippedFiles).toBeGreaterThan(0);
      expectReceipt(hookReceipts('b1-654')[0], { count: 1, basis: { eventId: 1 }, exact: true, coverage: 'partial', reasons: ['receipt-coverage-partial'] });
    }, 30_000);

    it('B2: an oversized realtime candidate is skipped (sparse; never read) → partial', () => {
      appendIndex('b2-654', row('b2-654', { auditEventId: eid(41) }));
      const big = auditFileForDate('2026-08-09');
      appendTo(big, { type: 'noise' });
      truncateSync(big, 64 * 1024 * 1024 + 1);
      const { result } = run('b2-654');
      expect(result.coverage).toBe('partial');
      expect(result.coverageGaps.receipts.skippedFiles).toBe(1);
    }, 30_000);

    it('B3: an index past its 64 MiB prefix is truncated → partial; the receipt beyond it is unseen', () => {
      const r = row('b3-654', { auditEventId: eid(42) });
      appendIndex('b3-654', r);
      truncateSync(indexPath('b3-654'), 64 * 1024 * 1024 + 16);
      appendFileSync(indexPath('b3-654'), `\n${JSON.stringify({ recordKind: 'summary', ...legacyReceipt('b3-654', [v1Fingerprint(r, '')]) })}\n`);
      const { result } = run('b3-654');
      expect(result.coverageGaps.receipts.index).toBe('truncated');
      expect(result).toMatchObject({ recorded: true, count: 1, coverage: 'partial' });
      expect(hookReceipts('b3-654')[0].overlapReasons).toContain('receipt-coverage-partial');
    }, 60_000);

    it('B4: a crafted >1 MiB receipt line is dropped, suppresses nothing, and is disclosed', () => {
      const r = row('b4-654', { auditEventId: eid(43) });
      appendIndex('b4-654', r);
      appendIndex('b4-654', { ...legacyReceipt('b4-654', [v1Fingerprint(r, '')]), pad: 'x'.repeat(1024 * 1024 + 8) });
      const { result } = run('b4-654');
      expect(result).toMatchObject({ recorded: true, count: 1, coverage: 'partial' });
      expect(result.coverageGaps.receipts.droppedLines).toBeGreaterThan(0);
    });

    it('B5: 16,385 pending IDs → 16,384 + 1 across two receipts, each line under 1 MiB, none twice', () => {
      const lines: string[] = [];
      for (let i = 0; i < 16385; i += 1) lines.push(JSON.stringify({ recordKind: 'guard', ...row('b5-654', { auditEventId: eid(100_000 + i) }) }));
      mkdirSync(join(auditDir(), 'session-guard'), { recursive: true });
      writeFileSync(indexPath('b5-654'), `${lines.join('\n')}\n`);
      expect(run('b5-654').result).toMatchObject({ recorded: true, count: 16384, pendingRemaining: 1 });
      expect(run('b5-654').result).toMatchObject({ recorded: true, count: 1 });
      const receipts = hookReceipts('b5-654');
      expect(receipts).toHaveLength(2);
      expect(receipts[0].pendingRemaining).toBe(1);
      expect(Buffer.byteLength(JSON.stringify(receipts[0]), 'utf8')).toBeLessThan(1024 * 1024);
      expect(new Set([...receipts[0].guardFingerprints, ...receipts[1].guardFingerprints]).size).toBe(16385);
      expect(run('b5-654').result).toMatchObject({ existing: true, count: 0 });
    }, 60_000);

    it('B6: a hard-linked realtime candidate is refused → partial', () => {
      appendIndex('b6-654', row('b6-654', { auditEventId: eid(44) }));
      appendTo(auditFileForDate('2026-08-09'), { type: 'noise' });
      linkSync(auditFileForDate('2026-08-09'), join(home, 'b6-hardlink'));
      const { result } = run('b6-654');
      expect(result.coverage).toBe('partial');
      expect(result.coverageGaps.receipts.refusedFiles).toBe(1);
      expect(result.coverageGaps.guards.refusedFiles).toBe(1);
    });

    itNonRoot('B7: an unreadable receipt file is a failed source in both passes → recount, partial, disclosed', () => {
      const r = row('b7-654', { auditEventId: eid(53) });
      appendIndex('b7-654', r);
      const file = auditFileForDate('2026-08-09');
      appendTo(file, legacyReceipt('b7-654', [v1Fingerprint(r, '')]));
      const { result } = run('b7-654', { during: withMode(file, 0o000, 0o600) });
      expect(result).toMatchObject({ recorded: true, count: 1, coverage: 'partial' });
      expect(result.coverageGaps.receipts.failedFiles).toBe(1);
      expect(result.coverageGaps.guards.failedFiles).toBe(1);
      expectReceipt(hookReceipts('b7-654')[0], { count: 1, basis: { eventId: 1 }, exact: true, coverage: 'partial', reasons: ['receipt-coverage-partial'] });
      // Readable again, the receipt it could not see and the new one both cover the guard.
      expect(run('b7-654').result).toMatchObject({ existing: true, count: 0, coverage: 'bounded-complete' });
    });

    itNonRoot('B8: an audit dir that cannot be listed is NEVER bounded-complete (discovery failure)', () => {
      const r = row('b8-654', { auditEventId: eid(45) });
      appendIndex('b8-654', r);
      appendTo(auditFile(), legacyReceipt('b8-654', [v1Fingerprint(r, '')]));
      mkdirSync(join(auditDir(), '.locks'), { recursive: true });
      const out = run('b8-654', { during: withMode(auditDir(), 0o100, 0o700) });
      expect(out.result.coverageGaps.receipts.auditDir).toBe('failed');
      expect(out.result).toMatchObject({ recorded: true, count: 1, coverage: 'partial' });
      expectReceipt(hookReceipts('b8-654')[0], { count: 1, basis: { eventId: 1 }, exact: true, coverage: 'partial', reasons: ['receipt-coverage-partial'] });
    });

    it('B9(i): nothing on disk is a KNOWN absence — bounded-complete, never "failed"', () => {
      const { result, stderr } = run('b9-654');
      // Nothing found, no receipt, no telemetry note, and no gap line: a failed
      // inspection of the (lock-created, empty) audit dir or the missing index
      // would have printed one. The listed/absent split itself is only on receipts.
      expect(result).toMatchObject({ recorded: false, count: 0, coverage: 'bounded-complete' });
      expect(stderr).not.toContain('coverage=partial');
      expect(hookReceipts('b9-654')).toHaveLength(0);
    });

    it('B9(ii): index present, audit dir listed with no realtime files → bounded-complete on the receipt', () => {
      appendIndex('b9b-654', row('b9b-654', { auditEventId: eid(52) }));
      expect(readdirSync(auditDir()).filter((f) => /^realtime-/.test(f))).toHaveLength(0);
      const { result } = run('b9b-654');
      expect(result).toMatchObject({ recorded: true, count: 1, coverage: 'bounded-complete' });
      for (const pass of ['receipts', 'guards'] as const) {
        expect(result.coverageGaps[pass]).toEqual({ auditDir: 'listed', index: 'read', skippedFiles: 0, refusedFiles: 0, failedFiles: 0, droppedLines: 0 });
      }
      expectReceipt(hookReceipts('b9b-654')[0], { count: 1, basis: { eventId: 1 }, exact: true });
    });

    itNonRoot('B10: an index that cannot be inspected is failed, not absent', () => {
      appendTo(auditFileForDate('2026-08-10'), row('b10-654', { auditEventId: eid(46) }));
      appendIndex('b10-654', row('b10-654', { auditEventId: eid(46) }));
      const out = run('b10-654', { during: withMode(join(auditDir(), 'session-guard'), 0o000, 0o700) });
      expect(out.result.coverageGaps.receipts.index).toBe('failed');
      expect(out.result.coverageGaps.guards.index).toBe('failed');
      expect(out.result).toMatchObject({ recorded: true, count: 1, coverage: 'partial', receipt: 'primary-only' });
    });

    it('B11 (receipts pass): a mid-stream failure after a guard line, before a receipt line → recount, disclosed', () => {
      const r = row('b11-654', { auditEventId: eid(47) });
      appendIndex('b11-654', r);
      const file = auditFileForDate('2026-08-09');
      appendTo(file, r);
      appendTo(file, { type: 'noise', pad: 'x'.repeat(70 * 1024) });
      appendTo(file, legacyReceipt('b11-654', [v1Fingerprint(r, '')]));
      // Test-owned preload: the first open of this file (receipts pass) fails on its second chunk read.
      const { result } = run('b11-654', { failRead: { name: 'realtime-2026-08-09.jsonl', open: 1 } });
      expect(result.coverageGaps.receipts.failedFiles).toBe(1);
      expect(result.coverageGaps.guards.failedFiles).toBe(0);
      expect(result).toMatchObject({ recorded: true, count: 1, coverage: 'partial' });
      expect(hookReceipts('b11-654')[0].overlapReasons).toEqual(['receipt-coverage-partial']);
    });

    it('B11 (guards pass): a guard source failing mid-stream is a gap, but adds no overlap reason', () => {
      appendIndex('b11g-654', row('b11g-654', { auditEventId: eid(48) }));
      const file = auditFileForDate('2026-08-09');
      appendTo(file, row('b11g-654', { auditEventId: eid(49) }));
      appendTo(file, { type: 'noise', pad: 'x'.repeat(70 * 1024) });
      // The second open of the same file is the guards pass.
      const { result } = run('b11g-654', { failRead: { name: 'realtime-2026-08-09.jsonl', open: 2 } });
      expect(result.coverageGaps.guards.failedFiles).toBe(1);
      expect(result.coverageGaps.receipts.failedFiles).toBe(0);
      // Rows of the failed source are neither counted nor suppressing: only the index guard.
      expect(result).toMatchObject({ recorded: true, count: 1, coverage: 'partial' });
      const r = hookReceipts('b11g-654')[0];
      expect(r.coverage).toBe('partial');
      expect(r.overlapReasons).toBeUndefined();
    });

    it('B12(i): existing travels with partial coverage and one gap line naming kinds and counts, no paths', () => {
      const r = row('b12-654', { auditEventId: eid(50) });
      appendIndex('b12-654', r);
      appendIndex('b12-654', legacyReceipt('b12-654', [v1Fingerprint(r, '')]));
      const outside = join(home, 'b12-outside.jsonl');
      writeFileSync(outside, '\n');
      symlinkSync(outside, auditFileForDate('2026-08-08'));
      const { result, stderr } = run('b12-654');
      expect(result).toMatchObject({ recorded: true, count: 0, existing: true, coverage: 'partial' });
      const gapLines = stderr.split('\n').filter((l) => l.includes('coverage=partial'));
      expect(gapLines).toHaveLength(1);
      expect(gapLines[0]).toContain('refusedFiles=1');
      expect(gapLines[0]).not.toContain(home);
    });

    it('B12(ii): the no-lock pending result carries coverage; telemetry notes are unchanged', () => {
      writeFileSync(join(home, '.shieldcortex', 'config.json'), JSON.stringify({
        autoMemory: { enableStop: true, stopHookSamplingTurns: 5, stopHookSalienceBypass: false },
      }));
      appendTo(auditFileForDate('2026-08-10'), row('b12b-654', { auditEventId: eid(51) }));
      const lockDir = join(auditDir(), '.locks');
      mkdirSync(lockDir, { recursive: true });
      writeFileSync(join(lockDir, `${sessionKey('b12b-654')}.lock`), JSON.stringify({ pid: process.pid, startedAt: new Date().toISOString() }));
      const { result, stderr } = run('b12b-654');
      expect(result).toMatchObject({ recorded: false, pending: true, coverage: 'bounded-complete' });
      expect(stderr).not.toContain('coverage=partial');
      expect(hookReceipts('b12b-654')).toHaveLength(0);
      expect(hookRows()).toEqual([
        expect.objectContaining({ exit_code: 1, notes: expect.stringContaining('action_guard_degraded_pending') }),
      ]);
      // The same no-lock path with a refused candidate: coverage travels with
      // the pending result as one gap line; the telemetry note is unchanged.
      const outside = join(home, 'b12b-outside.jsonl');
      writeFileSync(outside, '\n');
      symlinkSync(outside, auditFileForDate('2026-08-08'));
      const partial = run('b12b-654');
      expect(partial.result).toMatchObject({ recorded: false, pending: true, coverage: 'partial' });
      expect(partial.result.coverageGaps.receipts.refusedFiles).toBe(1);
      expect(partial.result.coverageGaps.guards.refusedFiles).toBe(1);
      const gapLine = partial.stderr.split('\n').find((l) => l.includes('coverage=partial'));
      expect(gapLine).toContain('refusedFiles=1');
      expect(gapLine).not.toContain(home);
      expect(hookReceipts('b12b-654')).toHaveLength(0);
      expect(hookRows()).toHaveLength(2);
      expect(hookRows()[1].notes).toContain('action_guard_degraded_pending');
    });

    it('X1 (reader contract, not reachability): hook then OpenClaw, and OpenClaw then hook, never count an ID twice', () => {
      for (const order of ['hook-first', 'openclaw-first'] as const) {
        const session = `x1-${order}`;
        const r = row(session, { auditEventId: eid(order === 'hook-first' ? 60 : 61) });
        appendTo(auditFileForDate('2026-08-10'), r);
        appendIndex(session, r);
        const openclaw = () => recordActionGuardDegraded(session, { home, salt: SESSION_SALT });
        if (order === 'hook-first') {
          expect(run(session).result.count).toBe(1);
          expect(openclaw()).toMatchObject({ existing: true, count: 0 });
        } else {
          expect(openclaw()).toMatchObject({ recorded: true, count: 1 });
          expect(run(session).result).toMatchObject({ existing: true, count: 0 });
        }
        const all = readdirSync(auditDir()).filter((f) => /^realtime-/.test(f)).flatMap((f) => rowsIn(join(auditDir(), f)))
          .filter((x) => x.type === 'session_summary' && x.sessionKey === sessionKey(session));
        expect(all).toHaveLength(1);
      }
    });
  });

});

function mkdtempCompat(prefix: string): string {
  return mkdtempSync(join(tmpdir(), prefix));
}
