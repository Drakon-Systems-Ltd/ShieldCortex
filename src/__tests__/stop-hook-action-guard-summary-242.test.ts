import { spawn, spawnSync } from 'node:child_process';
import { createHmac } from 'node:crypto';
import Database from 'better-sqlite3';
import { existsSync, lstatSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, symlinkSync, unlinkSync, utimesSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve, dirname } from 'node:path';
import { fileURLToPath } from 'node:url';
import { afterEach, beforeEach, describe, expect, it } from '@jest/globals';

const __dirname = dirname(fileURLToPath(import.meta.url));

const REPO = resolve(__dirname, '..', '..');
const STOP_HOOK = join(REPO, 'scripts', 'stop-hook.mjs');
const PRE_TOOL_HOOK = join(REPO, 'scripts', 'pre-tool-hook.mjs');
const SESSION_SALT = '0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef';
const SECRET_SENTINEL = 'PUPIL_OR_SECRET_VALUE_SHOULD_NOT_LEAVE_AUDIT_PREVIEW';

describe('stop hook — Action Guard run summary (#242)', () => {
  let home: string;

  beforeEach(() => {
    home = mkdtempCompat('sc-stop-242-');
    const db = new Database(dbFile());
    db.close();
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

  function runStopHook(payload: Record<string, unknown>, opts: { timeout?: number; env?: Record<string, string> } = {}) {
    return spawnSync(process.execPath, [STOP_HOOK], {
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
    // Race-hardening: concurrent lock writers can leave auditDir non-empty briefly (ENOTEMPTY).
    {
      const deadline = Date.now() + 2000;
      // eslint-disable-next-line no-constant-condition
      while (true) {
        try {
          rmSync(auditDir, { recursive: true, force: true });
          break;
        } catch (err: any) {
          if (err?.code !== 'ENOTEMPTY' && err?.code !== 'EBUSY') throw err;
          if (Date.now() > deadline) throw err;
          await new Promise((r) => setTimeout(r, 25));
        }
      }
    }
    symlinkSync(outside, auditDir);

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
    // Race-hardening: concurrent lock writers can leave auditDir non-empty briefly (ENOTEMPTY).
    {
      const deadline = Date.now() + 2000;
      // eslint-disable-next-line no-constant-condition
      while (true) {
        try {
          rmSync(auditDir, { recursive: true, force: true });
          break;
        } catch (err: any) {
          if (err?.code !== 'ENOTEMPTY' && err?.code !== 'EBUSY') throw err;
          if (Date.now() > deadline) throw err;
          await new Promise((r) => setTimeout(r, 25));
        }
      }
    }
    symlinkSync(outside, auditDir);

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
});

function mkdtempCompat(prefix: string): string {
  return mkdtempSync(join(tmpdir(), prefix));
}
