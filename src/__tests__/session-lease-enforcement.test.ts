import { spawn, type ChildProcess } from 'node:child_process';
import { once } from 'node:events';
import { mkdtempSync, mkdirSync, writeFileSync, rmSync, copyFileSync, readFileSync, existsSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import { describe, it, expect, beforeEach, afterEach } from '@jest/globals';

/**
 * #227 — ENFORCEMENT tests, not arithmetic tests.
 *
 * The PR was blocked because "green unit tests prove dead-code arithmetic,
 * not enforcement": zero runtime call sites consulted the lease. These tests
 * spawn the REAL PreToolUse hook as a real process against a sandbox home
 * carrying a real DECISIONS.md, and assert the tool call is actually refused
 * on the wire (the JSON decision payload) — the Claude Code plane, end to end.
 * The OpenClaw plane's wiring is covered by the interceptor suite; the parity
 * test pins both surfaces to keep consulting the lease.
 */

const HOOK_PATH = resolve(dirname(fileURLToPath(import.meta.url)), '..', '..', 'scripts', 'pre-tool-hook.mjs');
const DIST_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..', '..', 'dist');
const INSTALLED_COMMAND = `${process.execPath} ${join(DIST_ROOT, 'index.js')} hook pre-tool`;

type HookRun = { stdout: string; stderr: string; code: number };

function runHook(home: string, toolName: string, toolInput: Record<string, unknown>, sessionId = 'lease-enforcement-test'): Promise<HookRun> {
  return new Promise((res, reject) => {
    const child = spawn(process.execPath, [HOOK_PATH], {
      stdio: ['pipe', 'pipe', 'pipe'],
      env: {
        ...process.env,
        HOME: home,
        USERPROFILE: home,
        SHIELDCORTEX_CONFIG_DIR: join(home, '.shieldcortex'),
        SHIELDCORTEX_DIST_ROOT: DIST_ROOT,
      },
    });
    let stdout = '';
    let stderr = '';
    child.stdout.on('data', (c) => { stdout += c.toString(); });
    child.stderr.on('data', (c) => { stderr += c.toString(); });
    child.on('error', reject);
    child.on('close', (code) => res({ stdout, stderr, code: code ?? 0 }));
    child.stdin.write(JSON.stringify({
      session_id: sessionId,
      cwd: '/tmp',
      permission_mode: 'default',
      tool_name: toolName,
      tool_input: toolInput,
    }));
    child.stdin.end();
  });
}

function decisionOf(run: HookRun): { permissionDecision?: string; permissionDecisionReason?: string } {
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

function startHarness(home: string): ChildProcess {
  const source = join(home, 'lease-harness.mjs');
  writeFileSync(source, `
    import { spawn } from 'node:child_process';
    process.on('message', ({ id, sessionId }) => {
      const child = spawn('/bin/sh', ['-c', ${JSON.stringify(INSTALLED_COMMAND)}], {
        env: { ...process.env, HOME: ${JSON.stringify(home)}, USERPROFILE: ${JSON.stringify(home)},
          SHIELDCORTEX_CONFIG_DIR: ${JSON.stringify(join(home, '.shieldcortex'))}, SHIELDCORTEX_DIST_ROOT: ${JSON.stringify(DIST_ROOT)} },
        stdio: ['pipe', 'pipe', 'pipe'],
      });
      let stdout = ''; let stderr = '';
      child.stdout.on('data', c => { stdout += c; });
      child.stderr.on('data', c => { stderr += c; });
      child.on('close', code => process.send({ id, stdout, stderr, code }));
      child.stdin.end(JSON.stringify({ session_id: sessionId, cwd: '/tmp', permission_mode: 'default',
        tool_name: 'Bash', tool_input: { command: 'npm publish' } }));
    });
  `);
  return spawn(process.execPath, [source], { stdio: ['ignore', 'ignore', 'pipe', 'ipc'] });
}

let hookRequest = 0;
function throughHarness(harness: ChildProcess, sessionId: string): Promise<HookRun> {
  return new Promise((resolve, reject) => {
    const id = ++hookRequest;
    const onMessage = (reply: { id: number } & HookRun) => {
      if (reply.id !== id) return;
      harness.off('message', onMessage);
      resolve(reply);
    };
    harness.on('message', onMessage);
    harness.send({ id, sessionId }, (error) => { if (error) { harness.off('message', onMessage); reject(error); } });
  });
}

let home: string;
beforeEach(() => {
  home = mkdtempSync(join(tmpdir(), 'sc-lease-e2e-'));
  mkdirSync(join(home, '.shieldcortex'), { recursive: true });
  writeFileSync(
    join(home, '.shieldcortex', 'config.json'),
    JSON.stringify({ actionGuard: { enabled: true, enforce: true } }),
  );
});
afterEach(() => rmSync(home, { recursive: true, force: true }));

describe('#227 — the freeze binds the Claude Code plane, on the wire', () => {
  it('a lease minted by one hook remains held for another session after the first hook exits', async () => {
    const first = await runHook(home, 'Bash', { command: 'npm publish' }, 'session-a');
    expect(first.code).toBe(0);
    expect(decisionOf(first).permissionDecision).not.toBe('deny');

    const record = JSON.parse(readFileSync(join(home, '.shieldcortex', 'leases', 'leases.json'), 'utf-8'))
      .leases['npm-publish'];
    expect(typeof record.holder).toBe('string');
    expect(record.holder.length).toBeGreaterThan(0);
    expect(record.pid).toBe(process.pid);

    const second = await runHook(home, 'Bash', { command: 'npm publish' }, 'session-b');
    const decision = decisionOf(second);
    expect(decision.permissionDecision).toBe('deny');
    expect(decision.permissionDecisionReason).toContain('held by another session');
  });

  it('a frozen scope DENIES the tool call, quoting the freeze', async () => {
    writeFileSync(
      join(home, '.shieldcortex', 'DECISIONS.md'),
      '| FROZEN | 2026-08-10 | nobody publishes to npm until the independent review completes |\n',
    );

    const run = await runHook(home, 'Bash', { command: 'npm publish' });
    const decision = decisionOf(run);
    expect(decision.permissionDecision).toBe('deny');
    expect(decision.permissionDecisionReason ?? '').toContain('FROZEN');
    // The refusal explains how a freeze is lifted — refusals that don't say why
    // get routed around.
    expect(decision.permissionDecisionReason ?? '').toContain('DECISIONS.md');
  });

  it('the 11:30 replay: the freeze binds a session that never saw it, 77 seconds later', async () => {
    writeFileSync(
      join(home, '.shieldcortex', 'DECISIONS.md'),
      '| FROZEN | nobody installs this package on fleet hosts until an independent review |\n',
    );

    const run = await runHook(home, 'Bash', { command: 'npm install -g shieldcortex@4.48.0' });
    const decision = decisionOf(run);
    expect(decision.permissionDecision).toBe('deny');
  });

  it('an unscoped command is untouched by the lease layer', async () => {
    writeFileSync(
      join(home, '.shieldcortex', 'DECISIONS.md'),
      '| FROZEN | nobody publishes to npm until review |\n',
    );

    const run = await runHook(home, 'Bash', { command: 'git status' });
    const decision = decisionOf(run);
    // git status is benign: the guard allows with no decision payload at all.
    expect(decision.permissionDecision).toBeUndefined();
  });

  it('with no freeze on the scope, the lease layer does not deny', async () => {
    const run = await runHook(home, 'Bash', { command: 'npm install -g shieldcortex@latest' });
    const decision = decisionOf(run);
    expect(decision.permissionDecisionReason ?? '').not.toContain('FROZEN');
  });

  it('editing the ledger itself is a guarded action (integrity boundary)', async () => {
    const ledger = join(home, '.shieldcortex', 'DECISIONS.md');
    writeFileSync(ledger, '| FROZEN | npm publish until review |\n');

    const run = await runHook(home, 'Bash', { command: `echo lifted > ${ledger}` });
    const decision = decisionOf(run);
    // Any non-undefined decision that is not a clean pass counts: the edit must
    // not sail through as benign. (In default mode this surfaces as ask/deny.)
    expect(decision.permissionDecision === 'ask' || decision.permissionDecision === 'deny').toBe(true);
  });
});

describe('#553 — installed hook records the persistent harness', () => {
  it('holds a second harness through sh and launcher, re-enters the same session, then reaps a dead harness', async () => {
    const firstHarness = startHarness(home);
    const otherHarness = startHarness(home);
    try {
      await Promise.all([once(firstHarness, 'spawn'), once(otherHarness, 'spawn')]);
      const first = await throughHarness(firstHarness, 'session-a');
      expect(first.code).toBe(0);
      expect(decisionOf(first).permissionDecision).not.toBe('deny');

      const leaseFile = join(home, '.shieldcortex', 'leases', 'leases.json');
      if (!existsSync(leaseFile)) throw new Error(`installed hook did not write a lease: ${JSON.stringify(first)}`);
      const record = JSON.parse(readFileSync(leaseFile, 'utf8'))
        .leases['npm-publish'];
      expect(record.pid).toBe(firstHarness.pid);
      expect(() => process.kill(record.pid, 0)).not.toThrow();

      // A later hook of the same session re-enters; identity is the holder string (#625).
      const sameSession = await throughHarness(firstHarness, 'session-a');
      expect(decisionOf(sameSession).permissionDecision).not.toBe('deny');
      expect(JSON.parse(readFileSync(leaseFile, 'utf8')).leases['npm-publish'].pid).toBe(firstHarness.pid);
      const second = await throughHarness(otherHarness, 'session-b');
      expect(decisionOf(second).permissionDecision).toBe('deny');
      expect(decisionOf(second).permissionDecisionReason).toContain('held by another session');

      firstHarness.kill();
      await once(firstHarness, 'exit');
      const afterDeath = await throughHarness(otherHarness, 'session-b');
      expect(decisionOf(afterDeath).permissionDecision).not.toBe('deny');
    } finally {
      firstHarness.kill();
      otherHarness.kill();
    }
  }, 30000);
});

describe('#227 — the freeze binds DURING a guard outage (review MAJOR-1)', () => {
  // A dist that has the lease modules but NOT the tool-action-guard — the exact
  // shape of a mid-upgrade window. The freeze must still bind: the lease check
  // now runs BEFORE the guard loads, so a missing guard cannot let a frozen
  // action through the degraded fallback (which does not know the freeze).
  function runHookWithDegradedGuard(home: string, command: string): Promise<HookRun> {
    const partialDist = mkdtempSync(join(tmpdir(), 'sc-partial-dist-'));
    const leaseDir = join(partialDist, 'defence', 'iron-dome');
    mkdirSync(leaseDir, { recursive: true });
    // Copy only the lease modules; deliberately omit tool-action-guard.js.
    for (const f of ['session-lease.js', 'session-lease-store.js']) {
      copyFileSync(join(DIST_ROOT, 'defence', 'iron-dome', f), join(leaseDir, f));
    }
    return new Promise((res, reject) => {
      const child = spawn(process.execPath, [HOOK_PATH], {
        stdio: ['pipe', 'pipe', 'pipe'],
        env: {
          ...process.env, HOME: home, USERPROFILE: home,
          SHIELDCORTEX_CONFIG_DIR: join(home, '.shieldcortex'),
          SHIELDCORTEX_DIST_ROOT: partialDist,
        },
      });
      let stdout = ''; let stderr = '';
      child.stdout.on('data', (c) => { stdout += c.toString(); });
      child.stderr.on('data', (c) => { stderr += c.toString(); });
      child.on('error', reject);
      child.on('close', (code) => { rmSync(partialDist, { recursive: true, force: true }); res({ stdout, stderr, code: code ?? 0 }); });
      child.stdin.write(JSON.stringify({ session_id: 'degraded', cwd: '/tmp', permission_mode: 'default', tool_name: 'Bash', tool_input: { command } }));
      child.stdin.end();
    });
  }

  it('a frozen npm-publish is denied even when the guard module is missing', async () => {
    writeFileSync(join(home, '.shieldcortex', 'DECISIONS.md'), '| FROZEN | no publishes until review |\n');
    const run = await runHookWithDegradedGuard(home, 'npm publish');
    expect(decisionOf(run).permissionDecision).toBe('deny');
  });
});

describe('#550 — a bare mention of a protected file is not a scoped call, on the wire', () => {
  const leasesFile = () => join(home, '.shieldcortex', 'leases', 'leases.json');
  const seedForeignLease = (pid: number) => {
    mkdirSync(join(home, '.shieldcortex', 'leases'), { recursive: true });
    const now = Date.now();
    writeFileSync(leasesFile(), JSON.stringify({
      leases: {
        'security-config': { holder: 'openclaw-session-uuid', pid, acquiredAtMs: now, expiresAtMs: now + 600_000, token: 'gw' },
      },
    }, null, 2));
  };

  it('a write shape against a foreign live holder is still refused, record untouched', async () => {
    seedForeignLease(process.pid);
    const before = readFileSync(leasesFile(), 'utf-8');
    const run = await runHook(home, 'Bash', { command: `echo x > ${join(home, '.openclaw', 'openclaw.json')}` });
    const decision = decisionOf(run);
    expect(decision.permissionDecision).toBe('deny');
    expect(decision.permissionDecisionReason ?? '').toContain('held by another session');
    expect(JSON.parse(readFileSync(leasesFile(), 'utf-8')).leases).toEqual(JSON.parse(before).leases);
  });

  it('a bare mention of the file is not a scoped call at all — the lease layer is never consulted', async () => {
    seedForeignLease(1);
    const run = await runHook(home, 'Bash', { command: `git commit -m "gate ${join(home, '.openclaw', 'openclaw.json')} writes"` });
    expect(decisionOf(run).permissionDecisionReason ?? '').not.toContain('held by another session');
    expect(run.stderr).not.toContain('SESSION-LEASE');
  });
});
