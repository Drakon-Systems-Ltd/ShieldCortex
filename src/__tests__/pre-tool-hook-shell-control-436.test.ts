/**
 * #436 — live Claude control-plane tools through the REAL PreToolUse hook.
 *
 * Isolation copied from pre-tool-hook-retry-310.test.ts: fake HOME, shimmed
 * dist, never the operator's live audit/approvals.
 */
import { describe, it, expect, beforeAll, beforeEach, afterEach } from '@jest/globals';
import { execSync, spawnSync } from 'node:child_process';
import {
  chmodSync, existsSync, mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve, dirname } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { grantRetry } from '../defence/iron-dome/retry-control.js';

const repoRoot = resolve(dirname(fileURLToPath(import.meta.url)), '..', '..');
const HOOK = join(repoRoot, 'scripts', 'pre-tool-hook.mjs');
const REAL_DIST = join(repoRoot, 'dist', 'defence', 'iron-dome');

const CATASTROPHIC = { command: ['r', 'm', ' ', '-', 'r', 'f', ' ', '/'].join('') };

interface HookResult { decision?: string; reason?: string; stderr: string }
interface RetryStore {
  rows: Array<{
    id: string;
    hash: string;
    tool: string;
    grant?: { consumedAt?: number };
    claim?: unknown;
  }>;
}

describe('#436 — shell control through the real Claude Code hook', () => {
  let home: string;
  let distRoot: string;
  let jobCwd: string;
  let evidenceFile: string;
  let openclawBin: string;
  let decisionFile: string;

  beforeAll(() => {
    const probes = [
      'tool-action-guard.js', 'action-approvals.js', 'notify-config.js', 'operator-notify.js',
      'webhook-notify-channel.js', 'dnp-digest.js', 'retry-control.js', 'dnp-retry-waiter.js',
    ].map((f) => join(REAL_DIST, f));
    if (!probes.every((p) => existsSync(p))) {
      execSync('npm run build:ts', { cwd: repoRoot, stdio: 'ignore' });
    }
  }, 300_000);

  beforeEach(() => {
    home = mkdtempSync(join(tmpdir(), 'sc-436-hook-'));
    mkdirSync(join(home, '.shieldcortex'), { recursive: true });
    jobCwd = mkdtempSync(join(tmpdir(), 'sc-436-cwd-'));
    evidenceFile = join(home, 'webhook-evidence.jsonl');

    distRoot = mkdtempSync(join(tmpdir(), 'sc-436-dist-'));
    const ironDomeDir = join(distRoot, 'defence', 'iron-dome');
    mkdirSync(ironDomeDir, { recursive: true });
    for (const f of [
      'tool-action-guard.js', 'action-approvals.js', 'notify-config.js', 'operator-notify.js',
      'script-source-resolver.js', 'dnp-digest.js', 'retry-control.js', 'dnp-retry-waiter.js',
      'openclaw-approval-channel.js',
    ]) {
      const real = join(REAL_DIST, f);
      if (existsSync(real)) {
        writeFileSync(join(ironDomeDir, f), `export * from ${JSON.stringify(pathToFileURL(real).href)};\n`);
      }
    }
    writeFileSync(
      join(ironDomeDir, 'webhook-notify-channel.js'),
      [
        "import { appendFileSync as af } from 'node:fs';",
        'export function createWebhookNotifyChannel(opts) {',
        '  return {',
        "    name: 'webhook',",
        '    async send(notification) {',
        '      const u = new URL(opts.url);',
        "      const evidencePath = u.searchParams.get('evidence');",
        "      if (evidencePath) af(evidencePath, JSON.stringify(notification) + '\\n');",
        '      return { delivered: true };',
        '    },',
        '  };',
        '}',
      ].join('\n'),
    );

    decisionFile = join(home, 'decision.json');
    writeFileSync(decisionFile, JSON.stringify({ decision: null }));
    openclawBin = join(home, 'fake-openclaw');
    writeFileSync(openclawBin, `#!/bin/sh\ncat ${JSON.stringify(decisionFile)}\n`, { mode: 0o755 });
    chmodSync(openclawBin, 0o755);

    writeFileSync(
      join(home, '.shieldcortex', 'config.json'),
      JSON.stringify({
        actionGuard: {
          enabled: true,
          enforce: true,
          notify: { enabled: true, webhookUrl: `http://fake-webhook.invalid/hook?evidence=${encodeURIComponent(evidenceFile)}` },
        },
      }),
    );
  });

  afterEach(() => {
    for (const dir of [home, distRoot, jobCwd]) {
      try { rmSync(dir, { recursive: true, force: true }); } catch { /* best effort */ }
    }
  });

  function runHook(
    input: Record<string, unknown>,
    opts: { tool?: string; cwd?: string; permissionMode?: string } = {},
  ): HookResult {
    const payload = JSON.stringify({
      session_id: '436-session',
      cwd: opts.cwd ?? jobCwd,
      hook_event_name: 'PreToolUse',
      permission_mode: opts.permissionMode ?? 'bypassPermissions',
      tool_name: opts.tool ?? 'Bash',
      tool_input: input,
    });
    const run = spawnSync('node', [HOOK], {
      input: payload,
      env: {
        ...process.env,
        HOME: home,
        USERPROFILE: home,
        SHIELDCORTEX_DIST_ROOT: distRoot,
        SHIELDCORTEX_OPENCLAW_BIN: openclawBin,
      } as NodeJS.ProcessEnv,
      timeout: 30_000,
      encoding: 'utf8',
    });
    const stdout = run.stdout ?? '';
    if (!stdout.trim()) return { stderr: run.stderr ?? '' };
    const out = JSON.parse(stdout).hookSpecificOutput ?? {};
    return { decision: out.permissionDecision, reason: out.permissionDecisionReason, stderr: run.stderr ?? '' };
  }

  function store(): RetryStore | null {
    const p = join(home, '.shieldcortex', 'approvals', 'retry-control.json');
    return existsSync(p) ? (JSON.parse(readFileSync(p, 'utf8')) as RetryStore) : null;
  }

  function denialRows(): Array<Record<string, unknown>> {
    const file = join(home, '.shieldcortex', 'denials.jsonl');
    return existsSync(file)
      ? readFileSync(file, 'utf8').trim().split('\n').filter(Boolean).map((l) => JSON.parse(l))
      : [];
  }

  it('BashOutput {bash_id,filter} is allowed under bypassPermissions', () => {
    const r = runHook({ bash_id: 'bash_1', filter: 'ready' }, { tool: 'BashOutput' });
    expect(r.decision).toBeUndefined();
    expect(store()?.rows ?? []).toHaveLength(0);
  });

  it('KillShell {shell_id} is allowed', () => {
    const r = runHook({ shell_id: 'shell_1' }, { tool: 'KillShell' });
    expect(r.decision).toBeUndefined();
    expect(store()?.rows ?? []).toHaveLength(0);
  });

  it('KillBash {shell_id} is allowed', () => {
    const r = runHook({ shell_id: 'shell_1' }, { tool: 'KillBash' });
    expect(r.decision).toBeUndefined();
  });

  it('unknown field on BashOutput denies but mints a retry fingerprint', () => {
    const r = runHook({ bash_id: 'bash_1', evil_payload: 'x' }, { tool: 'BashOutput' });
    expect(r.decision).toBe('deny');
    const rows = store()?.rows ?? [];
    expect(rows).toHaveLength(1);
    expect(rows[0].tool).toBe('BashOutput');
    expect(rows[0].grant).toBeUndefined();

    const denials = denialRows();
    expect(denials.length).toBeGreaterThan(0);
    const blob = JSON.stringify(denials);
    expect(blob).toContain('BashOutput');
    expect(blob).toMatch(/invalid-tool-input|unknown-keys/);
    expect(blob).not.toContain('evil_payload');
  });

  it('schema-invalid denial is grantable once; different input cannot spend it', () => {
    const bad = { bash_id: 'bash_1', evil_payload: 'x' };
    expect(runHook(bad, { tool: 'BashOutput' }).decision).toBe('deny');
    const row = store()!.rows[0];
    const granted = grantRetry({ id: row.id }, { isInteractive: true }, { home });
    expect(granted.ok).toBe(true);

    const retried = runHook(bad, { tool: 'BashOutput' });
    expect(retried.decision).toBeUndefined();
    expect(retried.stderr).toContain('consumed operator RETRY grant');

    expect(runHook(bad, { tool: 'BashOutput' }).decision).toBe('deny');
    expect(runHook({ bash_id: 'bash_1', evil_payload: 'other' }, { tool: 'BashOutput' }).decision).toBe('deny');
  });

  it('catastrophic Bash still denies with no retry row', () => {
    const r = runHook(CATASTROPHIC, { tool: 'Bash' });
    expect(r.decision).toBe('deny');
    expect(store()?.rows ?? []).toHaveLength(0);
  });

  it('catastrophic Bash plus an unknown key still mints no retry row', () => {
    const r = runHook({ ...CATASTROPHIC, evil_payload: 'x' }, { tool: 'Bash' });
    expect(r.decision).toBe('deny');
    expect(store()?.rows ?? []).toHaveLength(0);
  });
});
