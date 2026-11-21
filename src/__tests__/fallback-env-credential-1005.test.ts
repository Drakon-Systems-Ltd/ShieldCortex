/**
 * #1005 (SCN-008a) fold r2, F5: the `env-credential-egress` OUTAGE row on the
 * OpenClaw interceptor and the Claude Code hook (Hermes reads the same fixture
 * in test_client_policy.py). With the guard unreachable:
 *  - gate: every case the guard cards on `env-credential-egress` gates on the
 *    fallback too — an unquoted `ssh [opts] host curl …`, a backslash-newline
 *    continuation, wrappers with option values, `busybox`, `\curl`, the
 *    backtick and `<(…)` printenv forms (Astra 5, Grok B2);
 *  - quiet: a known LOCAL option's value, a single-quoted or escaped `$`, and
 *    an echo/grep/gh mention fail open, as the guard allows them;
 *  - the new store names behave on the fallback exactly as an already-listed
 *    store does on origin/main: a Read or an echo naming `~/.aws/credentials`
 *    already gates on every fallback (the path row is a plain search), so one
 *    naming `~/.vault-token` gates the same way, and no more.
 *
 * Runs the REAL interceptor and the REAL hook with an empty dist. Classifier
 * input only: nothing here is executed as a shell command.
 */
import { describe, it, expect, beforeEach, afterEach } from '@jest/globals';
import { spawn } from 'node:child_process';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createInterceptor, DEFAULT_CONFIG, type InterceptAuditEntry } from '../../plugins/openclaw/interceptor.js';
import { evaluateToolCall } from '../defence/iron-dome/tool-action-guard.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const REPO = path.resolve(__dirname, '..', '..');
const HOOK_PATH = path.join(REPO, 'scripts', 'pre-tool-hook.mjs');

const FX = JSON.parse(fs.readFileSync(path.join(__dirname, 'fixtures', 'fallback-env-credential-1005.json'), 'utf-8')) as {
  gate: Array<[string, string]>;
  quiet: Array<[string, string]>;
  gaps: Array<[string, string, boolean, string]>;
  nonAscii: Array<[string, string, boolean]>;
};

/** A listed store on origin/main beside a store this change adds, same tool, same shape. */
const STORE_PAIRS: Array<[label: string, tool: string, listed: Record<string, unknown>, added: Record<string, unknown>]> = [
  ['Read', 'Read', { file_path: '/home/u/.aws/credentials' }, { file_path: '/home/u/.vault-token' }],
  ['Read, a .secret dir', 'Read', { file_path: '/home/u/.aws/credentials' }, { file_path: '/home/u/project/.secret/release.json' }],
  ['echo in single quotes', 'Bash', { command: "echo 'copy the sample into ~/.aws/credentials'" }, { command: "echo 'Create ~/.vault-token only when Vault login has succeeded.'" }],
  ['cat', 'Bash', { command: 'cat ~/.aws/credentials' }, { command: 'cat ~/.netrc' }],
];

const okPipeline = () => ({
  allowed: true,
  firewall: { result: 'ALLOW' as const, reason: '', threatIndicators: [] as string[], anomalyScore: 0, blockedPatterns: [] as string[] },
  trust: { score: 0.5 }, sensitivity: { level: 'INTERNAL' }, fragmentation: null, auditId: 1,
});

describe('#1005 fold r2 — the guard premise for the shared fixture', () => {
  it.each(FX.gate)('the guard cards env-credential-egress: %s', (_name, command) => {
    const v = evaluateToolCall('Bash', { command });
    expect({ d: v.decision, env: (v.signals ?? []).includes('env-credential-egress') }).toEqual({ d: 'require_approval', env: true });
  });
  it.each(FX.quiet)('the guard allows: %s', (_name, command) => {
    expect(evaluateToolCall('Bash', { command }).decision).toBe('allow');
  });
  it.each(FX.gaps)('pinned: %s', (_name, command, _fallbackGates, guardDecision) => {
    expect(evaluateToolCall('Bash', { command }).decision).toBe(guardDecision);
  });
});

describe('#1005 fold r2 — OpenClaw interceptor fallback', () => {
  const run = (toolName: string, args: Record<string, unknown>) => {
    const entries: InterceptAuditEntry[] = [];
    // No evaluateToolCall wired = guard unavailable. No requireApproval = unattended.
    const i = createInterceptor({ ...DEFAULT_CONFIG, actionGuard: { enabled: true, enforce: true, autoApprove: [] } } as never, okPipeline as never, { onAuditEntry: (e) => entries.push(e) });
    return { p: i.handleToolCall({ toolName, arguments: args }), entries };
  };
  async function gated(toolName: string, args: Record<string, unknown>): Promise<boolean> {
    const { p, entries } = run(toolName, args);
    try { await p; } catch { /* denied */ }
    return entries.some((e) => (e.outcome === 'auto_denied' || e.outcome === 'failure_denied') && e.firewallResult === 'ACTION_GUARD_FALLBACK');
  }

  it.each(FX.gate)('gates while degraded: %s', async (_name, command) => {
    expect(await gated('Bash', { command })).toBe(true);
  });
  it.each(FX.quiet)('fails open while degraded: %s', async (_name, command) => {
    const { p, entries } = run('Bash', { command });
    await expect(p).resolves.toBeUndefined();
    expect(entries.find((e) => e.action === 'gate_degraded')?.outcome).toBe('failure_allowed');
  });
  it.each(FX.gaps)('pinned: %s', async (_name, command, fallbackGates) => {
    expect(await gated('Bash', { command })).toBe(fallbackGates);
  });
  it.each(FX.nonAscii)('non-ASCII input, same answer as Hermes: %s', async (_name, command, fallbackGates) => {
    expect(await gated('Bash', { command })).toBe(fallbackGates);
  });
  it.each(STORE_PAIRS)('a new store behaves as a listed store does: %s', async (_l, tool, listed, added) => {
    const both = { listed: await gated(tool, listed), added: await gated(tool, added) };
    expect(both).toEqual({ listed: both.listed, added: both.listed });
    // origin/main's fallback already gates the listed store here (a plain search).
    expect(both.listed).toBe(true);
  });
});

describe('#1005 fold r2 — Claude Code hook fallback', () => {
  let tempHome: string;
  let emptyDist: string;

  beforeEach(() => {
    tempHome = fs.mkdtempSync(path.join(os.tmpdir(), 'sc-1005-r2-'));
    emptyDist = fs.mkdtempSync(path.join(os.tmpdir(), 'sc-1005-r2-dist-'));
    fs.mkdirSync(path.join(tempHome, '.shieldcortex'), { recursive: true });
    fs.writeFileSync(path.join(tempHome, '.shieldcortex', 'config.json'), JSON.stringify({ actionGuard: { enabled: true, enforce: true } }));
  });
  afterEach(() => {
    fs.rmSync(tempHome, { recursive: true, force: true });
    fs.rmSync(emptyDist, { recursive: true, force: true });
  });

  function runHook(toolName: string, toolInput: Record<string, unknown>): Promise<string | undefined> {
    return new Promise((res, rej) => {
      const env: Record<string, string | undefined> = { ...process.env };
      for (const key of Object.keys(env)) if (key.startsWith('SHIELDCORTEX_')) delete env[key];
      Object.assign(env, { HOME: tempHome, SHIELDCORTEX_DIST_ROOT: emptyDist, SHIELDCORTEX_CONFIG_DIR: path.join(tempHome, '.shieldcortex') });
      const child = spawn(process.execPath, [HOOK_PATH], { stdio: ['pipe', 'pipe', 'pipe'], env: env as NodeJS.ProcessEnv });
      let stdout = '';
      child.stdout.on('data', (c) => { stdout += c.toString(); });
      child.on('error', rej);
      child.on('close', () => res(stdout.trim() ? JSON.parse(stdout).hookSpecificOutput?.permissionDecision : undefined));
      child.stdin.write(JSON.stringify({ permission_mode: 'default', tool_name: toolName, tool_input: toolInput }));
      child.stdin.end();
    });
  }

  it.each(FX.gate)('asks while degraded: %s', async (_name, command) => {
    expect(await runHook('Bash', { command })).toBe('ask');
  });
  it.each(FX.quiet)('fails open while degraded: %s', async (_name, command) => {
    expect(await runHook('Bash', { command })).toBeUndefined();
  });
  it.each(FX.gaps)('pinned: %s', async (_name, command, fallbackGates) => {
    expect(await runHook('Bash', { command })).toBe(fallbackGates ? 'ask' : undefined);
  });
  it.each(FX.nonAscii)('non-ASCII input, same answer as Hermes: %s', async (_name, command, fallbackGates) => {
    expect(await runHook('Bash', { command })).toBe(fallbackGates ? 'ask' : undefined);
  });
  it.each(STORE_PAIRS)('a new store behaves as a listed store does: %s', async (_l, tool, listed, added) => {
    const both = { listed: await runHook(tool, listed), added: await runHook(tool, added) };
    expect(both).toEqual({ listed: 'ask', added: 'ask' });
  });
});
