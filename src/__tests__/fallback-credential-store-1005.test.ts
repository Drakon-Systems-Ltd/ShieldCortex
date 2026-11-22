/**
 * #1005 (SCN-008a): the named credential stores on the OUTAGE fallbacks of the
 * OpenClaw interceptor and the Claude Code hook (Hermes holds the same cases in
 * test_client_policy.py). With the guard unreachable:
 *  - the new store names behave on the fallback exactly as an already-listed
 *    store does on origin/main: a Read or an echo naming `~/.aws/credentials`
 *    already gates on every fallback (the path row is a plain search), so one
 *    naming `~/.vault-token` gates the same way, and no more;
 *  - a store name followed by non-ASCII text reads as the store on every
 *    fallback (JS `\w` is ASCII; Hermes compiles the row with re.ASCII).
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

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const REPO = path.resolve(__dirname, '..', '..');
const HOOK_PATH = path.join(REPO, 'scripts', 'pre-tool-hook.mjs');

/** A store name with a non-ASCII suffix: [label, command, fallback gates]. */
const NON_ASCII: Array<[string, string, boolean]> = [
  ['a store name with a non-ASCII suffix reads as the store', 'cat ./docs/.pgpass\u8bf4\u660e', true],
];

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

describe('#1005 SCN-008a — OpenClaw interceptor fallback, named credential stores', () => {
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

  it.each(NON_ASCII)('non-ASCII input, same answer as Hermes: %s', async (_name, command, fallbackGates) => {
    expect(await gated('Bash', { command })).toBe(fallbackGates);
  });
  it.each(STORE_PAIRS)('a new store behaves as a listed store does: %s', async (_l, tool, listed, added) => {
    const both = { listed: await gated(tool, listed), added: await gated(tool, added) };
    expect(both).toEqual({ listed: both.listed, added: both.listed });
    // origin/main's fallback already gates the listed store here (a plain search).
    expect(both.listed).toBe(true);
  });
});

describe('#1005 SCN-008a — Claude Code hook fallback, named credential stores', () => {
  let tempHome: string;
  let emptyDist: string;

  beforeEach(() => {
    tempHome = fs.mkdtempSync(path.join(os.tmpdir(), 'sc-1005-store-'));
    emptyDist = fs.mkdtempSync(path.join(os.tmpdir(), 'sc-1005-store-dist-'));
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

  it.each(NON_ASCII)('non-ASCII input, same answer as Hermes: %s', async (_name, command, fallbackGates) => {
    expect(await runHook('Bash', { command })).toBe(fallbackGates ? 'ask' : undefined);
  });
  it.each(STORE_PAIRS)('a new store behaves as a listed store does: %s', async (_l, tool, listed, added) => {
    const both = { listed: await runHook(tool, listed), added: await runHook(tool, added) };
    expect(both).toEqual({ listed: 'ask', added: 'ask' });
  });
});
