/**
 * #874 — Watch only (advisory) on a headless Claude Code session, through the
 * real scripts/pre-tool-hook.mjs and the built classifier.
 *
 * 20 Oct 2026, a host with Action Guard set to advisory: routine read-only
 * commands in a `bypassPermissions` session were denied with "required
 * approval but this session has no prompt surface" and the signal list showed
 * only `redacted-signal`. The ordinary dangerous tier was already let through
 * under advisory; the denials came from the guard self-protection floor, which
 * fired on plain READS of the guard's own config and whose two config signals
 * were redacted from every denial row and decision reason.
 *
 * Invariant pinned here:
 *   - advisory + no prompt surface + ordinary dangerous tier → runs, one
 *     warning line that names the signal, a `warned` audit row, no decision;
 *   - the fixture read-only commands → run with no decision;
 *   - a real write to the guard config is still denied, and names
 *     `touch-guard-config` instead of `redacted-signal`;
 *   - catastrophic still denies and names its signal;
 *   - enforce + no prompt surface is unchanged (still denies).
 */
import { spawn } from 'child_process';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { fileURLToPath } from 'url';
import { afterEach, beforeEach, describe, expect, it } from '@jest/globals';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = path.resolve(__dirname, '..', '..');
const HOOK_PATH = path.resolve(REPO_ROOT, 'scripts', 'pre-tool-hook.mjs');

type HookResult = { stdout: string; stderr: string; code: number };

function runHook(payload: unknown, env: NodeJS.ProcessEnv): Promise<HookResult> {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [HOOK_PATH], { stdio: ['pipe', 'pipe', 'pipe'], env: { ...process.env, ...env } });
    let stdout = '';
    let stderr = '';
    child.stdout.on('data', (c) => { stdout += c.toString(); });
    child.stderr.on('data', (c) => { stderr += c.toString(); });
    child.on('error', reject);
    child.on('close', (code) => resolve({ stdout, stderr, code: code ?? 0 }));
    child.stdin.write(JSON.stringify(payload));
    child.stdin.end();
  });
}

function call(command: string, permissionMode?: string): Record<string, unknown> {
  const payload: Record<string, unknown> = {
    session_id: 'sc-874-session',
    cwd: '/tmp',
    hook_event_name: 'PreToolUse',
    tool_name: 'Bash',
    tool_input: { command },
  };
  if (permissionMode !== undefined) payload.permission_mode = permissionMode;
  return payload;
}

function decisionOf(stdout: string): { permissionDecision?: string; permissionDecisionReason?: string } {
  return JSON.parse(stdout).hookSpecificOutput ?? {};
}

/** The six 20 Oct read-only / routine shapes the classifier can judge without the host's own scripts. */
const FIXTURE_COMMANDS = [
  'ls ~/.shieldcortex; du -sh ~/.shieldcortex/*; grep -n enabled ~/.shieldcortex/config.json',
  'cat ~/.shieldcortex/config.json',
  'jq .actionGuard ~/.shieldcortex/config.json',
  'shieldcortex guard --help',
  'grep -n -i "npm-publish" DECISIONS.md | tail -4',
  'python3 scripts/action_lease.py --help',
];

describe('#874 advisory posture on a session with no prompt surface', () => {
  let home: string;
  let env: NodeJS.ProcessEnv;

  beforeEach(() => {
    home = fs.mkdtempSync(path.join(os.tmpdir(), 'sc-874-'));
    env = { HOME: home, SHIELDCORTEX_CONFIG_DIR: path.join(home, '.shieldcortex') };
    writeConfig({ enforce: false });
  });
  afterEach(() => {
    fs.rmSync(home, { recursive: true, force: true });
  });

  function writeConfig(actionGuard: Record<string, unknown>): void {
    const dir = path.join(home, '.shieldcortex');
    fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(path.join(dir, 'config.json'), JSON.stringify({ actionGuard: { enabled: true, ...actionGuard } }));
  }

  function auditRows(): Array<Record<string, unknown>> {
    const dir = path.join(home, '.shieldcortex', 'audit');
    if (!fs.existsSync(dir)) return [];
    const file = fs.readdirSync(dir).find((n) => /^realtime-.*\.jsonl$/.test(n));
    if (!file) return [];
    return fs.readFileSync(path.join(dir, file), 'utf-8').trim().split('\n').filter(Boolean).map((l) => JSON.parse(l));
  }

  it.each(FIXTURE_COMMANDS)('fixture runs with no decision in bypassPermissions: %s', async (command) => {
    const result = await runHook(call(command, 'bypassPermissions'), env);
    expect(result.code).toBe(0);
    expect(result.stdout).toBe('');
    expect(result.stderr).not.toMatch(/DENIED|BLOCKED/);
  });

  it.each([
    ['bypassPermissions'],
    ['dontAsk'],
    [undefined],
  ])('an ordinary dangerous call runs with exactly one warning line naming its signal (mode %s)', async (mode) => {
    const result = await runHook(call('sudo systemctl stop nginx', mode), env);
    expect(result.code).toBe(0);
    expect(result.stdout).toBe('');
    const warnings = result.stderr.split('\n').filter((l) => /⚠️ Action Guard:/.test(l));
    expect(warnings).toHaveLength(1);
    expect(warnings[0]).toMatch(/advisory/);
    expect(warnings[0]).toMatch(/stop-process-or-service/);
    const row = auditRows().find((r) => r.outcome === 'warned');
    expect(row).toBeDefined();
    expect(row!.action).toBe('warn');
  });

  it('a real write to the guard config is still denied, and the reason names touch-guard-config', async () => {
    const result = await runHook(call('echo {} > ~/.shieldcortex/config.json', 'bypassPermissions'), env);
    const d = decisionOf(result.stdout);
    expect(d.permissionDecision).toBe('deny');
    expect(d.permissionDecisionReason).toMatch(/touch-guard-config/);
    expect(d.permissionDecisionReason).not.toMatch(/redacted-signal/);
    expect(d.permissionDecisionReason).toMatch(/Watch only \(advisory\)/);
    const denials = fs.readFileSync(path.join(home, '.shieldcortex', 'denials.jsonl'), 'utf-8');
    expect(denials).toMatch(/touch-guard-config/);
    expect(denials).not.toMatch(/redacted-signal/);
  });

  it('switching the guard off from a tool call is still denied, and names disable-action-guard', async () => {
    const result = await runHook(call('shieldcortex config --action-guard-disable', 'bypassPermissions'), env);
    const d = decisionOf(result.stdout);
    expect(d.permissionDecision).toBe('deny');
    expect(d.permissionDecisionReason).toMatch(/disable-action-guard/);
    expect(d.permissionDecisionReason).not.toMatch(/redacted-signal/);
  });

  it('catastrophic still denies under advisory and names the signal', async () => {
    const result = await runHook(call('rm -rf /', 'bypassPermissions'), env);
    const d = decisionOf(result.stdout);
    expect(d.permissionDecision).toBe('deny');
    expect(d.permissionDecisionReason).toMatch(/Catastrophic-tier/);
    expect(d.permissionDecisionReason).toMatch(/\[[a-z-]*(delete|root)[a-z-]*/);
    expect(d.permissionDecisionReason).not.toMatch(/^[^[]*\[redacted-signal\]$/);
  });

  describe('enforce still denies the remaining dangerous tier without a prompt surface', () => {
    beforeEach(() => writeConfig({ enforce: true }));

    it('an ordinary dangerous call with no prompt surface is still denied', async () => {
      const result = await runHook(call('sudo systemctl stop nginx', 'bypassPermissions'), env);
      const d = decisionOf(result.stdout);
      expect(d.permissionDecision).toBe('deny');
      expect(d.permissionDecisionReason).toMatch(/no prompt surface/);
      expect(d.permissionDecisionReason).not.toMatch(/Watch only/);
    });

    it('a guard-config write keeps the enforce wording, now with its signal named', async () => {
      const result = await runHook(call('echo {} > ~/.shieldcortex/config.json', 'bypassPermissions'), env);
      const d = decisionOf(result.stdout);
      expect(d.permissionDecision).toBe('deny');
      expect(d.permissionDecisionReason).toMatch(/required approval but this session has no prompt surface/);
      expect(d.permissionDecisionReason).toMatch(/touch-guard-config/);
    });

    it('a guard-config read no longer asks for approval on a prompting session', async () => {
      const result = await runHook(call('cat ~/.shieldcortex/config.json', 'default'), env);
      expect(result.stdout).toBe('');
    });
  });
});
