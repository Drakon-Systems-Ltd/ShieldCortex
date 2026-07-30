/**
 * Action Guard hook — an approval verdict with nowhere to ask becomes a DENY.
 *
 * Motivating incident (2026-07-30, aiquant): the hook returned
 * `permissionDecision: "ask"` for a global npm install in a headless
 * `bypassPermissions` session. Claude Code 2.1.76 discarded the ask and ran the
 * command; 2.1.220 on the same box, same hook, same policy, blocked it. The
 * guard's verdict was right both times — the harness decided what to do with it.
 *
 * `deny` is the one PreToolUse verdict every observed version honours, so when
 * approval is required and no prompt surface can be confirmed, the hook denies.
 * These tests pin that mapping per permission mode so a future refactor can't
 * quietly restore the version-dependent outcome.
 */
import { spawn } from 'child_process';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { fileURLToPath } from 'url';
import { afterEach, beforeEach, describe, expect, it } from '@jest/globals';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const HOOK_PATH = path.resolve(__dirname, '..', '..', 'scripts', 'pre-tool-hook.mjs');

/** Dangerous tier, not catastrophic — catastrophic denies regardless of mode. */
const DANGEROUS_COMMAND = 'sudo systemctl stop nginx';

type HookResult = { stdout: string; stderr: string; code: number };

function runHook(payload: unknown, envOverrides: NodeJS.ProcessEnv = {}): Promise<HookResult> {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [HOOK_PATH], {
      stdio: ['pipe', 'pipe', 'pipe'],
      env: { ...process.env, ...envOverrides },
    });
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

/** `permissionMode: undefined` omits the field, mirroring a harness that never sends it. */
function call(command: string, permissionMode?: string): Record<string, unknown> {
  const payload: Record<string, unknown> = {
    session_id: 'test-session',
    cwd: '/tmp',
    hook_event_name: 'PreToolUse',
    tool_name: 'Bash',
    tool_input: { command },
  };
  if (permissionMode !== undefined) payload.permission_mode = permissionMode;
  return payload;
}

function decisionOf(stdout: string): { permissionDecision?: string; permissionDecisionReason?: string } {
  const parsed = JSON.parse(stdout);
  expect(parsed.hookSpecificOutput?.hookEventName).toBe('PreToolUse');
  return parsed.hookSpecificOutput;
}

describe('Action Guard hook — prompt-surface rule', () => {
  const originalHome = process.env.HOME;
  let tempHome: string;

  beforeEach(() => {
    tempHome = fs.mkdtempSync(path.join(os.tmpdir(), 'sc-prompt-surface-'));
    process.env.HOME = tempHome;
  });
  afterEach(() => {
    process.env.HOME = originalHome;
    fs.rmSync(tempHome, { recursive: true, force: true });
  });

  function writeActionGuardConfig(actionGuard: Record<string, unknown>): void {
    const dir = path.join(tempHome, '.shieldcortex');
    fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(path.join(dir, 'config.json'), JSON.stringify({ actionGuard }));
  }

  function lastAudit(): Record<string, unknown> {
    const dir = path.join(tempHome, '.shieldcortex', 'audit');
    const file = fs.readdirSync(dir).find((n) => /^realtime-.*\.jsonl$/.test(n))!;
    const lines = fs.readFileSync(path.join(dir, file), 'utf-8').trim().split('\n');
    return JSON.parse(lines[lines.length - 1]);
  }

  describe('modes that can raise a prompt → ask', () => {
    it.each(['default', 'manual', 'acceptEdits', 'plan', 'auto'])('%s asks', async (mode) => {
      const result = await runHook(call(DANGEROUS_COMMAND, mode));
      expect(result.code).toBe(0);
      expect(decisionOf(result.stdout).permissionDecision).toBe('ask');
      expect(lastAudit().outcome).toBe('asked');
    });
  });

  describe('modes with no prompt surface → deny', () => {
    // bypassPermissions and dontAsk are documented as showing no prompt; an
    // unknown or absent mode means the harness hasn't told us it can prompt.
    it.each([
      ['bypassPermissions', 'bypassPermissions'],
      ['dontAsk', 'dontAsk'],
      ['an unrecognised mode', 'yoloMode'],
      ['an empty mode string', ''],
    ])('%s denies', async (_label, mode) => {
      const result = await runHook(call(DANGEROUS_COMMAND, mode));
      expect(result.code).toBe(0);
      const decision = decisionOf(result.stdout);
      expect(decision.permissionDecision).toBe('deny');
      // The deny reason reaches Claude (an "ask" reason does not), so it has to
      // carry both the original verdict and a way forward.
      expect(decision.permissionDecisionReason).toMatch(/ShieldCortex Action Guard/);
      expect(decision.permissionDecisionReason).toMatch(/autoApprove|enforce/);
    });

    it('denies when the harness sends no permission_mode at all', async () => {
      const result = await runHook(call(DANGEROUS_COMMAND));
      expect(result.code).toBe(0);
      expect(decisionOf(result.stdout).permissionDecision).toBe('deny');
    });
  });

  describe('audit trail', () => {
    it('records the mode and a distinct outcome, keeping the verdict as require_approval', async () => {
      await runHook(call(DANGEROUS_COMMAND, 'bypassPermissions'));
      const entry = lastAudit();
      // The guard's verdict didn't change — only what could be done with it.
      expect(entry.action).toBe('require_approval');
      expect(entry.outcome).toBe('denied_no_prompt_surface');
      expect(entry.permissionMode).toBe('bypassPermissions');
      expect(String(entry.noPromptSurfaceReason)).toMatch(/no prompt/i);
    });

    it('separates a prompt-surface deny from a catastrophic auto-deny', async () => {
      await runHook(call('rm -rf /', 'bypassPermissions'));
      const entry = lastAudit();
      expect(entry.outcome).toBe('auto_denied');
      expect(entry.severity).toBe('critical');
    });

    it('records the mode on the ask path too', async () => {
      await runHook(call(DANGEROUS_COMMAND, 'default'));
      expect(lastAudit().permissionMode).toBe('default');
    });
  });

  describe('the rule narrows nothing else', () => {
    it('enforce:false stays advisory in bypassPermissions — no decision emitted', async () => {
      writeActionGuardConfig({ enforce: false });
      const result = await runHook(call(DANGEROUS_COMMAND, 'bypassPermissions'));
      expect(result.code).toBe(0);
      expect(result.stdout).toBe('');
      expect(result.stderr).toMatch(/action guard/i);
    });

    it('an autoApprove match still defers to Claude Code, never denied', async () => {
      writeActionGuardConfig({ autoApprove: ['sudo_command'] });
      const result = await runHook(call(DANGEROUS_COMMAND, 'bypassPermissions'));
      expect(result.code).toBe(0);
      expect(result.stdout).toBe('');
    });

    it('benign commands emit nothing regardless of mode', async () => {
      const result = await runHook(call('ls -la', 'bypassPermissions'));
      expect(result.code).toBe(0);
      expect(result.stdout).toBe('');
    });
  });

  describe('degraded guard (WS2 fallback) follows the same rule', () => {
    let emptyDist: string;
    beforeEach(() => { emptyDist = fs.mkdtempSync(path.join(os.tmpdir(), 'sc-emptydist-')); });
    afterEach(() => { fs.rmSync(emptyDist, { recursive: true, force: true }); });

    it('denies a dangerous op when the guard cannot scan and nothing can prompt', async () => {
      const result = await runHook(call(DANGEROUS_COMMAND, 'bypassPermissions'), {
        SHIELDCORTEX_DIST_ROOT: emptyDist,
      });
      expect(result.code).toBe(0);
      expect(decisionOf(result.stdout).permissionDecision).toBe('deny');
      const entry = lastAudit();
      expect(entry.action).toBe('gate_degraded');
      expect(entry.outcome).toBe('denied_no_prompt_surface');
      expect(entry.threats).toContain('fallback-scan');
    });

    it('still asks when the guard cannot scan but a prompt can be raised', async () => {
      const result = await runHook(call(DANGEROUS_COMMAND, 'default'), {
        SHIELDCORTEX_DIST_ROOT: emptyDist,
      });
      expect(decisionOf(result.stdout).permissionDecision).toBe('ask');
      expect(lastAudit().outcome).toBe('asked');
    });
  });
});
