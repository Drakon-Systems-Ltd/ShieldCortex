import { spawn } from 'child_process';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { fileURLToPath } from 'url';
import { afterEach, beforeEach, describe, expect, it } from '@jest/globals';

const __dirname = path.dirname(fileURLToPath(import.meta.url));

/**
 * Issue #209 — single source of truth for Action Guard config.
 *
 * Before this fix the Claude Code hook read ONLY top-level `actionGuard` and
 * the OpenClaw plugin read ONLY `interceptor.actionGuard`, so the two surfaces
 * could silently hold different enforcement postures. The resolution (#209):
 * top-level `actionGuard` governs every surface; `interceptor.actionGuard` is
 * a deprecated alias that fills gaps per key — an explicit top-level value
 * always wins, and a conflicting alias value is reported, not honoured.
 *
 * These tests pin the HOOK side of that contract. The plugin side is pinned in
 * plugins/openclaw/__tests__/action-guard-209-alias.test.ts and the doctor
 * surfacing in src/cli/__tests__/doctor-action-guard.test.ts — the three merge
 * implementations live in different build units and must stay in step.
 */

const HOOK_PATH = path.resolve(__dirname, '..', '..', 'scripts', 'pre-tool-hook.mjs');

type HookResult = { stdout: string; stderr: string; code: number };

function runHook(payload: unknown): Promise<HookResult> {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [HOOK_PATH], {
      stdio: ['pipe', 'pipe', 'pipe'],
      env: { ...process.env },
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

function bashCall(command: string): Record<string, unknown> {
  return {
    session_id: 'test-session',
    cwd: '/tmp',
    permission_mode: 'default',
    hook_event_name: 'PreToolUse',
    tool_name: 'Bash',
    tool_input: { command },
  };
}

describe('pre-tool hook — #209 interceptor.actionGuard alias resolution', () => {
  const originalHome = process.env.HOME;
  let tempHome: string;

  beforeEach(() => {
    tempHome = fs.mkdtempSync(path.join(os.tmpdir(), 'shieldcortex-209-'));
    process.env.HOME = tempHome;
  });

  afterEach(() => {
    process.env.HOME = originalHome;
    fs.rmSync(tempHome, { recursive: true, force: true });
  });

  function writeConfig(cfg: Record<string, unknown>): void {
    const dir = path.join(tempHome, '.shieldcortex');
    fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(path.join(dir, 'config.json'), JSON.stringify(cfg));
  }

  it('honours the deprecated alias when no top-level block exists (back-compat)', async () => {
    writeConfig({
      actionGuard: { enabled: true, enforce: false },
      interceptor: { actionGuard: { enforce: false } },
    });
    const result = await runHook(bashCall('sudo systemctl stop nginx'));
    expect(result.code).toBe(0);
    // enforce:false via the alias → warn-mode: stderr warning, no decision.
    expect(result.stdout).toBe('');
    expect(result.stderr).toMatch(/action guard/i);
  });

  it('top-level actionGuard wins over a conflicting alias value', async () => {
    writeConfig({
      actionGuard: { enabled: true, enforce: true },
      interceptor: { actionGuard: { enforce: false } },
    });
    const result = await runHook(bashCall('sudo systemctl stop nginx'));
    expect(result.code).toBe(0);
    // Top-level enforce:true governs: the dangerous tier gates.
    const parsed = JSON.parse(result.stdout);
    expect(parsed.hookSpecificOutput.permissionDecision).toBe('ask');
  });

  it('alias fills per-key gaps the top-level block does not set', async () => {
    // Top-level sets only enforce; the alias's autoApprove must still apply.
    writeConfig({
      actionGuard: { enabled: true, enforce: true },
      interceptor: { actionGuard: { autoApprove: ['sudo_command'] } },
    });
    const result = await runHook(bashCall('sudo systemctl stop nginx'));
    expect(result.code).toBe(0);
    // autoApprove match → no decision emitted (defers to Claude Code).
    expect(result.stdout).toBe('');
  });

  it('reports a conflict on stderr and points at the doctor migration', async () => {
    writeConfig({
      actionGuard: { enabled: true, enforce: true },
      interceptor: { actionGuard: { enforce: false } },
    });
    const result = await runHook(bashCall('sudo systemctl stop nginx'));
    expect(result.code).toBe(0);
    expect(result.stderr).toMatch(/interceptor\.actionGuard/);
    expect(result.stderr).toMatch(/--fix-action-guard/);
  });

  it('catastrophic deny survives every alias combination', async () => {
    writeConfig({
      actionGuard: { enabled: true, enforce: false },
      interceptor: { actionGuard: { enforce: false, enabled: true } },
    });
    const result = await runHook(bashCall('rm -rf /'));
    expect(result.code).toBe(0);
    const parsed = JSON.parse(result.stdout);
    expect(parsed.hookSpecificOutput.permissionDecision).toBe('deny');
  });
});
