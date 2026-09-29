import { spawn } from 'child_process';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { fileURLToPath } from 'url';
import { afterEach, beforeEach, describe, expect, it } from '@jest/globals';
import { parseSelfReport } from '../posture/posture-record.js';

/**
 * #613 — the Claude Code PreToolUse hook writes a process-side posture
 * self-report. The report is best-effort: it must never throw into the gate
 * and must never change an allow / ask / deny decision.
 *
 * The hook runs against an EMPTY dist root, so every call takes the WS2
 * degraded path. That is deterministic, needs no build, and is exactly the
 * path where a broken side effect would be most tempting to fail open on.
 */

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const REPO = path.resolve(__dirname, '..', '..');
const HOOK_PATH = path.join(REPO, 'scripts', 'pre-tool-hook.mjs');

let tempHome: string;
let emptyDist: string;
let configDir: string;

beforeEach(() => {
  tempHome = fs.mkdtempSync(path.join(os.tmpdir(), 'sc-hook-posture-613-'));
  emptyDist = fs.mkdtempSync(path.join(os.tmpdir(), 'sc-hook-posture-dist-'));
  configDir = path.join(tempHome, '.shieldcortex');
  fs.mkdirSync(configDir, { recursive: true });
});

afterEach(() => {
  fs.rmSync(tempHome, { recursive: true, force: true });
  fs.rmSync(emptyDist, { recursive: true, force: true });
});

function setGuard(actionGuard: Record<string, unknown>): void {
  fs.writeFileSync(path.join(configDir, 'config.json'), JSON.stringify({ actionGuard }));
}

function runHook(command: string, permissionMode = 'default'): Promise<{ stdout: string; code: number }> {
  return new Promise((res, rej) => {
    const child = spawn(process.execPath, [HOOK_PATH], {
      stdio: ['pipe', 'pipe', 'pipe'],
      env: {
        PATH: '/usr/bin:/bin',
        HOME: tempHome,
        SHIELDCORTEX_DIST_ROOT: emptyDist,
        SHIELDCORTEX_CONFIG_DIR: configDir,
      },
    });
    let stdout = '';
    child.stdout.on('data', (c) => { stdout += c.toString(); });
    child.on('error', rej);
    child.on('close', (code) => res({ stdout, code: code ?? 0 }));
    child.stdin.write(JSON.stringify({ permission_mode: permissionMode, tool_name: 'Bash', tool_input: { command } }));
    child.stdin.end();
  });
}

const reportPath = () => path.join(configDir, 'posture', 'claude_code--default.json');

function readReport() {
  const text = fs.readFileSync(reportPath(), 'utf8');
  const parsed = parseSelfReport(text, Buffer.byteLength(text));
  if (parsed.kind !== 'valid') throw new Error(`hook wrote an invalid report: ${parsed.reason}`);
  return parsed.report;
}

describe('#613 Claude Code hook self-report', () => {
  it('writes a schema-valid report the CLI accepts (enforce, degraded scanner)', async () => {
    setGuard({ enabled: true, enforce: true });
    await runHook('ls -la');
    const r = readReport();
    expect(r.runtime).toBe('claude_code');
    expect(r.profile).toBe('default');
    expect(r.loaded).toBe(true);
    expect(r.configured_posture).toBe('enforce');
    // Empty dist: the guard could not load, and the report says so.
    expect(r.scanner).toBe('degraded');
    expect(r.degraded_intervals.length).toBeGreaterThan(0);
    expect(r.policy_hash).toMatch(/^sha256:[0-9a-f]{64}$/);
    expect(r.plugin_hash).toMatch(/^sha256:[0-9a-f]{64}$/);
    expect(r.last_denial_at).toBeNull();
    const mode = fs.statSync(reportPath()).mode & 0o777;
    expect(mode & 0o077).toBe(0);
  });

  it('enforce:false reports advisory; enabled:false reports intentionally-off', async () => {
    setGuard({ enabled: true, enforce: false });
    await runHook('ls -la');
    expect(readReport().configured_posture).toBe('advisory');
    setGuard({ enabled: false });
    await runHook('ls -la');
    expect(readReport().configured_posture).toBe('intentionally-off');
  });

  it('a deny is recorded as an observed denial', async () => {
    setGuard({ enabled: true, enforce: true });
    // Promptless session: the dangerous tier denies rather than asks.
    const out = await runHook('crontab -e', 'bypassPermissions');
    expect(out.stdout).toMatch(/"permissionDecision":"deny"/);
    expect(readReport().last_denial_at).not.toBeNull();
  });

  it('leaves no temp files behind (write is temp + rename)', async () => {
    setGuard({ enabled: true, enforce: true });
    await runHook('ls -la');
    await runHook('git status');
    const left = fs.readdirSync(path.join(configDir, 'posture'));
    expect(left).toEqual(['claude_code--default.json']);
  });
});

describe('#613 a self-report failure never changes a decision', () => {
  const battery: Array<[string, string]> = [
    ['ls -la', 'default'],
    ['git status', 'default'],
    ['crontab -e', 'default'],
    ['crontab -e', 'bypassPermissions'],
    ['sudo systemctl stop nginx', 'dontAsk'],
  ];

  it('identical stdout and exit code with the posture path blocked', async () => {
    setGuard({ enabled: true, enforce: true });
    const normal: Array<{ stdout: string; code: number }> = [];
    for (const [cmd, mode] of battery) normal.push(await runHook(cmd, mode));

    // Block the report: `posture` is a regular file, so mkdir and rename fail.
    fs.rmSync(path.join(configDir, 'posture'), { recursive: true, force: true });
    fs.writeFileSync(path.join(configDir, 'posture'), 'not a directory');
    const blocked: Array<{ stdout: string; code: number }> = [];
    for (const [cmd, mode] of battery) blocked.push(await runHook(cmd, mode));

    const decision = (s: string) => {
      const m = s.match(/"permissionDecision":"(\w+)"/);
      return m ? m[1] : 'none';
    };
    expect(blocked.map((b) => b.code)).toEqual(normal.map((n) => n.code));
    expect(blocked.map((b) => decision(b.stdout))).toEqual(normal.map((n) => decision(n.stdout)));
    // Sanity: the battery exercises allow, ask and deny.
    expect(new Set(normal.map((n) => decision(n.stdout)))).toEqual(new Set(['none', 'ask', 'deny']));
  });
});
