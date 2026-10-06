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

function runHook(command: string, permissionMode = 'default', sessionId?: string, hookPath = HOOK_PATH): Promise<{ stdout: string; code: number }> {
  return new Promise((res, rej) => {
    const child = spawn(process.execPath, [hookPath], {
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
    child.stdin.write(JSON.stringify({
      permission_mode: permissionMode,
      tool_name: 'Bash',
      tool_input: { command },
      ...(sessionId ? { session_id: sessionId } : {}),
    }));
    child.stdin.end();
  });
}

const reportDir = () => path.join(configDir, 'posture', 'claude_code', 'default');
const reportPath = () => {
  const files = fs.readdirSync(reportDir()).filter((f) => f.endsWith('.json'));
  if (files.length !== 1) throw new Error(`expected one report, found ${files.join(', ')}`);
  return path.join(reportDir(), files[0]);
};

function readReport() {
  const text = fs.readFileSync(reportPath(), 'utf8');
  const parsed = parseSelfReport(text, Buffer.byteLength(text));
  if (parsed.kind !== 'valid') throw new Error(`hook wrote an invalid report: ${parsed.kind === "invalid" ? parsed.reason : parsed.kind}`);
  return parsed.report;
}

describe('#613 Claude Code hook self-report', () => {
  it('writes a schema-valid report the CLI accepts (enforce, degraded scanner)', async () => {
    setGuard({ enabled: true, enforce: true });
    await runHook('ls -la');
    const r = readReport();
    expect(r.runtime).toBe('claude_code');
    expect(r.profile).toBe('default');
    expect(r.instance.liveness).toBe('per-call');
    expect(r.instance.pid).toBeNull();
    expect(r.loaded).toBe(true);
    expect(r.configured_posture).toBe('enforce');
    // Empty dist: the guard could not load, and the report says so.
    expect(r.scanner).toBe('degraded');
    expect(r.degraded_intervals.length).toBeGreaterThan(0);
    expect(r.policy_hash).toMatch(/^sha256:[0-9a-f]{64}$/);
    expect(r.plugin.hash).toMatch(/^sha256:[0-9a-f]{64}$/);
    expect(r.denials.blocked_action).toBeNull();
    expect(r.denials.synthetic_probe).toBeNull();
    const mode = fs.statSync(reportPath()).mode & 0o777;
    expect(mode & 0o077).toBe(0);
    for (const d of [path.join(configDir, 'posture'), path.join(configDir, 'posture', 'claude_code'), reportDir()]) {
      expect(fs.statSync(d).mode & 0o077).toBe(0);
    }
  });

  it('enforce:false reports advisory; enabled:false reports intentionally-off', async () => {
    setGuard({ enabled: true, enforce: false });
    await runHook('ls -la');
    expect(readReport().configured_posture).toBe('advisory');
    setGuard({ enabled: false });
    await runHook('ls -la');
    expect(readReport().configured_posture).toBe('intentionally-off');
  });

  it('a deny is recorded as a blocked action with its own timestamp, tested path and identity', async () => {
    setGuard({ enabled: true, enforce: true });
    // Promptless session: the dangerous tier denies rather than asks.
    const out = await runHook('crontab -e', 'bypassPermissions');
    expect(out.stdout).toMatch(/"permissionDecision":"deny"/);
    const r = readReport();
    expect(r.denials.blocked_action).not.toBeNull();
    expect(r.denials.blocked_action!.tested_path).toBe('PreToolUse:Bash');
    expect(r.denials.blocked_action!.instance).toBe(r.instance.key);
    expect(r.denials.blocked_action!.policy_hash).toBe(r.policy_hash);
    expect(r.denials.blocked_action_count).toBe(1);
    expect(r.denials.synthetic_probe).toBeNull();
  });

  it('a later allowed call keeps the earlier denial with its ORIGINAL timestamp', async () => {
    setGuard({ enabled: true, enforce: true });
    await runHook('crontab -e', 'bypassPermissions', 'sess-1');
    const first = readReport().denials.blocked_action!.at;
    // Force a rewrite past the throttle: a posture change is always written.
    setGuard({ enabled: true, enforce: false });
    await runHook('ls -la', 'default', 'sess-1');
    const r = readReport();
    expect(r.configured_posture).toBe('advisory');
    expect(r.denials.blocked_action!.at).toBe(first);
    expect(r.denials.blocked_action!.configured_posture).toBe('enforce');
  });

  it('two sessions are two instances, never last-writer-wins; the raw session id is not stored', async () => {
    setGuard({ enabled: true, enforce: true });
    await runHook('ls -la', 'default', 'session-alpha');
    await runHook('ls -la', 'default', 'session-beta');
    const files = fs.readdirSync(reportDir()).sort();
    expect(files).toHaveLength(2);
    for (const f of files) {
      expect(f).toMatch(/^c[0-9a-f]{24}\.json$/);
      expect(fs.readFileSync(path.join(reportDir(), f), 'utf8')).not.toMatch(/session-alpha|session-beta/);
    }
  });

  it('leaves no temp files behind (write is temp + rename)', async () => {
    setGuard({ enabled: true, enforce: true });
    await runHook('ls -la');
    await runHook('git status');
    const left = fs.readdirSync(reportDir());
    expect(left).toEqual(['c-nosession.json']);
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

  /** A copy of the hook whose posture writer is missing, broken at import, or throws. */
  function hookCopy(writer: string | null): string {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sc-hook-copy-613-'));
    copies.push(dir);
    fs.mkdirSync(path.join(dir, 'scripts', 'lib'), { recursive: true });
    fs.copyFileSync(HOOK_PATH, path.join(dir, 'scripts', 'pre-tool-hook.mjs'));
    fs.copyFileSync(path.join(REPO, 'scripts', 'lib', 'state-perms.mjs'), path.join(dir, 'scripts', 'lib', 'state-perms.mjs'));
    if (writer !== null) fs.writeFileSync(path.join(dir, 'scripts', 'lib', 'posture-self-report.mjs'), writer);
    return path.join(dir, 'scripts', 'pre-tool-hook.mjs');
  }
  const copies: string[] = [];
  afterEach(() => {
    for (const d of copies.splice(0)) fs.rmSync(d, { recursive: true, force: true });
  });

  it('identical decisions when the writer module is missing, fails to import, or throws', async () => {
    setGuard({ enabled: true, enforce: true });
    const decision = (s: string) => {
      const m = s.match(/"permissionDecision":"(\w+)"/);
      return m ? m[1] : 'none';
    };
    const normal: string[] = [];
    for (const [cmd, mode] of battery) normal.push(decision((await runHook(cmd, mode)).stdout));
    const variants = [
      hookCopy(null),
      hookCopy("throw new Error('broken at import');\n"),
      hookCopy([
        "export function noteContext() { throw new Error('x'); }",
        "export function noteConfig() { throw new Error('x'); }",
        "export function noteTool() { throw new Error('x'); }",
        "export function noteScanner() { throw new Error('x'); }",
        "export function writeReport() { throw new Error('x'); }",
      ].join('\n')),
    ];
    for (const hook of variants) {
      const got: string[] = [];
      for (const [cmd, mode] of battery) got.push(decision((await runHook(cmd, mode, undefined, hook)).stdout));
      expect(got).toEqual(normal);
    }
    expect(new Set(normal)).toEqual(new Set(['none', 'ask', 'deny']));
  });
});
