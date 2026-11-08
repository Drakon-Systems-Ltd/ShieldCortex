/**
 * #1025 — the audit-only native-exec observation through the REAL
 * scripts/pre-tool-hook.mjs as a subprocess, across separate calls, against
 * real files under a test-owned home, with the built guard (dist).
 *
 * Two homes run the same commands: one where the agent's Write was recorded
 * in the provenance store, one where it was not. The hook's decision (stdout)
 * must be identical; only the audit rows differ, by the `nativeExec` field.
 * The Guard is enabled only in this test's own config file; no default, host
 * config or posture is touched. The "native" file is an ELF magic stub;
 * nothing is executed.
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
const ELF_STUB = Buffer.from([0x7f, 0x45, 0x4c, 0x46, 2, 1, 1, 0, ...new Array(56).fill(0)]);

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

interface Box { home: string; work: string; configDir: string; env: NodeJS.ProcessEnv }

function makeBox(root: string, name: string): Box {
  const home = path.join(root, name, 'home');
  const work = path.join(root, name, 'work');
  const configDir = path.join(home, '.shieldcortex');
  fs.mkdirSync(work, { recursive: true });
  fs.mkdirSync(configDir, { recursive: true });
  fs.writeFileSync(path.join(configDir, 'config.json'), JSON.stringify({ actionGuard: { enabled: true } }));
  return { home, work, configDir, env: { HOME: home, SHIELDCORTEX_CONFIG_DIR: configDir } };
}

function auditRows(box: Box): Array<Record<string, unknown>> {
  const dir = path.join(box.configDir, 'audit');
  if (!fs.existsSync(dir)) return [];
  return fs.readdirSync(dir)
    .filter((n) => /^realtime-.*\.jsonl$/.test(n))
    .flatMap((n) => fs.readFileSync(path.join(dir, n), 'utf-8').trim().split('\n').filter(Boolean))
    .map((l) => JSON.parse(l));
}

const SESSION = 'sc-1025-hook-session';

describe('#1025 native-exec observation through the real Claude Code hook', () => {
  let root: string;
  let recorded: Box;
  let control: Box;

  beforeEach(() => {
    root = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'sc-1025-hook-')));
    recorded = makeBox(root, 'recorded');
    control = makeBox(root, 'control');
  });
  afterEach(() => {
    fs.rmSync(root, { recursive: true, force: true });
  });

  const call = (box: Box, tool_name: string, tool_input: Record<string, unknown>) => runHook({
    session_id: SESSION, cwd: box.work, hook_event_name: 'PreToolUse', permission_mode: 'default', tool_name, tool_input,
  }, box.env);

  /** In `recorded` the Write goes through the hook (and is recorded); in
   *  `control` the same bytes appear with no hook call. */
  async function plant(name: string): Promise<void> {
    await call(recorded, 'Write', { file_path: path.join(recorded.work, name), content: 'stub' });
    for (const box of [recorded, control]) fs.writeFileSync(path.join(box.work, name), ELF_STUB, { mode: 0o755 });
  }

  it.each([
    './helper',
    'LD_PRELOAD=./libx.so /bin/true',
    'eval "$(echo ./helper)"',
  ])('%j: identical hook decision; only the recorded home logs nativeExec', async (command) => {
    await plant('helper');
    await plant('libx.so');
    const before = auditRows(recorded).length;
    const a = await call(recorded, 'Bash', { command });
    const b = await call(control, 'Bash', { command });
    expect(a.stdout).toBe(b.stdout);
    expect(a.code).toBe(b.code);

    const rowsA = auditRows(recorded).slice(before);
    const rowsB = auditRows(control);
    expect(rowsB.some((r) => r.nativeExec)).toBe(false);
    const withNative = rowsA.filter((r) => r.nativeExec);
    expect(withNative.length).toBeGreaterThan(0);
    for (const r of withNative) {
      expect(JSON.stringify(r.nativeExec)).not.toMatch(/helper|libx|work/);
      expect((r.nativeExec as { uses: unknown[] }).uses.length).toBeGreaterThan(0);
    }
    // Rows other than the benign-observation row are the same rows, same decisions.
    const view = (rows: Array<Record<string, unknown>>) => rows.map((r) => ({ action: r.action, outcome: r.outcome, severity: r.severity, threats: r.threats }));
    const extra = rowsA.length - rowsB.length;
    expect(extra === 0 || extra === 1).toBe(true);
    if (extra === 0) expect(view(rowsA)).toEqual(view(rowsB));
    else {
      expect(rowsB).toHaveLength(0);
      expect(rowsA[0].action).toBe('allow');
      expect(rowsA[0].outcome).toBe('allowed');
    }
  });

  it('same-call compile then run is logged as compiled-output/sameCall with an identical decision', async () => {
    const command = 'cc main.c -o app && ./app';
    const a = await call(recorded, 'Bash', { command });
    const b = await call(control, 'Bash', { command });
    expect(a.stdout).toBe(b.stdout);
    const native = auditRows(recorded).filter((r) => r.nativeExec);
    expect(native.length).toBeGreaterThan(0);
    expect((native[0].nativeExec as { uses: unknown[] }).uses).toContainEqual({ action: 'exec', provenance: 'compiled-output', sameCall: true });
  });

  it('a failed write (bytes unchanged since the record) is not logged', async () => {
    fs.writeFileSync(path.join(recorded.work, 'tool'), ELF_STUB, { mode: 0o755 });
    await call(recorded, 'Write', { file_path: path.join(recorded.work, 'tool'), content: 'stub' });
    await call(recorded, 'Bash', { command: './tool' });
    expect(auditRows(recorded).some((r) => r.nativeExec)).toBe(false);
  });

  it('no session id: nothing recorded, nothing observed (current behaviour)', async () => {
    const payload = (tool_name: string, tool_input: Record<string, unknown>) => ({ cwd: recorded.work, hook_event_name: 'PreToolUse', permission_mode: 'default', tool_name, tool_input });
    await runHook(payload('Write', { file_path: path.join(recorded.work, 'helper'), content: 'x' }), recorded.env);
    fs.writeFileSync(path.join(recorded.work, 'helper'), ELF_STUB, { mode: 0o755 });
    await runHook(payload('Bash', { command: './helper' }), recorded.env);
    expect(auditRows(recorded).some((r) => r.nativeExec)).toBe(false);
    expect(fs.existsSync(path.join(recorded.configDir, 'native-provenance'))).toBe(false);
  });
});
