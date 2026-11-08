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
import { spawn, spawnSync } from 'child_process';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { fileURLToPath } from 'url';
import { afterEach, beforeEach, describe, expect, it } from '@jest/globals';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = path.resolve(__dirname, '..', '..');
const HOOK_PATH = path.resolve(REPO_ROOT, 'scripts', 'pre-tool-hook.mjs');
const ELF_STUB = Buffer.from([0x7f, 0x45, 0x4c, 0x46, 2, 1, 1, 0, ...new Array(56).fill(0)]);

/** Whether a `mkfifo` executable can be started at all. Run with no operands
 *  (prints usage, creates nothing) and a timeout; only "not found" counts as
 *  unavailable, so a broken mkfifo still runs, and fails, the FIFO test. */
const HAS_MKFIFO = process.platform !== 'win32'
  && (spawnSync('mkfifo', [], { stdio: 'ignore', timeout: 5000 }).error as NodeJS.ErrnoException | undefined)?.code !== 'ENOENT';

type HookResult = { stdout: string; stderr: string; code: number; timedOut?: true };

/** `timeoutMs`: SIGKILL the hook after that long and report `timedOut`, so a
 *  hook that parks fails the test instead of hanging Jest. */
function runHook(payload: unknown, env: NodeJS.ProcessEnv, timeoutMs = 0): Promise<HookResult> {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [HOOK_PATH], { stdio: ['pipe', 'pipe', 'pipe'], env: { ...process.env, ...env } });
    let stdout = '';
    let stderr = '';
    let timedOut = false;
    const timer = timeoutMs > 0 ? setTimeout(() => { timedOut = true; child.kill('SIGKILL'); }, timeoutMs) : null;
    child.stdout.on('data', (c) => { stdout += c.toString(); });
    child.stderr.on('data', (c) => { stderr += c.toString(); });
    child.on('error', reject);
    child.on('close', (code) => {
      if (timer) clearTimeout(timer);
      resolve({ stdout, stderr, code: code ?? 0, ...(timedOut ? { timedOut: true as const } : {}) });
    });
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

  const call = (box: Box, tool_name: string, tool_input: Record<string, unknown>, timeoutMs = 0) => runHook({
    session_id: SESSION, cwd: box.work, hook_event_name: 'PreToolUse', permission_mode: 'default', tool_name, tool_input,
  }, box.env, timeoutMs);

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

  (HAS_MKFIFO ? it : it.skip)('a FIFO planted beside a real record cannot park the hook: a catastrophic call is still denied (POSIX: mkfifo)', async () => {
    await plant('helper');
    // Learn the session directory and the record name prefix exactly as the
    // agent could (`ls`), and plant a FIFO with the same path hash.
    const store = path.join(recorded.configDir, 'native-provenance');
    const [sessionDir] = fs.readdirSync(store);
    const [rec] = fs.readdirSync(path.join(store, sessionDir));
    const fifo = path.join(store, sessionDir, `${rec.split('.')[0]}.9.ffffff`);
    const made = spawnSync('mkfifo', [fifo], { encoding: 'utf8', timeout: 5000, killSignal: 'SIGKILL' });
    expect({ error: made.error?.message, status: made.status, stderr: made.stderr }).toEqual({ error: undefined, status: 0, stderr: '' });

    // Assembled: this file is scanned by the guard it drives.
    const command = `${['rm', '-rf', '~'].join(' ')} ; ./helper`;
    const a = await call(recorded, 'Bash', { command }, 8000);
    const b = await call(control, 'Bash', { command }, 8000);
    expect(a.timedOut).toBeUndefined();
    expect(b.timedOut).toBeUndefined();
    expect(JSON.parse(a.stdout).hookSpecificOutput.permissionDecision).toBe('deny');
    expect(a.stdout).toBe(b.stdout);
    expect(a.code).toBe(b.code);
  }, 30_000);

  it('20k empty record-named files planted beside a real record cannot stall the hook: 16 spellings of a catastrophic call are still denied', async () => {
    await plant('helper');
    // Learn the record name prefix exactly as the agent could (`ls`), then
    // stuff the session directory with empty files under the same path hash.
    const store = path.join(recorded.configDir, 'native-provenance');
    const [sessionDir] = fs.readdirSync(store);
    const dir = path.join(store, sessionDir);
    const [rec] = fs.readdirSync(dir);
    const hash = rec.split('.')[0];
    for (let i = 0; i < 20_000; i++) fs.closeSync(fs.openSync(path.join(dir, `${hash}.${i}.ab`), 'w'));

    // Sixteen distinct spellings of one path. Assembled: this file is scanned
    // by the guard it drives.
    const spellings = Array.from({ length: 16 }, (_, i) => `${'./'.repeat(i + 1)}helper`);
    const command = [['rm', '-rf', '~'].join(' '), ...spellings].join(' ; ');
    const started = Date.now();
    const a = await call(recorded, 'Bash', { command }, 8000);
    const ms = Date.now() - started;
    const b = await call(control, 'Bash', { command }, 8000);
    expect(a.timedOut).toBeUndefined();
    expect(b.timedOut).toBeUndefined();
    expect(JSON.parse(a.stdout).hookSpecificOutput.permissionDecision).toBe('deny');
    expect(a.stdout).toBe(b.stdout);
    expect(a.code).toBe(b.code);
    expect(ms).toBeLessThan(5000); // generous; the unbounded probe took ~7 s for this plant
  }, 60_000);

  it('fold r3: a ~600-level deep tree under a catastrophic redirect is denied quickly and records nothing', async () => {
    fs.mkdirSync(path.join(recorded.work, ...new Array(600).fill('a')), { recursive: true });
    const store = path.join(recorded.configDir, 'native-provenance');
    const before = fs.existsSync(store) ? fs.readdirSync(store).sort() : null;
    const command = `${['rm', '-rf', '~'].join(' ')} ; echo hi > ${'a/'.repeat(600)}${'b/'.repeat(600)}x`;
    const started = Date.now();
    const a = await call(recorded, 'Bash', { command }, 8000);
    const ms = Date.now() - started;
    const b = await call(control, 'Bash', { command }, 8000);
    expect(a.timedOut).toBeUndefined();
    expect(JSON.parse(a.stdout).hookSpecificOutput.permissionDecision).toBe('deny');
    expect(a.stdout).toBe(b.stdout);
    expect(a.code).toBe(b.code);
    expect(ms).toBeLessThan(5000); // base (unbounded record) took ~9.5 s
    expect(fs.existsSync(store) ? fs.readdirSync(store).sort() : null).toEqual(before); // a block records nothing
  }, 60_000);

  it('fold r3: a first-record allow beside a planted 20k-file expired session dir records, quickly, and leaves that dir whole', async () => {
    const store = path.join(recorded.configDir, 'native-provenance');
    const big = path.join(store, 'sc-ffffffffffffffff');
    fs.mkdirSync(big, { recursive: true, mode: 0o700 });
    fs.chmodSync(store, 0o700);
    for (let i = 0; i < 20_000; i++) fs.closeSync(fs.openSync(path.join(big, `f${i}`), 'w'));
    const old = (Date.now() - 3 * 24 * 60 * 60 * 1000) / 1000;
    fs.utimesSync(big, old, old);
    const started = Date.now();
    const a = await call(recorded, 'Write', { file_path: path.join(recorded.work, 'tool'), content: 'stub' }, 8000);
    const ms = Date.now() - started;
    expect(a.timedOut).toBeUndefined();
    expect(ms).toBeLessThan(5000);
    expect(fs.readdirSync(big)).toHaveLength(20_000); // over-full doomed dir: skipped, not deleted
    const sessions = fs.readdirSync(store).filter((n) => n !== 'sc-ffffffffffffffff' && /^sc-[a-f0-9]{16}$/.test(n));
    expect(sessions).toHaveLength(1);
    expect(fs.readdirSync(path.join(store, sessions[0]))).toHaveLength(1); // the record was published
  }, 60_000);

  it('no session id: nothing recorded, nothing observed (current behaviour)', async () => {
    const payload = (tool_name: string, tool_input: Record<string, unknown>) => ({ cwd: recorded.work, hook_event_name: 'PreToolUse', permission_mode: 'default', tool_name, tool_input });
    await runHook(payload('Write', { file_path: path.join(recorded.work, 'helper'), content: 'x' }), recorded.env);
    fs.writeFileSync(path.join(recorded.work, 'helper'), ELF_STUB, { mode: 0o755 });
    await runHook(payload('Bash', { command: './helper' }), recorded.env);
    expect(auditRows(recorded).some((r) => r.nativeExec)).toBe(false);
    expect(fs.existsSync(path.join(recorded.configDir, 'native-provenance'))).toBe(false);
  });
});
