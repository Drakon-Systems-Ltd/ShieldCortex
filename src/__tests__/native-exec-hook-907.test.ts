/**
 * #907 PR 1 — adapter fixture (implementation, not simulation): the REAL
 * scripts/pre-tool-hook.mjs as a subprocess, across separate calls, against
 * real files under a test-pinned home and config dir, with the built guard.
 *
 * Each hook process records its write/compile captures in the per-session
 * agent-artifact ledger and a later, separate hook process reads them at exec
 * (cross-process). The test plays the host: it lets a recorded call "land" by
 * changing the file itself between hook calls, or leaves the file unchanged to
 * model a failed write.
 *
 * Pinned (design §5 adapter-fixture obligation, §8):
 *   - write → exec (row A) → deny, names the floor signal;
 *   - failed write → exec (Rule P) → the door (ask), never a deny;
 *   - install-root write → exec (Rule H) → deny; an unwritten install-root
 *     native image keeps current behaviour;
 *   - producing write → four non-changing write-family calls + a real chmod →
 *     exec → deny (no window);
 *   - supported compile → exec (row B) → runs, audited (Q1 = AUDIT);
 *   - no session id → writes are not held, a native exec is the door;
 *   - an unwritable store holds the write (door), never lets it through.
 *
 * The Guard is enabled only in this test's own config file; no default,
 * host config or posture is changed.
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

// A benign, non-runnable native-format stub: ELF magic + zero padding.
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

function decisionOf(r: HookResult): { permissionDecision?: string; permissionDecisionReason?: string } {
  if (!r.stdout.trim()) return {};
  return JSON.parse(r.stdout).hookSpecificOutput ?? {};
}

describe('#907 native-exec floor through the real Claude Code hook', () => {
  let root: string;
  let home: string;
  let work: string;
  let configDir: string;
  let env: NodeJS.ProcessEnv;
  let sessionId: string | undefined;

  beforeEach(() => {
    root = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), 'sc-907-hook-')));
    home = path.join(root, 'home');
    work = path.join(root, 'work');
    configDir = path.join(home, '.shieldcortex');
    fs.mkdirSync(work, { recursive: true });
    fs.mkdirSync(configDir, { recursive: true });
    fs.writeFileSync(path.join(configDir, 'config.json'), JSON.stringify({ actionGuard: { enabled: true } }));
    env = { HOME: home, SHIELDCORTEX_CONFIG_DIR: configDir };
    sessionId = `sc-907-${path.basename(root)}`;
  });
  afterEach(() => {
    fs.rmSync(root, { recursive: true, force: true });
  });

  const base = () => ({
    ...(sessionId ? { session_id: sessionId } : {}),
    cwd: work,
    hook_event_name: 'PreToolUse',
    permission_mode: 'default',
  });
  const write = (file: string) =>
    runHook({ ...base(), tool_name: 'Write', tool_input: { file_path: file, content: 'stub' } }, env);
  const edit = (file: string) =>
    runHook({ ...base(), tool_name: 'Edit', tool_input: { file_path: file, old_string: 'a', new_string: 'b' } }, env);
  const bash = (command: string) =>
    runHook({ ...base(), tool_name: 'Bash', tool_input: { command } }, env);

  function auditRows(): Array<Record<string, unknown>> {
    const dir = path.join(configDir, 'audit');
    if (!fs.existsSync(dir)) return [];
    return fs.readdirSync(dir)
      .filter((n) => /^realtime-.*\.jsonl$/.test(n))
      .flatMap((n) => fs.readFileSync(path.join(dir, n), 'utf-8').trim().split('\n').filter(Boolean))
      .map((l) => JSON.parse(l));
  }

  const doorAudited = () => auditRows().some((row) => JSON.stringify(row).includes('unclassified-executable'));

  it('write → exec (row A) → deny naming exec-agent-written-native-bytes', async () => {
    const helper = path.join(work, 'helper');
    expect(decisionOf(await write(helper)).permissionDecision).toBeUndefined();
    fs.writeFileSync(helper, ELF_STUB, { mode: 0o755 }); // the write lands
    const r = await bash('./helper');
    const d = decisionOf(r);
    expect(d.permissionDecision).toBe('deny');
    expect(r.stderr).toMatch(/native-exec-of-agent-artifact/);
    expect(r.stderr).toMatch(/exec-agent-written-native-bytes/);
  });

  it('failed write against an existing native file → exec → the door (ask), never deny', async () => {
    const tool = path.join(work, 'tool');
    fs.writeFileSync(tool, ELF_STUB, { mode: 0o755 });
    await write(tool); // recorded, but the file is not changed
    const d = decisionOf(await bash('./tool'));
    expect(d.permissionDecision).toBe('ask');
    expect(doorAudited()).toBe(true);
  });

  it('install-root write → exec (Rule H) → deny; an unwritten install-root native image is not gated', async () => {
    const binDir = path.join(work, 'node_modules', '.bin');
    fs.mkdirSync(binDir, { recursive: true });
    const planted = path.join(binDir, 'tool');
    await write(planted);
    fs.writeFileSync(planted, ELF_STUB, { mode: 0o755 });
    expect(decisionOf(await bash(planted)).permissionDecision).toBe('deny');

    const installed = path.join(binDir, 'other');
    fs.writeFileSync(installed, ELF_STUB, { mode: 0o755 });
    expect(decisionOf(await bash(installed)).permissionDecision).toBeUndefined();
  });

  it('producing write → four non-changing write-family calls + chmod → exec → deny (no window)', async () => {
    const helper = path.join(work, 'helper');
    await write(helper);
    fs.writeFileSync(helper, ELF_STUB);
    for (let k = 0; k < 4; k++) await edit(helper); // failed edits: file unchanged
    fs.chmodSync(helper, 0o755); // metadata-only
    expect(decisionOf(await bash('./helper')).permissionDecision).toBe('deny');
  });

  it('supported compile → exec (row B) → runs, audited with exec-of-agent-compiled-artifact (Q1 = AUDIT)', async () => {
    fs.writeFileSync(path.join(work, 'helper.c'), 'int main(void){return 0;}\n');
    expect(decisionOf(await bash('cc helper.c -o helper')).permissionDecision).toBeUndefined();
    fs.writeFileSync(path.join(work, 'helper'), ELF_STUB, { mode: 0o755 }); // the compile lands
    const r = await bash('./helper');
    expect(decisionOf(r).permissionDecision).toBeUndefined();
    const audited = auditRows().some((row) => JSON.stringify(row).includes('exec-of-agent-compiled-artifact'));
    expect(audited).toBe(true);
  });

  it('no session id → the write is not held; a native exec is the door', async () => {
    sessionId = undefined;
    const helper = path.join(work, 'helper');
    expect(decisionOf(await write(helper)).permissionDecision).toBeUndefined();
    fs.writeFileSync(helper, ELF_STUB, { mode: 0o755 });
    expect(decisionOf(await bash('./helper')).permissionDecision).toBe('ask');
    expect(doorAudited()).toBe(true);
  });

  it('an unwritable store holds the write (door), never lets it through unrecorded', async () => {
    fs.writeFileSync(path.join(configDir, 'artifacts'), 'not a directory');
    const d = decisionOf(await write(path.join(work, 'helper')));
    expect(d.permissionDecision).toBe('ask');
    expect(doorAudited()).toBe(true);
  });

  // -- review round 1 regressions, through the real hook ----------------------

  it('r1 B6: a structurally broken store (ENOTDIR) is incomplete history — an unwritten install-root image is the door, not relieved', async () => {
    const binDir = path.join(work, 'node_modules', '.bin');
    fs.mkdirSync(binDir, { recursive: true });
    const installed = path.join(binDir, 'other');
    fs.writeFileSync(installed, ELF_STUB, { mode: 0o755 });
    expect(decisionOf(await bash(installed)).permissionDecision).toBeUndefined(); // healthy store: Rule H relief
    fs.writeFileSync(path.join(configDir, 'artifacts'), 'not a directory');
    expect(decisionOf(await bash(installed)).permissionDecision).toBe('ask');
  });

  it('r1 B1: an agent-written native image named python3 is denied, with or without an inline program', async () => {
    const fake = path.join(work, 'python3');
    await write(fake);
    fs.writeFileSync(fake, ELF_STUB, { mode: 0o755 });
    for (const cmd of ['./python3', "./python3 -c 'print(1)'"]) {
      const r = await bash(cmd);
      expect(decisionOf(r).permissionDecision).toBe('deny');
      expect(r.stderr).toMatch(/exec-agent-written-native-bytes/);
    }
  });

  it("r1 B2: a relative path without './' is resolved like one with it", async () => {
    fs.mkdirSync(path.join(work, 'bin'), { recursive: true });
    const helper = path.join(work, 'bin', 'helper');
    await write(helper);
    fs.writeFileSync(helper, ELF_STUB, { mode: 0o755 });
    for (const cmd of ['bin/helper', './bin/helper', 'cd bin && ./helper']) {
      expect(decisionOf(await bash(cmd)).permissionDecision).toBe('deny');
    }
  });

  it('r1 B3: reading or printing an agent-written native file name is not running it', async () => {
    const helper = path.join(work, 'helper');
    await write(helper);
    fs.writeFileSync(helper, ELF_STUB, { mode: 0o755 });
    for (const cmd of ["cat <<'EOF'\n./helper\nLD_PRELOAD=./helper ls\nEOF", 'echo "first line\n./helper\nlast"', 'ls # ./helper']) {
      expect(decisionOf(await bash(cmd)).permissionDecision).toBeUndefined();
    }
    expect(auditRows().some((row) => JSON.stringify(row).includes('native-exec-of-agent-artifact'))).toBe(false);
    expect(decisionOf(await bash('true && ./helper')).permissionDecision).toBe('deny'); // a real exec still is
  });
});
