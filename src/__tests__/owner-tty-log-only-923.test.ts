/**
 * #923 — an owner-present interactive terminal is log-only on the
 * no-prompt-surface branch, through the real scripts/pre-tool-hook.mjs and the
 * built classifier.
 *
 * Principle 4 of #875: when a human owns the terminal Claude Code runs in, an
 * ordinary dangerous call in `bypassPermissions` / `dontAsk` / unknown mode is
 * logged (one warning line, a `warned` audit row) instead of denied. Headless
 * paths — subagents, crons, agent-launched or pty-wrapped Claude — keep the
 * deny; catastrophic and the guard self-protection floor deny everywhere.
 *
 * Every process tree below is SYNTHETIC: written into a temp dir and handed to
 * the hook through `SHIELDCORTEX_TEST_PROC_ROOT`, so no case parses live /proc
 * for its proof. No host records are reproduced here.
 */
import { spawn } from 'child_process';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { fileURLToPath } from 'url';
import { afterEach, beforeEach, describe, expect, it } from '@jest/globals';
// The hook imports this published .mjs file; keep the unit cases on the same module.
// @ts-ignore no declaration is emitted for scripts outside the TS build
import { proveOwnerPresentHarness, HARNESS_AGENT_ENV_MARKERS } from '../../scripts/lib/owner-tty.mjs';
import { AGENT_ENV_MARKERS } from '../cli/approve-provenance.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = path.resolve(__dirname, '..', '..');
const HOOK_PATH = path.resolve(REPO_ROOT, 'scripts', 'pre-tool-hook.mjs');
const DANGEROUS = 'sudo systemctl stop nginx';
const TTY = 34816; // /dev/pts/0

type HookResult = { stdout: string; stderr: string; code: number };
type Proc = { comm: string; ppid: number; sid: number; tty: number; argv?: string[]; env?: string[] | null };

function runHook(payload: unknown, env: NodeJS.ProcessEnv, opts: { hookPath?: string; nodeArgs?: string[] } = {}): Promise<HookResult> {
  return new Promise((resolve, reject) => {
    const child = spawn(process.execPath, [...(opts.nodeArgs ?? []), opts.hookPath ?? HOOK_PATH], {
      stdio: ['pipe', 'pipe', 'pipe'],
      env: { ...process.env, ...env },
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

function call(command: string, permissionMode?: string, extra: Record<string, unknown> = {}): Record<string, unknown> {
  const payload: Record<string, unknown> = {
    session_id: 'sc-923-session',
    cwd: '/tmp',
    hook_event_name: 'PreToolUse',
    tool_name: 'Bash',
    tool_input: { command },
    ...extra,
  };
  if (permissionMode !== undefined) payload.permission_mode = permissionMode;
  return payload;
}

function decisionOf(stdout: string): { permissionDecision?: string; permissionDecisionReason?: string } {
  return stdout.trim() ? JSON.parse(stdout).hookSpecificOutput ?? {} : {};
}

/** Write a synthetic proc tree: one `<root>/<pid>/{stat,cmdline,environ}` per row. */
function writeTree(root: string, rows: Record<number, Proc>): void {
  for (const [pid, p] of Object.entries(rows)) {
    const dir = path.join(root, pid);
    fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(path.join(dir, 'stat'), `${pid} (${p.comm}) S ${p.ppid} ${p.sid} ${p.sid} ${p.tty} -1 4194560 0 0 0 0 0 0 0 0 20 0 1 0\n`);
    fs.writeFileSync(path.join(dir, 'cmdline'), (p.argv ?? [p.comm]).join('\0') + '\0');
    if (p.env !== null) fs.writeFileSync(path.join(dir, 'environ'), (p.env ?? ['HOME=/home/owner', 'PATH=/usr/bin', 'TERM=xterm-256color']).join('\0') + '\0');
  }
}

/**
 * Synthetic owner-present tree: sshd → login bash (session leader, pts/0) →
 * claude. The hook's parent is this jest worker, so the HARNESS row is keyed
 * on `process.pid`.
 */
function ownerTree(over: Partial<Record<'harness' | 'shell' | 'sshd', Partial<Proc>>> = {}, extra: Record<number, Proc> = {}): Record<number, Proc> {
  return {
    3100: { comm: 'sshd', ppid: 1, sid: 3100, tty: 0, ...over.sshd },
    3200: { comm: 'bash', ppid: 3100, sid: 3200, tty: TTY, argv: ['-bash'], ...over.shell },
    [process.pid]: { comm: 'claude', ppid: 3200, sid: 3200, tty: TTY, argv: ['claude', '--dangerously-skip-permissions'], ...over.harness },
    ...extra,
  };
}

describe('#923 owner-present harness TTY is log-only on the no-prompt-surface branch', () => {
  let home: string;
  let procRoot: string;
  let env: NodeJS.ProcessEnv;

  beforeEach(() => {
    home = fs.mkdtempSync(path.join(os.tmpdir(), 'sc-923-'));
    procRoot = path.join(home, 'synthetic-proc');
    env = { HOME: home, SHIELDCORTEX_CONFIG_DIR: path.join(home, '.shieldcortex'), SHIELDCORTEX_TEST_PROC_ROOT: procRoot };
    const dir = path.join(home, '.shieldcortex');
    fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(path.join(dir, 'config.json'), JSON.stringify({ actionGuard: { enabled: true, enforce: true } }));
  });
  afterEach(() => {
    fs.rmSync(home, { recursive: true, force: true });
  });

  function auditRows(): Array<Record<string, unknown>> {
    const dir = path.join(home, '.shieldcortex', 'audit');
    if (!fs.existsSync(dir)) return [];
    return fs.readdirSync(dir).filter((n) => /^realtime-.*\.jsonl$/.test(n))
      .flatMap((f) => fs.readFileSync(path.join(dir, f), 'utf-8').trim().split('\n').filter(Boolean).map((l) => JSON.parse(l)));
  }

  function expectLogOnly(result: HookResult): void {
    expect(result.code).toBe(0);
    expect(result.stdout).toBe('');
    const warnings = result.stderr.split('\n').filter((l) => /⚠️ Action Guard:/.test(l));
    expect(warnings).toHaveLength(1);
    expect(warnings[0]).toMatch(/owner-present terminal/);
    expect(warnings[0]).toMatch(/stop-process-or-service/);
    const rows = auditRows();
    const row = rows.find((r) => r.outcome === 'warned');
    expect(row).toBeDefined();
    expect(row!.action).toBe('warn');
    expect(row!.logOnlyReason).toBe('owner-present-tty');
    expect(rows.some((r) => r.outcome === 'denied_no_prompt_surface')).toBe(false);
  }

  async function expectNoPromptDeny(result: HookResult): Promise<void> {
    expect(decisionOf(result.stdout).permissionDecision).toBe('deny');
    expect(auditRows().some((r) => r.outcome === 'denied_no_prompt_surface')).toBe(true);
    expect(auditRows().some((r) => r.logOnlyReason === 'owner-present-tty')).toBe(false);
  }

  // (1) synthetic owner-present harness TTY
  it.each([['bypassPermissions'], ['dontAsk'], [undefined]])(
    'synthetic owner-present harness TTY: ordinary dangerous call is logged, not denied (mode %s)',
    async (mode) => {
      writeTree(procRoot, ownerTree());
      expectLogOnly(await runHook(call(DANGEROUS, mode), env));
    },
  );

  // (2) unproven / no TTY → today's deny
  it.each<[string, () => void, NodeJS.ProcessEnv]>([
    ['harness tty_nr is 0', () => writeTree(procRoot, ownerTree({ harness: { tty: 0 } })), {}],
    ['no synthetic tree (live /proc: the parent is a jest worker, not Claude)', () => undefined, { SHIELDCORTEX_TEST_PROC_ROOT: '' }],
    ['harness row missing', () => writeTree(procRoot, { 3200: ownerTree()[3200] }), {}],
    ['harness environment unreadable', () => writeTree(procRoot, ownerTree({ harness: { env: null } })), {}],
    ['an ancestor is unreadable', () => writeTree(procRoot, { [process.pid]: ownerTree()[process.pid] }), {}],
    ['harness is not Claude Code', () => writeTree(procRoot, ownerTree({ harness: { comm: 'node', argv: ['node', '/srv/runner.js'] } })), {}],
  ])('unproven owner presence keeps the deny: %s', async (_label, setup, envOver) => {
    setup();
    const result = await runHook(call(DANGEROUS, 'bypassPermissions'), { ...env, ...envOver });
    await expectNoPromptDeny(result);
  });

  // (3) catastrophic
  it('owner-present TTY + catastrophic still denies', async () => {
    writeTree(procRoot, ownerTree());
    const result = await runHook(call('rm -rf /', 'bypassPermissions'), env);
    expect(decisionOf(result.stdout).permissionDecision).toBe('deny');
    expect(auditRows().some((r) => r.logOnlyReason === 'owner-present-tty')).toBe(false);
  });

  // (4) guard-config write
  it('owner-present TTY + guard-config write still denies, naming touch-guard-config', async () => {
    writeTree(procRoot, ownerTree());
    const result = await runHook(call('echo {} > ~/.shieldcortex/config.json', 'bypassPermissions'), env);
    const d = decisionOf(result.stdout);
    expect(d.permissionDecision).toBe('deny');
    expect(d.permissionDecisionReason).toMatch(/touch-guard-config/);
  });

  // (5) disable-action-guard
  it('owner-present TTY + switching the guard off still denies, naming disable-action-guard', async () => {
    writeTree(procRoot, ownerTree());
    const result = await runHook(call('shieldcortex config --action-guard-disable', 'bypassPermissions'), env);
    const d = decisionOf(result.stdout);
    expect(d.permissionDecision).toBe('deny');
    expect(d.permissionDecisionReason).toMatch(/disable-action-guard/);
  });

  // (6) subagent / cron / agent-launched — TTY claimed, still denied
  it.each<[string, () => void, Record<string, unknown>]>([
    ['payload agent_id (subagent)', () => writeTree(procRoot, ownerTree()), { agent_id: 'a1b2', agent_type: 'general-purpose' }],
    ['subagent transcript path', () => writeTree(procRoot, ownerTree()), { transcript_path: '/home/owner/.claude/projects/p/s/subagents/agent-1.jsonl' }],
    ['cron session key', () => writeTree(procRoot, ownerTree()), { session_id: 'agent:main:cron:nightly' }],
    ['harness launched with CLAUDECODE in its environment', () => writeTree(procRoot, ownerTree({ harness: { env: ['HOME=/home/owner', 'CLAUDECODE=1'] } })), {}],
    ['harness launched by the Agent SDK', () => writeTree(procRoot, ownerTree({ harness: { env: ['HOME=/home/owner', 'CLAUDE_CODE_ENTRYPOINT=sdk-ts'] } })), {}],
    ['harness nested under another claude', () => writeTree(procRoot, ownerTree({ shell: { ppid: 3050 } }, { 3050: { comm: 'claude', ppid: 3100, sid: 3200, tty: TTY } })), {}],
    ['harness under cron', () => writeTree(procRoot, ownerTree({ shell: { ppid: 3050 } }, { 3050: { comm: 'cron', ppid: 1, sid: 3050, tty: 0 } })), {}],
    ['harness under script(1)', () => writeTree(procRoot, ownerTree({ shell: { ppid: 3050 } }, { 3050: { comm: 'script', ppid: 3100, sid: 3100, tty: 0 } })), {}],
    ['session leader spawned by python (pty.spawn)', () => writeTree(procRoot, ownerTree({ shell: { ppid: 3050 } }, { 3050: { comm: 'python3', ppid: 3100, sid: 3100, tty: 0 } })), {}],
  ])('subagent / scheduled / agent-launched harness keeps the deny: %s', async (_label, setup, extra) => {
    setup();
    const result = await runHook(call(DANGEROUS, 'bypassPermissions', extra), env);
    await expectNoPromptDeny(result);
  });

  // (7) prompting modes unchanged
  it.each([['default'], ['acceptEdits'], ['plan']])('prompting mode %s still asks with an owner-present TTY', async (mode) => {
    writeTree(procRoot, ownerTree());
    const result = await runHook(call(DANGEROUS, mode), env);
    expect(decisionOf(result.stdout).permissionDecision).toBe('ask');
    expect(auditRows().some((r) => r.outcome === 'asked')).toBe(true);
    expect(auditRows().some((r) => r.logOnlyReason === 'owner-present-tty')).toBe(false);
  });

  // (9) the hook's own isTTY is irrelevant: a pty wrapper around the hook proves nothing
  it('hook child with isTTY true but harness tty_nr 0 still denies', async () => {
    writeTree(procRoot, ownerTree({ harness: { tty: 0 }, shell: { tty: 0 } }));
    const preload = path.join(home, 'fake-tty.cjs');
    fs.writeFileSync(preload, "for (const s of ['stdin', 'stdout', 'stderr']) Object.defineProperty(process[s], 'isTTY', { value: true, configurable: true });\n");
    const result = await runHook(call(DANGEROUS, 'bypassPermissions'), env, { nodeArgs: ['--require', preload] });
    await expectNoPromptDeny(result);
  });

  // (8) mutation: the allow in (1) is the proof's, and (9) depends on tty_nr
  describe('mutations of the detector (copied install)', () => {
    function mutantInstall(from: string, to: string): string {
      const dir = path.join(home, 'install');
      fs.mkdirSync(path.join(dir, 'scripts', 'lib'), { recursive: true });
      fs.copyFileSync(HOOK_PATH, path.join(dir, 'scripts', 'pre-tool-hook.mjs'));
      const libDir = path.join(REPO_ROOT, 'scripts', 'lib');
      for (const f of fs.readdirSync(libDir)) {
        if (f.endsWith('.mjs')) fs.copyFileSync(path.join(libDir, f), path.join(dir, 'scripts', 'lib', f));
      }
      const target = path.join(dir, 'scripts', 'lib', 'owner-tty.mjs');
      const src = fs.readFileSync(target, 'utf-8');
      expect(src).toContain(from);
      fs.writeFileSync(target, src.replace(from, to));
      return path.join(dir, 'scripts', 'pre-tool-hook.mjs');
    }
    const mutantEnv = () => ({ ...env, SHIELDCORTEX_DIST_ROOT: path.join(REPO_ROOT, 'dist') });

    it('control: the unmutated copy reproduces (1)', async () => {
      writeTree(procRoot, ownerTree());
      const hookPath = mutantInstall('return { proven: true, harnessPid };', 'return { proven: true, harnessPid };');
      expectLogOnly(await runHook(call(DANGEROUS, 'bypassPermissions'), mutantEnv(), { hookPath }));
    });

    it('TTY proof disabled → (1) is denied again', async () => {
      writeTree(procRoot, ownerTree());
      const hookPath = mutantInstall('return { proven: true, harnessPid };', "return { proven: false, reason: 'mutant' };");
      await expectNoPromptDeny(await runHook(call(DANGEROUS, 'bypassPermissions'), mutantEnv(), { hookPath }));
    });

    it('tty_nr check removed → (9) would be allowed, so (9) pins it', async () => {
      writeTree(procRoot, ownerTree({ harness: { tty: 0 }, shell: { tty: 0 } }));
      const hookPath = mutantInstall('if (harness.tty === 0)', 'if (false)');
      expectLogOnly(await runHook(call(DANGEROUS, 'bypassPermissions'), mutantEnv(), { hookPath }));
    });

    it('a missing detector module fails closed', async () => {
      writeTree(procRoot, ownerTree());
      const hookPath = mutantInstall('import { readFileSync }', 'import { readFileSync, NOPE }');
      await expectNoPromptDeny(await runHook(call(DANGEROUS, 'bypassPermissions'), mutantEnv(), { hookPath }));
    });
  });
});

describe('#923 detector unit seams', () => {
  let root: string;
  beforeEach(() => { root = fs.mkdtempSync(path.join(os.tmpdir(), 'sc-923-proc-')); });
  afterEach(() => { fs.rmSync(root, { recursive: true, force: true }); });

  const tree = (): Record<number, Proc> => ({
    300: { comm: 'sshd', ppid: 1, sid: 300, tty: 0 },
    400: { comm: 'bash', ppid: 300, sid: 400, tty: TTY },
    500: { comm: 'claude', ppid: 400, sid: 400, tty: TTY },
  });

  it('synthetic owner-present tree is proven on linux', () => {
    writeTree(root, tree());
    expect(proveOwnerPresentHarness({ hookData: {}, platform: 'linux', procRoot: root, parentPid: 500, selfPid: 600 }))
      .toEqual({ proven: true, harnessPid: 500 });
  });

  it.each([['darwin'], ['win32'], ['freebsd']])('unproven on %s, whatever the tree says', (platform) => {
    writeTree(root, tree());
    expect(proveOwnerPresentHarness({ hookData: {}, platform, procRoot: root, parentPid: 500, selfPid: 600 }).proven).toBe(false);
  });

  it('skips the launcher shell to reach the harness, and never treats this process as one', () => {
    writeTree(root, { ...tree(), 550: { comm: 'sh', ppid: 500, sid: 400, tty: TTY, argv: ['/bin/sh', '-c', 'node hook.mjs'] } });
    expect(proveOwnerPresentHarness({ hookData: {}, platform: 'linux', procRoot: root, parentPid: 550, selfPid: 600 }).proven).toBe(true);
    expect(proveOwnerPresentHarness({ hookData: {}, platform: 'linux', procRoot: root, parentPid: 0, selfPid: 600 }).proven).toBe(false);
  });

  it('harness env markers track approve-provenance, narrowing only CLAUDE_CODE_', () => {
    const expected = AGENT_ENV_MARKERS.filter((m) => m !== 'CLAUDE_CODE_');
    expect([...HARNESS_AGENT_ENV_MARKERS].filter((m: string) => m !== 'CLAUDE_CODE_ENTRYPOINT').sort()).toEqual([...expected].sort());
    writeTree(root, { ...tree(), 500: { ...tree()[500], env: ['HOME=/h', 'CLAUDE_CODE_USE_BEDROCK=1'] } });
    expect(proveOwnerPresentHarness({ hookData: {}, platform: 'linux', procRoot: root, parentPid: 500, selfPid: 600 }).proven).toBe(true);
  });
});
