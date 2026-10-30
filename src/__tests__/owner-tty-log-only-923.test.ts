/**
 * #923 — an owner-present interactive terminal is log-only on the
 * no-prompt-surface branch, through the real scripts/pre-tool-hook.mjs and the
 * built classifier.
 *
 * Principle 4 of #875: when a human owns the terminal Claude Code runs in, an
 * ordinary dangerous call in `dontAsk` / unknown mode is logged (one warning
 * line, a `warned` audit row) instead of denied. `bypassPermissions` keeps the
 * deny, and so do headless paths — subagents, crons, print mode, tmux/screen,
 * agent-launched or pty-wrapped Claude; catastrophic and the guard
 * self-protection floor deny everywhere.
 *
 * Every process tree below is SYNTHETIC. The hook has no environment seam for
 * /proc (review finding 6), so hook-level cases run a COPIED install whose
 * detector's `PROC_ROOT` constant is rewritten to a temp tree; detector unit
 * cases inject an in-memory proc reader and transcript reader directly. No
 * case parses live /proc for its proof. No host records are reproduced here.
 */
import { spawn } from 'child_process';
import fs from 'fs';
import os from 'os';
import path from 'path';
import { fileURLToPath } from 'url';
import { afterEach, beforeEach, describe, expect, it } from '@jest/globals';
// The hook imports this published .mjs file; keep the unit cases on the same module.
// @ts-ignore no declaration is emitted for scripts outside the TS build
import { proveOwnerPresentHarness, HARNESS_AGENT_ENV_MARKERS, TERMINAL_EXE_PATHS } from '../../scripts/lib/owner-tty.mjs';
import { AGENT_ENV_MARKERS } from '../cli/approve-provenance.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = path.resolve(__dirname, '..', '..');
const HOOK_PATH = path.resolve(REPO_ROOT, 'scripts', 'pre-tool-hook.mjs');
const DETECTOR_PATH = path.resolve(REPO_ROOT, 'scripts', 'lib', 'owner-tty.mjs');
const PROC_ROOT_LINE = "const PROC_ROOT = '/proc';";
const DANGEROUS = 'sudo systemctl stop nginx';
const TTY = 34816; // /dev/pts/0
const SESSION = 'sc-923-session';
const TOOL_USE = 'toolu_sc923';
// The detector proves owner presence on Linux only; elsewhere the same tree is
// unproven and keeps the deny, so log-only expectations are Linux-gated.
const ON_LINUX = process.platform === 'linux';
const itLinux = ON_LINUX ? it : it.skip;
const itNonLinux = ON_LINUX ? it.skip : it;

type HookResult = { stdout: string; stderr: string; code: number };
type Proc = {
  comm: string; ppid: number; sid: number; tty: number;
  pgrp?: number; tpgid?: number; argv?: string[]; env?: string[] | null;
  /** All four uids in `status` (default 1000, the owner). */
  uid?: number;
  /** Target of the `exe` link; absent = unreadable (non-dumpable, root, or EACCES). */
  exe?: string;
  /** stat field 22, clock ticks since boot (default 1000: every row started in the same tick). */
  start?: number;
  /** Files of this row that cannot be read (finding 7). */
  unreadable?: Array<'stat' | 'cmdline' | 'environ' | 'status'>;
};
type Rows = Record<number, Proc>;

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

function decisionOf(stdout: string): { permissionDecision?: string; permissionDecisionReason?: string } {
  return stdout.trim() ? JSON.parse(stdout).hookSpecificOutput ?? {} : {};
}

function statLine(pid: number | string, p: Proc): string {
  const pgrp = p.pgrp ?? Number(pid);
  const tpgid = p.tpgid ?? (p.tty === 0 ? -1 : pgrp);
  return `${pid} (${p.comm}) S ${p.ppid} ${pgrp} ${p.sid} ${p.tty} ${tpgid} 4194560 0 0 0 0 0 0 0 0 20 0 1 0 ${p.start ?? 1000} 0 0\n`;
}

function rowFiles(pid: number | string, p: Proc): Record<string, string> {
  const files: Record<string, string> = {
    stat: statLine(pid, p),
    cmdline: (p.argv ?? [p.comm]).join('\0') + '\0',
    status: `Name:\t${p.comm}\nUid:\t${p.uid ?? 1000}\t${p.uid ?? 1000}\t${p.uid ?? 1000}\t${p.uid ?? 1000}\nGid:\t1000\t1000\t1000\t1000\n`,
  };
  if (p.env !== null) files.environ = (p.env ?? ['HOME=/home/owner', 'PATH=/usr/bin', 'TERM=xterm-256color']).join('\0') + '\0';
  for (const f of p.unreadable ?? []) delete files[f];
  return files;
}

/** Write a synthetic proc tree: one `<root>/<pid>/{stat,cmdline,status,environ,exe}` per row. */
function writeTree(root: string, rows: Rows): void {
  for (const [pid, p] of Object.entries(rows)) {
    const dir = path.join(root, pid);
    fs.mkdirSync(dir, { recursive: true });
    for (const [name, body] of Object.entries(rowFiles(pid, p))) fs.writeFileSync(path.join(dir, name), body);
    // A dangling link is fine: the detector reads the link, it never follows it.
    if (p.exe !== undefined) fs.symlinkSync(p.exe, path.join(dir, 'exe'));
  }
}

/** The same tree as an injected in-memory `(pid, file) => Buffer | null` reader. */
function memProc(rows: Rows): (pid: number, file: string) => Buffer | null {
  return (pid, file) => {
    const p = rows[pid];
    if (!p) return null;
    const body = rowFiles(pid, p)[file];
    return body === undefined ? null : Buffer.from(body);
  };
}

/** The same tree's `exe` links as an injected `(pid, link) => string | null` reader. */
function memLink(rows: Rows): (pid: number, link: string) => string | null {
  return (pid, link) => (link === 'exe' ? rows[pid]?.exe ?? null : null);
}

/** One transcript record for the call being vetted; top-level interactive CLI unless overridden. */
function transcriptRecord(over: Record<string, unknown> = {}): string {
  return JSON.stringify({
    parentUuid: 'p-1', isSidechain: false, type: 'assistant', uuid: 'u-1', sessionId: SESSION, entrypoint: 'cli',
    message: { role: 'assistant', content: [{ type: 'tool_use', id: TOOL_USE, name: 'Bash', input: { command: DANGEROUS } }] },
    ...over,
  });
}

/**
 * Synthetic owner-present tree, OpenSSH 9.6 shape: root `sshd: owner [priv]`
 * → user-owned, non-dumpable (exe unreadable) `sshd: owner@pts/0` → login bash
 * (session leader, pts/0) → claude (foreground job). The harness row is keyed
 * on `harnessPid`.
 */
function ownerTree(harnessPid: number, over: Partial<Record<'harness' | 'shell' | 'sshd', Partial<Proc>>> = {}, extra: Rows = {}): Rows {
  return {
    3000: { comm: 'sshd', ppid: 1, sid: 3000, tty: 0, uid: 0, argv: ['sshd: owner [priv]'] },
    3100: { comm: 'sshd', ppid: 3000, sid: 3100, tty: 0, argv: ['sshd: owner@pts/0'], ...over.sshd },
    3200: { comm: 'bash', ppid: 3100, sid: 3200, tty: TTY, tpgid: harnessPid, argv: ['-bash'], ...over.shell },
    [harnessPid]: { comm: 'claude', ppid: 3200, sid: 3200, tty: TTY, argv: ['claude'], ...over.harness },
    ...extra,
  };
}

/** Node-run Claude Code (comm `node`, npm cli path in argv) → sh: a nested harness whose own env was scrubbed (`env -i`). */
const NODE_CLAUDE_ANCESTOR: Rows = {
  3050: { comm: 'node', ppid: 3100, sid: 3100, tty: 0, argv: ['node', '/usr/lib/node_modules/@anthropic-ai/claude-code/cli.js'] },
  3060: { comm: 'sh', ppid: 3050, sid: 3060, tty: 0, argv: ['/bin/sh', '-c', 'env -i claude'] },
};

/** A same-uid `systemd --user` in the root sshd's slot: what a setsid + double-fork daemon reparents to. */
const DAEMON_PARENT: Rows = { 3000: { comm: 'systemd', ppid: 1, sid: 3000, tty: 0, argv: ['/usr/lib/systemd/systemd', '--user'] } };

describe('#923 owner-present harness TTY is log-only on the no-prompt-surface branch', () => {
  let home: string;
  let procRoot: string;
  let transcriptPath: string;
  let env: NodeJS.ProcessEnv;
  // The hook's parent is this jest worker, so the HARNESS row is keyed on it.
  const HARNESS = process.pid;

  beforeEach(() => {
    home = fs.mkdtempSync(path.join(os.tmpdir(), 'sc-923-'));
    procRoot = path.join(home, 'synthetic-proc');
    fs.mkdirSync(procRoot, { recursive: true });
    const project = path.join(home, '.claude', 'projects', 'p');
    fs.mkdirSync(project, { recursive: true });
    transcriptPath = path.join(project, `${SESSION}.jsonl`);
    fs.writeFileSync(transcriptPath, `${JSON.stringify({ type: 'user', isSidechain: false, sessionId: SESSION })}\n${transcriptRecord()}\n`);
    env = {
      HOME: home,
      SHIELDCORTEX_CONFIG_DIR: path.join(home, '.shieldcortex'),
      SHIELDCORTEX_DIST_ROOT: path.join(REPO_ROOT, 'dist'),
    };
    const dir = path.join(home, '.shieldcortex');
    fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(path.join(dir, 'config.json'), JSON.stringify({ actionGuard: { enabled: true, enforce: true } }));
  });
  afterEach(() => {
    fs.rmSync(home, { recursive: true, force: true });
  });

  function call(command: unknown, permissionMode?: string, extra: Record<string, unknown> = {}): Record<string, unknown> {
    const payload: Record<string, unknown> = {
      session_id: SESSION,
      transcript_path: transcriptPath,
      cwd: '/tmp',
      hook_event_name: 'PreToolUse',
      tool_name: 'Bash',
      tool_input: { command },
      tool_use_id: TOOL_USE,
      ...extra,
    };
    if (permissionMode !== undefined) payload.permission_mode = permissionMode;
    return payload;
  }

  /**
   * A copied install (hook + scripts/lib) whose detector reads `procRoot`
   * instead of /proc, optionally with one more source substitution (mutants).
   */
  function install(mutation?: [string, string]): string {
    const dir = path.join(home, 'install');
    fs.mkdirSync(path.join(dir, 'scripts', 'lib'), { recursive: true });
    fs.copyFileSync(HOOK_PATH, path.join(dir, 'scripts', 'pre-tool-hook.mjs'));
    const libDir = path.join(REPO_ROOT, 'scripts', 'lib');
    for (const f of fs.readdirSync(libDir)) {
      if (f.endsWith('.mjs')) fs.copyFileSync(path.join(libDir, f), path.join(dir, 'scripts', 'lib', f));
    }
    const target = path.join(dir, 'scripts', 'lib', 'owner-tty.mjs');
    let src = fs.readFileSync(target, 'utf-8');
    expect(src).toContain(PROC_ROOT_LINE);
    src = src.replace(PROC_ROOT_LINE, `const PROC_ROOT = ${JSON.stringify(procRoot)};`);
    if (mutation) {
      expect(src).toContain(mutation[0]);
      src = src.replace(mutation[0], mutation[1]);
    }
    fs.writeFileSync(target, src);
    return path.join(dir, 'scripts', 'pre-tool-hook.mjs');
  }

  const runInstalled = (payload: unknown, mutation?: [string, string]) => runHook(payload, env, { hookPath: install(mutation) });

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

  function expectNoPromptDeny(result: HookResult): void {
    expect(decisionOf(result.stdout).permissionDecision).toBe('deny');
    expect(auditRows().some((r) => r.outcome === 'denied_no_prompt_surface')).toBe(true);
    expect(auditRows().some((r) => r.logOnlyReason === 'owner-present-tty')).toBe(false);
  }

  function expectDenyNotLogged(result: HookResult): void {
    expect(decisionOf(result.stdout).permissionDecision).toBe('deny');
    expect(auditRows().some((r) => r.logOnlyReason === 'owner-present-tty')).toBe(false);
  }

  // (1) synthetic owner-present harness TTY
  itLinux.each([['dontAsk'], [undefined]])(
    'synthetic owner-present harness TTY: ordinary dangerous call is logged, not denied (mode %s)',
    async (mode) => {
      writeTree(procRoot, ownerTree(HARNESS));
      expectLogOnly(await runInstalled(call(DANGEROUS, mode)));
    },
  );

  // (1') off Linux the same owner-present tree is unproven: today's deny
  itNonLinux.each([['dontAsk'], [undefined]])(
    'non-linux: the same synthetic owner-present tree still denies (mode %s)',
    async (mode) => {
      writeTree(procRoot, ownerTree(HARNESS));
      expectNoPromptDeny(await runInstalled(call(DANGEROUS, mode)));
    },
  );

  // Finding 1: bypassPermissions never enters the log-only branch
  it('finding 1: bypassPermissions keeps the deny even with a proven owner-present terminal', async () => {
    writeTree(procRoot, ownerTree(HARNESS));
    expectNoPromptDeny(await runInstalled(call(DANGEROUS, 'bypassPermissions')));
  });

  // Finding 6: no environment seam — the shipped hook reads only /proc
  it('finding 6: the shipped hook ignores SHIELDCORTEX_TEST_PROC_ROOT on an unlocked host', async () => {
    writeTree(procRoot, ownerTree(HARNESS));
    const result = await runHook(call(DANGEROUS, 'dontAsk'), { ...env, SHIELDCORTEX_TEST_PROC_ROOT: procRoot });
    expectNoPromptDeny(result);
    for (const file of [HOOK_PATH, DETECTOR_PATH]) {
      expect(fs.readFileSync(file, 'utf-8')).not.toMatch(/SHIELDCORTEX_TEST_PROC_ROOT|procRoot:/);
    }
  });

  // (2) unproven owner presence → today's deny (one per finding, through the hook)
  it.each<[string, () => void, Record<string, unknown>]>([
    ['harness tty_nr is 0', () => writeTree(procRoot, ownerTree(HARNESS, { harness: { tty: 0 } })), {}],
    ['harness row missing', () => writeTree(procRoot, { 3200: ownerTree(HARNESS)[3200] }), {}],
    ['harness environment unreadable', () => writeTree(procRoot, ownerTree(HARNESS, { harness: { env: null } })), {}],
    ['an ancestor is unreadable', () => writeTree(procRoot, { [HARNESS]: ownerTree(HARNESS)[HARNESS] }), {}],
    ['harness is not Claude Code', () => writeTree(procRoot, ownerTree(HARNESS, { harness: { comm: 'node', argv: ['node', '/srv/runner.js'] } })), {}],
    ['finding 2: harness launched with --print', () => writeTree(procRoot, ownerTree(HARNESS, { harness: { argv: ['claude', '-p', 'do it'] } })), {}],
    ['finding 2: harness under a detached tmux server', () => writeTree(procRoot, ownerTree(HARNESS, { sshd: { comm: 'tmux: server', argv: ['tmux'] } })), {}],
    ['finding 3: claude is its own session leader under python3 (pty.spawn)', () => writeTree(procRoot, {
      3050: { comm: 'python3', ppid: 3100, sid: 3100, tty: 0, argv: ['python3', 'drive.py'] },
      3100: { comm: 'sshd', ppid: 1, sid: 3100, tty: 0 },
      [HARNESS]: { comm: 'claude', ppid: 3050, sid: HARNESS, tty: TTY, argv: ['claude'] },
    }), {}],
    ['finding 5: payload carries no tool_use_id', () => writeTree(procRoot, ownerTree(HARNESS)), { tool_use_id: undefined }],
    ['finding 5: payload carries no transcript_path', () => writeTree(procRoot, ownerTree(HARNESS)), { transcript_path: undefined }],
    ['finding 5: the call is a sidechain record', () => {
      writeTree(procRoot, ownerTree(HARNESS));
      fs.writeFileSync(transcriptPath, `${transcriptRecord({ isSidechain: true })}\n`);
    }, {}],
    ['finding 7: harness cmdline unreadable (comm claude)', () => writeTree(procRoot, ownerTree(HARNESS, { harness: { unreadable: ['cmdline'] } })), {}],
    ['round 3 finding 1: daemonised driver renamed "sshd", reparented to init', () => writeTree(procRoot, ownerTree(HARNESS, { sshd: { ppid: 1 } })), {}],
    ['round 3 finding 1: "sshd" under a user-owned systemd --user', () => writeTree(procRoot, ownerTree(HARNESS, { sshd: { ppid: 3000 } }, DAEMON_PARENT)), {}],
    ['round 3 finding 1: comm sshd but exe python3', () => writeTree(procRoot, ownerTree(HARNESS, { sshd: { exe: '/usr/bin/python3.12' } })), {}],
    ['round 3 finding 1: comm xterm, exe unreadable', () => writeTree(procRoot, ownerTree(HARNESS, { sshd: { comm: 'xterm', ppid: 1 } })), {}],
    ['round 4 pid reuse: the root sshd started after its sshd session', () => writeTree(procRoot, ownerTree(HARNESS, { sshd: { start: 900 } })), {}],
  ])('unproven owner presence keeps the deny: %s', async (_label, setup, extra) => {
    setup();
    expectNoPromptDeny(await runInstalled(call(DANGEROUS, 'dontAsk', extra)));
  });

  it('no synthetic tree (shipped hook, live /proc: the parent is a jest worker, not Claude) keeps the deny', async () => {
    expectNoPromptDeny(await runHook(call(DANGEROUS, 'dontAsk'), env));
  });

  // (3) catastrophic
  it('owner-present TTY + catastrophic still denies', async () => {
    writeTree(procRoot, ownerTree(HARNESS));
    expectDenyNotLogged(await runInstalled(call('rm -rf /', 'dontAsk')));
  });

  // (4) guard-config write
  it('owner-present TTY + guard-config write still denies, naming touch-guard-config', async () => {
    writeTree(procRoot, ownerTree(HARNESS));
    const result = await runInstalled(call('echo {} > ~/.shieldcortex/config.json', 'dontAsk'));
    expectDenyNotLogged(result);
    expect(decisionOf(result.stdout).permissionDecisionReason).toMatch(/touch-guard-config/);
  });

  // (5) disable-action-guard
  it('owner-present TTY + switching the guard off still denies, naming disable-action-guard', async () => {
    writeTree(procRoot, ownerTree(HARNESS));
    const result = await runInstalled(call('shieldcortex config --action-guard-disable', 'dontAsk'));
    expectDenyNotLogged(result);
    expect(decisionOf(result.stdout).permissionDecisionReason).toMatch(/disable-action-guard/);
  });

  // (5') unscanned: a tool input the schema rejects is never widened
  it('owner-present TTY + unscanned (schema-invalid) tool input still denies', async () => {
    writeTree(procRoot, ownerTree(HARNESS));
    expectDenyNotLogged(await runInstalled(call(42, 'dontAsk')));
  });

  // (6) subagent / cron / agent-launched — TTY claimed, still denied
  it.each<[string, () => void, Record<string, unknown>]>([
    ['payload agent_id (subagent)', () => writeTree(procRoot, ownerTree(HARNESS)), { agent_id: 'a1b2', agent_type: 'general-purpose' }],
    ['subagent transcript path', () => writeTree(procRoot, ownerTree(HARNESS)), { transcript_path: '/home/owner/.claude/projects/p/s/subagents/agent-1.jsonl' }],
    ['cron session key', () => writeTree(procRoot, ownerTree(HARNESS)), { session_id: 'agent:main:cron:nightly' }],
    ['harness launched with CLAUDECODE in its environment', () => writeTree(procRoot, ownerTree(HARNESS, { harness: { env: ['HOME=/home/owner', 'CLAUDECODE=1'] } })), {}],
    ['harness launched by the Agent SDK', () => writeTree(procRoot, ownerTree(HARNESS, { harness: { env: ['HOME=/home/owner', 'CLAUDE_CODE_ENTRYPOINT=sdk-ts'] } })), {}],
    ['harness nested under another claude', () => writeTree(procRoot, ownerTree(HARNESS, { shell: { ppid: 3050 } }, { 3050: { comm: 'claude', ppid: 3100, sid: 3200, tty: TTY } })), {}],
    ['harness nested under a node-run claude (cli.js argv), env scrubbed', () => writeTree(procRoot, ownerTree(HARNESS, { shell: { ppid: 3060 } }, NODE_CLAUDE_ANCESTOR)), {}],
    ['harness under cron', () => writeTree(procRoot, ownerTree(HARNESS, { shell: { ppid: 3050 } }, { 3050: { comm: 'cron', ppid: 1, sid: 3050, tty: 0 } })), {}],
    ['harness under script(1)', () => writeTree(procRoot, ownerTree(HARNESS, { shell: { ppid: 3050 } }, { 3050: { comm: 'script', ppid: 3100, sid: 3100, tty: 0 } })), {}],
    ['session leader spawned by python (pty.spawn)', () => writeTree(procRoot, ownerTree(HARNESS, { shell: { ppid: 3050 } }, { 3050: { comm: 'python3', ppid: 3100, sid: 3100, tty: 0 } })), {}],
  ])('subagent / scheduled / agent-launched harness keeps the deny: %s', async (_label, setup, extra) => {
    setup();
    expectNoPromptDeny(await runInstalled(call(DANGEROUS, 'dontAsk', extra)));
  });

  // (7) prompting modes unchanged
  it.each([['default'], ['acceptEdits'], ['plan']])('prompting mode %s still asks with an owner-present TTY', async (mode) => {
    writeTree(procRoot, ownerTree(HARNESS));
    const result = await runInstalled(call(DANGEROUS, mode));
    expect(decisionOf(result.stdout).permissionDecision).toBe('ask');
    expect(auditRows().some((r) => r.outcome === 'asked')).toBe(true);
    expect(auditRows().some((r) => r.logOnlyReason === 'owner-present-tty')).toBe(false);
  });

  // (9) the hook's own isTTY is irrelevant: a pty wrapper around the hook proves nothing
  it('hook child with isTTY true but harness tty_nr 0 still denies', async () => {
    writeTree(procRoot, ownerTree(HARNESS, { harness: { tty: 0 }, shell: { tty: 0 } }));
    const preload = path.join(home, 'fake-tty.cjs');
    fs.writeFileSync(preload, "for (const s of ['stdin', 'stdout', 'stderr']) Object.defineProperty(process[s], 'isTTY', { value: true, configurable: true });\n");
    const result = await runHook(call(DANGEROUS, 'dontAsk'), env, { hookPath: install(), nodeArgs: ['--require', preload] });
    expectNoPromptDeny(result);
  });

  // (8) mutation: the allow in (1) is the proof's, and (9) depends on tty_nr
  describe('mutations of the detector (copied install)', () => {
    itLinux('control: the unmutated copy reproduces (1)', async () => {
      writeTree(procRoot, ownerTree(HARNESS));
      expectLogOnly(await runInstalled(call(DANGEROUS, 'dontAsk'), ['return { proven: true, harnessPid };', 'return { proven: true, harnessPid };']));
    });

    it('TTY proof disabled → (1) is denied again', async () => {
      writeTree(procRoot, ownerTree(HARNESS));
      expectNoPromptDeny(await runInstalled(call(DANGEROUS, 'dontAsk'), ['return { proven: true, harnessPid };', "return { proven: false, reason: 'mutant' };"]));
    });

    itLinux('tty_nr check removed → (9) would be allowed, so (9) pins it', async () => {
      // tpgid stays the harness's pgrp so only the tty_nr check bites.
      writeTree(procRoot, ownerTree(HARNESS, { harness: { tty: 0, tpgid: HARNESS }, shell: { tty: 0 } }));
      expectLogOnly(await runInstalled(call(DANGEROUS, 'dontAsk'), ['if (harness.tty === 0)', 'if (false)']));
    });

    itLinux('root-sshd anchor removed → a "sshd" under systemd --user would be logged, so the anchor is what denies it', async () => {
      writeTree(procRoot, ownerTree(HARNESS, { sshd: { ppid: 3000 } }, DAEMON_PARENT));
      expectLogOnly(await runInstalled(call(DANGEROUS, 'dontAsk'),
        ["if (!isRootOwned(monitor) || !nameIn(monitor.comm, SSHD_NAMES)) return 'sshd session is not under a root sshd';", '']));
    });

    itLinux('exe interpreter check removed → comm "sshd" with exe python3 under a root sshd would be logged', async () => {
      writeTree(procRoot, ownerTree(HARNESS, { sshd: { exe: '/usr/bin/python3.12' } }));
      expectNoPromptDeny(await runInstalled(call(DANGEROUS, 'dontAsk')));
      fs.rmSync(path.join(home, '.shieldcortex', 'audit'), { recursive: true, force: true });
      expectLogOnly(await runInstalled(call(DANGEROUS, 'dontAsk'),
        ['return nameIn(proc.comm, list) || (exe !== null && nameIn(exe, list));', 'return nameIn(proc.comm, list);']));
    });

    it('a missing detector module fails closed', async () => {
      writeTree(procRoot, ownerTree(HARNESS));
      expectNoPromptDeny(await runInstalled(call(DANGEROUS, 'dontAsk'), ['import { resolveHarnessPid }', 'import { resolveHarnessPid, NOPE }']));
    });
  });
});

describe('#923 detector unit seams (injected in-memory readers)', () => {
  const tree = (): Rows => ({
    250: { comm: 'sshd', ppid: 1, sid: 250, tty: 0, uid: 0, argv: ['sshd: owner [priv]'] },
    300: { comm: 'sshd', ppid: 250, sid: 300, tty: 0, argv: ['sshd: owner@pts/0'] },
    400: { comm: 'bash', ppid: 300, sid: 400, tty: TTY, tpgid: 500, argv: ['-bash'] },
    500: { comm: 'claude', ppid: 400, sid: 400, tty: TTY, argv: ['claude'] },
  });
  const TRANSCRIPT = `/home/owner/.claude/projects/p/${SESSION}.jsonl`;
  const payload = (over: Record<string, unknown> = {}) => ({ session_id: SESSION, transcript_path: TRANSCRIPT, tool_use_id: TOOL_USE, ...over });
  const topLevel = (over: Record<string, unknown> = {}) => (p: string) => (p === TRANSCRIPT ? `${transcriptRecord(over)}\n` : null);

  function prove(rows: Rows, opts: { hookData?: unknown; platform?: string; parentPid?: number; readTranscript?: (p: string) => string | null } = {}) {
    return proveOwnerPresentHarness({
      hookData: opts.hookData ?? payload(),
      platform: opts.platform ?? 'linux',
      readProcFile: memProc(rows),
      readProcLink: memLink(rows),
      readTranscript: opts.readTranscript ?? topLevel(),
      parentPid: opts.parentPid ?? 500,
      selfPid: 600,
    });
  }

  it('synthetic owner-present tree is proven on linux', () => {
    expect(prove(tree())).toEqual({ proven: true, harnessPid: 500 });
  });

  it('claude as its own session leader directly under sshd (`ssh -t host claude`) is proven', () => {
    expect(prove({ 250: tree()[250], 300: tree()[300], 500: { comm: 'claude', ppid: 300, sid: 500, tty: TTY, argv: ['claude'] } }))
      .toEqual({ proven: true, harnessPid: 500 });
  });

  it.each([['darwin'], ['win32'], ['freebsd']])('unproven on %s, whatever the tree says', (platform) => {
    expect(prove(tree(), { platform }).proven).toBe(false);
  });

  it('skips the launcher shell to reach the harness, and never treats this process as one', () => {
    const rows = { ...tree(), 550: { comm: 'sh', ppid: 500, sid: 400, tty: TTY, argv: ['/bin/sh', '-c', 'node hook.mjs'] } };
    expect(prove(rows, { parentPid: 550 }).proven).toBe(true);
    expect(prove(rows, { parentPid: 0 }).proven).toBe(false);
  });

  it('an ancestor recognised as Claude Code by argv (comm node) is nested, not owner-present', () => {
    const rows: Rows = {
      ...tree(),
      250: { comm: 'sshd', ppid: 360, sid: 250, tty: 0, uid: 0 },
      350: { comm: 'node', ppid: 1, sid: 350, tty: 0, argv: ['node', '/usr/lib/node_modules/@anthropic-ai/claude-code/cli.js'] },
      360: { comm: 'sh', ppid: 350, sid: 360, tty: 0, argv: ['/bin/sh', '-c', 'env -i sshd'] },
    };
    expect(prove(rows)).toEqual({ proven: false, reason: 'harness is nested under an agent' });
    expect(prove({ ...rows, 350: { ...rows[350], argv: ['node', '/srv/runner.js'] } })).toEqual({ proven: true, harnessPid: 500 });
  });

  it('harness env markers track approve-provenance, narrowing only CLAUDE_CODE_', () => {
    const expected = AGENT_ENV_MARKERS.filter((m) => m !== 'CLAUDE_CODE_');
    expect([...HARNESS_AGENT_ENV_MARKERS].filter((m: string) => m !== 'CLAUDE_CODE_ENTRYPOINT').sort()).toEqual([...expected].sort());
    expect(prove({ ...tree(), 500: { ...tree()[500], env: ['HOME=/h', 'CLAUDE_CODE_USE_BEDROCK=1'] } }).proven).toBe(true);
  });

  // Finding 2: a TTY is not a human. Non-interactive launches and multiplexers are unproven.
  it.each<[string, string[]]>([
    ['-p', ['claude', '-p', 'fix it']],
    ['--print', ['claude', '--print', 'fix it']],
    ['--print=', ['claude', '--print=fix']],
    ['-p in a short-flag cluster', ['claude', '-cp', 'fix it']],
    ['--output-format stream-json', ['claude', '--output-format', 'stream-json']],
    ['--input-format=stream-json', ['claude', '--input-format=stream-json']],
    ['node-run claude -p', ['node', '/usr/lib/node_modules/@anthropic-ai/claude-code/cli.js', '-p', 'x']],
    ['--dangerously-skip-permissions', ['claude', '--dangerously-skip-permissions']],
    ['--permission-mode bypassPermissions', ['claude', '--permission-mode', 'bypassPermissions']],
    ['--permission-mode=bypassPermissions', ['claude', '--permission-mode=bypassPermissions']],
  ])('finding 2: non-interactive or bypass launch is unproven: %s', (_label, argv) => {
    const rows = tree();
    rows[500] = { ...rows[500], comm: argv[0] === 'node' ? 'node' : 'claude', argv };
    expect(prove(rows)).toEqual({ proven: false, reason: expect.stringMatching(/print mode|stream format|bypass mode/) });
  });

  it.each<[string, (r: Rows) => Rows]>([
    ['harness is a background job (tpgid != pgrp)', (r) => ({ ...r, 500: { ...r[500], tpgid: 400 } })],
    ['detached tmux server ancestor', (r) => ({ ...r, 300: { comm: 'tmux: server', ppid: 1, sid: 300, tty: 0, argv: ['tmux', 'new', '-d'] } })],
    ['screen ancestor', (r) => ({ ...r, 300: { comm: 'screen', ppid: 1, sid: 300, tty: 0, argv: ['SCREEN', '-dmS', 'x'] } })],
    ['TMUX in the harness environment', (r) => ({ ...r, 500: { ...r[500], env: ['HOME=/h', 'TMUX=/tmp/tmux-1000/default,1,0'] } })],
    ['STY in the harness environment', (r) => ({ ...r, 500: { ...r[500], env: ['HOME=/h', 'STY=1.pts-0.host'] } })],
  ])('finding 2: no positive interactive evidence is unproven: %s', (_label, mutate) => {
    expect(prove(mutate(tree()))).toEqual({ proven: false, reason: expect.stringMatching(/foreground job|terminal multiplexer/) });
  });

  // Finding 3: a direct pty.spawn makes claude its own session leader; its parent is still checked.
  it.each<[string, Proc]>([
    ['python3', { comm: 'python3', ppid: 300, sid: 300, tty: 0, argv: ['python3', 'drive.py'] }],
    ['node', { comm: 'node', ppid: 300, sid: 300, tty: 0, argv: ['node', 'drive.js'] }],
    ['an unrecognised parent', { comm: 'runner', ppid: 300, sid: 300, tty: 0, argv: ['runner'] }],
  ])('finding 3: claude as session leader spawned by %s is unproven', (_label, parent) => {
    expect(prove({
      250: tree()[250],
      300: tree()[300],
      350: parent,
      500: { comm: 'claude', ppid: 350, sid: 500, tty: TTY, argv: ['claude'] },
    })).toEqual({ proven: false, reason: expect.stringMatching(/spawned by an interpreter|terminal executable unreadable/) });
  });

  it.each<[string, (r: Rows) => Rows]>([
    ['session leader is not a shell', (r) => ({ ...r, 400: { ...r[400], comm: 'node', argv: ['node', 'x.js'] } })],
    ['harness is not a direct child of its session shell', (r) => ({
      ...r, 450: { comm: 'make', ppid: 400, sid: 400, tty: TTY, argv: ['make'] }, 500: { ...r[500], ppid: 450 },
    })],
    ['session leader on another terminal', (r) => ({ ...r, 400: { ...r[400], tty: TTY + 1 } })],
  ])('finding 3: session shape not a human login is unproven: %s', (_label, mutate) => {
    expect(prove(mutate(tree()))).toEqual({ proven: false, reason: expect.stringMatching(/not a shell|not started by its session shell|another terminal/) });
  });

  // Finding 5: only positive top-level provenance proves; a missing marker never does.
  it.each<[string, Record<string, unknown>, ((p: string) => string | null) | undefined]>([
    ['no tool_use_id', { tool_use_id: undefined }, undefined],
    ['no session_id', { session_id: undefined }, undefined],
    ['no transcript_path', { transcript_path: undefined }, undefined],
    ['relative transcript_path', { transcript_path: `${SESSION}.jsonl` }, undefined],
    ['transcript is another session\'s file', { transcript_path: '/home/owner/.claude/projects/p/other.jsonl' }, undefined],
    ['transcript unreadable', {}, () => null],
    ['tool call not in the transcript', { tool_use_id: 'toolu_other' }, undefined],
    ['record is a sidechain', {}, topLevel({ isSidechain: true })],
    ['record has no isSidechain field', {}, topLevel({ isSidechain: undefined })],
    ['record carries an agentId', {}, topLevel({ agentId: 'a1' })],
    ['record from another session', {}, topLevel({ sessionId: 'other' })],
    ['SDK / print entrypoint', {}, topLevel({ entrypoint: 'sdk-cli' })],
    ['no entrypoint', {}, topLevel({ entrypoint: undefined })],
    ['record is not an assistant message', {}, topLevel({ type: 'user' })],
  ])('finding 5: absent or non-top-level provenance is unproven: %s', (_label, over, readTranscript) => {
    expect(prove(tree(), { hookData: payload(over), readTranscript }))
      .toEqual({ proven: false, reason: expect.stringMatching(/provenance|transcript|main chain|subagent|another session|interactive CLI|assistant record/) });
  });

  // Finding 7: anything unreadable that the decision needs is unproven.
  it.each<[string, (r: Rows) => Rows]>([
    ['harness cmdline unreadable (comm claude)', (r) => ({ ...r, 500: { ...r[500], unreadable: ['cmdline'] } })],
    ['harness cmdline empty', (r) => ({ ...r, 500: { ...r[500], argv: [] } })],
    ['harness environ unreadable', (r) => ({ ...r, 500: { ...r[500], unreadable: ['environ'] } })],
    ['session leader cmdline unreadable', (r) => ({ ...r, 400: { ...r[400], unreadable: ['cmdline'] } })],
    ['session leader parent unreadable', (r) => ({ ...r, 300: { ...r[300], unreadable: ['stat'] } })],
    ['session leader parent missing', (r) => { const { 300: _gone, ...rest } = r; return rest; }],
    ['ancestor cmdline unreadable', (r) => ({ ...r, 300: { ...r[300], unreadable: ['cmdline'] } })],
  ])('finding 7: unreadable process data is unproven: %s', (_label, mutate) => {
    expect(prove(mutate(tree()))).toEqual({ proven: false, reason: expect.stringMatching(/unreadable/) });
  });

  // Round 3 finding 1: comm is self-set. Identity is the exe link and the
  // status uids; comm only ever adds a deny. `leader(parent)` puts `parent`
  // (pid 300) under login bash 400 → claude 500, with `extra` rows above it.
  describe('round 3 finding 1: session leader parent is anchored on exe and uids, not comm', () => {
    const leader = (parent: Proc, extra: Rows = {}): Rows => ({ ...extra, 300: parent, 400: tree()[400], 500: tree()[500] });
    const ROOT_SSHD: Proc = { comm: 'sshd', ppid: 1, sid: 250, tty: 0, uid: 0, argv: ['sshd: owner [priv]'] };

    it.each<[string, Rows, string]>([
      ['comm sshd, exe /usr/bin/python3, user-owned, parent init',
        leader({ comm: 'sshd', ppid: 1, sid: 300, tty: 0, exe: '/usr/bin/python3' }), 'session leader spawned by an interpreter'],
      ['comm sshd, exe unreadable (non-dumpable), user-owned, parent systemd --user (uid 1001)',
        leader({ comm: 'sshd', ppid: 200, sid: 300, tty: 0 }, { 200: { comm: 'systemd', ppid: 1, sid: 200, tty: 0, uid: 1001, argv: ['/usr/lib/systemd/systemd', '--user'] } }),
        'sshd session is not under a root sshd'],
      ['comm sshd, exe unreadable, parent pid 1', leader({ comm: 'sshd', ppid: 1, sid: 300, tty: 0 }), 'sshd session is not under a root sshd'],
      ['comm sshd-session, exe unreadable, parent a user-owned "sshd"',
        leader({ comm: 'sshd-session', ppid: 250, sid: 300, tty: 0 }, { 250: { ...ROOT_SSHD, uid: 1000 } }), 'sshd session is not under a root sshd'],
      ['comm sshd under a root parent that is not sshd',
        leader({ comm: 'sshd', ppid: 250, sid: 300, tty: 0 }, { 250: { ...ROOT_SSHD, comm: 'polkitd' } }), 'sshd session is not under a root sshd'],
      ['root sshd parent with a mixed uid set (euid 0 only)',
        leader({ comm: 'sshd', ppid: 250, sid: 300, tty: 0 }, { 250: ROOT_SSHD }), ''],
      // The ancestry walk reads the same row first, so it names the refusal.
      ['comm sshd, the root parent unreadable', leader({ comm: 'sshd', ppid: 250, sid: 300, tty: 0 }), 'ancestor unreadable'],
      ['root-owned, but comm is not sshd or login', leader({ comm: 'bash', ppid: 1, sid: 300, tty: 0, uid: 0 }), 'session leader parent is root but not sshd or login'],
      ['comm gnome-terminal-, exe /home/x/bin/gnome-terminal-server (not an allowlisted path)',
        leader({ comm: 'gnome-terminal-', ppid: 200, sid: 300, tty: 0, exe: '/home/x/bin/gnome-terminal-server' }, { 200: { comm: 'systemd', ppid: 1, sid: 200, tty: 0, argv: ['systemd', '--user'] } }),
        'session leader not started by a login or terminal'],
      ['comm xterm, exe unreadable', leader({ comm: 'xterm', ppid: 1, sid: 300, tty: 0 }), 'terminal executable unreadable'],
      ['comm xterm, exe /usr/bin/xterm but a path-prefix lookalike (/usr/bin/xterm-evil)',
        leader({ comm: 'xterm', ppid: 1, sid: 300, tty: 0, exe: '/usr/bin/xterm-evil' }), 'session leader not started by a login or terminal'],
      ['interpreter by exe, comm renamed bash', leader({ comm: 'bash', ppid: 1, sid: 300, tty: 0, exe: '/usr/bin/python3.12' }), 'session leader spawned by an interpreter'],
      ['interpreter by exe, comm renamed sshd, under a real root sshd',
        leader({ comm: 'sshd', ppid: 250, sid: 300, tty: 0, exe: '/usr/bin/python3.12' }, { 250: ROOT_SSHD }), 'session leader spawned by an interpreter'],
      ['interpreter by exe (deleted), comm renamed xterm', leader({ comm: 'xterm', ppid: 1, sid: 300, tty: 0, exe: '/usr/bin/node (deleted)' }), 'session leader spawned by an interpreter'],
    ])('unproven: %s', (label, rows, reason) => {
      if (label.startsWith('root sshd parent with a mixed uid set')) {
        // euid 0 alone is not root-owned: rewrite the status to real 1000, effective 0.
        const read = memProc(rows);
        const mixed = (pid: number, file: string) => (pid === 250 && file === 'status'
          ? Buffer.from('Name:\tsshd\nUid:\t1000\t0\t0\t0\n') : read(pid, file));
        expect(proveOwnerPresentHarness({
          hookData: payload(), platform: 'linux', readProcFile: mixed, readProcLink: memLink(rows), readTranscript: topLevel(), parentPid: 500, selfPid: 600,
        })).toEqual({ proven: false, reason: 'sshd session is not under a root sshd' });
        return;
      }
      expect(prove(rows)).toEqual({ proven: false, reason });
    });

    it.each<[string, Rows]>([
      ['OpenSSH 9.6: user-owned non-dumpable sshd under a root sshd (not pid 1)', leader({ comm: 'sshd', ppid: 250, sid: 300, tty: 0, argv: ['sshd: owner@pts/0'] }, { 250: ROOT_SSHD })],
      ['OpenSSH >= 9.8: user-owned non-dumpable sshd-session under a root sshd-session',
        leader({ comm: 'sshd-session', ppid: 250, sid: 300, tty: 0, argv: ['sshd-session: owner@pts/0'] }, { 250: { ...ROOT_SSHD, comm: 'sshd-session', argv: ['sshd-session: owner [priv]'] } })],
      ['root-owned login as the session leader parent', leader({ comm: 'login', ppid: 1, sid: 300, tty: TTY, uid: 0, argv: ['/bin/login', '-p', '--'] })],
      ['root-owned sshd as the session leader parent (root login)', leader({ comm: 'sshd', ppid: 1, sid: 300, tty: 0, uid: 0 })],
      ['terminal emulator with a readable allowlisted exe',
        leader({ comm: 'gnome-terminal-', ppid: 200, sid: 300, tty: 0, exe: '/usr/libexec/gnome-terminal-server', argv: ['/usr/libexec/gnome-terminal-server'] },
          { 200: { comm: 'systemd', ppid: 1, sid: 200, tty: 0, argv: ['/usr/lib/systemd/systemd', '--user'] } })],
      ['terminal emulator whose comm differs from its allowlisted exe', leader({ comm: 'kitty-wrapper', ppid: 1, sid: 300, tty: 0, exe: '/usr/lib/kitty/bin/kitty' })],
    ])('proven: %s', (_label, rows) => {
      expect(prove(rows)).toEqual({ proven: true, harnessPid: 500 });
    });

    it('a pty tool in the ancestry is found by exe when its comm was renamed', () => {
      const rows = leader({ comm: 'sshd', ppid: 250, sid: 300, tty: 0 }, { 250: { ...ROOT_SSHD, ppid: 240 }, 240: { comm: 'bash', ppid: 1, sid: 240, tty: 0, exe: '/usr/bin/script' } });
      expect(prove(rows)).toEqual({ proven: false, reason: 'harness runs under a pty tool' });
      expect(prove({ ...rows, 240: { ...rows[240], exe: '/usr/bin/expect' } })).toEqual({ proven: false, reason: 'harness runs under a pty tool' });
      expect(prove({ ...rows, 240: { ...rows[240], exe: '/usr/bin/bash' } })).toEqual({ proven: true, harnessPid: 500 });
    });

    it('a multiplexer or scheduler in the ancestry is found by exe when its comm was renamed', () => {
      const rows = leader({ comm: 'sshd', ppid: 250, sid: 300, tty: 0 }, { 250: { ...ROOT_SSHD, ppid: 240 }, 240: { comm: 'bash', ppid: 1, sid: 240, tty: 0, exe: '/usr/bin/tmux' } });
      expect(prove(rows)).toEqual({ proven: false, reason: 'harness runs under a terminal multiplexer' });
      expect(prove({ ...rows, 240: { ...rows[240], exe: '/usr/sbin/cron' } })).toEqual({ proven: false, reason: 'harness runs under a scheduler' });
    });

    it('a process whose status has no full Uid line is unreadable, never root', () => {
      const rows = leader({ comm: 'sshd', ppid: 250, sid: 300, tty: 0 }, { 250: ROOT_SSHD });
      const read = memProc(rows);
      const noUid = (pid: number, file: string) => (pid === 250 && file === 'status' ? Buffer.from('Name:\tsshd\nUid:\t0\t0\n') : read(pid, file));
      expect(proveOwnerPresentHarness({
        hookData: payload(), platform: 'linux', readProcFile: noUid, readProcLink: memLink(rows), readTranscript: topLevel(), parentPid: 500, selfPid: 600,
      })).toEqual({ proven: false, reason: 'ancestor unreadable' });
    });

    it('the terminal allowlist is exact absolute paths: no globs, no directories, nothing under /home or /tmp', () => {
      for (const p of TERMINAL_EXE_PATHS as readonly string[]) {
        expect(p).toMatch(/^\/usr\/(?:bin|lib|lib64|libexec)\/[A-Za-z0-9._/-]+[A-Za-z0-9]$/);
        expect(p).not.toMatch(/[*?]/);
      }
    });
  });

  // Round 4 (Grok): pid-reuse TOCTOU. Every /proc read is its own syscall, so
  // a parent can exit and its pid be recycled — by a genuine root sshd for an
  // `ssh localhost` the attacker opened — between the child's stat and the
  // parent's status. `phased` serves `later` for every file of `pid` once its
  // stat has been read `reads` times: the recycle lands mid-proof.
  describe('round 4: child → parent hops survive pid reuse', () => {
    const ROOT_SSHD: Proc = { comm: 'sshd', ppid: 1, sid: 250, tty: 0, uid: 0, argv: ['sshd: owner [priv]'] };
    const proveWith = (rows: Rows, readProcFile: (pid: number, file: string) => Buffer | null) => proveOwnerPresentHarness({
      hookData: payload(), platform: 'linux', readProcFile, readProcLink: memLink(rows), readTranscript: topLevel(), parentPid: 500, selfPid: 600,
    });
    function phased(rows: Rows, pid: number, later: Proc | null, reads = 1) {
      const before = memProc(rows);
      const after = later === null ? () => null : memProc({ ...rows, [pid]: later });
      let n = 0;
      return (p: number, file: string) => {
        if (p === pid && file === 'stat') n++;
        return p === pid && n > reads ? after(p, file) : before(p, file);
      };
    }
    // Sane, strictly increasing start times: root sshd < sshd session < shell < claude.
    const aged = (r: Rows): Rows => ({ ...r, 250: { ...r[250], start: 100 }, 300: { ...r[300], start: 200 }, 400: { ...r[400], start: 300 }, 500: { ...r[500], start: 400 } });

    it.each<[string, Rows]>([
      ['OpenSSH 9.6 (sshd → sshd), increasing start times', aged(tree())],
      ['OpenSSH >= 9.8 (sshd-session → sshd-session), increasing start times', aged({
        ...tree(),
        250: { ...ROOT_SSHD, comm: 'sshd-session', argv: ['sshd-session: owner [priv]'] },
        300: { comm: 'sshd-session', ppid: 250, sid: 300, tty: 0, argv: ['sshd-session: owner@pts/0'] },
      })],
      ['every process started in the same clock tick', tree()],
    ])('proven: %s', (_label, rows) => {
      expect(prove(rows)).toEqual({ proven: true, harnessPid: 500 });
    });

    it('a root sshd anchor younger than its sshd session is a reused pid', () => {
      const rows = aged(tree());
      expect(prove({ ...rows, 250: { ...rows[250], start: 250 } })).toEqual({ proven: false, reason: 'ancestor pid was reused' });
    });

    it('the root sshd pid recycled after the ancestry walk, before the anchor read, is caught on the anchor hop', () => {
      const rows = aged(tree());
      // Walk reads 250 once; the anchor read in loginParentFailure is the second.
      expect(proveWith(rows, phased(rows, 250, { ...rows[250], start: 9000 }))).toEqual({ proven: false, reason: 'ancestor pid was reused' });
    });

    it('a root-owned login parent recycled after the walk (younger than the leader) is denied', () => {
      const rows: Rows = { ...aged(tree()), 300: { comm: 'login', ppid: 1, sid: 300, tty: TTY, uid: 0, argv: ['/bin/login', '-p', '--'], start: 200 } };
      delete rows[250];
      expect(prove(rows)).toEqual({ proven: true, harnessPid: 500 });
      expect(proveWith(rows, phased(rows, 300, { ...rows[300], start: 9000 }))).toEqual({ proven: false, reason: 'ancestor pid was reused' });
    });

    it('a root-owned login parent statically younger than the leader is denied', () => {
      const rows: Rows = { ...aged(tree()), 300: { comm: 'login', ppid: 1, sid: 300, tty: TTY, uid: 0, argv: ['/bin/login', '-p', '--'], start: 350 } };
      delete rows[250];
      expect(prove(rows)).toEqual({ proven: false, reason: 'ancestor pid was reused' });
    });

    it('the sshd session reparented between its first and second stat read (its parent exited) is denied', () => {
      const rows = aged(tree());
      expect(proveWith(rows, phased(rows, 300, { ...rows[300], ppid: 1 }))).toEqual({ proven: false, reason: 'ancestor changed during the check' });
    });

    it('the leader reparented after the walk, before the leader-parent read, is denied', () => {
      const rows = aged(tree());
      // 400's stat: walk read (1), re-read on the 400 → 300 hop (2), session-leader read (3), re-read on leader → parent (4).
      expect(proveWith(rows, phased(rows, 400, { ...rows[400], ppid: 1 }, 3))).toEqual({ proven: false, reason: 'ancestor changed during the check' });
    });

    it('a child whose own pid was recycled between reads (start time changed) is denied', () => {
      const rows = aged(tree());
      expect(proveWith(rows, phased(rows, 300, { ...rows[300], start: 5000 }))).toEqual({ proven: false, reason: 'ancestor changed during the check' });
    });

    it('a child whose stat vanishes on the re-read is unproven', () => {
      const rows = aged(tree());
      expect(proveWith(rows, phased(rows, 300, null))).toEqual({ proven: false, reason: 'ancestor re-read unreadable' });
    });

    it.each<[string, string, string]>([
      ['harness stat has no starttime', '500 (claude) S 400 500 400 34816 500 4194560 0 0 0 0 0 0 0 0 20 0 1 0\n', 'harness unreadable'],
      ['harness starttime is not a number', '500 (claude) S 400 500 400 34816 500 4194560 0 0 0 0 0 0 0 0 20 0 1 0 abc 0 0\n', 'harness unreadable'],
      ['harness starttime is negative', '500 (claude) S 400 500 400 34816 500 4194560 0 0 0 0 0 0 0 0 20 0 1 0 -5 0 0\n', 'harness unreadable'],
    ])('missing or malformed starttime is unproven: %s', (_label, stat, reason) => {
      const rows = tree();
      const read = memProc(rows);
      expect(proveWith(rows, (pid, file) => (pid === 500 && file === 'stat' ? Buffer.from(stat) : read(pid, file)))).toEqual({ proven: false, reason });
    });

    it('an ancestor with a malformed starttime is unreadable', () => {
      const rows = tree();
      const read = memProc(rows);
      const bad = (pid: number, file: string) => (pid === 250 && file === 'stat' ? Buffer.from('250 (sshd) S 1 250 250 0 -1 4194560 0 0 0 0 0 0 0 0 20 0 1 0 1e3 0 0\n') : read(pid, file));
      expect(proveWith(rows, bad)).toEqual({ proven: false, reason: 'ancestor unreadable' });
    });
  });

  it('finding 7: a harness whose stat lacks tpgid is unproven', () => {
    const rows = tree();
    const read = memProc(rows);
    const truncated = (pid: number, file: string) => (pid === 500 && file === 'stat'
      ? Buffer.from(`500 (claude) S 400 500 400 ${TTY}\n`) : read(pid, file));
    expect(proveOwnerPresentHarness({
      hookData: payload(), platform: 'linux', readProcFile: truncated, readProcLink: memLink(rows), readTranscript: topLevel(), parentPid: 500, selfPid: 600,
    })).toEqual({ proven: false, reason: 'harness unreadable' });
  });
});
