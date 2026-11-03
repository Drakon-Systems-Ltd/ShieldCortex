/**
 * #815 C — `shieldcortex approve` provenance: OpenClaw config exports are not
 * agent evidence.
 *
 * jarvis's login profile exports OpenClaw config locations (OPENCLAW_HOME and
 * friends). Every `OPENCLAW_*` name used to be a hard "agent-environment"
 * refusal, so the owner's own SSH shell could not approve. Now:
 *
 *   - CHILD markers (OPENCLAW_SHELL, OPENCLAW_CLI, OPENCLAW_AGENT_ID, session
 *     ids, CLAUDECODE, HERMES_SESSION_*, …, and any OPENCLAW_* name not on the
 *     config-export list) still refuse outright.
 *   - CONFIG exports (exact names) are skipped by the environment scan and
 *     read by nothing else, so the verdict with them set is EXACTLY the
 *     verdict with them unset. Agent-ancestor, manufactured-pty and
 *     no-controlling-terminal refusals come from the tree and are unchanged.
 *
 * Fix round 1 (Astra B1/B2): the first cut made the exports switch on extra
 * "strict" refusals, which refused an owner whose session is led by ash / nu /
 * pwsh / elvish, a shell inside sudo's PTY (leader is the sudo monitor) and
 * the init-parent WSL / console bash, all of which pass with no export. So
 * every tree here runs twice, with and without the exports, and the two
 * verdicts must be identical.
 *
 * Synthetic trees through the same seam as approve-provenance-502.test.ts.
 */
import { describe, expect, it } from '@jest/globals';

import {
  OPENCLAW_CONFIG_EXPORTS,
  describeProvenanceRefusal,
  makeDarwinProcReader,
  operatorProvenance,
  type ProcInfo,
  type ProvenanceReason,
  type ProvenanceSeam,
  type ProvenanceVerdict,
  type PsRunner,
} from '../approve-provenance.js';

type Row = [pid: number, ppid: number, sid: number, comm: string, tty?: number];
type Env = NodeJS.ProcessEnv;

function seam(rows: Row[], leafPid: number, env: Env = {}, platform: NodeJS.Platform = 'linux'): ProvenanceSeam {
  const map = new Map<number, ProcInfo>(rows.map(([pid, ppid, sid, comm, tty]) => [pid, { pid, ppid, sid, comm, tty: tty ?? 1 }]));
  return { pid: leafPid, env, platform, proc: (pid) => map.get(pid) ?? null };
}

const INIT: Row = [1, 0, 1, 'systemd'];

/** The jarvis login-profile shape: config exports plus ordinary login env. */
const JARVIS_ENV: Env = {
  HOME: '/home/michael',
  SHELL: '/bin/bash',
  TERM: 'xterm-256color',
  SSH_TTY: '/dev/pts/0',
  OPENCLAW_HOME: '/home/michael/.openclaw',
  OPENCLAW_STATE_DIR: '/home/michael/.openclaw/state',
  OPENCLAW_CONFIG_PATH: '/home/michael/.openclaw/openclaw.json',
};

/** Every export-bearing environment the invariant is checked under. */
const EXPORT_ENVS: [label: string, env: Env][] = [
  ['jarvis profile', JARVIS_ENV],
  ...OPENCLAW_CONFIG_EXPORTS.map((n): [string, Env] => [`${n} alone`, { [n]: '/x' }]),
  ['all four exports', Object.fromEntries(OPENCLAW_CONFIG_EXPORTS.map((n) => [n, '/x']))],
];

function withoutExports(env: Env): Env {
  return Object.fromEntries(Object.entries(env).filter(([k]) => !OPENCLAW_CONFIG_EXPORTS.includes(k)));
}

/**
 * Run the same seam with and without the config exports; the two verdicts
 * must be identical, field for field (ok, reason, detail, chain). Returns the
 * export-bearing verdict.
 */
function paired(make: (env: Env) => ProvenanceSeam, env: Env): ProvenanceVerdict {
  const bare = withoutExports(env);
  expect(Object.keys(env).some((k) => OPENCLAW_CONFIG_EXPORTS.includes(k))).toBe(true);
  expect(Object.keys(bare).some((k) => k.startsWith('OPENCLAW_'))).toBe(false);
  const exported = operatorProvenance(make(env));
  expect(exported).toEqual(operatorProvenance(make(bare)));
  return exported;
}

/** sshd → bash (leader) → node (approve). */
const SSH_TREE: Row[] = [INIT, [100, 1, 100, 'sshd'], [101, 100, 101, 'bash'], [102, 101, 101, 'node']];

/** sshd → <shell> (leader) → node. */
const sshShell = (shell: string): Row[] => [INIT, [100, 1, 100, 'sshd'], [101, 100, 101, shell], [102, 101, 101, 'node']];

/**
 * sudo with use_pty (the default): the outer sudo stays in the login session,
 * the sudo MONITOR leads a new session on a fresh pty, and the human's shell
 * runs under it. Layout observed live by Astra (`sudo` sid leader on pts/1,
 * `bash` its child in the same session).
 */
const SUDO_PTY_TREE: Row[] = [
  INIT,
  [100, 1, 100, 'sshd'],
  [101, 100, 101, 'bash'],
  [200, 101, 101, 'sudo'],
  [201, 200, 201, 'sudo'],
  [202, 201, 201, 'bash'],
  [203, 202, 201, 'node'],
];

/** WSL / console: the login bash's parent is init (pid 1). */
const INIT_PARENT_BASH: Row[] = [INIT, [101, 1, 101, 'bash'], [102, 101, 101, 'node']];

type Case = [label: string, rows: Row[], leaf: number, ok: boolean, reason: ProvenanceReason | null];

/** Owner sessions: allowed with or without the exports. */
const OWNER_CASES: Case[] = [
  ['sshd to bash (jarvis)', SSH_TREE, 102, true, null],
  ['B1: sshd to ash', sshShell('ash'), 102, true, null],
  ['B1: sshd to nu', sshShell('nu'), 102, true, null],
  ['B1: sshd to pwsh', sshShell('pwsh'), 102, true, null],
  ['B1: sshd to elvish', sshShell('elvish'), 102, true, null],
  ['B1: bash inside a sudo PTY (session leader is the sudo monitor)', SUDO_PTY_TREE, 203, true, null],
  ['B2: init-parent bash (WSL / console)', INIT_PARENT_BASH, 102, true, null],
  ['B2: init-parent bash where pid 1 itself cannot be read', [[101, 1, 101, 'bash'], [102, 101, 101, 'node']], 102, true, null],
  ['sshd-session to zsh', [INIT, [100, 1, 100, 'sshd-session'], [101, 100, 101, 'zsh'], [102, 101, 101, 'node']], 102, true, null],
  ['tmux server to bash', [INIT, [90, 1, 90, 'tmux: server'], [101, 90, 101, 'bash'], [102, 101, 101, 'node']], 102, true, null],
  ['agetty to login to bash (console)', [INIT, [100, 1, 100, 'agetty'], [101, 100, 101, 'login'], [102, 101, 102, 'bash'], [103, 102, 102, 'node']], 103, true, null],
  ['gnome-terminal-server to bash', [INIT, [100, 1, 100, 'gnome-terminal-server'], [101, 100, 101, 'bash'], [102, 101, 101, 'node']], 102, true, null],
  ['login shell argv[0] "-bash" under sshd', [INIT, [100, 1, 100, 'sshd'], [101, 100, 101, '-bash'], [102, 101, 101, 'node']], 102, true, null],
  ['nested human bash to bash to node', [INIT, [100, 1, 100, 'sshd'], [101, 100, 101, 'bash'], [102, 101, 101, 'bash'], [103, 102, 101, 'node']], 103, true, null],
  ['unlisted program leading the session under sshd', [INIT, [100, 1, 100, 'sshd'], [101, 100, 101, 'some-daemon'], [102, 101, 101, 'node']], 102, true, null],
  // N1 residual, pinned so it stays visible: an unlisted parent is not refused.
  ['residual: bash under an unlisted "arbitrary-launcher"', [INIT, [100, 1, 100, 'arbitrary-launcher'], [101, 100, 101, 'bash'], [102, 101, 101, 'node']], 102, true, null],
];

/** Agent and manufactured-terminal shapes: refused with or without the exports, for the same reason. */
const REFUSED_CASES: Case[] = [
  ['pty wrapper: script as session leader', [INIT, [20, 1, 20, 'script'], [22, 20, 20, 'node']], 22, false, 'pty-tool-session-leader'],
  ['pty wrapper: script -c places a shell leader on its pty', [INIT, [100, 1, 100, 'sshd'], [101, 100, 101, 'bash'],
    [102, 101, 101, 'script'], [103, 102, 103, 'sh'], [104, 103, 103, 'node']], 104, false, 'pty-tool-session-leader'],
  ['pty wrapper: script -c inside a sudo PTY', [...SUDO_PTY_TREE.slice(0, 6),
    [203, 202, 201, 'script'], [204, 203, 204, 'sh'], [205, 204, 204, 'node']], 205, false, 'pty-tool-session-leader'],
  ['pty wrapper: expect as session leader', [INIT, [20, 1, 20, 'expect'], [22, 20, 20, 'node']], 22, false, 'pty-tool-session-leader'],
  ['pty wrapper: python pty.spawn (bash leader, interpreter parent)', [INIT, [30, 1, 30, 'python3'], [31, 30, 31, 'bash'], [32, 31, 31, 'node']], 32, false, 'pty-interpreter-parent'],
  ['pty wrapper: python as session leader', [INIT, [60, 1, 60, 'python3'], [61, 60, 60, 'node']], 61, false, 'pty-interpreter-leader'],
  ['detached: setsid child with no controlling tty', [INIT, [50, 1, 50, 'node', 0]], 50, false, 'no-controlling-terminal'],
  ['detached: no controlling tty even under a clean sshd tree', [INIT, [100, 1, 100, 'sshd'], [101, 100, 101, 'bash'], [102, 101, 101, 'node', 0]], 102, false, 'no-controlling-terminal'],
  ['detached: no controlling tty under an init-parent bash', [INIT, [101, 1, 101, 'bash'], [102, 101, 101, 'node', 0]], 102, false, 'no-controlling-terminal'],
  ['detached: agent above the recovered session leader (orphaned leaf keeps the bash sid)', [INIT, [10, 1, 10, 'openclaw'], [20, 10, 20, 'bash'], [30, 1, 20, 'node']], 30, false, 'agent-ancestor'],
  ['detached: agent spawned a session-leading shell under itself', [INIT, [10, 1, 10, 'openclaw'], [11, 10, 10, 'bash'],
    [12, 11, 12, 'bash'], [13, 12, 12, 'node']], 13, false, 'agent-ancestor'],
  ...['openclaw', 'OPENCLAW', 'hermes', 'claude', 'codex'].map((agent): Case => [`agent ancestor ${agent} in the chain`,
    [INIT, [100, 1, 100, 'sshd'], [101, 100, 101, 'bash'], [102, 101, 101, agent], [103, 102, 103, 'bash'], [104, 103, 103, 'node']], 104, false, 'agent-ancestor']),
  ['agent ancestor above a sudo PTY', [INIT, [10, 1, 10, 'claude'], [101, 10, 101, 'bash'], [200, 101, 101, 'sudo'],
    [201, 200, 201, 'sudo'], [202, 201, 201, 'bash'], [203, 202, 201, 'node']], 203, false, 'agent-ancestor'],
  ['unreadable tree on Linux: a hole mid-walk', [INIT, [101, 77, 101, 'bash'], [102, 101, 101, 'node']], 102, false, 'process-tree-unreadable'],
  ['session leader gone', [INIT, [100, 1, 100, 'sshd'], [102, 100, 101, 'node']], 102, false, 'no-session-leader'],
];

describe('#815 C invariant: config exports alone give exactly the empty-environment verdict', () => {
  describe.each(EXPORT_ENVS)('%s', (_envLabel, env) => {
    it.each([...OWNER_CASES, ...REFUSED_CASES])('%s', (_label, rows, leaf, ok, reason) => {
      const v = paired((e) => seam(rows, leaf, e), env);
      expect(v.ok).toBe(ok);
      expect(v.reason).toBe(reason);
    });

    it('unreadable tree on Linux (this process cannot be inspected) refuses the same way', () => {
      const v = paired((e) => ({ pid: 102, env: e, platform: 'linux', proc: () => null }), env);
      expect(v.reason).toBe('process-tree-unreadable');
    });

    it('unreadable tree on macOS refuses the same way', () => {
      const v = paired((e) => ({ pid: 102, env: e, platform: 'darwin', proc: () => null }), env);
      expect(v.reason).toBe('process-tree-unreadable');
    });

    it('macOS leader under launchd refuses the same way', () => {
      const v = paired((e) => seam([[1, 0, 1, 'launchd'], [401, 1, 401, '-zsh'], [450, 401, 401, 'node']], 450, e, 'darwin'), env);
      expect(v.reason).toBe('orphaned-shell-leader');
    });

    it.each(['win32', 'freebsd'] as NodeJS.Platform[])('non-tree platform %s keeps the environment-only check', (platform) => {
      const v = paired((e) => ({ pid: 1, env: e, platform, proc: () => null }), env);
      expect(v.ok).toBe(true);
      expect(v.detail).toMatch(/environment check only/);
    });
  });
});

describe('#815 C Astra round-1 reproducer, verbatim', () => {
  // The exact rows and proc function from state/reviews/sc-pr-987-1-astra.md.
  // At the reviewed head the export rows came back ok:false
  // (non-shell-session-leader / orphaned-shell-leader).
  it.each([['SSH ash', 'ash', 100], ['WSL/console bash', 'bash', 1]] as [string, string, number][])('%s', (_label, shell, ppid) => {
    const rows = [[1, 0, 1, 'systemd'], [100, 1, 100, 'sshd'], [101, ppid, 101, shell], [102, 101, 101, 'node']] as const;
    const proc = (pid: number): ProcInfo | null => {
      const r = rows.find((x) => x[0] === pid);
      return r ? { pid: r[0], ppid: r[1], sid: r[2], comm: r[3], tty: pid === 102 ? 1 : 0 } : null;
    };
    for (const env of [{}, { OPENCLAW_HOME: '/x' }]) {
      const { ok, reason } = operatorProvenance({ pid: 102, platform: 'linux', env, proc });
      expect({ env, ok, reason }).toEqual({ env, ok: true, reason: null });
    }
  });
});

describe('#815 C B2: the init-parent owner beside the detached-agent shapes', () => {
  it('owner: WSL / console bash with the jarvis exports is allowed', () => {
    const v = operatorProvenance(seam(INIT_PARENT_BASH, 102, JARVIS_ENV));
    expect(v.ok).toBe(true);
    expect(v.reason).toBeNull();
  });

  it('agent child on the same tree: OPENCLAW_SHELL beside the exports refuses', () => {
    const v = operatorProvenance(seam(INIT_PARENT_BASH, 102, { ...JARVIS_ENV, OPENCLAW_SHELL: 'exec' }));
    expect(v.reason).toBe('agent-environment');
  });

  it('agent child on the same tree: OPENCLAW_CLI beside the exports refuses', () => {
    const v = operatorProvenance(seam(INIT_PARENT_BASH, 102, { ...JARVIS_ENV, OPENCLAW_CLI: '1' }));
    expect(v.reason).toBe('agent-environment');
  });

  it('detached agent: setsid child that kept a manufactured pty but has no controlling tty', () => {
    const v = operatorProvenance(seam([INIT, [101, 1, 101, 'bash'], [102, 101, 101, 'node', 0]], 102, JARVIS_ENV));
    expect(v.reason).toBe('no-controlling-terminal');
  });

  it('detached agent: orphaned leaf whose session leader sits under the agent', () => {
    const v = operatorProvenance(seam([INIT, [10, 1, 10, 'openclaw'], [20, 10, 20, 'bash'], [30, 1, 20, 'node']], 30, JARVIS_ENV));
    expect(v.reason).toBe('agent-ancestor');
  });
});

describe('#815 C child markers stay HARD refusals, even beside config exports, on every owner shape', () => {
  const MARKERS: [label: string, marker: Env][] = [
    ['OPENCLAW_SHELL (set by the OpenClaw exec tool)', { OPENCLAW_SHELL: 'exec' }],
    ['OPENCLAW_CLI', { OPENCLAW_CLI: '1' }],
    ['OPENCLAW_AGENT_ID', { OPENCLAW_AGENT_ID: 'main' }],
    ['OPENCLAW_SESSION_ID', { OPENCLAW_SESSION_ID: 's-1' }],
    ['OPENCLAW_PARENT_PID', { OPENCLAW_PARENT_PID: '4242' }],
    ['OPENCLAW_GATEWAY_TOKEN', { OPENCLAW_GATEWAY_TOKEN: 't' }],
    ['empty-valued OPENCLAW_SHELL', { OPENCLAW_SHELL: '' }],
    ['unknown OPENCLAW_SOMETHING_NEW', { OPENCLAW_SOMETHING_NEW: '1' }],
    ['near-miss OPENCLAW_HOME_DIR (exact match only)', { OPENCLAW_HOME_DIR: '/h' }],
    ['near-miss OPENCLAW_CONFIG_DIR (not a name OpenClaw reads)', { OPENCLAW_CONFIG_DIR: '/c' }],
    ['near-miss OPENCLAW_PROFILE_ID', { OPENCLAW_PROFILE_ID: 'p' }],
    ['CLAWDBOT_STATE_DIR (legacy prefix stays hard)', { CLAWDBOT_STATE_DIR: '/s' }],
    ['CLAUDECODE', { CLAUDECODE: '1' }],
    ['CLAUDE_CODE_ENTRYPOINT', { CLAUDE_CODE_ENTRYPOINT: 'cli' }],
    ['HERMES_SESSION_ID', { HERMES_SESSION_ID: 'x' }],
    ['HERMES_SUPERVISED_CHILD', { HERMES_SUPERVISED_CHILD: '1' }],
    ['CODEX_THREAD_ID', { CODEX_THREAD_ID: 't' }],
  ];

  describe.each(OWNER_CASES.map(([label, rows, leaf]) => [label, rows, leaf] as [string, Row[], number]))('%s', (_tree, rows, leaf) => {
    it.each(MARKERS)('%s', (_label, marker) => {
      const v = operatorProvenance(seam(rows, leaf, { ...JARVIS_ENV, ...marker }));
      expect(v.ok).toBe(false);
      expect(v.reason).toBe('agent-environment');
    });
  });

  it.each(['win32', 'freebsd'] as NodeJS.Platform[])('non-tree platform %s: a child marker beside the exports refuses', (platform) => {
    const v = operatorProvenance({ pid: 1, env: { ...JARVIS_ENV, OPENCLAW_SHELL: 'exec' }, platform, proc: () => null });
    expect(v.reason).toBe('agent-environment');
  });

  it('child marker refuses whichever order the env keys arrive in', () => {
    const before = operatorProvenance(seam(SSH_TREE, 102, { OPENCLAW_AGENT_ID: 'main', OPENCLAW_HOME: '/h' }));
    const after = operatorProvenance(seam(SSH_TREE, 102, { OPENCLAW_HOME: '/h', OPENCLAW_AGENT_ID: 'main' }));
    expect(before.reason).toBe('agent-environment');
    expect(after.reason).toBe('agent-environment');
    expect(after.detail).toMatch(/OPENCLAW_AGENT_ID/);
  });
});

describe('#815 C wording', () => {
  it('a pass does not claim positive proof of a human (N1)', () => {
    const v = operatorProvenance(seam(SSH_TREE, 102, JARVIS_ENV));
    expect(v.ok).toBe(true);
    expect(v.detail).not.toMatch(/login session led by a shell under a terminal provider/);
    expect(v.detail).toMatch(/unlisted terminal provider or a multiplexer is not refused/);
    expect(v.detail).toMatch(/not proof that a human opened the terminal/);
  });

  it('a refusal never names a config export: it is not why the command refused (N2)', () => {
    for (const s of [
      { pid: 102, env: JARVIS_ENV, platform: 'linux' as const, proc: () => null },
      { pid: 102, env: JARVIS_ENV, platform: 'darwin' as const, proc: () => null },
      seam([INIT, [20, 1, 20, 'script'], [22, 20, 20, 'node']], 22, JARVIS_ENV),
    ]) {
      const v = operatorProvenance(s);
      expect(v.ok).toBe(false);
      expect(describeProvenanceRefusal(v).join('\n')).not.toMatch(/OPENCLAW_(HOME|STATE_DIR|CONFIG_PATH|PROFILE)/);
    }
  });
});

describe('#815 C on macOS through the real Darwin reader', () => {
  interface FakeProc { ppid: number; tty: string; comm: string; stat: string }
  function fakePs(procs: Record<number, FakeProc>): PsRunner {
    return (args: string[]) => {
      if (args[0] === '-t') {
        const rows = Object.entries(procs).filter(([, p]) => p.tty === args[1]);
        if (rows.length === 0) throw new Error('ps exited 1');
        return rows.map(([pid, p]) => `${pid} ${p.stat}`).join('\n') + '\n';
      }
      const p = procs[Number(args[args.indexOf('-p') + 1])];
      if (!p) throw new Error('ps exited 1');
      return `${p.ppid} ${p.tty} ${p.comm}\n`;
    };
  }
  const LAUNCHD: FakeProc = { ppid: 0, tty: '??', comm: '/sbin/launchd', stat: 'Ss' };
  const run = (procs: Record<number, FakeProc>, leaf: number) =>
    paired((env) => ({ pid: leaf, env, platform: 'darwin', proc: makeDarwinProcReader(fakePs(procs)) }), { OPENCLAW_HOME: '/Users/m/.openclaw' });

  it('Terminal.app (login leader under Terminal) is allowed', () => {
    expect(run({
      1: LAUNCHD,
      500: { ppid: 1, tty: '??', comm: '/System/Applications/Utilities/Terminal.app/Contents/MacOS/Terminal', stat: 'S' },
      600: { ppid: 500, tty: 'ttys000', comm: 'login', stat: 'Ss' },
      601: { ppid: 600, tty: 'ttys000', comm: '-zsh', stat: 'S' },
      700: { ppid: 601, tty: 'ttys000', comm: 'node', stat: 'S+' },
    }, 700).ok).toBe(true);
  });

  it('SSH (-zsh leader under sshd-session) is allowed', () => {
    expect(run({
      1: LAUNCHD,
      390: { ppid: 1, tty: '??', comm: 'sshd-session: michael [priv]', stat: 'Ss' },
      400: { ppid: 390, tty: '??', comm: 'sshd-session: michael@ttys001', stat: 'S' },
      401: { ppid: 400, tty: 'ttys001', comm: '-zsh', stat: 'Ss' },
      450: { ppid: 401, tty: 'ttys001', comm: 'node', stat: 'S+' },
    }, 450).ok).toBe(true);
  });

  it('sudo PTY under an SSH -zsh (sudo monitor leads the new session) is allowed', () => {
    expect(run({
      1: LAUNCHD,
      390: { ppid: 1, tty: '??', comm: 'sshd-session: michael [priv]', stat: 'Ss' },
      400: { ppid: 390, tty: '??', comm: 'sshd-session: michael@ttys001', stat: 'S' },
      401: { ppid: 400, tty: 'ttys001', comm: '-zsh', stat: 'Ss' },
      410: { ppid: 401, tty: 'ttys001', comm: 'sudo', stat: 'S+' },
      411: { ppid: 410, tty: 'ttys002', comm: 'sudo', stat: 'Ss' },
      412: { ppid: 411, tty: 'ttys002', comm: 'zsh', stat: 'S' },
      450: { ppid: 412, tty: 'ttys002', comm: 'node', stat: 'S+' },
    }, 450).ok).toBe(true);
  });

  it('no session leader found on the tty is refused', () => {
    const v = run({
      1: LAUNCHD,
      401: { ppid: 1, tty: 'ttys002', comm: '-zsh', stat: 'S' },
      450: { ppid: 401, tty: 'ttys002', comm: 'node', stat: 'S+' },
    }, 450);
    expect(v.ok).toBe(false);
    expect(v.reason).toBe('no-session-leader');
  });

  it('an agent above the Terminal.app session is refused', () => {
    const v = run({
      1: LAUNCHD,
      300: { ppid: 1, tty: '??', comm: 'claude', stat: 'S' },
      500: { ppid: 300, tty: '??', comm: 'Terminal', stat: 'S' },
      600: { ppid: 500, tty: 'ttys000', comm: 'login', stat: 'Ss' },
      601: { ppid: 600, tty: 'ttys000', comm: '-zsh', stat: 'S' },
      700: { ppid: 601, tty: 'ttys000', comm: 'node', stat: 'S+' },
    }, 700);
    expect(v.reason).toBe('agent-ancestor');
  });
});
