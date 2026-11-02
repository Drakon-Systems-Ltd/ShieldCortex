/**
 * #815 C — `shieldcortex approve` provenance: the env markers are split.
 *
 * jarvis's login profile exports OpenClaw config locations (OPENCLAW_HOME and
 * friends). Every `OPENCLAW_*` name used to be a hard "agent-environment"
 * refusal, so the owner's own SSH shell could not approve. Now:
 *
 *   - CHILD markers (OPENCLAW_SHELL, OPENCLAW_AGENT_ID, session ids,
 *     CLAUDECODE, HERMES_SESSION_*, …, and any OPENCLAW_* name not on the
 *     config-export list) still refuse outright.
 *   - CONFIG exports (exact names) do not refuse by themselves, but approve
 *     then needs a tree that positively vouches for a human: readable, a
 *     controlling tty, a shell leader whose parent is a terminal provider
 *     (not init), no pty tool / interpreter, no agent ancestor.
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
  type ProvenanceSeam,
  type PsRunner,
} from '../approve-provenance.js';

type Row = [pid: number, ppid: number, sid: number, comm: string, tty?: number];

function seam(rows: Row[], leafPid: number, env: NodeJS.ProcessEnv = {}, platform: NodeJS.Platform = 'linux'): ProvenanceSeam {
  const map = new Map<number, ProcInfo>(rows.map(([pid, ppid, sid, comm, tty]) => [pid, { pid, ppid, sid, comm, tty: tty ?? 1 }]));
  return { pid: leafPid, env, platform, proc: (pid) => map.get(pid) ?? null };
}

const INIT: Row = [1, 0, 1, 'systemd'];

/** The jarvis login-profile shape: config exports plus ordinary login env. */
const JARVIS_ENV: NodeJS.ProcessEnv = {
  HOME: '/home/michael',
  SHELL: '/bin/bash',
  TERM: 'xterm-256color',
  SSH_TTY: '/dev/pts/0',
  OPENCLAW_HOME: '/home/michael/.openclaw',
  OPENCLAW_STATE_DIR: '/home/michael/.openclaw/state',
  OPENCLAW_CONFIG_PATH: '/home/michael/.openclaw/openclaw.json',
};

/** sshd → bash (leader) → node (approve). */
const SSH_TREE: Row[] = [INIT, [100, 1, 100, 'sshd'], [101, 100, 101, 'bash'], [102, 101, 101, 'node']];

describe('#815 C config exports — the owner at a real login session is ALLOWED', () => {
  it('jarvis profile: OPENCLAW_HOME/STATE_DIR/CONFIG_PATH + bash under sshd + tty', () => {
    const v = operatorProvenance(seam(SSH_TREE, 102, JARVIS_ENV));
    expect(v.ok).toBe(true);
    expect(v.reason).toBeNull();
    expect(v.detail).toMatch(/OPENCLAW_HOME/);
  });

  it.each(OPENCLAW_CONFIG_EXPORTS.map((n) => [n]))('%s alone under sshd → bash is allowed', (name) => {
    expect(operatorProvenance(seam(SSH_TREE, 102, { [name]: '/x' })).ok).toBe(true);
  });

  it.each([
    ['sshd-session to zsh', [INIT, [100, 1, 100, 'sshd-session'], [101, 100, 101, 'zsh'], [102, 101, 101, 'node']] as Row[], 102],
    ['tmux server to bash', [INIT, [90, 1, 90, 'tmux: server'], [101, 90, 101, 'bash'], [102, 101, 101, 'node']] as Row[], 102],
    ['agetty to login to bash (console)', [INIT, [100, 1, 100, 'agetty'], [101, 100, 101, 'login'], [102, 101, 102, 'bash'], [103, 102, 102, 'node']] as Row[], 103],
    ['gnome-terminal-server to bash', [INIT, [100, 1, 100, 'gnome-terminal-server'], [101, 100, 101, 'bash'], [102, 101, 101, 'node']] as Row[], 102],
    ['login shell argv[0] "-bash" under sshd', [INIT, [100, 1, 100, 'sshd'], [101, 100, 101, '-bash'], [102, 101, 101, 'node']] as Row[], 102],
    ['nested human bash to bash to node', [INIT, [100, 1, 100, 'sshd'], [101, 100, 101, 'bash'], [102, 101, 101, 'bash'], [103, 102, 101, 'node']] as Row[], 103],
  ])('%s', (_label, rows, leaf) => {
    expect(operatorProvenance(seam(rows, leaf, JARVIS_ENV)).ok).toBe(true);
  });
});

describe('#815 C config exports — every non-human shape is still REFUSED', () => {
  it('pty wrapper: script as session leader', () => {
    const v = operatorProvenance(seam([INIT, [20, 1, 20, 'script'], [22, 20, 20, 'node']], 22, JARVIS_ENV));
    expect(v.ok).toBe(false);
    expect(v.reason).toBe('pty-tool-session-leader');
  });

  it('pty wrapper: script -c places a shell leader on its pty', () => {
    const v = operatorProvenance(seam([INIT, [100, 1, 100, 'sshd'], [101, 100, 101, 'bash'],
      [102, 101, 101, 'script'], [103, 102, 103, 'sh'], [104, 103, 103, 'node']], 104, JARVIS_ENV));
    expect(v.ok).toBe(false);
    expect(v.reason).toBe('pty-tool-session-leader');
  });

  it('pty wrapper: expect as session leader', () => {
    const v = operatorProvenance(seam([INIT, [20, 1, 20, 'expect'], [22, 20, 20, 'node']], 22, JARVIS_ENV));
    expect(v.reason).toBe('pty-tool-session-leader');
  });

  it('pty wrapper: python pty.spawn (bash leader, interpreter parent)', () => {
    const v = operatorProvenance(seam([INIT, [30, 1, 30, 'python3'], [31, 30, 31, 'bash'], [32, 31, 31, 'node']], 32, JARVIS_ENV));
    expect(v.reason).toBe('pty-interpreter-parent');
  });

  it('pty wrapper: python as session leader', () => {
    const v = operatorProvenance(seam([INIT, [60, 1, 60, 'python3'], [61, 60, 60, 'node']], 61, JARVIS_ENV));
    expect(v.reason).toBe('pty-interpreter-leader');
  });

  it('env -i under an agent: no env at all, ancestry finds the agent', () => {
    const v = operatorProvenance(seam([INIT, [10, 1, 10, 'openclaw'], [11, 10, 10, 'bash'],
      [12, 11, 12, 'bash'], [13, 12, 12, 'node']], 13, {}));
    expect(v.ok).toBe(false);
    expect(v.reason).toBe('agent-ancestor');
  });

  it('setsid-detached child with no controlling tty', () => {
    const v = operatorProvenance(seam([INIT, [50, 1, 50, 'node', 0]], 50, JARVIS_ENV));
    expect(v.ok).toBe(false);
    expect(v.reason).toBe('no-controlling-terminal');
  });

  it('no controlling tty even under a clean sshd tree', () => {
    const v = operatorProvenance(seam([INIT, [100, 1, 100, 'sshd'], [101, 100, 101, 'bash'], [102, 101, 101, 'node', 0]], 102, JARVIS_ENV));
    expect(v.reason).toBe('no-controlling-terminal');
  });

  it('orphaned shell leader under init (allowed WITHOUT exports, refused WITH them)', () => {
    const rows: Row[] = [INIT, [101, 1, 101, 'bash'], [102, 101, 101, 'node']];
    expect(operatorProvenance(seam(rows, 102, {})).ok).toBe(true);
    const v = operatorProvenance(seam(rows, 102, JARVIS_ENV));
    expect(v.ok).toBe(false);
    expect(v.reason).toBe('orphaned-shell-leader');
    expect(v.detail).toMatch(/OPENCLAW_CONFIG_PATH, OPENCLAW_HOME, OPENCLAW_STATE_DIR/);
  });

  it('shell leader whose parent is unreadable at pid 1 (parent missing) is refused', () => {
    // pid 1 not in the table: the leader's parent cannot be shown to be a terminal provider.
    const v = operatorProvenance(seam([[101, 1, 101, 'bash'], [102, 101, 101, 'node']], 102, JARVIS_ENV));
    expect(v.ok).toBe(false);
    expect(v.reason).toBe('orphaned-shell-leader');
  });

  it('leader that is not a shell (unknown program) is refused when exports are present', () => {
    const rows: Row[] = [INIT, [100, 1, 100, 'sshd'], [101, 100, 101, 'some-daemon'], [102, 101, 101, 'node']];
    expect(operatorProvenance(seam(rows, 102, {})).ok).toBe(true);
    const v = operatorProvenance(seam(rows, 102, JARVIS_ENV));
    expect(v.ok).toBe(false);
    expect(v.reason).toBe('non-shell-session-leader');
  });

  it.each(['openclaw', 'hermes', 'claude'])('agent ancestor %s in the chain', (agent) => {
    const v = operatorProvenance(seam([INIT, [100, 1, 100, 'sshd'], [101, 100, 101, 'bash'],
      [102, 101, 101, agent], [103, 102, 103, 'bash'], [104, 103, 103, 'node']], 104, JARVIS_ENV));
    expect(v.ok).toBe(false);
    expect(v.reason).toBe('agent-ancestor');
  });

  it('agent above the recovered session leader (orphaned leaf keeps the bash sid)', () => {
    const v = operatorProvenance(seam([INIT, [10, 1, 10, 'openclaw'], [20, 10, 20, 'bash'], [30, 1, 20, 'node']], 30, JARVIS_ENV));
    expect(v.reason).toBe('agent-ancestor');
  });

  it('unreadable tree on Linux: this process cannot be inspected', () => {
    const v = operatorProvenance({ pid: 102, env: JARVIS_ENV, platform: 'linux', proc: () => null });
    expect(v.ok).toBe(false);
    expect(v.reason).toBe('process-tree-unreadable');
  });

  it('unreadable tree on Linux: a hole mid-walk', () => {
    const v = operatorProvenance(seam([INIT, [101, 77, 101, 'bash'], [102, 101, 101, 'node']], 102, JARVIS_ENV));
    expect(v.reason).toBe('process-tree-unreadable');
  });

  it.each(['win32', 'freebsd'] as NodeJS.Platform[])('non-tree platform %s: no env-only degrade with exports present', (platform) => {
    // Without exports the same platform degrades to env-only and allows.
    expect(operatorProvenance({ pid: 1, env: {}, platform, proc: () => null }).ok).toBe(true);
    const v = operatorProvenance({ pid: 1, env: { OPENCLAW_HOME: '/h' }, platform, proc: () => null });
    expect(v.ok).toBe(false);
    expect(v.reason).toBe('process-tree-unreadable');
    expect(v.detail).toMatch(/OPENCLAW_HOME/);
  });

  it('non-tree platform refuses even when its seam happens to return a clean-looking tree', () => {
    const v = operatorProvenance(seam(SSH_TREE, 102, JARVIS_ENV, 'win32'));
    expect(v.ok).toBe(false);
    expect(v.reason).toBe('process-tree-unreadable');
  });

  it('refusal copy names the export that was seen', () => {
    const v = operatorProvenance(seam([INIT, [101, 1, 101, 'bash'], [102, 101, 101, 'node']], 102, { OPENCLAW_HOME: '/h' }));
    expect(describeProvenanceRefusal(v).join('\n')).toMatch(/OPENCLAW_HOME, which a login profile may export/);
  });
});

describe('#815 C child markers stay HARD refusals, even beside config exports on a clean human tree', () => {
  it.each([
    ['OPENCLAW_SHELL (set by the OpenClaw exec tool)', { OPENCLAW_SHELL: 'exec' }],
    ['OPENCLAW_AGENT_ID', { OPENCLAW_AGENT_ID: 'main' }],
    ['OPENCLAW_SESSION_ID', { OPENCLAW_SESSION_ID: 's-1' }],
    ['OPENCLAW_PARENT_PID', { OPENCLAW_PARENT_PID: '4242' }],
    ['OPENCLAW_GATEWAY_TOKEN', { OPENCLAW_GATEWAY_TOKEN: 't' }],
    ['unknown OPENCLAW_SOMETHING_NEW', { OPENCLAW_SOMETHING_NEW: '1' }],
    ['near-miss OPENCLAW_HOME_DIR (exact match only)', { OPENCLAW_HOME_DIR: '/h' }],
    ['near-miss OPENCLAW_CONFIG_DIR (not a name OpenClaw reads)', { OPENCLAW_CONFIG_DIR: '/c' }],
    ['CLAWDBOT_STATE_DIR (legacy prefix stays hard)', { CLAWDBOT_STATE_DIR: '/s' }],
    ['CLAUDECODE', { CLAUDECODE: '1' }],
    ['CLAUDE_CODE_ENTRYPOINT', { CLAUDE_CODE_ENTRYPOINT: 'cli' }],
    ['HERMES_SESSION_ID', { HERMES_SESSION_ID: 'x' }],
    ['HERMES_SUPERVISED_CHILD', { HERMES_SUPERVISED_CHILD: '1' }],
    ['CODEX_THREAD_ID', { CODEX_THREAD_ID: 't' }],
  ])('%s', (_label, marker) => {
    const v = operatorProvenance(seam(SSH_TREE, 102, { ...JARVIS_ENV, ...marker }));
    expect(v.ok).toBe(false);
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
    operatorProvenance({ pid: leaf, env: { OPENCLAW_HOME: '/Users/m/.openclaw' }, platform: 'darwin', proc: makeDarwinProcReader(fakePs(procs)) });

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

  it('no session leader found on the tty is refused', () => {
    const v = run({
      1: LAUNCHD,
      401: { ppid: 1, tty: 'ttys002', comm: '-zsh', stat: 'S' },
      450: { ppid: 401, tty: 'ttys002', comm: 'node', stat: 'S+' },
    }, 450);
    expect(v.ok).toBe(false);
    expect(v.reason).toBe('no-session-leader');
  });
});
