/**
 * Operator provenance for `shieldcortex approve` (#502).
 *
 * ## The hole
 *
 * The approve gate was `stdin.isTTY && stdout.isTTY`. That answers "is there a
 * terminal device" — not "is there a human". `script -qec '…' /dev/null`,
 * `expect`, `unbuffer`, `python -c 'import pty; pty.spawn(…)'` all hand a real
 * pseudo-terminal to a child, so an agent with a shell tool could mint its own
 * one-shot approval and then run the command it was just refused. The TTY was
 * the whole gate, and a pty is one syscall away.
 *
 * ## What this checks instead
 *
 * Two independent questions, both of which must come back clean:
 *
 *   1. **Environment.** Every agent host we integrate with stamps its child
 *      environment (`CLAUDECODE`, `HERMES_SESSION_ID`, `OPENCLAW_*`, `CODEX_*`,
 *      …). A pty wrapper inherits that environment. If any of those names is
 *      present, this process was launched by an agent, whatever device is on
 *      fd 0.
 *
 *   2. **Process ancestry.** Walk from this process to the session leader and
 *      on to PID 1. Refuse if the session leader is a pty *tool* rather than a
 *      shell (`script`, `expect`, `unbuffer`, `socat`, an interpreter that
 *      just called `pty.spawn`), or if ANY ancestor is a known agent process
 *      (`claude`, `openclaw`, `hermes`, `codex`, …). A human's `approve` lives
 *      in a session whose leader is a login shell; the agent's cannot, because
 *      the agent's shell tool is a descendant of the agent.
 *
 * `env -i` defeats (1); (2) still sees the ancestry. `setsid -f` re-parents
 * to init and defeats (2)'s agent-ancestor half. If it detaches BEFORE
 * allocating a pty, the thing that then allocates one becomes the session
 * leader or its parent, which (2) refuses. If it detaches AFTER — allocate
 * with `script`, then `setsid -f` a child that keeps the inherited fds —
 * the child still passes `isTTY` but has NO controlling terminal
 * (`setsid` drops it; fds are not the same thing). A human's shell always
 * has one, so:
 *
 *   3. **Controlling terminal.** `/proc/self/stat` tty_nr must be non-zero
 *      (`ps -o tty=` not `??` on macOS). Checked before the walk.
 *
 * None of this is a cryptographic boundary. Together they turn "one syscall"
 * into "forge a login shell's ancestry AND acquire a controlling terminal
 * under a clean environment", which is the honest bar a same-UID control can
 * set. The OS-owned lock (#501) is where a stronger boundary lives; on a
 * locked host an operator can additionally pin approvals to the card (#143).
 *
 * ## Unknowns
 *
 * An unrecognised session-leader parent (a terminal emulator we have not
 * listed) is ALLOWED. Refusing unknowns would card every human on an
 * unfamiliar terminal, and a control that teaches operators to uninstall it
 * protects nobody. The refusal list is the known-bad set; the message names
 * what was seen so a false refusal is one bug report away from a fix.
 */

import { readFileSync, readdirSync } from 'node:fs';
import { execFileSync } from 'node:child_process';

// ── Signals ───────────────────────────────────────────

/**
 * Environment names that an agent host stamps on its children. Presence of
 * ANY of these means "launched by an agent". Matched as exact names or
 * prefixes (a trailing `_` marks a prefix).
 */
export const AGENT_ENV_MARKERS: readonly string[] = [
  'CLAUDECODE',
  'CLAUDE_CODE_',
  'HERMES_SESSION_',
  'HERMES_SUPERVISED_CHILD',
  'OPENCLAW_',
  'CLAWDBOT_',
  'CODEX_SANDBOX',
  'CODEX_THREAD_ID',
  'CURSOR_AGENT',
  'AIDER_',
  'GEMINI_CLI',
  'COPILOT_AGENT',
];

/**
 * Process names (`comm`) of agent hosts. Any ancestor matching one of these
 * means this process is a descendant of an agent's tool call. Matched on the
 * basename, case-insensitively, as a whole name.
 */
export const AGENT_PROCESS_NAMES: readonly string[] = [
  'claude', 'claude-code',
  'openclaw', 'clawdbot',
  'hermes',
  'codex',
  'aider',
  'gemini',
  'cursor-agent',
  'copilot',
];

/**
 * Session leaders that are pty TOOLS, not shells. A human's interactive
 * session is led by a shell; these lead an agent's synthetic one.
 */
export const PTY_TOOL_NAMES: readonly string[] = [
  'script', 'scriptlive', 'scriptreplay',
  'expect', 'unbuffer', 'autoexpect',
  'socat', 'empty',
  'pty', 'ptyspawn', 'forkpty',
];

/**
 * Interpreters that, when they are the PARENT of the session leader, almost
 * certainly just called `pty.spawn` / `pty.fork` / `node-pty`. A human's shell
 * is spawned by a terminal provider, not by a bare interpreter.
 */
export const PTY_INTERPRETER_NAMES: readonly string[] = [
  'python', 'python3', 'python2',
  'node', 'nodejs', 'bun', 'deno',
  'perl', 'ruby', 'php',
];

/** Shells that a human's session is led by. An orphaned one (parent is init)
 *  is the shape of "daemonise, take a fresh pty, exec bash". */
export const SHELL_NAMES: readonly string[] = [
  'bash', 'sh', 'zsh', 'fish', 'dash', 'ksh', 'csh', 'tcsh',
];

/** Process names of init. A session leader whose parent is one of these was
 *  re-parented — the honest login path always has a terminal provider
 *  (sshd, login, tmux, gnome-terminal-server, …) as the leader's parent. */
export const INIT_NAMES: readonly string[] = [
  'systemd', 'init', 'systemd-init',
];

// ── Process tree ──────────────────────────────────────

export interface ProcInfo {
  pid: number;
  ppid: number;
  /** Session id (`sid`). */
  sid: number;
  /** Short executable name, as `/proc/<pid>/comm` or `ps -o comm=` basename. */
  comm: string;
  /** Controlling terminal device number; 0 when the process has none. */
  tty: number;
}

/** The injectable seam — tests hand in a synthetic tree. */
export interface ProvenanceSeam {
  /** Look up one process, or null if it no longer exists / cannot be read. */
  proc(pid: number): ProcInfo | null;
  pid: number;
  env: NodeJS.ProcessEnv;
  platform: NodeJS.Platform;
}

function basenameLower(s: string): string {
  const b = s.replace(/^.*[\\/]/, '').toLowerCase();
  // Strip a version suffix: python3.12 → python3 → python; node20 → node.
  return b.replace(/[\d.]+$/, '').replace(/-?$/, '') || b;
}

function nameIn(comm: string, list: readonly string[]): boolean {
  const b = basenameLower(comm);
  const raw = comm.replace(/^.*[\\/]/, '').toLowerCase();
  return list.includes(b) || list.includes(raw);
}

function readProcLinux(pid: number): ProcInfo | null {
  try {
    const stat = readFileSync(`/proc/${pid}/stat`, 'utf8');
    // comm may contain spaces/parens; it is wrapped in the LAST ')'.
    const close = stat.lastIndexOf(')');
    const open = stat.indexOf('(');
    const comm = stat.slice(open + 1, close);
    const rest = stat.slice(close + 2).split(' ');
    // fields after comm: state(0) ppid(1) pgrp(2) session(3) tty_nr(4)
    return { pid, ppid: Number(rest[1]), sid: Number(rest[3]), comm, tty: Number(rest[4]) };
  } catch {
    return null;
  }
}

function readProcDarwin(pid: number): ProcInfo | null {
  try {
    const out = execFileSync('ps', ['-o', 'ppid=,sess=,tty=,comm=', '-p', String(pid)], {
      encoding: 'utf8',
      timeout: 2000,
      stdio: ['ignore', 'pipe', 'ignore'],
    }).trim();
    if (!out) return null;
    const m = /^\s*(\d+)\s+(\d+)\s+(\S+)\s+(.*)$/.exec(out);
    if (!m) return null;
    return { pid, ppid: Number(m[1]), sid: Number(m[2]), comm: m[4].trim(), tty: m[3] === '??' || m[3] === '-' ? 0 : 1 };
  } catch {
    return null;
  }
}

export function defaultProvenanceSeam(): ProvenanceSeam {
  const platform = process.platform;
  const linux = platform === 'linux' && (() => { try { readdirSync('/proc'); return true; } catch { return false; } })();
  return {
    pid: process.pid,
    env: process.env,
    platform,
    proc: linux ? readProcLinux : platform === 'darwin' ? readProcDarwin : () => null,
  };
}

// ── The verdict ───────────────────────────────────────

export type ProvenanceReason =
  | 'agent-environment'
  | 'agent-ancestor'
  | 'pty-tool-session-leader'
  | 'pty-interpreter-parent'
  | 'no-controlling-terminal'
  | 'pty-interpreter-leader'
  | 'no-session-leader';

export interface ProvenanceVerdict {
  ok: boolean;
  reason: ProvenanceReason | null;
  /** Operator-facing sentence. Names what was seen; never a secret. */
  detail: string;
  /** The ancestry actually walked, leaf first, for the refusal message. */
  chain: string[];
}

const MAX_WALK = 64;

/**
 * Is this process plausibly a human at a terminal, and NOT a descendant of an
 * agent's tool call? Cheap; called once per `approve` grant.
 *
 * On a platform with no readable process tree, only the environment half
 * runs — that is a weaker check and the verdict says so in `detail`.
 */
export function operatorProvenance(seam: ProvenanceSeam = defaultProvenanceSeam()): ProvenanceVerdict {
  // 1) Environment.
  for (const name of Object.keys(seam.env)) {
    for (const marker of AGENT_ENV_MARKERS) {
      const hit = marker.endsWith('_') ? name.startsWith(marker) : name === marker;
      if (hit) {
        return {
          ok: false,
          reason: 'agent-environment',
          detail: `the environment carries ${name}, which an agent host sets on its children — this shell was launched by an agent, whatever device is on stdin.`,
          chain: [],
        };
      }
    }
  }

  // 2) Ancestry.
  const self = seam.proc(seam.pid);
  if (!self) {
    return {
      ok: true,
      reason: null,
      detail: 'process tree unreadable on this platform; environment check only.',
      chain: [],
    };
  }

  // A process can hold TTY file descriptors without a CONTROLLING terminal:
  // `setsid()` drops the controlling terminal but does not close inherited
  // fds. That is the shape of "allocate a pty with script, detach a child
  // that keeps the fds, let the launcher exit" — the chain then reads
  // node → systemd, every ancestry check passes, and isTTY is still true.
  // A human's interactive shell ALWAYS has a controlling terminal, so its
  // absence is decisive on its own. (GPT-6 review of #523, r1.)
  if (self.tty === 0) {
    return {
      ok: false,
      reason: 'no-controlling-terminal',
      detail: `this process has terminal file descriptors but no controlling terminal — the shape of a detached child that inherited a manufactured pty, not of a shell a human is typing into.`,
      chain: [self.comm],
    };
  }

  const chain: string[] = [];
  let cur: ProcInfo | null = self;

  for (let i = 0; cur && i < MAX_WALK; i += 1) {
    chain.push(cur.comm);
    if (nameIn(cur.comm, AGENT_PROCESS_NAMES)) {
      return {
        ok: false,
        reason: 'agent-ancestor',
        detail: `an ancestor of this process is "${cur.comm}" (pid ${cur.pid}), an agent host — a human's terminal is never a child of the agent.`,
        chain,
      };
    }
    if (cur.ppid <= 0 || cur.ppid === cur.pid) break;
    cur = seam.proc(cur.ppid);
  }

  // The session leader is the process whose pid === OUR sid. Look it up
  // DIRECTLY — not "the first ancestor that happens to lead some session".
  // GPT-6 r3, reproduced live: python takes a fresh pty as leader, then
  // double-forks the leaf so the leaf is adopted by init while KEEPING
  // python's sid. The parent chain is node → systemd; the old walk picked
  // systemd's session and never saw python. self.sid does.
  const leader: ProcInfo | null = self.sid > 0 ? seam.proc(self.sid) : null;
  if (leader === null) {
    return {
      ok: false,
      reason: 'no-session-leader',
      detail: `this process's session leader (pid ${self.sid}) is gone — an interactive login session's leader is the shell a human is typing into, and it outlives every command it runs.`,
      chain,
    };
  }
  if (!chain.includes(leader.comm)) chain.push(`[leader ${leader.comm}]`);
  const leaderParent: ProcInfo | null = leader.ppid > 0 ? seam.proc(leader.ppid) : null;
  if (nameIn(leader.comm, AGENT_PROCESS_NAMES)) {
    return {
      ok: false,
      reason: 'agent-ancestor',
      detail: `this session is led by "${leader.comm}" (pid ${leader.pid}), an agent host.`,
      chain,
    };
  }
  // GPT-6 r4: the recovered leader's PARENT was fetched and then only
  // checked against pty-tool / interpreter lists. An agent that spawns a
  // session-leading shell and then orphans the leaf is node to systemd in
  // the parent walk, bash via self.sid, and the agent is sitting on
  // leader.ppid unread. Walk that branch.
  {
    let up: ProcInfo | null = leaderParent;
    for (let i = 0; up && i < MAX_WALK; i += 1) {
      if (nameIn(up.comm, AGENT_PROCESS_NAMES)) {
        return {
          ok: false,
          reason: 'agent-ancestor',
          detail: `this session's leader "${leader.comm}" (pid ${leader.pid}) is a descendant of "${up.comm}" (pid ${up.pid}), an agent host — a human's terminal is never a child of the agent.`,
          chain,
        };
      }
      if (up.ppid <= 0 || up.ppid === up.pid) break;
      up = seam.proc(up.ppid);
    }
  }
  // GPT-6 r4: the recovered leader's PARENT was fetched and then only
  // checked against pty-tool / interpreter lists. An agent that spawns a
  // session-leading shell (codex → bash, hermes → bash) and then orphans
  // the leaf is node → systemd in the parent walk, bash via self.sid, and
  // the agent is sitting on leader.ppid unread. Walk that branch.
  {
    let up: ProcInfo | null = leaderParent;
    for (let i = 0; up && i < MAX_WALK; i += 1) {
      if (nameIn(up.comm, AGENT_PROCESS_NAMES)) {
        return {
          ok: false,
          reason: 'agent-ancestor',
          detail: `this session's leader "${leader.comm}" (pid ${leader.pid}) is a descendant of "${up.comm}" (pid ${up.pid}), an agent host — a human's terminal is never a child of the agent.`,
          chain,
        };
      }
      if (up.ppid <= 0 || up.ppid === up.pid) break;
      up = seam.proc(up.ppid);
    }
  }

  // `script -c` (and expect/unbuffer) fork the child shell into a NEW session
  // on the pty they allocated, so the leader is the shell and the tool is its
  // PARENT. Older/other tools stay leader themselves. Check both.
  if (nameIn(leader.comm, PTY_TOOL_NAMES)) {
    return {
      ok: false,
      reason: 'pty-tool-session-leader',
      detail: `this session is led by "${leader.comm}" (pid ${leader.pid}), a pseudo-terminal tool, not a login shell — the terminal on stdin was manufactured.`,
      chain,
    };
  }
  if (leaderParent && nameIn(leaderParent.comm, PTY_TOOL_NAMES)) {
    return {
      ok: false,
      reason: 'pty-tool-session-leader',
      detail: `this session's leader "${leader.comm}" (pid ${leader.pid}) was placed on its terminal by "${leaderParent.comm}" (pid ${leaderParent.pid}), a pseudo-terminal tool — the terminal on stdin was manufactured.`,
      chain,
    };
  }

  // `pty.spawn` shape: the leader IS a shell, but its parent is a bare
  // interpreter that forked+setsid'd it onto a fresh pty.
  if (leaderParent && nameIn(leaderParent.comm, PTY_INTERPRETER_NAMES)) {
    return {
      ok: false,
      reason: 'pty-interpreter-parent',
      detail: `this session's leader "${leader.comm}" (pid ${leader.pid}) was spawned directly by "${leaderParent.comm}" (pid ${leaderParent.pid}) — the shape of an interpreter allocating a pseudo-terminal, not of a terminal a human opened.`,
      chain,
    };
  }

  // GPT-6 r2: daemonise, openpty, TIOCSCTTY, keep the interpreter as leader
  // (or exec bash so the leader IS the shell and its parent is init). Live
  // on this box: node → python3 → systemd, isTTY true, tty_nr nonzero,
  // every earlier check passed. A human's leader-parent is sshd / login /
  // tmux / a terminal emulator, never init.
  if (nameIn(leader.comm, PTY_INTERPRETER_NAMES)) {
    return {
      ok: false,
      reason: 'pty-interpreter-leader',
      detail: `this session is led by "${leader.comm}" (pid ${leader.pid}), an interpreter, not a login shell — the shape of a process that allocated its own pseudo-terminal.`,
      chain,
    };
  }

  // Residual, not refused: a SHELL leader whose parent is init. That is
  // both "daemonise, openpty, exec bash" (GPT-6 r2) AND a WSL / console
  // login (bash's parent is init). Refusing it cards every WSL user.
  // Documented on the issue; the OS-owned lock (#501) is the next bar.

  return { ok: true, reason: null, detail: 'interactive session led by a shell with no agent ancestor.', chain };
}

/** One operator-facing paragraph for a refusal. */
export function describeProvenanceRefusal(v: ProvenanceVerdict): string[] {
  const lines = [
    'shieldcortex approve must be run by a human in a terminal the agent did not open.',
    `Refusing: ${v.detail}`,
  ];
  if (v.chain.length) lines.push(`  ancestry: ${v.chain.join(' ← ')}`);
  lines.push('  Open a terminal yourself (ssh, Terminal.app, tmux) and run the same command there.');
  return lines;
}
