/**
 * Owner-present harness terminal (#923, principle 4 of #875).
 *
 * The PreToolUse hook is ALWAYS an agent child and its stdin is a pipe, so
 * neither `process.stdin.isTTY` nor `operatorProvenance()` (the approve CLI's
 * check, which refuses whenever agent env markers are set) can say whether a
 * human owns the session. What can: the HARNESS — the persistent process the
 * hook was spawned by — how it was launched, and the session's own transcript.
 *
 * Proven only when every one of these holds; anything unreadable, missing or
 * unknown is "unproven", and the caller keeps today's deny:
 *
 *   1. Linux. Other platforms are unproven (no cheap, portable read of another
 *      process's controlling terminal and launch environment).
 *   2. The hook payload carries no subagent marker (`agent_id`, `agent_type`,
 *      a `/subagents/` transcript, a `:subagent:` / `:cron:` session key) AND
 *      positive top-level provenance: the payload's `tool_use_id` is found in
 *      the payload's own session transcript (`<session_id>.jsonl`) on an
 *      assistant record with `isSidechain: false`, no `agentId`, the same
 *      `sessionId` and the interactive `entrypoint: "cli"`. A subagent's call
 *      is recorded in its own `subagents/` transcript (or, on older builds, as
 *      a sidechain record), so a missing marker alone never proves anything.
 *      LIVE ORDERING (#923 r3, Claude Code 2.1.314): in an interactive session
 *      the assistant record is written to `<session_id>.jsonl` only AFTER this
 *      hook returns — absent at hook start, still absent with the hook holding
 *      the call for 6 s (print mode likewise, and it is `entrypoint:
 *      "sdk-cli"` anyway). So on that build this check never passes and the
 *      whole proof is unproven: fail-closed dead code, kept so that a build
 *      which records the call first (or a payload with a positive top-level
 *      marker) is not silently trusted on a missing subagent marker.
 *   3. The harness pid resolves (scripts/lib/harness-pid.mjs) to a pid > 1 that
 *      is not this process, and its stat, cmdline, status and environ are all
 *      readable.
 *   4. The harness is Claude Code (`claude` comm/argv0, or the npm cli path)
 *      launched interactively: no `-p` / `--print` (alone or in a short-flag
 *      cluster), no `--output-format` / `--input-format`, and not launched in
 *      bypass (`--dangerously-skip-permissions`, `--permission-mode
 *      bypassPermissions`).
 *   5. The harness has a controlling terminal (`tty_nr != 0`) and is in that
 *      terminal's foreground process group (`tpgid == pgrp`). This process's
 *      own fds are never consulted, so a `script` / `expect` / `pty.spawn`
 *      wrapper that hands THIS process a pty proves nothing.
 *   6. The harness's own launch environment carries no agent marker and no
 *      terminal-multiplexer marker (`TMUX`, `STY`).
 *   7. No ancestor of the harness, up to init, is an agent host (by comm, or by
 *      the Claude Code argv0 / npm cli path of check 4), a pty tool, a
 *      scheduler (cron/at) or a terminal multiplexer (tmux/screen/…: attachment
 *      of a human cannot be proven, so any multiplexer is unproven).
 *   8. The session is a human's login: the session leader is either the harness
 *      itself or a shell that is the harness's direct parent on the same
 *      terminal, and the leader's parent is never an interpreter (the
 *      `pty.spawn` shape, by comm OR by exe) and is anchored by evidence the
 *      session's uid cannot forge (`loginParentFailure`): a root-owned sshd /
 *      login, a per-session sshd whose parent is a root-owned sshd, or a
 *      terminal emulator whose readable exe is an exact allowlisted path.
 *
 *   9. Every child → parent hop above (the ancestry walk, harness → session
 *      leader, leader → its parent, per-session sshd → root sshd) survives pid
 *      reuse (`hopFailure`): the parent started no later than the child, and
 *      the child's stat, re-read after the parent's, still names that parent
 *      and the same start time. /proc reads are not atomic, and a recycled
 *      pid can be a genuine root sshd the attacker summoned.
 *
 * The controls are the root anchor and the exe-path allowlist of check 8 and
 * the transcript provenance of check 2. comm is self-set (prctl, exec of a
 * symlink), so it only ever ADDS a deny; identity comes from the exe link and
 * the uids in status. The interpreter / pty-tool / agent / scheduler deny
 * lists of checks 7 and 8 match comm OR the exe's basename, and are defence
 * in depth, NOT a control: a copied interpreter (`cp python3 /tmp/x`) plus
 * PR_SET_NAME evades both.
 *
 * There is no environment seam. Tests hand `proveOwnerPresentHarness` in-memory
 * proc file / link readers and a transcript reader; the hook always uses /proc.
 */
import { closeSync, constants, fstatSync, openSync, readFileSync, readlinkSync, readSync } from 'node:fs';
import { basename, dirname, isAbsolute, join } from 'node:path';
import { resolveHarnessPid } from './harness-pid.mjs';

const PROC_ROOT = '/proc';
/** Only the tail of the transcript is read: the call being vetted is the newest record. */
const TRANSCRIPT_TAIL_BYTES = 4 * 1024 * 1024;

/**
 * Agent-host markers looked for in the HARNESS's launch environment. Kept in
 * step with AGENT_ENV_MARKERS in src/cli/approve-provenance.ts, except that the
 * `CLAUDE_CODE_` prefix is narrowed to `CLAUDE_CODE_ENTRYPOINT`: humans set
 * `CLAUDE_CODE_USE_BEDROCK` and friends in their own shell, while the
 * entrypoint is stamped by Claude Code / the Agent SDK on what they spawn.
 * A trailing `_` marks a prefix.
 */
export const HARNESS_AGENT_ENV_MARKERS = Object.freeze([
  'CLAUDECODE',
  'CLAUDE_CODE_ENTRYPOINT',
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
]);

/** Agent hosts (AGENT_PROCESS_NAMES in approve-provenance.ts). */
const AGENT_PROCESS_NAMES = ['claude', 'claude-code', 'openclaw', 'clawdbot', 'hermes', 'codex', 'aider', 'gemini', 'cursor-agent', 'copilot'];
/** Pty tools (PTY_TOOL_NAMES in approve-provenance.ts). */
const PTY_TOOL_NAMES = ['script', 'scriptlive', 'scriptreplay', 'expect', 'unbuffer', 'autoexpect', 'socat', 'empty', 'pty', 'ptyspawn', 'forkpty'];
/** Interpreters that, as the session leader's parent, just called pty.spawn. */
const PTY_INTERPRETER_NAMES = ['python', 'python3', 'python2', 'node', 'nodejs', 'bun', 'deno', 'perl', 'ruby', 'php'];
const SCHEDULER_NAMES = ['cron', 'crond', 'anacron', 'atd', 'fcron'];
/** Multiplexers keep a session alive with nobody attached. `tmux` runs as `tmux: server`. */
const MULTIPLEXER_RE = /^(?:tmux|screen|zellij|byobu|dtach|abduco)(?::|$)/;
const MULTIPLEXER_ENV = ['TMUX', 'TMUX_PANE', 'STY', 'ZELLIJ'];
/** Interactive shells that may lead the harness's session. */
const SHELL_NAMES = ['bash', 'zsh', 'fish', 'sh', 'dash', 'ksh', 'mksh', 'tcsh', 'csh', 'ash'];
/**
 * Terminal emulators, by the kernel's resolved path of their executable
 * (`/proc/<pid>/exe`). Exact paths only: no globs, no prefixes, nothing under a
 * user-writable directory. comm is set by the process itself (prctl, or exec
 * of a symlink), so it never proves a terminal. Script-run terminals
 * (terminator, guake: exe is python) are absent on purpose — they are
 * indistinguishable from a `pty.spawn` driver and are refused by the
 * interpreter check anyway.
 */
export const TERMINAL_EXE_PATHS = Object.freeze([
  '/usr/libexec/gnome-terminal-server', '/usr/lib/gnome-terminal/gnome-terminal-server', '/usr/lib/gnome-terminal-server',
  '/usr/bin/kgx',
  '/usr/libexec/ptyxis-agent', '/usr/lib/ptyxis-agent',
  '/usr/bin/konsole',
  '/usr/bin/xterm',
  '/usr/bin/alacritty',
  '/usr/bin/kitty', '/usr/lib/kitty/bin/kitty', '/usr/lib64/kitty/bin/kitty',
  '/usr/bin/wezterm-gui',
  '/usr/bin/foot',
  '/usr/bin/ghostty',
  '/usr/bin/tilix',
  '/usr/bin/xfce4-terminal',
  '/usr/bin/mate-terminal',
  '/usr/bin/lxterminal',
  '/usr/bin/qterminal',
  '/usr/bin/urxvt', '/usr/bin/rxvt-unicode', '/usr/bin/urxvtd',
  '/usr/bin/rxvt',
  '/usr/bin/sakura',
  '/usr/bin/terminology',
  '/usr/bin/st',
]);
/** SSH per-session processes (OpenSSH < 9.8: `sshd`; >= 9.8: `sshd-session`). */
const SSHD_NAMES = ['sshd', 'sshd-session'];
/** What a ROOT-owned session leader parent may be: comm of a root process is not user-forgeable. */
const ROOT_LOGIN_PARENT_NAMES = ['sshd', 'sshd-session', 'login'];
const MAX_ANCESTRY = 64;

const validPid = (pid) => Number.isInteger(pid) && pid > 1;

function nameOf(comm) {
  const raw = basename(String(comm ?? '')).toLowerCase();
  return { raw, bare: raw.replace(/[\d.]+$/, '') || raw };
}

function nameIn(comm, list) {
  const { raw, bare } = nameOf(comm);
  return list.includes(raw) || list.includes(bare);
}

/** The kernel's exe path with a ` (deleted)` suffix dropped; null when unreadable. */
function exePath(proc) {
  return typeof proc.exe === 'string' && proc.exe ? proc.exe.replace(/ \(deleted\)$/, '') : null;
}

/**
 * Deny-list match on EITHER comm or the basename of the executable (so a
 * `python3.12` renamed to `bash` is still python). Additive: an unreadable exe
 * leaves comm as the only signal, it never clears one. Defence in depth only:
 * a renamed copy of an interpreter matches neither.
 */
function procNameIn(proc, list) {
  const exe = exePath(proc);
  return nameIn(proc.comm, list) || (exe !== null && nameIn(exe, list));
}

function isMultiplexer(proc) {
  const exe = exePath(proc);
  return MULTIPLEXER_RE.test(String(proc.comm).toLowerCase())
    || MULTIPLEXER_RE.test(nameOf(proc.argv[0]).raw)
    || (exe !== null && MULTIPLEXER_RE.test(nameOf(exe).raw));
}

const allUids = (proc, pred) => Array.isArray(proc.uids) && proc.uids.length === 4 && proc.uids.every(pred);
/** Real, effective, saved and fs uid all 0. A same-uid process cannot create one. */
const isRootOwned = (proc) => allUids(proc, (u) => u === 0);
/** No uid is 0 (a mixed set, e.g. a setuid binary mid-transition, is neither). */
const isUserOwned = (proc) => allUids(proc, (u) => u !== 0);

/** `(pid, file) => Buffer | null` over the real /proc. */
export function procFileReader(root = PROC_ROOT) {
  return (pid, file) => {
    try {
      return readFileSync(join(root, String(pid), file));
    } catch {
      return null;
    }
  };
}

/**
 * `(pid, link) => string | null` over the real /proc. The kernel's `exe` link
 * is already the resolved path of the executable. It is unreadable (EACCES)
 * for a non-dumpable process — OpenSSH's per-session sshd, `systemd --user`,
 * anything root — and an attacker can make its own process non-dumpable, so
 * null never means "trusted".
 */
export function procLinkReader(root = PROC_ROOT) {
  return (pid, link) => {
    try {
      return readlinkSync(join(root, String(pid), link));
    } catch {
      return null;
    }
  };
}

/** `[real, effective, saved, fs]` from the `Uid:` line of a status file, or null. */
export function parseStatusUids(statusBuf) {
  if (!statusBuf) return null;
  const m = /^Uid:\s+(\d+)\s+(\d+)\s+(\d+)\s+(\d+)\s*$/m.exec(statusBuf.toString('utf8'));
  return m ? m.slice(1, 5).map(Number) : null;
}

/**
 * The stat fields the proof needs, or null when the stat is missing or any of
 * them is absent or not a decimal integer. After the `)` that closes comm,
 * rest[0] is field 3 (state), so ppid is field 4 and starttime (field 22,
 * clock ticks since boot) is rest[19].
 */
function parseStat(statBuf) {
  if (!statBuf) return null;
  const stat = statBuf.toString('utf8');
  const open = stat.indexOf('(');
  const close = stat.lastIndexOf(')');
  if (open < 0 || close < open) return null;
  // fields after comm: state(0) ppid(1) pgrp(2) session(3) tty_nr(4) tpgid(5) … starttime(19)
  const rest = stat.slice(close + 2).trim().split(/\s+/);
  // `Number('')` is 0: a truncated stat must not read as "no tty" / pid 0.
  const [ppid, pgrp, sid, tty, tpgid] = [1, 2, 3, 4, 5].map((i) => (/^-?\d+$/.test(rest[i] ?? '') ? Number(rest[i]) : NaN));
  if (![ppid, pgrp, sid, tty, tpgid].every(Number.isInteger)) return null;
  const starttime = /^\d+$/.test(rest[19] ?? '') ? Number(rest[19]) : NaN;
  if (!Number.isSafeInteger(starttime)) return null;
  return { ppid, pgrp, sid, tty, tpgid, starttime, comm: stat.slice(open + 1, close) };
}

/**
 * One process, or null when any field the decision needs is unreadable: a
 * missing stat, an unparseable field (starttime included), an unreadable or
 * empty cmdline, a status without a full `Uid:` line. `exe` is null when the
 * link cannot be read.
 */
export function readProc(readProcFile, pid, readProcLink = () => null) {
  const stat = parseStat(readProcFile(pid, 'stat'));
  if (!stat) return null;
  const cmdline = readProcFile(pid, 'cmdline');
  if (!cmdline) return null;
  const argv = cmdline.toString('utf8').split('\0').filter(Boolean);
  if (argv.length === 0) return null;
  const uids = parseStatusUids(readProcFile(pid, 'status'));
  if (!uids) return null;
  const exe = readProcLink(pid, 'exe');
  return { pid, ...stat, argv, uids, exe: typeof exe === 'string' && exe ? exe : null };
}

/**
 * PID-reuse guard for one trusted child → parent hop, called only AFTER every
 * read of `parent` (stat, cmdline, status, exe) the decision uses. Each read
 * is a separate syscall, so between the child's stat and the parent's status
 * the real parent can exit and its pid be recycled — e.g. by a fresh root
 * sshd for an `ssh localhost` the attacker opened. Null when the hop holds,
 * else why not:
 *
 *   - the parent started after the child: a pid number cannot be the parent
 *     of a process older than itself, so it was recycled;
 *   - the child's stat, re-read now, names another parent or another start
 *     time: the parent exited (the child was reparented) or the child pid
 *     itself was recycled while we read;
 *   - the re-read fails: unproven.
 */
function hopFailure(readProcFile, child, parent) {
  if (parent.starttime > child.starttime) return 'ancestor pid was reused';
  const again = parseStat(readProcFile(child.pid, 'stat'));
  if (!again) return 'ancestor re-read unreadable';
  if (again.ppid !== child.ppid || again.starttime !== child.starttime) return 'ancestor changed during the check';
  return null;
}

/** Names in the process's environ, or null when it cannot be read. */
function readEnvNames(readProcFile, pid) {
  const buf = readProcFile(pid, 'environ');
  if (!buf) return null;
  return buf.toString('utf8').split('\0').filter(Boolean).map((kv) => kv.split('=', 1)[0]);
}

function hasAgentMarker(names) {
  return names.some((n) => HARNESS_AGENT_ENV_MARKERS.some((m) => (m.endsWith('_') ? n.startsWith(m) : n === m)));
}

const CLAUDE_CLI_RE = /(?:^|\/)@anthropic-ai\/claude-code\/cli\.(?:m?js)$/;

function isClaudeHarness(proc) {
  if (nameIn(proc.comm, ['claude'])) return true;
  if (proc.argv.length > 0 && nameIn(proc.argv[0], ['claude'])) return true;
  return proc.argv.slice(0, 3).some((a) => CLAUDE_CLI_RE.test(a));
}

/** Why the harness's own argv says it is not an interactive, prompting launch; null when it does not. */
export function nonInteractiveLaunch(argv) {
  const cli = argv.findIndex((a) => CLAUDE_CLI_RE.test(a));
  const args = argv.slice(cli >= 0 ? cli + 1 : 1);
  for (let i = 0; i < args.length; i++) {
    const a = args[i];
    if (a === '--print' || a.startsWith('--print=') || /^-[a-zA-Z]*p[a-zA-Z]*$/.test(a)) return 'harness runs in print mode';
    if (/^--(?:output|input)-format(?:=|$)/.test(a)) return 'harness runs a non-interactive stream format';
    if (a === '--dangerously-skip-permissions' || a.startsWith('--dangerously-skip-permissions=')) return 'harness was launched in bypass mode';
    if (a === '--permission-mode' && args[i + 1] === 'bypassPermissions') return 'harness was launched in bypass mode';
    if (a === '--permission-mode=bypassPermissions') return 'harness was launched in bypass mode';
  }
  return null;
}

/** Subagent / scheduled-job markers in the hook payload. */
export function hookPayloadSubagentMarker(hookData) {
  if (!hookData || typeof hookData !== 'object') return 'no hook payload';
  for (const key of ['agent_id', 'agentId', 'agent_type', 'agentType', 'parent_session_id', 'parentSessionId', 'parent_tool_use_id']) {
    if (hookData[key] !== undefined && hookData[key] !== null && hookData[key] !== '') return `payload ${key}`;
  }
  const transcript = typeof hookData.transcript_path === 'string' ? hookData.transcript_path : '';
  if (/[\\/]subagents?[\\/]/i.test(transcript)) return 'subagent transcript';
  const sessionId = typeof hookData.session_id === 'string' ? hookData.session_id : '';
  if (/:(?:subagent|cron)(?::|$)/i.test(sessionId)) return 'subagent/cron session key';
  return null;
}

/**
 * The last `TRANSCRIPT_TAIL_BYTES` of a regular file, or null. Opened
 * non-blocking and without following a final symlink, so a FIFO or a link
 * planted at the path never hangs or redirects the hook.
 */
export function readTranscriptTail(path) {
  let fd;
  try {
    fd = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
    const st = fstatSync(fd);
    if (!st.isFile()) return null;
    const length = Math.min(st.size, TRANSCRIPT_TAIL_BYTES);
    const buf = Buffer.alloc(length);
    const got = readSync(fd, buf, 0, length, st.size - length);
    const text = buf.subarray(0, got).toString('utf8');
    // A cut first line is not a record.
    return st.size > length ? text.slice(text.indexOf('\n') + 1) : text;
  } catch {
    return null;
  } finally {
    if (fd !== undefined) {
      try { closeSync(fd); } catch { /* already closed */ }
    }
  }
}

/**
 * Positive top-level provenance (check 2). Returns null when proven, else why
 * not. Absence of any field is a refusal: nothing here defaults to "top level".
 */
export function topLevelProvenanceFailure(hookData, readTranscript = readTranscriptTail) {
  const sessionId = typeof hookData?.session_id === 'string' ? hookData.session_id : '';
  const toolUseId = typeof hookData?.tool_use_id === 'string' ? hookData.tool_use_id : '';
  const transcript = typeof hookData?.transcript_path === 'string' ? hookData.transcript_path : '';
  if (!sessionId || !toolUseId) return 'no top-level provenance in payload';
  if (!transcript || !isAbsolute(transcript) || transcript.includes('\0')) return 'no top-level transcript';
  if (basename(transcript) !== `${sessionId}.jsonl` || /subagents?$/i.test(basename(dirname(transcript)))) {
    return 'transcript is not the session transcript';
  }
  const text = readTranscript(transcript);
  if (typeof text !== 'string') return 'transcript unreadable';
  const lines = text.split('\n');
  for (let i = lines.length - 1; i >= 0; i--) {
    const line = lines[i];
    if (!line.includes(toolUseId)) continue;
    let rec;
    try {
      rec = JSON.parse(line);
    } catch {
      continue;
    }
    const content = rec?.message?.content;
    if (!Array.isArray(content) || !content.some((c) => c && c.type === 'tool_use' && c.id === toolUseId)) continue;
    if (rec.type !== 'assistant') return 'tool call is not an assistant record';
    if (rec.isSidechain !== false) return 'tool call is not on the main chain';
    if (rec.agentId !== undefined && rec.agentId !== null) return 'tool call belongs to a subagent';
    if (rec.sessionId !== sessionId) return 'tool call belongs to another session';
    if (rec.entrypoint !== 'cli') return 'session is not the interactive CLI';
    return null;
  }
  return 'tool call not found in the session transcript';
}

/**
 * Is this hook running under an owner-present harness terminal?
 * Returns `{ proven: true, harnessPid }` or `{ proven: false, reason }`.
 */
export function proveOwnerPresentHarness({
  hookData,
  platform = process.platform,
  readProcFile = procFileReader(),
  readProcLink = procLinkReader(),
  readTranscript = readTranscriptTail,
  parentPid = process.ppid,
  selfPid = process.pid,
} = {}) {
  const no = (reason) => ({ proven: false, reason });
  if (platform !== 'linux') return no('unsupported platform');
  const marker = hookPayloadSubagentMarker(hookData);
  if (marker) return no(marker);
  const provenance = topLevelProvenanceFailure(hookData, readTranscript);
  if (provenance) return no(provenance);

  const read = (pid) => readProc(readProcFile, pid, readProcLink);
  const hop = (child, parent) => hopFailure(readProcFile, child, parent);
  const harnessPid = resolveHarnessPid(parentPid, (pid) => {
    const p = read(pid);
    return p && validPid(p.ppid) ? { ppid: p.ppid, argv: p.argv } : null;
  });
  if (!validPid(harnessPid) || harnessPid === selfPid) return no('harness pid unresolved');
  const harness = read(harnessPid);
  if (!harness) return no('harness unreadable');
  if (!isClaudeHarness(harness)) return no('harness is not Claude Code');
  const launch = nonInteractiveLaunch(harness.argv);
  if (launch) return no(launch);
  if (harness.tty === 0) return no('harness has no controlling terminal');
  if (harness.tpgid !== harness.pgrp) return no('harness is not the foreground job of its terminal');

  const envNames = readEnvNames(readProcFile, harnessPid);
  if (envNames === null) return no('harness environment unreadable');
  if (hasAgentMarker(envNames)) return no('harness was launched by an agent');
  if (envNames.some((n) => MULTIPLEXER_ENV.includes(n))) return no('harness runs under a terminal multiplexer');

  let child = harness;
  for (let depth = 0; validPid(child.ppid); depth++) {
    if (depth >= MAX_ANCESTRY) return no('ancestry too deep');
    const p = read(child.ppid);
    if (!p) return no('ancestor unreadable');
    const reused = hop(child, p);
    if (reused) return no(reused);
    // A node-run Claude Code (`node …/@anthropic-ai/claude-code/cli.js`) has
    // comm `node`, so the comm list alone misses it under a scrubbed env.
    if (procNameIn(p, AGENT_PROCESS_NAMES) || isClaudeHarness(p)) return no('harness is nested under an agent');
    if (procNameIn(p, PTY_TOOL_NAMES)) return no('harness runs under a pty tool');
    if (procNameIn(p, SCHEDULER_NAMES)) return no('harness runs under a scheduler');
    if (isMultiplexer(p)) return no('harness runs under a terminal multiplexer');
    child = p;
  }

  if (!validPid(harness.sid)) return no('harness session unknown');
  let leader = harness;
  if (harness.sid !== harnessPid) {
    leader = read(harness.sid);
    if (!leader) return no('session leader unreadable');
    if (!nameIn(leader.comm, SHELL_NAMES)) return no('session leader is not a shell');
    if (harness.ppid !== leader.pid) return no('harness is not started by its session shell');
    if (leader.tty !== harness.tty) return no('session leader is on another terminal');
    const reused = hop(harness, leader);
    if (reused) return no(reused);
  }
  if (!validPid(leader.ppid)) return no('session leader parent unknown');
  const leaderParent = read(leader.ppid);
  if (!leaderParent) return no('session leader parent unreadable');
  // The walk above vetted these pids, but this is a fresh read: re-anchor it.
  const reused = hop(leader, leaderParent);
  if (reused) return no(reused);
  if (procNameIn(leaderParent, PTY_INTERPRETER_NAMES)) return no('session leader spawned by an interpreter');
  const login = loginParentFailure(leaderParent, read, hop);
  if (login) return no(login);
  return { proven: true, harnessPid };
}

/**
 * Check 8's anchor: null when the session leader's parent is a login or a
 * terminal by evidence the session's own uid cannot forge, else why not.
 *
 *   (A) SSH or console login anchored on root. Either the parent is itself
 *       root-owned (all four uids 0) with comm sshd / sshd-session / login, or
 *       it is the per-session sshd / sshd-session whose own parent is a
 *       root-owned sshd / sshd-session that is not init. That per-session
 *       process runs as the user and is non-dumpable, so its exe is
 *       unreadable; the root parent is what a same-uid daemon (reparented to
 *       init or `systemd --user`) cannot fake.
 *   (B) A user-owned terminal emulator whose READABLE exe is an exact path in
 *       TERMINAL_EXE_PATHS.
 *
 * Anything else — an unreadable exe with no root anchor included — is unproven.
 */
function loginParentFailure(parent, read, hop) {
  if (isRootOwned(parent)) {
    return nameIn(parent.comm, ROOT_LOGIN_PARENT_NAMES) ? null : 'session leader parent is root but not sshd or login';
  }
  if (nameIn(parent.comm, SSHD_NAMES)) {
    if (!validPid(parent.ppid)) return 'sshd session is not under a root sshd';
    const monitor = read(parent.ppid);
    if (!monitor) return 'sshd session parent unreadable';
    const reused = hop(parent, monitor);
    if (reused) return reused;
    if (!isRootOwned(monitor) || !nameIn(monitor.comm, SSHD_NAMES)) return 'sshd session is not under a root sshd';
    return null;
  }
  if (!isUserOwned(parent)) return 'session leader not started by a login or terminal';
  const exe = exePath(parent);
  if (exe === null) return 'terminal executable unreadable';
  if (!TERMINAL_EXE_PATHS.includes(exe)) return 'session leader not started by a login or terminal';
  return null;
}
