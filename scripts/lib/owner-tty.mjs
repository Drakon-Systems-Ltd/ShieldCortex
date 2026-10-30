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
 *   3. The harness pid resolves (scripts/lib/harness-pid.mjs) to a pid > 1 that
 *      is not this process, and its stat, cmdline and environ are all readable.
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
 *      terminal, and the leader's parent is sshd, login or a known terminal
 *      emulator — never an interpreter (the `pty.spawn` shape) or anything
 *      else.
 *
 * There is no environment seam. Tests hand `proveOwnerPresentHarness` an
 * in-memory proc reader and transcript reader; the hook always uses /proc.
 */
import { closeSync, constants, fstatSync, openSync, readFileSync, readSync } from 'node:fs';
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
 * What may have started the session leader: a remote or console login, or a
 * terminal emulator (comm is cut at 15 bytes: `gnome-terminal-`).
 */
const LOGIN_PARENT_NAMES = [
  'sshd', 'sshd-session', 'login',
  'gnome-terminal-', 'gnome-terminal-server', 'kgx', 'ptyxis-agent', 'konsole', 'xterm', 'uxterm', 'alacritty',
  'kitty', 'wezterm-gui', 'foot', 'ghostty', 'terminator', 'tilix', 'xfce4-terminal', 'mate-terminal',
  'lxterminal', 'qterminal', 'urxvt', 'rxvt', 'sakura', 'terminology', 'st',
];
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

function isMultiplexer(proc) {
  return MULTIPLEXER_RE.test(String(proc.comm).toLowerCase())
    || MULTIPLEXER_RE.test(nameOf(proc.argv[0]).raw);
}

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
 * One process, or null when any field the decision needs is unreadable: a
 * missing stat, an unparseable field, an unreadable or empty cmdline.
 */
export function readProc(readProcFile, pid) {
  const statBuf = readProcFile(pid, 'stat');
  if (!statBuf) return null;
  const stat = statBuf.toString('utf8');
  const open = stat.indexOf('(');
  const close = stat.lastIndexOf(')');
  if (open < 0 || close < open) return null;
  // fields after comm: state(0) ppid(1) pgrp(2) session(3) tty_nr(4) tpgid(5)
  const rest = stat.slice(close + 2).trim().split(/\s+/);
  // `Number('')` is 0: a truncated stat must not read as "no tty" / pid 0.
  const [ppid, pgrp, sid, tty, tpgid] = [1, 2, 3, 4, 5].map((i) => (/^-?\d+$/.test(rest[i] ?? '') ? Number(rest[i]) : NaN));
  if (![ppid, pgrp, sid, tty, tpgid].every(Number.isInteger)) return null;
  const cmdline = readProcFile(pid, 'cmdline');
  if (!cmdline) return null;
  const argv = cmdline.toString('utf8').split('\0').filter(Boolean);
  if (argv.length === 0) return null;
  return { pid, ppid, pgrp, sid, tty, tpgid, comm: stat.slice(open + 1, close), argv };
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

  const read = (pid) => readProc(readProcFile, pid);
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

  let pid = harness.ppid;
  for (let hop = 0; validPid(pid); hop++) {
    if (hop >= MAX_ANCESTRY) return no('ancestry too deep');
    const p = read(pid);
    if (!p) return no('ancestor unreadable');
    // A node-run Claude Code (`node …/@anthropic-ai/claude-code/cli.js`) has
    // comm `node`, so the comm list alone misses it under a scrubbed env.
    if (nameIn(p.comm, AGENT_PROCESS_NAMES) || isClaudeHarness(p)) return no('harness is nested under an agent');
    if (nameIn(p.comm, PTY_TOOL_NAMES)) return no('harness runs under a pty tool');
    if (nameIn(p.comm, SCHEDULER_NAMES)) return no('harness runs under a scheduler');
    if (isMultiplexer(p)) return no('harness runs under a terminal multiplexer');
    pid = p.ppid;
  }

  if (!validPid(harness.sid)) return no('harness session unknown');
  let leader = harness;
  if (harness.sid !== harnessPid) {
    leader = read(harness.sid);
    if (!leader) return no('session leader unreadable');
    if (!nameIn(leader.comm, SHELL_NAMES)) return no('session leader is not a shell');
    if (harness.ppid !== leader.pid) return no('harness is not started by its session shell');
    if (leader.tty !== harness.tty) return no('session leader is on another terminal');
  }
  if (!validPid(leader.ppid)) return no('session leader parent unknown');
  const leaderParent = read(leader.ppid);
  if (!leaderParent) return no('session leader parent unreadable');
  if (nameIn(leaderParent.comm, PTY_INTERPRETER_NAMES)) return no('session leader spawned by an interpreter');
  if (!nameIn(leaderParent.comm, LOGIN_PARENT_NAMES)) return no('session leader not started by a login or terminal');
  return { proven: true, harnessPid };
}
