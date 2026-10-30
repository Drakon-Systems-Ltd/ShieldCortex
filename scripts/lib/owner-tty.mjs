/**
 * Owner-present harness terminal (#923, principle 4 of #875).
 *
 * The PreToolUse hook is ALWAYS an agent child and its stdin is a pipe, so
 * neither `process.stdin.isTTY` nor `operatorProvenance()` (the approve CLI's
 * check, which refuses whenever agent env markers are set) can say whether a
 * human owns the session. What can: the HARNESS — the persistent process the
 * hook was spawned by — and how it was launched.
 *
 * Proven only when every one of these holds; anything unreadable or unknown is
 * "unproven", and the caller keeps today's deny:
 *
 *   1. Linux. Other platforms are unproven (no cheap, portable read of another
 *      process's controlling terminal and launch environment).
 *   2. The harness pid resolves (scripts/lib/harness-pid.mjs) to a pid > 1 that
 *      is not this process.
 *   3. The harness is Claude Code (`claude` comm/argv0, or the npm cli path).
 *   4. The harness has a controlling terminal: `/proc/<pid>/stat` tty_nr != 0.
 *      This process's own fds are never consulted, so a `script` / `expect` /
 *      `pty.spawn` wrapper that hands THIS process a pty proves nothing.
 *   5. The harness's own launch environment (`/proc/<pid>/environ`) carries no
 *      agent marker. A human's shell launches a top-level Claude without one; a
 *      Claude started from another agent's tool call inherits `CLAUDECODE` etc.
 *   6. No ancestor of the harness, up to init, is an agent host, a pty tool or
 *      a scheduler (cron/at), and the harness session leader was not spawned
 *      by a bare interpreter (the `pty.spawn` shape). An unreadable ancestor is
 *      unproven.
 *   7. The hook payload carries no subagent marker (`agent_id`, `agent_type`,
 *      a `/subagents/` transcript, a `:subagent:` / `:cron:` session key).
 *
 * Test seam: `SHIELDCORTEX_TEST_PROC_ROOT` points every read at a synthetic
 * proc tree. The caller honours it only on a host without a policy lock — the
 * same gate as `SHIELDCORTEX_DIST_ROOT`, which on an unlocked host already
 * lets whoever sets the hook's environment substitute the classifier itself.
 */
import { readFileSync } from 'node:fs';
import { basename, join } from 'node:path';
import { resolveHarnessPid } from './harness-pid.mjs';

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

/** One process from `<procRoot>/<pid>`, or null when it cannot be read. */
export function readProc(procRoot, pid) {
  try {
    const stat = readFileSync(join(procRoot, String(pid), 'stat'), 'utf8');
    const open = stat.indexOf('(');
    const close = stat.lastIndexOf(')');
    if (open < 0 || close < open) return null;
    const rest = stat.slice(close + 2).split(/\s+/);
    // fields after comm: state(0) ppid(1) pgrp(2) session(3) tty_nr(4)
    const ppid = Number(rest[1]);
    const sid = Number(rest[3]);
    const tty = Number(rest[4]);
    if (!Number.isInteger(ppid) || !Number.isInteger(sid) || !Number.isInteger(tty)) return null;
    let argv = [];
    try {
      argv = readFileSync(join(procRoot, String(pid), 'cmdline')).toString('utf8').split('\0').filter(Boolean);
    } catch {
      argv = [];
    }
    return { pid, ppid, sid, tty, comm: stat.slice(open + 1, close), argv };
  } catch {
    return null;
  }
}

/** Names in `<procRoot>/<pid>/environ`, or null when it cannot be read. */
function readEnvNames(procRoot, pid) {
  try {
    return readFileSync(join(procRoot, String(pid), 'environ')).toString('utf8')
      .split('\0').filter(Boolean).map((kv) => kv.split('=', 1)[0]);
  } catch {
    return null;
  }
}

function hasAgentMarker(names) {
  return names.some((n) => HARNESS_AGENT_ENV_MARKERS.some((m) => (m.endsWith('_') ? n.startsWith(m) : n === m)));
}

function isClaudeHarness(proc) {
  if (nameIn(proc.comm, ['claude'])) return true;
  if (proc.argv.length > 0 && nameIn(proc.argv[0], ['claude'])) return true;
  return proc.argv.slice(0, 3).some((a) => /(?:^|\/)@anthropic-ai\/claude-code\/cli\.(?:m?js)$/.test(a));
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
 * Is this hook running under an owner-present harness terminal?
 * Returns `{ proven: true, harnessPid }` or `{ proven: false, reason }`.
 */
export function proveOwnerPresentHarness({
  hookData,
  platform = process.platform,
  procRoot = '/proc',
  parentPid = process.ppid,
  selfPid = process.pid,
} = {}) {
  const no = (reason) => ({ proven: false, reason });
  if (platform !== 'linux') return no('unsupported platform');
  const marker = hookPayloadSubagentMarker(hookData);
  if (marker) return no(marker);

  const read = (pid) => readProc(procRoot, pid);
  const harnessPid = resolveHarnessPid(parentPid, (pid) => {
    const p = read(pid);
    return p && validPid(p.ppid) && p.argv.length ? { ppid: p.ppid, argv: p.argv } : null;
  });
  if (!validPid(harnessPid) || harnessPid === selfPid) return no('harness pid unresolved');
  const harness = read(harnessPid);
  if (!harness) return no('harness unreadable');
  if (!isClaudeHarness(harness)) return no('harness is not Claude Code');
  if (harness.tty === 0) return no('harness has no controlling terminal');

  const envNames = readEnvNames(procRoot, harnessPid);
  if (envNames === null) return no('harness environment unreadable');
  if (hasAgentMarker(envNames)) return no('harness was launched by an agent');

  let pid = harness.ppid;
  for (let hop = 0; validPid(pid); hop++) {
    if (hop >= MAX_ANCESTRY) return no('ancestry too deep');
    const p = read(pid);
    if (!p) return no('ancestor unreadable');
    if (nameIn(p.comm, AGENT_PROCESS_NAMES)) return no('harness is nested under an agent');
    if (nameIn(p.comm, PTY_TOOL_NAMES)) return no('harness runs under a pty tool');
    if (nameIn(p.comm, SCHEDULER_NAMES)) return no('harness runs under a scheduler');
    pid = p.ppid;
  }

  if (validPid(harness.sid) && harness.sid !== harnessPid) {
    const leader = read(harness.sid);
    if (!leader) return no('session leader unreadable');
    const leaderParent = validPid(leader.ppid) ? read(leader.ppid) : null;
    if (leaderParent && nameIn(leaderParent.comm, PTY_INTERPRETER_NAMES)) return no('session leader spawned by an interpreter');
  }
  return { proven: true, harnessPid };
}
