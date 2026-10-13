/**
 * #628 — one approval card per guarded call when claude-cli runs under an
 * OpenClaw gateway with the ShieldCortex interceptor armed.
 *
 * On that stack two planes judge every native tool call: the Claude Code
 * `PreToolUse` hook (this package's `scripts/pre-tool-hook.mjs`, spawned by
 * claude-cli) and the OpenClaw `before_tool_call` interceptor (the plugin,
 * running inside the gateway, reached through the SDK `PreToolUse` callback
 * OpenClaw registers on the same claude-cli child). Both ran their own card
 * for the same call. The owner decision on #628: the interceptor owns the
 * card; the hook stands down ONLY on proof that the interceptor carded this
 * exact call, and the proof must rest on kernel truth.
 *
 * This module is the hook half; the gateway half is
 * plugins/openclaw/card-owner.ts. The hook adopts the interceptor's card only
 * when ALL of these hold, checked in this order:
 *
 *  1. A launch-chain ANCHOR exists that the agent's uid cannot write: the
 *     root-owned file `single-card-gateway.json` in ShieldCortex's protected
 *     root (`/etc/shieldcortex`, or the root-owned pointer's target; the same
 *     #501 boundary as the policy lock, verified with `verifyProtectedFile`).
 *     It names the gateway: its executable, its entry script, the exact
 *     interpreter flags before that script, and the exact values of the
 *     loader variables (`NODE_OPTIONS`, `LD_PRELOAD`, …) it runs with.
 *     Writing it is root's statement that the gateway's whole code-load
 *     surface (its config, plugin directories and service definition) is
 *     outside the agent's write reach; the hook cannot check that part.
 *  2. The harness's (claude-cli's) executable, and for a node-family
 *     interpreter its entry script, are root-owned files in directory chains
 *     the agent's uid cannot write (`verifyProtectedFile`, after resolving
 *     with `realpathSync.native`). The same holds for the harness's DIRECT
 *     parent, and that parent IS the anchored gateway: same executable, same
 *     interpreter flags, same entry script, same loader variables. A
 *     forwarding `claude` launcher dropped in a user-writable PATH or install
 *     directory fails here (round-2 review blocker 2): it is not the anchored
 *     gateway, and a user-writable claude is not a root-owned harness.
 *  3. That parent holds, in its OWN fd table, a listening abstract socket
 *     named for (its pid, its start time, this call's tool_use_id, this
 *     call's command or target path) — /proc/net/unix plus /proc/<parent>/fd.
 *  4. The hook connects and the gateway reports how the operator RESOLVED
 *     the card: `approved` or `denied`. Anything else — the host's
 *     `cancelled` (which is also how it reports an approval surface that is
 *     unavailable or a request it could not deliver), `timeout`, a closed
 *     socket, no answer within the hook's wait budget, a malformed reply —
 *     and the hook cards itself as before (round-2 review blocker 1: the
 *     socket's existence proves a REQUEST, not a presented card).
 *  5. After the reply, the same socket inode is still listed under that name
 *     and still in the parent's fd table, both stat lines are unchanged, and
 *     the launch chain still verifies — so the line was read from the
 *     anchored gateway's socket, not from one bound after it let go.
 *
 * `approved` makes the hook take its normal allow path (no decision of its
 * own); `denied` makes it deny. A call the hook itself would block never gets
 * here: every hook deny returns first, so a gateway answer can never loosen
 * the hook's verdict, and the strictest verdict wins.
 *
 * The wait bound: the hook waits at most {@link MAX_CARD_OWNER_WAIT_MS}
 * (default {@link DEFAULT_CARD_OWNER_WAIT_MS}) for the marker AND the answer
 * together, inside the 10 s PreToolUse timeout ShieldCortex installs. An
 * operator who takes longer than that gets two cards: the hook falls back to
 * its own, never to an allow or a silent deny.
 *
 * Why a same-user agent cannot forge it: the anchor, the executables, the
 * entry scripts and every directory above them are outside its write reach,
 * so it can neither stand up a different gateway under the anchored identity
 * nor replace claude with a forwarding launcher. A name it binds first makes
 * the gateway's own bind fail, and its inode is not in the gateway's fd
 * table. PID reuse changes the start time, which changes the name. A sibling
 * session's call has a different tool_use_id, so a different name. Env,
 * argv (beyond the identity checks above), marker files and filesystem
 * sockets are never read as proof.
 *
 * On a default user-level install (claude and OpenClaw in user-writable
 * directories) there is no anchor and the chain is not root-owned, so this
 * never proves anything and both planes card exactly as before. Single card
 * needs a hardened launch chain. Any doubt is "not proven": two cards, never
 * zero.
 */

import { createHash } from 'node:crypto';
import { readFileSync, readdirSync, readlinkSync, realpathSync } from 'node:fs';
import { connect } from 'node:net';
import { basename, isAbsolute, join } from 'node:path';

import {
  defaultProtectedFsSeam,
  resolveProtectedRoot,
  verifyProtectedFile,
  type ProtectedFsSeam,
} from './protected-root.js';

/** Abstract socket name prefix. Versioned: a derivation change is a new name. */
export const CARD_OWNER_NAME_PREFIX = 'shieldcortex-card-owner-v1-';

/** tool_use_id as the Anthropic API mints it (`toolu_…`), bounded. Anything
 *  else is not an id this proof will bind to. */
const TOOL_USE_ID_RE = /^[A-Za-z0-9_-]{8,128}$/;

/** A start time is the decimal clock-tick count from /proc/<pid>/stat. */
const START_TIME_RE = /^\d{1,20}$/;

/** Default time the hook waits for the interceptor's card to appear AND be
 *  answered, together. The hook fires a few tens of ms before the
 *  interceptor (field data on #628); the rest is the operator's time. */
export const DEFAULT_CARD_OWNER_WAIT_MS = 6_000;
/** Hard ceiling, inside the 10 s PreToolUse timeout ShieldCortex installs
 *  (src/setup/settings-hooks.ts), leaving room for the hook's own card when
 *  no answer comes. */
export const MAX_CARD_OWNER_WAIT_MS = 8_000;
const POLL_INTERVAL_MS = 50;

export interface CardOwnerHolder {
  pid: number;
  startTime: string;
}

/**
 * The part of the call both planes see identically: the command for a shell
 * tool, else the target path for a file tool. OpenClaw passes claude-cli's
 * native input through to `before_tool_call` (adding `path` beside
 * `file_path`), so these fields match byte for byte. A call that carries
 * neither binds to its tool_use_id alone, which is already unique per call.
 *
 * MUST stay identical to `cardOwnerSurface` in plugins/openclaw/card-owner.ts
 * (the two build units cannot share an import; a parity test pins them).
 */
export function cardOwnerSurface(input: unknown): string[] {
  const rec = input && typeof input === 'object' && !Array.isArray(input) ? (input as Record<string, unknown>) : {};
  if (typeof rec.command === 'string') return ['command', rec.command];
  for (const key of ['file_path', 'notebook_path', 'path']) {
    if (typeof rec[key] === 'string') return ['path', rec[key] as string];
  }
  return ['none'];
}

/** The abstract socket name (without the leading NUL) a holder binds for one
 *  call, or null when the call carries no usable tool_use_id. */
export function cardOwnerSocketName(holder: CardOwnerHolder, toolUseId: unknown, input: unknown): string | null {
  if (typeof toolUseId !== 'string' || !TOOL_USE_ID_RE.test(toolUseId)) return null;
  if (!Number.isInteger(holder.pid) || holder.pid <= 1 || !START_TIME_RE.test(holder.startTime)) return null;
  const digest = createHash('sha256')
    .update(JSON.stringify(['v1', holder.pid, holder.startTime, toolUseId, ...cardOwnerSurface(input)]))
    .digest('hex')
    .slice(0, 48);
  return `${CARD_OWNER_NAME_PREFIX}${digest}`;
}

export interface ProcStat {
  pid: number;
  ppid: number;
  startTime: string;
}

/** ppid and start time from /proc/<pid>/stat. The comm field may hold spaces
 *  and parentheses, so fields are counted from the LAST `)`. */
export function readProcStat(pid: number, procRoot = '/proc'): ProcStat | null {
  if (!Number.isInteger(pid) || pid <= 0) return null;
  try {
    const stat = readFileSync(join(procRoot, String(pid), 'stat'), 'utf8');
    const end = stat.lastIndexOf(')');
    if (end < 0) return null;
    const rest = stat.slice(end + 2).trim().split(/\s+/);
    // rest[0] is field 3 (state); ppid is field 4, starttime field 22.
    const state = rest[0];
    if (state === 'Z' || state === 'X') return null;
    const ppid = Number(rest[1]);
    const startTime = rest[19];
    if (!Number.isInteger(ppid) || ppid < 0 || typeof startTime !== 'string' || !START_TIME_RE.test(startTime)) return null;
    return { pid, ppid, startTime };
  } catch {
    return null;
  }
}

/** argv of a process from /proc/<pid>/cmdline. Used only to decide whether a
 *  wait is worth doing — never as proof. */
export function readProcArgv(pid: number, procRoot = '/proc'): string[] {
  try {
    return readFileSync(join(procRoot, String(pid), 'cmdline')).toString('utf8').split('\0').filter(Boolean);
  } catch {
    return [];
  }
}

/** Inodes of LISTENING Unix sockets bound to exactly `@<name>` (abstract). */
export function listeningAbstractSocketInodes(name: string, procRoot = '/proc'): Set<string> {
  const inodes = new Set<string>();
  let table: string;
  try {
    table = readFileSync(join(procRoot, 'net', 'unix'), 'utf8');
  } catch {
    return inodes;
  }
  const want = `@${name}`;
  for (const line of table.split('\n').slice(1)) {
    // Num RefCount Protocol Flags Type St Inode Path
    const f = line.trim().split(/\s+/);
    if (f.length < 8) continue;
    const [, , , flags, type, st, inode] = f;
    const path = f.slice(7).join(' ');
    if (path !== want) continue;
    // __SO_ACCEPTCON (listening), SOCK_STREAM, SS_UNCONNECTED.
    if (flags !== '00010000' || type !== '0001' || st !== '01') continue;
    if (/^\d+$/.test(inode)) inodes.add(inode);
  }
  return inodes;
}

const SOCKET_LINK_RE = /^socket:\[(\d+)\]$/;

/** Which of `inodes` `pid`'s own fd table holds as a socket, or null. */
export function heldSocketInode(pid: number, inodes: Set<string>, procRoot = '/proc'): string | null {
  if (inodes.size === 0) return null;
  const fdDir = join(procRoot, String(pid), 'fd');
  let fds: string[];
  try {
    fds = readdirSync(fdDir);
  } catch {
    return null;
  }
  for (const fd of fds) {
    let target: string;
    try {
      target = readlinkSync(join(fdDir, fd));
    } catch {
      continue;
    }
    const m = target.match(SOCKET_LINK_RE);
    if (m && inodes.has(m[1])) return m[1];
  }
  return null;
}

/** Whether `pid`'s own fd table holds one of `inodes` as a socket. */
export function processHoldsSocketInode(pid: number, inodes: Set<string>, procRoot = '/proc'): boolean {
  return heldSocketInode(pid, inodes, procRoot) !== null;
}

/** The harness was launched by OpenClaw's claude-cli transport: stdio
 *  permission prompts over stream-json. A WAIT trigger only — argv is not
 *  proof, and a harness that does not look like this skips the wait so plain
 *  Claude Code pays nothing. */
export function looksLikeOpenClawClaudeChild(argv: readonly string[]): boolean {
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i];
    if (a === '--permission-prompt-tool' && argv[i + 1] === 'stdio') return true;
    if (a === '--permission-prompt-tool=stdio') return true;
  }
  return false;
}

// ── 1. The anchor ────────────────────────────────────────────────────────────

/** The anchor's file name inside the protected root (#501). */
export const CARD_OWNER_ANCHOR_FILENAME = 'single-card-gateway.json';

/** Loader variables that put code into a process ahead of its own image. The
 *  gateway's values must match the anchor exactly; the harness's must be
 *  absent or equal to the anchored gateway's (it inherits them). */
export const CARD_OWNER_LOADER_ENV_KEYS = ['LD_PRELOAD', 'LD_AUDIT', 'LD_LIBRARY_PATH', 'NODE_OPTIONS', 'NODE_PATH'] as const;
type LoaderEnvKey = (typeof CARD_OWNER_LOADER_ENV_KEYS)[number];

/** What a verified anchor says about the gateway. */
export interface CardOwnerAnchor {
  /** Absolute path of the gateway's executable (`/proc/<gw>/exe`). */
  exe: string;
  /** Absolute path of its entry script; required when `exe` is node-family. */
  entry: string | null;
  /** The exact interpreter flags between the executable and the entry. */
  execArgv: string[];
  /** Exact values of the loader variables the gateway runs with. Absent = unset. */
  env: Partial<Record<LoaderEnvKey, string>>;
}

export type CardOwnerAnchorRead =
  | { ok: true; path: string; anchor: CardOwnerAnchor }
  | { ok: false; reason: string };

function isPlainObject(v: unknown): v is Record<string, unknown> {
  return !!v && typeof v === 'object' && !Array.isArray(v);
}

/** Strict: an unknown key, a wrong type or another version is not an anchor.
 *  A malformed root-owned file is doubt, and doubt is two cards. */
export function parseCardOwnerAnchor(raw: unknown): CardOwnerAnchor | null {
  if (!isPlainObject(raw)) return null;
  if (Object.keys(raw).some((k) => k !== 'version' && k !== 'gateway')) return null;
  if (raw.version !== 1 || !isPlainObject(raw.gateway)) return null;
  const gw = raw.gateway;
  if (Object.keys(gw).some((k) => !['exe', 'entry', 'execArgv', 'env'].includes(k))) return null;
  if (typeof gw.exe !== 'string' || !isAbsolute(gw.exe)) return null;
  if (gw.entry !== undefined && (typeof gw.entry !== 'string' || !isAbsolute(gw.entry))) return null;
  const execArgv = gw.execArgv ?? [];
  if (!Array.isArray(execArgv) || execArgv.length > 32 || execArgv.some((a) => typeof a !== 'string' || a === '')) return null;
  const env: Partial<Record<LoaderEnvKey, string>> = {};
  if (gw.env !== undefined) {
    if (!isPlainObject(gw.env)) return null;
    for (const [k, v] of Object.entries(gw.env)) {
      if (!(CARD_OWNER_LOADER_ENV_KEYS as readonly string[]).includes(k) || typeof v !== 'string') return null;
      env[k as LoaderEnvKey] = v;
    }
  }
  return { exe: gw.exe, entry: typeof gw.entry === 'string' ? gw.entry : null, execArgv: execArgv as string[], env };
}

export interface CardOwnerAnchorOptions {
  /** Filesystem seam for the ownership checks (tests mock uid/mode here). */
  fsSeam?: ProtectedFsSeam;
  /** Where the anchor lives. Default: `<protected root>/single-card-gateway.json`. */
  anchorPath?: string;
}

/** Read and verify the anchor. Missing is the normal answer on every host
 *  today, and means "never adopt the interceptor's card". Never throws. */
export function readCardOwnerAnchor(opts: CardOwnerAnchorOptions = {}): CardOwnerAnchorRead {
  try {
    const seam = opts.fsSeam ?? defaultProtectedFsSeam();
    let path = opts.anchorPath;
    if (!path) {
      const root = resolveProtectedRoot(seam);
      if (!root.supported) return { ok: false, reason: `no protected root (${root.reason})` };
      path = `${root.root}/${CARD_OWNER_ANCHOR_FILENAME}`;
    }
    const verdict = verifyProtectedFile(path, seam);
    if (!verdict.ok) return { ok: false, reason: verdict.reason === 'missing' ? 'no launch-chain anchor' : `anchor ${verdict.reason}` };
    const contents = seam.readFile(path);
    if (contents === null) return { ok: false, reason: 'anchor unreadable' };
    let parsed: unknown;
    try {
      parsed = JSON.parse(contents);
    } catch {
      return { ok: false, reason: 'anchor malformed' };
    }
    const anchor = parseCardOwnerAnchor(parsed);
    return anchor ? { ok: true, path, anchor } : { ok: false, reason: 'anchor malformed' };
  } catch {
    return { ok: false, reason: 'anchor error' };
  }
}

// ── 2. The launch chain ──────────────────────────────────────────────────────

/** Interpreters whose script is the program: the entry must be verified too. */
const NODE_FAMILY_RE = /^(?:node|nodejs|bun)(?:[-_.]?\d[\w.-]*)?$/;
/** Interpreters this proof does not know how to find the program for. A
 *  root-owned /bin/sh running a user-writable script is a user-writable
 *  program, so any of these is doubt. */
const OTHER_INTERPRETER_RE =
  /^(?:sh|bash|dash|zsh|ksh|mksh|fish|busybox|env|deno|java|osascript|pwsh|(?:python|perl|ruby|php|lua|tclsh)[\d.]*)$/;

export interface LaunchChainOptions extends CardOwnerAnchorOptions {
  procRoot?: string;
  /** The resolution oracle. Default `realpathSync.native` (the kernel's own). */
  realpath?: (path: string) => string;
}

type Check = { ok: true } | { ok: false; reason: string };

function readEnviron(pid: number, procRoot: string): Map<string, string> | null {
  try {
    const env = new Map<string, string>();
    for (const pair of readFileSync(join(procRoot, String(pid), 'environ')).toString('utf8').split('\0')) {
      const eq = pair.indexOf('=');
      if (eq > 0) env.set(pair.slice(0, eq), pair.slice(eq + 1));
    }
    return env;
  } catch {
    return null;
  }
}

/**
 * Verify the image one process runs: its executable and (node-family) entry
 * script are root-owned in directory chains the agent's uid cannot write. When
 * `expected` is given the process must also BE that program: same executable,
 * same interpreter flags, same entry script.
 */
function verifyProcessImage(
  pid: number,
  role: 'harness' | 'gateway',
  expected: CardOwnerAnchor | null,
  opts: LaunchChainOptions,
): Check {
  const procRoot = opts.procRoot ?? '/proc';
  const seam = opts.fsSeam ?? defaultProtectedFsSeam();
  const real = opts.realpath ?? ((p: string) => realpathSync.native(p));
  let exe: string;
  try {
    exe = readlinkSync(join(procRoot, String(pid), 'exe'));
  } catch {
    return { ok: false, reason: `${role} executable unreadable` };
  }
  if (!isAbsolute(exe) || exe.endsWith(' (deleted)')) return { ok: false, reason: `${role} executable replaced` };
  let exeReal: string;
  try {
    exeReal = real(exe);
  } catch {
    return { ok: false, reason: `${role} executable unresolvable` };
  }
  if (exeReal !== exe) return { ok: false, reason: `${role} executable moved` };
  const exeVerdict = verifyProtectedFile(exeReal, seam);
  if (!exeVerdict.ok) return { ok: false, reason: `${role} executable ${exeVerdict.reason}` };

  const name = basename(exeReal);
  if (OTHER_INTERPRETER_RE.test(name)) return { ok: false, reason: `${role} runs under an unsupported interpreter` };
  const argv = readProcArgv(pid, procRoot);
  let entryReal: string | null = null;
  if (NODE_FAMILY_RE.test(name)) {
    const flags = expected ? expected.execArgv : [];
    for (let i = 0; i < flags.length; i++) {
      if (argv[1 + i] !== flags[i]) return { ok: false, reason: `${role} interpreter flags differ` };
    }
    const entryArg = argv[1 + flags.length];
    if (!entryArg || entryArg.startsWith('-')) return { ok: false, reason: `${role} has no entry script` };
    let entryPath = entryArg;
    if (!isAbsolute(entryPath)) {
      try {
        entryPath = join(readlinkSync(join(procRoot, String(pid), 'cwd')), entryArg);
      } catch {
        return { ok: false, reason: `${role} entry script unresolvable` };
      }
    }
    try {
      entryReal = real(entryPath);
    } catch {
      return { ok: false, reason: `${role} entry script unresolvable` };
    }
    const entryVerdict = verifyProtectedFile(entryReal, seam);
    if (!entryVerdict.ok) return { ok: false, reason: `${role} entry script ${entryVerdict.reason}` };
  }

  if (expected) {
    let anchoredExe: string;
    let anchoredEntry: string | null = null;
    try {
      anchoredExe = real(expected.exe);
      if (expected.entry) anchoredEntry = real(expected.entry);
    } catch {
      return { ok: false, reason: 'anchored gateway path unresolvable' };
    }
    if (exeReal !== anchoredExe || entryReal !== anchoredEntry) return { ok: false, reason: 'parent is not the anchored gateway' };
  }
  return { ok: true };
}

/** Loader variables: the gateway's must equal the anchor's; the harness's must
 *  be unset or equal to the anchored gateway's. */
function verifyLoaderEnv(pid: number, role: 'harness' | 'gateway', anchor: CardOwnerAnchor, procRoot: string): Check {
  const env = readEnviron(pid, procRoot);
  if (!env) return { ok: false, reason: `${role} environment unreadable` };
  for (const key of CARD_OWNER_LOADER_ENV_KEYS) {
    const have = env.get(key) ?? '';
    const want = anchor.env[key] ?? '';
    if (have === want) continue;
    if (role === 'harness' && have === '') continue;
    return { ok: false, reason: `${role} ${key} differs from the anchor` };
  }
  return { ok: true };
}

/** Steps 1–2 of the module doc: the harness and its direct parent run
 *  root-owned images, and the parent is the anchored gateway. */
export function verifyAnchoredLaunchChain(
  input: { harnessPid: number; gatewayPid: number; anchor: CardOwnerAnchor },
  opts: LaunchChainOptions = {},
): Check {
  try {
    const procRoot = opts.procRoot ?? '/proc';
    const harness = verifyProcessImage(input.harnessPid, 'harness', null, opts);
    if (!harness.ok) return harness;
    const gateway = verifyProcessImage(input.gatewayPid, 'gateway', input.anchor, opts);
    if (!gateway.ok) return gateway;
    const gwEnv = verifyLoaderEnv(input.gatewayPid, 'gateway', input.anchor, procRoot);
    if (!gwEnv.ok) return gwEnv;
    return verifyLoaderEnv(input.harnessPid, 'harness', input.anchor, procRoot);
  } catch {
    return { ok: false, reason: 'launch chain error' };
  }
}

// ── 3. The marker ────────────────────────────────────────────────────────────

export type CardOwnerProof =
  | { proven: true; holderPid: number; holderStartTime: string; harnessStartTime: string; socketName: string; inode: string }
  | { proven: false; reason: string };

export interface CardOwnerProofInput {
  /** The claude-cli process this hook belongs to (resolveHarnessPid). */
  harnessPid: number;
  toolUseId: unknown;
  toolInput: unknown;
  procRoot?: string;
  platform?: NodeJS.Platform;
}

/**
 * One look, no waiting: does the harness's direct parent hold a listening
 * marker for this call? Proves a REQUEST for a card exists, nothing more — the
 * caller must still get the card's resolution before it may act on it.
 */
export function proveInterceptorOwnsCard(input: CardOwnerProofInput): CardOwnerProof {
  const procRoot = input.procRoot ?? '/proc';
  if ((input.platform ?? process.platform) !== 'linux') return { proven: false, reason: 'not linux' };
  if (typeof input.toolUseId !== 'string' || !TOOL_USE_ID_RE.test(input.toolUseId)) {
    return { proven: false, reason: 'no tool_use_id' };
  }
  const harness = readProcStat(input.harnessPid, procRoot);
  if (!harness) return { proven: false, reason: 'harness not readable' };
  if (harness.ppid <= 1) return { proven: false, reason: 'harness has no gateway parent' };
  const parent = readProcStat(harness.ppid, procRoot);
  if (!parent) return { proven: false, reason: 'parent not readable' };
  // A parent is never younger than its child. A reused pid would be.
  if (BigInt(parent.startTime) > BigInt(harness.startTime)) return { proven: false, reason: 'parent younger than harness' };
  const name = cardOwnerSocketName({ pid: parent.pid, startTime: parent.startTime }, input.toolUseId, input.toolInput);
  if (!name) return { proven: false, reason: 'no socket name' };
  const inodes = listeningAbstractSocketInodes(name, procRoot);
  if (inodes.size === 0) return { proven: false, reason: 'no interceptor card for this call' };
  const inode = heldSocketInode(parent.pid, inodes, procRoot);
  if (!inode) return { proven: false, reason: 'card socket not held by the gateway parent' };
  // Re-read: the parent must still be the same process, and still our parent.
  const parentAfter = readProcStat(parent.pid, procRoot);
  const harnessAfter = readProcStat(input.harnessPid, procRoot);
  if (!parentAfter || parentAfter.startTime !== parent.startTime) return { proven: false, reason: 'parent changed during check' };
  if (!harnessAfter || harnessAfter.ppid !== parent.pid || harnessAfter.startTime !== harness.startTime) {
    return { proven: false, reason: 'harness changed during check' };
  }
  return {
    proven: true,
    holderPid: parent.pid,
    holderStartTime: parent.startTime,
    harnessStartTime: harness.startTime,
    socketName: name,
    inode,
  };
}

/** Clamp a configured wait to [0, MAX]. Anything unparseable is the default. */
export function cardOwnerWaitMs(raw: unknown): number {
  const n = typeof raw === 'string' && raw.trim() !== '' ? Number(raw) : typeof raw === 'number' ? raw : NaN;
  if (!Number.isFinite(n)) return DEFAULT_CARD_OWNER_WAIT_MS;
  return Math.max(0, Math.min(MAX_CARD_OWNER_WAIT_MS, Math.floor(n)));
}

// ── 4. The resolution ────────────────────────────────────────────────────────

export type CardOwnerResolution = 'approved' | 'denied' | 'unresolved';

/** The gateway's one line, strictly: `{"v":1,"toolUseId":…,"resolution":…}`
 *  for THIS call, nothing else. MUST match `cardOwnerReply` in
 *  plugins/openclaw/card-owner.ts. Anything else is null (the hook cards). */
export function parseCardOwnerReply(line: string, toolUseId: string): CardOwnerResolution | null {
  let raw: unknown;
  try {
    raw = JSON.parse(line);
  } catch {
    return null;
  }
  if (!isPlainObject(raw) || Object.keys(raw).length !== 3) return null;
  if (raw.v !== 1 || raw.toolUseId !== toolUseId) return null;
  const r = raw.resolution;
  return r === 'approved' || r === 'denied' || r === 'unresolved' ? r : null;
}

const MAX_REPLY_BYTES = 512;

/** Connect to the abstract name and read one line, until `timeoutMs`. Null on
 *  anything but a complete line. Never throws. */
export function readCardOwnerReply(name: string, timeoutMs: number): Promise<string | null> {
  return new Promise((done) => {
    let settled = false;
    let buf = '';
    const finish = (v: string | null) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      try { sock.destroy(); } catch { /* gone */ }
      done(v);
    };
    const timer = setTimeout(() => finish(null), Math.max(0, timeoutMs));
    const sock = connect({ path: `\0${name}` });
    sock.setEncoding('utf8');
    sock.on('data', (d: string) => {
      buf += d;
      const nl = buf.indexOf('\n');
      if (nl >= 0) finish(buf.slice(0, nl));
      else if (buf.length > MAX_REPLY_BYTES) finish(null);
    });
    sock.on('error', () => finish(null));
    sock.on('close', () => finish(null));
  });
}

/** The looks-like trigger plus the anchor and chain: whether this hook may
 *  even wait. Every failure here is a fact waiting will not change. */
function precheck(input: AwaitCardOwnerInput): { ok: true; anchor: CardOwnerAnchor } | { ok: false; reason: string } {
  const procRoot = input.procRoot ?? '/proc';
  if ((input.platform ?? process.platform) !== 'linux') return { ok: false, reason: 'not linux' };
  if (!looksLikeOpenClawClaudeChild(readProcArgv(input.harnessPid, procRoot))) {
    return { ok: false, reason: 'harness is not an OpenClaw claude-cli child' };
  }
  if (typeof input.toolUseId !== 'string' || !TOOL_USE_ID_RE.test(input.toolUseId)) return { ok: false, reason: 'no tool_use_id' };
  const harness = readProcStat(input.harnessPid, procRoot);
  if (!harness || harness.ppid <= 1) return { ok: false, reason: 'harness has no gateway parent' };
  const anchor = readCardOwnerAnchor(input);
  if (!anchor.ok) return anchor;
  const chain = verifyAnchoredLaunchChain({ harnessPid: input.harnessPid, gatewayPid: harness.ppid, anchor: anchor.anchor }, input);
  if (!chain.ok) return chain;
  return { ok: true, anchor: anchor.anchor };
}

export interface AwaitCardOwnerInput extends CardOwnerProofInput, LaunchChainOptions {
  /** Total budget for the marker to appear AND the card to be answered. */
  waitMs?: number;
}

export type CardOwnerOutcome =
  | {
      kind: 'approved' | 'denied';
      holderPid: number;
      holderStartTime: string;
      socketName: string;
    }
  | { kind: 'fallback'; reason: string };

/**
 * The whole adoption decision (steps 1–5 of the module doc), bounded by
 * `waitMs`. `approved` / `denied` only when the anchored gateway reported an
 * operator answer for this exact call; every other path is `fallback`, and the
 * hook cards as before. Plain Claude Code and every unanchored host return at
 * once, without waiting. Never throws.
 */
export async function awaitInterceptorResolution(input: AwaitCardOwnerInput): Promise<CardOwnerOutcome> {
  try {
    const deadline = Date.now() + (input.waitMs ?? DEFAULT_CARD_OWNER_WAIT_MS);
    const pre = precheck(input);
    if (!pre.ok) return { kind: 'fallback', reason: pre.reason };
    const procRoot = input.procRoot ?? '/proc';

    let proof: CardOwnerProof;
    for (;;) {
      proof = proveInterceptorOwnsCard(input);
      if (proof.proven) break;
      // Only "not there yet" is worth waiting on.
      if (proof.reason !== 'no interceptor card for this call' || Date.now() >= deadline) {
        return { kind: 'fallback', reason: proof.reason };
      }
      await new Promise((r) => setTimeout(r, POLL_INTERVAL_MS));
    }

    const line = await readCardOwnerReply(proof.socketName, deadline - Date.now());
    if (line === null) return { kind: 'fallback', reason: 'no resolution from the gateway' };
    const resolution = parseCardOwnerReply(line, input.toolUseId as string);
    if (resolution === null) return { kind: 'fallback', reason: 'malformed resolution' };

    // Step 5: the line came from the socket the anchored gateway still holds.
    const inodes = listeningAbstractSocketInodes(proof.socketName, procRoot);
    if (!inodes.has(proof.inode) || heldSocketInode(proof.holderPid, new Set([proof.inode]), procRoot) === null) {
      return { kind: 'fallback', reason: 'card socket changed during the wait' };
    }
    const parentAfter = readProcStat(proof.holderPid, procRoot);
    const harnessAfter = readProcStat(input.harnessPid, procRoot);
    if (!parentAfter || parentAfter.startTime !== proof.holderStartTime) return { kind: 'fallback', reason: 'parent changed during the wait' };
    if (!harnessAfter || harnessAfter.ppid !== proof.holderPid || harnessAfter.startTime !== proof.harnessStartTime) {
      return { kind: 'fallback', reason: 'harness changed during the wait' };
    }
    const chain = verifyAnchoredLaunchChain({ harnessPid: input.harnessPid, gatewayPid: proof.holderPid, anchor: pre.anchor }, input);
    if (!chain.ok) return { kind: 'fallback', reason: chain.reason };

    if (resolution === 'unresolved') return { kind: 'fallback', reason: 'card not answered by the operator' };
    return { kind: resolution, holderPid: proof.holderPid, holderStartTime: proof.holderStartTime, socketName: proof.socketName };
  } catch {
    return { kind: 'fallback', reason: 'proof error' };
  }
}
