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
 * card; the hook stands down ONLY on a live proof that the interceptor is
 * carding this exact call, and the proof must rest on kernel truth.
 *
 * The proof (this module is the hook half; the gateway half is
 * plugins/openclaw/card-owner.ts):
 *
 *  1. When the interceptor puts a card up, the gateway process binds a
 *     listening Unix socket in the Linux abstract namespace whose name is a
 *     digest of (gateway pid, gateway start time, the call's tool_use_id, the
 *     call's command or target path). It holds that socket while the card is
 *     pending and closes it shortly after the operator answers.
 *  2. The hook resolves its harness (the claude-cli process) from /proc and
 *     takes the harness's DIRECT parent, with its start time, from
 *     /proc/<pid>/stat. It derives the name that parent would have bound for
 *     THIS call, finds that name among listening sockets in /proc/net/unix,
 *     and requires the socket's inode to be in the parent's own fd table
 *     (/proc/<parent>/fd). It re-reads both stat lines afterwards, so a parent
 *     that died, was replaced, or a harness that was re-parented mid-check
 *     fails the proof.
 *
 * Why a same-user agent cannot forge it: every input is kernel state. A name
 * the agent binds first makes the gateway's own bind fail, and the agent's
 * inode is not in the gateway's fd table. A socket file, an env var, a
 * registry or marker file, or argv carries no weight at all — nothing here
 * reads them as proof. PID reuse changes the start time, which changes the
 * name. A sibling session's call has a different tool_use_id (minted by the
 * Anthropic API, per call), so it derives a different name. A claude the
 * agent launches from its own shell has that shell (not the gateway) as its
 * parent, so the gateway's marker never matches it.
 *
 * The honest bound: what is proven is "the harness's DIRECT parent holds a
 * listening socket named for this call". For the gateway's own claude-cli
 * child, only the gateway can be that parent, so this is the interceptor's
 * card. A same-user agent that writes its own wrapper process and launches a
 * claude under it controls that claude's parent, can bind the name itself,
 * and so can make THAT claude's hook stand down. That is not a gate it
 * gains: the wrapper already answers that claude's permission prompts (its
 * `can_use_tool`), can launch it without this hook at all (`--settings`,
 * `--setting-sources`, its own HOME), and can run the command directly
 * without any claude. What it suppresses is the hook's own notification card
 * for a harness the agent owns. The gateway's claude-cli child, which is the
 * gated session, cannot be re-parented by the agent. See the PR threat model.
 *
 * Any doubt — not Linux, no tool_use_id, unreadable /proc, a name that is not
 * held by the parent, a parent that changed — is "not proven", and the hook
 * cards exactly as before: two cards, never zero.
 */

import { createHash } from 'node:crypto';
import { readFileSync, readdirSync, readlinkSync } from 'node:fs';
import { join } from 'node:path';

/** Abstract socket name prefix. Versioned: a derivation change is a new name. */
export const CARD_OWNER_NAME_PREFIX = 'shieldcortex-card-owner-v1-';

/** tool_use_id as the Anthropic API mints it (`toolu_…`), bounded. Anything
 *  else is not an id this proof will bind to. */
const TOOL_USE_ID_RE = /^[A-Za-z0-9_-]{8,128}$/;

/** A start time is the decimal clock-tick count from /proc/<pid>/stat. */
const START_TIME_RE = /^\d{1,20}$/;

/** Default time the hook waits for the interceptor's card to appear. The hook
 *  fires a few tens of ms before the interceptor (field data on #628), and the
 *  interceptor needs its own guard pass before it cards. */
export const DEFAULT_CARD_OWNER_WAIT_MS = 2_000;
const MAX_CARD_OWNER_WAIT_MS = 5_000;
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

/** Whether `pid`'s own fd table holds one of `inodes` as a socket. */
export function processHoldsSocketInode(pid: number, inodes: Set<string>, procRoot = '/proc'): boolean {
  if (inodes.size === 0) return false;
  const fdDir = join(procRoot, String(pid), 'fd');
  let fds: string[];
  try {
    fds = readdirSync(fdDir);
  } catch {
    return false;
  }
  for (const fd of fds) {
    let target: string;
    try {
      target = readlinkSync(join(fdDir, fd));
    } catch {
      continue;
    }
    const m = target.match(SOCKET_LINK_RE);
    if (m && inodes.has(m[1])) return true;
  }
  return false;
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

export type CardOwnerProof =
  | { proven: true; holderPid: number; holderStartTime: string; socketName: string }
  | { proven: false; reason: string };

export interface CardOwnerProofInput {
  /** The claude-cli process this hook belongs to (resolveHarnessPid). */
  harnessPid: number;
  toolUseId: unknown;
  toolInput: unknown;
  procRoot?: string;
  platform?: NodeJS.Platform;
}

/** One proof attempt, no waiting. */
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
  if (!processHoldsSocketInode(parent.pid, inodes, procRoot)) {
    return { proven: false, reason: 'card socket not held by the gateway parent' };
  }
  // Re-read: the parent must still be the same process, and still our parent.
  const parentAfter = readProcStat(parent.pid, procRoot);
  const harnessAfter = readProcStat(input.harnessPid, procRoot);
  if (!parentAfter || parentAfter.startTime !== parent.startTime) return { proven: false, reason: 'parent changed during check' };
  if (!harnessAfter || harnessAfter.ppid !== parent.pid || harnessAfter.startTime !== harness.startTime) {
    return { proven: false, reason: 'harness changed during check' };
  }
  return { proven: true, holderPid: parent.pid, holderStartTime: parent.startTime, socketName: name };
}

/** Clamp a configured wait to [0, MAX]. Anything unparseable is the default. */
export function cardOwnerWaitMs(raw: unknown): number {
  const n = typeof raw === 'string' && raw.trim() !== '' ? Number(raw) : typeof raw === 'number' ? raw : NaN;
  if (!Number.isFinite(n)) return DEFAULT_CARD_OWNER_WAIT_MS;
  return Math.max(0, Math.min(MAX_CARD_OWNER_WAIT_MS, Math.floor(n)));
}

export interface AwaitCardOwnerInput extends CardOwnerProofInput {
  waitMs?: number;
}

/**
 * Wait (bounded) for the interceptor's card for this call to appear, then
 * prove it. Skips the wait entirely — returning not-proven at once — when the
 * harness was not launched by OpenClaw's claude-cli transport, so plain
 * Claude Code is unaffected. Never throws.
 */
export async function awaitInterceptorCardOwner(input: AwaitCardOwnerInput): Promise<CardOwnerProof> {
  try {
    const procRoot = input.procRoot ?? '/proc';
    if ((input.platform ?? process.platform) !== 'linux') return { proven: false, reason: 'not linux' };
    if (!looksLikeOpenClawClaudeChild(readProcArgv(input.harnessPid, procRoot))) {
      return { proven: false, reason: 'harness is not an OpenClaw claude-cli child' };
    }
    const deadline = Date.now() + (input.waitMs ?? DEFAULT_CARD_OWNER_WAIT_MS);
    for (;;) {
      const proof = proveInterceptorOwnsCard(input);
      if (proof.proven) return proof;
      // Only the "not there yet" answer is worth waiting on; every other
      // failure is a fact about the process tree that waiting will not change.
      if (proof.reason !== 'no interceptor card for this call' || Date.now() >= deadline) return proof;
      await new Promise((r) => setTimeout(r, POLL_INTERVAL_MS));
    }
  } catch {
    return { proven: false, reason: 'proof error' };
  }
}
