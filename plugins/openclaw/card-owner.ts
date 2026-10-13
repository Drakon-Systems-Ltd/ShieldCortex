/**
 * #628 — the gateway half of "one approval card per guarded call".
 *
 * When the interceptor puts a card up for a call that carries a host
 * `toolCallId` (claude-cli's `tool_use_id`), this process binds a listening
 * Unix socket in the Linux abstract namespace named for (this process's pid
 * and start time, the tool_use_id, the call's command or target path). The
 * Claude Code hook for the same call proves from /proc that this process
 * holds it (src/defence/iron-dome/card-owner.ts has the proof, the launch-chain
 * anchor and the threat model), connects, and waits to be told how the card
 * was RESOLVED:
 *
 *   `approved`   the operator chose allow-once or allow-always;
 *   `denied`     the operator chose deny;
 *   `unresolved` anything else the host reported (`cancelled` — which is also
 *                how the host reports an approval surface that is unavailable
 *                or a request it could not deliver — or `timeout`, or a
 *                decision this build does not know).
 *
 * The socket's existence is NOT a claim that a card was presented: the host
 * may still fail to deliver it. Only an operator answer is. The hook adopts
 * `approved` / `denied` and cards itself on anything else, including no
 * answer, a closed socket or a malformed reply (round-2 review blocker 1).
 *
 * Bound only on a host build known to hold the claude-cli call on this card
 * until the operator answers ({@link CARD_OWNER_MIN_HOST_VERSION}).
 *
 * The socket reads nothing from a peer. Each connection gets one JSON line
 * once the card is resolved, then is closed; the listener stays up for a
 * linger after the answer so a hook can re-verify that the socket it read
 * from is still the one this process holds. Any failure to bind (not Linux,
 * the name already taken, no tool call id) just means no marker, and the hook
 * cards as it always has. Nothing here can change a verdict.
 *
 * Self-contained on purpose: this plugin never imports the main package at
 * compile time. `cardOwnerSurface`, `cardOwnerSocketName` and the reply shape
 * MUST stay identical to src/defence/iron-dome/card-owner.ts; a parity test
 * pins them.
 */

import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { createServer, type Server, type Socket } from 'node:net';

const CARD_OWNER_NAME_PREFIX = 'shieldcortex-card-owner-v1-';
const TOOL_USE_ID_RE = /^[A-Za-z0-9_-]{8,128}$/;
const START_TIME_RE = /^\d{1,20}$/;

/**
 * The oldest OpenClaw build whose claude-cli transport is known to HOLD the
 * native call on the interceptor's card: its SDK `PreToolUse` callback awaits
 * `before_tool_call`'s approval inline (`extensions/anthropic/cli.runtime.ts`
 * → `requestToolPermission` → `runBeforeToolCallHook` with no `approvalMode`,
 * i.e. `request`), so the callback's allow/deny is the operator's answer.
 * Older builds may defer the approval and let the call continue (#628 review
 * on 2026.7.1's native hook relay), where a hook that stood down would leave
 * the call ungated. Below this version, or with no runtime-reported version
 * at all, no marker is bound and the hook cards as before.
 */
export const CARD_OWNER_MIN_HOST_VERSION = '2026.9.8';

/** A release version, whole string: `[v]YYYY.M.D`. A prerelease or build
 *  suffix (`2026.9.8-beta.0`, `2026.9.8+abc`) or any trailing junk is not a
 *  release, so it does not satisfy the floor (#628 review nit). */
const HOST_RELEASE_RE = /^v?(\d{4})\.(\d{1,2})\.(\d{1,4})$/;

/** Whether a runtime-reported host version is a release at or above the
 *  floor. Junk, absent, unparseable, or a prerelease is "no". */
export function hostHoldsCallsOnCard(version: unknown): boolean {
  if (typeof version !== 'string') return false;
  const parse = (v: string) => {
    const m = v.trim().match(HOST_RELEASE_RE);
    return m ? [Number(m[1]), Number(m[2]), Number(m[3])] : null;
  };
  const have = parse(version);
  const floor = parse(CARD_OWNER_MIN_HOST_VERSION)!;
  if (!have) return false;
  for (let i = 0; i < 3; i++) {
    if (have[i] !== floor[i]) return have[i] > floor[i];
  }
  return true;
}

/** Kept up past the answer so a hook that connects late still reads it, and
 *  a hook that already read it can re-verify the socket it read from. */
export const CARD_OWNER_LINGER_MS = 10_000;
/** Never outlive the host's own card ceiling (600 s) by much, even if the
 *  host never reports a decision. */
export const CARD_OWNER_MAX_HOLD_MS = 630_000;

export function cardOwnerSurface(input: unknown): string[] {
  const rec = input && typeof input === 'object' && !Array.isArray(input) ? (input as Record<string, unknown>) : {};
  if (typeof rec.command === 'string') return ['command', rec.command];
  for (const key of ['file_path', 'notebook_path', 'path']) {
    if (typeof rec[key] === 'string') return ['path', rec[key] as string];
  }
  return ['none'];
}

export function cardOwnerSocketName(
  holder: { pid: number; startTime: string },
  toolUseId: unknown,
  input: unknown,
): string | null {
  if (typeof toolUseId !== 'string' || !TOOL_USE_ID_RE.test(toolUseId)) return null;
  if (!Number.isInteger(holder.pid) || holder.pid <= 1 || !START_TIME_RE.test(holder.startTime)) return null;
  const digest = createHash('sha256')
    .update(JSON.stringify(['v1', holder.pid, holder.startTime, toolUseId, ...cardOwnerSurface(input)]))
    .digest('hex')
    .slice(0, 48);
  return `${CARD_OWNER_NAME_PREFIX}${digest}`;
}

/** The three things the hook can be told. Only the first two change what the
 *  hook does; `unresolved` is the same as no answer at all. */
export type CardOwnerResolution = 'approved' | 'denied' | 'unresolved';

/** A host card decision → what the hook is told. Only an operator's button is
 *  an answer; `timeout`, `cancelled` and anything unknown are `unresolved`. */
export function cardOwnerResolution(decision: unknown): CardOwnerResolution {
  if (decision === 'allow-once' || decision === 'allow-always') return 'approved';
  if (decision === 'deny') return 'denied';
  return 'unresolved';
}

/** The one line a connection receives. MUST match `parseCardOwnerReply` in
 *  src/defence/iron-dome/card-owner.ts. */
export function cardOwnerReply(toolUseId: string, resolution: CardOwnerResolution): string {
  return `${JSON.stringify({ v: 1, toolUseId, resolution })}\n`;
}

/** Bound on simultaneous connections; extras are dropped (the hook then cards). */
const MAX_PENDING_CONNECTIONS = 16;

/** This process's own identity: pid plus start time from /proc/self/stat. */
export function selfHolderIdentity(): { pid: number; startTime: string } | null {
  try {
    const stat = readFileSync('/proc/self/stat', 'utf8');
    const end = stat.lastIndexOf(')');
    if (end < 0) return null;
    const startTime = stat.slice(end + 2).trim().split(/\s+/)[19];
    return typeof startTime === 'string' && START_TIME_RE.test(startTime) ? { pid: process.pid, startTime } : null;
  } catch {
    return null;
  }
}

export interface CardOwnerMarker {
  /** The abstract name held (no leading NUL). */
  readonly name: string;
  /** The host reported the card's decision: answer every waiting hook, then
   *  close after the linger. The first call wins. Idempotent. */
  resolve(decision: unknown): void;
  /** Close now, answering nobody (a waiting hook cards). Idempotent. */
  close(): void;
}

export interface HoldCardOwnerOptions {
  toolCallId: unknown;
  params: unknown;
  /** The host's own runtime-reported version (`api.runtime.version`). When
   *  given, no marker is bound unless {@link hostHoldsCallsOnCard} says yes.
   *  The plugin always passes it; omitting it is for unit tests only. */
  hostVersion?: string | null;
  /** Test seam: bind under another identity (PID-reuse tests). */
  holder?: { pid: number; startTime: string };
  lingerMs?: number;
  maxHoldMs?: number;
  platform?: NodeJS.Platform;
}

/**
 * Bind and hold the marker for one card. Returns null when no marker can be
 * held — the hook then cards as before. Never throws.
 */
export function holdCardOwnerMarker(opts: HoldCardOwnerOptions): CardOwnerMarker | null {
  try {
    if ((opts.platform ?? process.platform) !== 'linux') return null;
    if ('hostVersion' in opts && !hostHoldsCallsOnCard(opts.hostVersion)) return null;
    const holder = opts.holder ?? selfHolderIdentity();
    if (!holder) return null;
    const name = cardOwnerSocketName(holder, opts.toolCallId, opts.params);
    if (!name) return null;
    const toolUseId = opts.toolCallId as string;

    let closed = false;
    let reply: string | null = null;
    let maxTimer: ReturnType<typeof setTimeout> | undefined;
    let lingerTimer: ReturnType<typeof setTimeout> | undefined;
    const pending = new Set<Socket>();
    const answer = (sock: Socket, line: string) => {
      try { sock.end(line); } catch { sock.destroy(); }
    };
    const server: Server = createServer((sock) => {
      // Nothing is read from a peer; a peer that writes is ignored.
      sock.on('error', () => sock.destroy());
      sock.on('data', () => {});
      if (closed) return void sock.destroy();
      if (reply !== null) return answer(sock, reply);
      if (pending.size >= MAX_PENDING_CONNECTIONS) return void sock.destroy();
      pending.add(sock);
      sock.on('close', () => pending.delete(sock));
    });
    const close = () => {
      if (closed) return;
      closed = true;
      if (maxTimer) clearTimeout(maxTimer);
      if (lingerTimer) clearTimeout(lingerTimer);
      // Unanswered waiters see a close with no line: the hook cards.
      for (const sock of pending) sock.destroy();
      pending.clear();
      try { server.close(); } catch { /* already closed */ }
    };
    // EADDRINUSE (someone else holds the name) or anything else: no marker.
    server.on('error', close);
    server.listen({ path: `\0${name}`, exclusive: true });
    server.unref();
    maxTimer = setTimeout(close, opts.maxHoldMs ?? CARD_OWNER_MAX_HOLD_MS);
    maxTimer.unref?.();
    return {
      name,
      resolve(decision: unknown) {
        if (closed || reply !== null) return;
        reply = cardOwnerReply(toolUseId, cardOwnerResolution(decision));
        for (const sock of pending) answer(sock, reply);
        pending.clear();
        lingerTimer = setTimeout(close, opts.lingerMs ?? CARD_OWNER_LINGER_MS);
        lingerTimer.unref?.();
      },
      close,
    };
  } catch {
    return null;
  }
}
