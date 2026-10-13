/**
 * #628 — the gateway half of "one approval card per guarded call".
 *
 * When the interceptor puts a card up for a call that carries a host
 * `toolCallId` (claude-cli's `tool_use_id`), this process binds a listening
 * Unix socket in the Linux abstract namespace named for (this process's pid
 * and start time, the tool_use_id, the call's command or target path), and
 * holds it while the card is pending. The Claude Code hook for the same call
 * stands down from its own card only if it finds that socket in THIS
 * process's fd table, and only if this process is its claude-cli's direct
 * parent (src/defence/iron-dome/card-owner.ts has the proof and the threat
 * model).
 *
 * Bound only on a host build known to hold the claude-cli call on this card
 * until the operator answers ({@link CARD_OWNER_MIN_HOST_VERSION}): the
 * marker says "this call waits on a human here", so it must not exist where
 * the host might let the call run on.
 *
 * The socket accepts nothing: a connection is closed at once. It is a fact
 * in the kernel's tables, not a channel. Any failure to bind (not Linux, the
 * name already taken, no tool call id) just means no marker, and the hook
 * cards as it always has. Nothing here can change a verdict.
 *
 * Self-contained on purpose: this plugin never imports the main package at
 * compile time. `cardOwnerSurface` and `cardOwnerSocketName` MUST stay
 * identical to the copies in src/defence/iron-dome/card-owner.ts; a parity
 * test pins them.
 */

import { createHash } from 'node:crypto';
import { readFileSync } from 'node:fs';
import { createServer, type Server } from 'node:net';

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

/** Whether a runtime-reported host version is at or above the floor. Junk,
 *  absent or unparseable is "no". */
export function hostHoldsCallsOnCard(version: unknown): boolean {
  if (typeof version !== 'string') return false;
  const parse = (v: string) => {
    const m = v.trim().match(/^v?(\d{4})\.(\d{1,2})\.(\d{1,4})(?:$|[^0-9])/);
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

/** Kept a little past the answer so a hook that is still polling sees the
 *  card it is about to defer to rather than racing the close. */
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
  /** The operator answered: close after the linger. Idempotent. */
  release(): void;
  /** Close now. Idempotent. */
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

    let closed = false;
    let maxTimer: ReturnType<typeof setTimeout> | undefined;
    let lingerTimer: ReturnType<typeof setTimeout> | undefined;
    const server: Server = createServer((sock) => sock.destroy());
    const close = () => {
      if (closed) return;
      closed = true;
      if (maxTimer) clearTimeout(maxTimer);
      if (lingerTimer) clearTimeout(lingerTimer);
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
      release() {
        if (closed || lingerTimer) return;
        lingerTimer = setTimeout(close, opts.lingerMs ?? CARD_OWNER_LINGER_MS);
        lingerTimer.unref?.();
      },
      close,
    };
  } catch {
    return null;
  }
}
