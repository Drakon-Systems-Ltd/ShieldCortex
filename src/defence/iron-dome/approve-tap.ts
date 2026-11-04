/**
 * ShieldCortex — one-tap approve from the operator's chat (#815 Part B).
 *
 * A headless denial (`denied_no_prompt_surface`) already leaves a #310
 * retry-control fingerprint, and `shieldcortex approve --denial <actionId>`
 * in a real terminal turns it into ONE scoped, short-lived retry grant. This
 * module adds a second, authenticated way for the owner to give that same
 * answer from a phone, for Hermes and Claude Code hosts. (OpenClaw hosts keep
 * their native approval channel, #220; nothing here touches OpenClaw.)
 *
 * ## The flow
 *
 *   1. When a card is produced for a denial, the guard calls
 *      `mintApproveTapNonce({ actionId })`. It mints a single-use 128-bit
 *      nonce bound to {actionId, argsHash, exp}, exp <= 10 minutes after the
 *      mint. The store keeps sha256(nonce), never the nonce itself.
 *   2. The card carries `{actionId, nonce}` on its Approve button (card
 *      version 2, wired once #996 lands) and `argsHash` + `exp` beside it, all
 *      inside the webhook body the webhook secret already signs. The Telegram
 *      callback carries `{actionId, nonce}` only.
 *   3. sc-notify-bridge accepts the tap only from the configured approver's
 *      Telegram user id, then calls `POST /approve-tap` on loopback with
 *      `{actionId, argsHash, nonce, exp, approver, hmac}`, where `hmac` is
 *      HMAC-SHA256 under the APPROVE secret (a separate credential from the
 *      webhook secret) over `canonicalTapMessage` below.
 *   4. `verifyApproveTap` checks everything, consumes the nonce, and writes
 *      the same #310 retry grant `approve --denial` writes (`via: 'tap'`,
 *      `approver: 'telegram:<uid>'`). The next identical call in the same
 *      directory spends it, exactly as it spends a terminal grant.
 *
 * ## The canonical MAC form (v1)
 *
 *   HMAC-SHA256(key = the approve secret's trimmed bytes, message = UTF-8 of)
 *
 *     shieldcortex-approve-tap/v1\n
 *     actionId=<act-+ 16 lowercase hex>\n
 *     argsHash=<64 lowercase hex>\n
 *     nonce=<32 lowercase hex>\n
 *     exp=<decimal integer, ms since the Unix epoch>\n
 *     approver=telegram:<decimal uid>
 *
 *   (no trailing newline), sent as 64 lowercase hex. Every field is checked
 *   against its exact pattern BEFORE the message is built, so no field can
 *   carry a newline or a second `key=` into it. The approver IS inside the
 *   MAC: a tap the bridge signed for one Telegram user cannot be replayed
 *   under another.
 *
 * ## Fail closed, nothing written
 *
 * Every refusal before the nonce is consumed writes NOTHING: a bad or missing
 * HMAC, the webhook secret used in place of the approve secret, a wrong
 * approver, an unknown/used/expired/over-long nonce, an argsHash that is not
 * the denied call's, an unknown action, and a catastrophic or
 * self-protection-floor action. Those two tiers stay terminal-only. Once all
 * of that has passed the nonce is spent first and the grant written second,
 * so a concurrent double submit sees a spent nonce; if the grant store then
 * refuses (an operator Deny since the card went out, a live retry already
 * granted), the nonce stays spent and nothing is granted.
 *
 * ## Same UID — the tap path refuses to arm
 *
 * The HMAC is only as good as the key's secrecy. If the agent runs as the
 * user that owns the approve secret, the agent can read the key and mint its
 * own taps, so the tap path refuses to arm at all and says why. On such a
 * host the stronger boundary is the #501 OS lock (`sudo shieldcortex
 * protect`) plus the terminal approve. `checkApproveTapArming` is the one
 * check; doctor reports it warn-only, and both mint and verify refuse on it.
 *
 * The secret value never appears in a log line, an error message, a return
 * value other than the loader's, or a card.
 */

import { createHash, createHmac, randomBytes, timingSafeEqual } from 'node:crypto';
import {
  closeSync,
  constants as fsConstants,
  existsSync,
  fstatSync,
  lstatSync,
  mkdirSync,
  openSync,
  readFileSync,
  readSync,
  renameSync,
  rmSync,
  rmdirSync,
  statSync,
  writeFileSync,
} from 'node:fs';
import type { IncomingMessage, ServerResponse } from 'node:http';
import { join, isAbsolute } from 'node:path';

import { mkdirSecure } from '../../setup/state-permissions.js';
import { approvalsDir } from './action-approvals.js';
import {
  DEFAULT_RETRY_GRANT_TTL_MS,
  grantRetry,
  lookupRetryRow,
  suppressionIsLive,
  type RetryGrant,
  type RetryRow,
} from './retry-control.js';
import { CATASTROPHIC_SIGNALS, GUARD_SELF_PROTECTION_SIGNALS } from './tool-action-guard.js';

// ── Constants ─────────────────────────────────────────────────────────────

/** The hard ceiling on a tap nonce's life, mint to expiry. A nonce whose
 *  stored or presented lifetime is longer is refused even with a valid MAC. */
export const APPROVE_TAP_MAX_NONCE_LIFETIME_MS = 10 * 60 * 1000;
export const APPROVE_TAP_MIN_NONCE_LIFETIME_MS = 30 * 1000;
/** Domain-separation prefix and version of the canonical MAC message. */
export const APPROVE_TAP_MAC_PREFIX = 'shieldcortex-approve-tap/v1';
export const APPROVE_TAP_PATH = '/approve-tap';
export const DEFAULT_APPROVE_TAP_PORT = 3047;
/** Outstanding (unexpired) nonces kept at once. Past it, minting refuses —
 *  a card storm cannot grow this file without bound. */
export const MAX_LIVE_TAP_NONCES = 64;
/** Request bodies are tiny; anything bigger is not a tap. */
export const MAX_TAP_BODY_BYTES = 4096;
/** Secret file bounds (bytes on disk / characters once trimmed). */
const SECRET_FILE_MAX_BYTES = 4096;
const SECRET_MIN_CHARS = 32;
const SECRET_MAX_CHARS = 1024;
/** A mint time this far ahead of our clock is not a mint we made. */
const MINT_CLOCK_SKEW_MS = 5_000;

const ACTION_ID_RE = /^act-[0-9a-f]{16}$/;
const HEX64_RE = /^[0-9a-f]{64}$/;
const NONCE_RE = /^[0-9a-f]{32}$/;
const APPROVER_RE = /^telegram:[1-9][0-9]{0,19}$/;
const TELEGRAM_UID_RE = /^[1-9][0-9]{0,19}$/;
const ROW_ID_RE = /^[0-9a-f]{32}$/;
/** Printable ASCII without spaces: a secret is one token, not prose (and a
 *  multi-line file such as a private key is refused rather than adopted). */
const SECRET_RE = /^[\x21-\x7e]+$/;

/** A tool call the guard could not fully read: approve those from a terminal. */
const UNSCANNED_SIGNALS: readonly string[] = Object.freeze([
  'fallback-scan', 'invalid-tool-input', 'unknown-keys', 'not-object', 'nested-invalid',
  'type-coercion', 'missing-handle',
]);
/** The retry store keeps at most this many signals per row; a full list may
 *  have been cut, so it cannot prove the floor is absent. */
const RETRY_ROW_SIGNAL_CAP = 8;

// ── Config ────────────────────────────────────────────────────────────────

export interface ApproveTapConfig {
  /** Strict `true` only. Off by default. */
  enabled: boolean;
  /** Absolute path of the approve secret (0600, owned by the bridge's user). */
  secretPath?: string;
  /** The ONE Telegram user id whose taps are accepted (decimal string). */
  approverTelegramUid?: string;
  /** Loopback port for `POST /approve-tap`. */
  port: number;
}

/** Total: any input yields a config; junk degrades to "off" / absent. Reads
 *  the `actionGuard.approveTap` block. */
export function normaliseApproveTapConfig(raw: unknown): ApproveTapConfig {
  const block = raw && typeof raw === 'object' && !Array.isArray(raw) ? (raw as Record<string, unknown>) : {};
  const cfg: ApproveTapConfig = { enabled: block.enabled === true, port: DEFAULT_APPROVE_TAP_PORT };
  const p = block.secretPath;
  if (typeof p === 'string' && p.length > 0 && p.length <= 4096 && !p.includes('\0') && isAbsolute(p)) {
    cfg.secretPath = p;
  }
  const uid = block.approverTelegramUid;
  const uidStr = typeof uid === 'number' && Number.isSafeInteger(uid) ? String(uid) : typeof uid === 'string' ? uid.trim() : '';
  if (TELEGRAM_UID_RE.test(uidStr)) cfg.approverTelegramUid = uidStr;
  const port = block.port;
  if (typeof port === 'number' && Number.isInteger(port) && port >= 1024 && port <= 65535) cfg.port = port;
  return cfg;
}

// ── Plain-English reasons ─────────────────────────────────────────────────

export type TapArmingFailure =
  | 'disabled' | 'unsupported-platform' | 'agent-is-root' | 'no-approver' | 'no-secret-path'
  | 'secret-missing' | 'secret-symlink' | 'secret-not-file' | 'secret-mode' | 'same-uid'
  | 'secret-root-owned' | 'secret-unreadable' | 'secret-malformed' | 'secret-is-webhook-secret'
  | 'secret-stat-failed' | 'secret-not-bridge-owned' | 'bad-bridge-uid';

const OS_LOCK_POINTER =
  'On a single-user host the stronger boundary is the #501 OS lock (`sudo shieldcortex protect`), '
  + 'and approvals still work from a terminal: `shieldcortex approve --denial <actionId>`.';

/** One plain-English sentence (or two) per refusal. Never contains the secret. */
export function describeTapArmingFailure(reason: TapArmingFailure, ctx: { path?: string; uid?: number } = {}): string {
  const where = ctx.path ? ` at ${ctx.path}` : '';
  switch (reason) {
    case 'disabled':
      return 'One-tap approve is off (`actionGuard.approveTap.enabled` is not true).';
    case 'unsupported-platform':
      return 'One-tap approve needs a POSIX host with user ids; it cannot arm here. ' + OS_LOCK_POINTER;
    case 'agent-is-root':
      return 'One-tap approve is OFF: the agent runs as root, so it can read any file, including the approve secret, '
        + 'and approve its own blocked actions. Run the agent as an unprivileged user. ' + OS_LOCK_POINTER;
    case 'no-approver':
      return 'One-tap approve is OFF: `actionGuard.approveTap.approverTelegramUid` is not set to a Telegram user id, '
        + 'so there is nobody whose tap could be accepted.';
    case 'no-secret-path':
      return 'One-tap approve is OFF: `actionGuard.approveTap.secretPath` is not set to an absolute path.';
    case 'secret-missing':
      return `One-tap approve is OFF: there is no approve secret${where}.`;
    case 'secret-symlink':
      return `One-tap approve is OFF: the approve secret${where} is a symbolic link. Use a regular file.`;
    case 'secret-not-file':
      return `One-tap approve is OFF: the approve secret${where} is not a regular file.`;
    case 'secret-mode':
      return `One-tap approve is OFF: the approve secret${where} can be read or written by other users. `
        + 'It must be mode 0600 (chmod 600).';
    case 'same-uid':
      return `One-tap approve is OFF: the approve secret${where} is owned by uid ${ctx.uid ?? '?'}, the same user the `
        + 'agent runs as. Any process of that user, including the agent, could read the key and approve its own '
        + 'blocked actions. Give the secret to the bridge\'s own user (chown <bridge-user>; chmod 600). '
        + OS_LOCK_POINTER;
    case 'secret-root-owned':
      return `One-tap approve is OFF: the approve secret${where} is owned by root. It must belong to the `
        + 'notify bridge\'s own (unprivileged) user.';
    case 'secret-unreadable':
      return `The approve secret${where} cannot be read by this process. The tap endpoint must start as root `
        + '(it reads the secret, then drops to the agent\'s user before it listens).';
    case 'secret-malformed':
      return `One-tap approve is OFF: the approve secret${where} is not a single token of ${SECRET_MIN_CHARS} to `
        + `${SECRET_MAX_CHARS} printable characters.`;
    case 'secret-is-webhook-secret':
      return 'One-tap approve is OFF: the approve secret is the same as the webhook secret. It must be a separate '
        + 'credential, so that holding the webhook key alone can never approve anything.';
    case 'secret-not-bridge-owned':
      return `One-tap approve is OFF: the approve secret${where} is owned by uid ${ctx.uid ?? '?'}, not the notify `
        + 'bridge\'s user named by --bridge-uid. Only the bridge\'s own key is accepted.';
    case 'bad-bridge-uid':
      return 'One-tap approve is OFF: --bridge-uid must be the notify bridge\'s own unprivileged user, different '
        + 'from the agent\'s user and not root.';
    case 'secret-stat-failed':
    default:
      return `One-tap approve is OFF: the approve secret${where} could not be checked.`;
  }
}

// ── UID seam and arming ───────────────────────────────────────────────────

export interface TapStat {
  uid: number;
  mode: number;
  isFile: boolean;
  isSymbolicLink: boolean;
}

/** Everything the arming check reads from the OS, injectable for tests. */
export interface TapArmingDeps {
  /** The uid the agent / guard runs as. Default: this process's euid. */
  agentUid?: number | null;
  /** lstat of the secret path. Default: `fs.lstatSync`. Throw an errno-coded
   *  error to model ENOENT / EACCES. */
  lstat?: (p: string) => TapStat;
  platform?: NodeJS.Platform;
}

function defaultLstat(p: string): TapStat {
  const st = lstatSync(p);
  return { uid: st.uid, mode: st.mode, isFile: st.isFile(), isSymbolicLink: st.isSymbolicLink() };
}

function processEuid(): number | null {
  return typeof process.geteuid === 'function' ? process.geteuid() : null;
}

export type TapArming =
  | { armed: true; secretVisible: boolean; message: string }
  | { armed: false; reason: TapArmingFailure; message: string };

function refuse(reason: TapArmingFailure, ctx: { path?: string; uid?: number } = {}): TapArming {
  return { armed: false, reason, message: describeTapArmingFailure(reason, ctx) };
}

/** Mode bits outside 0600 (group/other anything, or owner execute). */
function modeTooWide(mode: number): boolean {
  return (mode & 0o777 & ~0o600) !== 0;
}

/**
 * May the tap path arm on this host? Reads only metadata (lstat), so it is
 * what the hook (mint), doctor and the endpoint all ask. It is deliberately
 * NOT a key check: the agent's user should NOT be able to read the secret, so
 * an EACCES on lstat (the secret sits in the bridge's private directory) is
 * the good case, reported as armed with `secretVisible: false`. The endpoint
 * still opens the file itself and re-checks owner and mode on the open fd
 * (`loadApproveTapSecret`) before it trusts a byte of it.
 */
/** Config and agent-uid preconditions shared by arming and the loader:
 *  the resolved agent uid, or the refusal. */
function tapPreconditions(
  config: ApproveTapConfig,
  deps: { agentUid?: number | null; platform?: NodeJS.Platform },
): { ok: true; agentUid: number; path: string } | { ok: false; refusal: TapArming } {
  if (!config.enabled) return { ok: false, refusal: refuse('disabled') };
  const platform = deps.platform ?? process.platform;
  const agentUid = deps.agentUid === undefined ? processEuid() : deps.agentUid;
  if (platform === 'win32' || agentUid === null || !Number.isInteger(agentUid)) {
    return { ok: false, refusal: refuse('unsupported-platform') };
  }
  if (agentUid === 0) return { ok: false, refusal: refuse('agent-is-root') };
  if (!config.approverTelegramUid) return { ok: false, refusal: refuse('no-approver') };
  if (!config.secretPath) return { ok: false, refusal: refuse('no-secret-path') };
  return { ok: true, agentUid, path: config.secretPath };
}

/** The ownership and mode rules for the secret's own metadata, or null when
 *  they hold. One function, so arming (lstat) and loading (fstat on the open
 *  fd) cannot disagree. */
function judgeSecretMeta(
  st: { uid: number; mode: number; isFile: boolean; isSymbolicLink?: boolean },
  agentUid: number,
  path: string,
): TapArming | null {
  if (st.isSymbolicLink) return refuse('secret-symlink', { path });
  if (!st.isFile) return refuse('secret-not-file', { path });
  if (modeTooWide(st.mode)) return refuse('secret-mode', { path });
  if (st.uid === agentUid) return refuse('same-uid', { path, uid: st.uid });
  if (st.uid === 0) return refuse('secret-root-owned', { path });
  return null;
}

export function checkApproveTapArming(config: ApproveTapConfig, deps: TapArmingDeps = {}): TapArming {
  const pre = tapPreconditions(config, deps);
  if (!pre.ok) return pre.refusal;
  const { agentUid, path } = pre;
  let st: TapStat;
  try {
    st = (deps.lstat ?? defaultLstat)(path);
  } catch (err) {
    const code = (err as NodeJS.ErrnoException)?.code;
    if (code === 'EACCES' || code === 'EPERM') {
      return {
        armed: true,
        secretVisible: false,
        message: `One-tap approve is armed: the approve secret at ${path} is out of this user's reach, which is `
          + 'what keeps the agent from reading it. The tap endpoint checks its owner and mode when it starts.',
      };
    }
    if (code === 'ENOENT' || code === 'ENOTDIR') return refuse('secret-missing', { path });
    return refuse('secret-stat-failed', { path });
  }
  const bad = judgeSecretMeta(st, agentUid, path);
  if (bad) return bad;
  return {
    armed: true,
    secretVisible: true,
    message: `One-tap approve is armed: the approve secret at ${path} is mode 0600 and owned by uid ${st.uid}, `
      + `not the agent's uid ${agentUid}.`,
  };
}

// ── Secret loading (the endpoint only) ────────────────────────────────────

export interface TapSecretOpenResult {
  uid: number;
  mode: number;
  isFile: boolean;
  /** Raw bytes, at most SECRET_FILE_MAX_BYTES + 1. */
  bytes: Buffer;
}

export interface TapSecretDeps {
  agentUid?: number | null;
  /** Opens WITHOUT following a symlink and reports the open fd's own stat.
   *  Default: O_RDONLY | O_NOFOLLOW | O_NONBLOCK, then fstat on the fd. */
  openSecret?: (p: string) => TapSecretOpenResult;
  platform?: NodeJS.Platform;
}

function defaultOpenSecret(p: string): TapSecretOpenResult {
  const flags = fsConstants.O_RDONLY | (fsConstants.O_NOFOLLOW ?? 0) | (fsConstants.O_NONBLOCK ?? 0);
  const fd = openSync(p, flags);
  try {
    const st = fstatSync(fd);
    if (!st.isFile()) return { uid: st.uid, mode: st.mode, isFile: false, bytes: Buffer.alloc(0) };
    const buf = Buffer.alloc(SECRET_FILE_MAX_BYTES + 1);
    let n = 0;
    while (n < buf.length) {
      const got = readSync(fd, buf, n, buf.length - n, null);
      if (got <= 0) break;
      n += got;
    }
    return { uid: st.uid, mode: st.mode, isFile: true, bytes: buf.subarray(0, n) };
  } finally {
    closeSync(fd);
  }
}

export type TapSecretLoad =
  | { ok: true; key: Buffer; ownerUid: number }
  | { ok: false; reason: TapArmingFailure; message: string };

/**
 * Read the approve secret for the endpoint. The owner and mode are taken from
 * the OPEN fd (no lstat-then-open window), the open refuses a symlink, and the
 * same rules as arming apply. `webhookSecret`, when given, must differ: the
 * approve secret is a separate credential. The key is returned as bytes and
 * never placed in a message.
 */
export function loadApproveTapSecret(
  config: ApproveTapConfig,
  opts: TapSecretDeps & {
    webhookSecret?: string;
    /** The bridge's uid as the root-run endpoint was told it (never from the
     *  agent-writable config). When given, the secret's owner must equal it. */
    bridgeUid?: number;
  } = {},
): TapSecretLoad {
  const pre = tapPreconditions(config, opts);
  if (!pre.ok) {
    const r = pre.refusal as Extract<TapArming, { armed: false }>;
    return { ok: false, reason: r.reason, message: r.message };
  }
  const { agentUid, path } = pre;
  const fail = (reason: TapArmingFailure, uid?: number): TapSecretLoad => ({
    ok: false, reason, message: describeTapArmingFailure(reason, { path, uid }),
  });
  let opened: TapSecretOpenResult;
  try {
    opened = (opts.openSecret ?? defaultOpenSecret)(path);
  } catch (err) {
    const code = (err as NodeJS.ErrnoException)?.code;
    if (code === 'ELOOP' || code === 'EMLINK') return fail('secret-symlink');
    if (code === 'ENOENT' || code === 'ENOTDIR') return fail('secret-missing');
    if (code === 'EACCES' || code === 'EPERM') return fail('secret-unreadable');
    return fail('secret-stat-failed');
  }
  const bad = judgeSecretMeta({ ...opened, isSymbolicLink: false }, agentUid, path);
  if (bad && !bad.armed) return { ok: false, reason: bad.reason, message: bad.message };
  if (opts.bridgeUid !== undefined) {
    if (!Number.isInteger(opts.bridgeUid) || opts.bridgeUid <= 0 || opts.bridgeUid === agentUid) return fail('bad-bridge-uid');
    if (opened.uid !== opts.bridgeUid) return fail('secret-not-bridge-owned', opened.uid);
  }
  if (opened.bytes.length > SECRET_FILE_MAX_BYTES) return fail('secret-malformed');
  const text = opened.bytes.toString('utf8').trim();
  if (text.length < SECRET_MIN_CHARS || text.length > SECRET_MAX_CHARS || !SECRET_RE.test(text)) {
    return fail('secret-malformed');
  }
  const key = Buffer.from(text, 'utf8');
  if (typeof opts.webhookSecret === 'string') {
    const hook = Buffer.from(opts.webhookSecret.trim(), 'utf8');
    if (hook.length === key.length && timingSafeEqual(hook, key)) return fail('secret-is-webhook-secret');
  }
  return { ok: true, key, ownerUid: opened.uid };
}

// ── Canonical MAC ─────────────────────────────────────────────────────────

export interface TapMacFields {
  actionId: string;
  argsHash: string;
  nonce: string;
  exp: number;
  approver: string;
}

function fieldsAreCanonical(f: TapMacFields): boolean {
  return typeof f.actionId === 'string' && ACTION_ID_RE.test(f.actionId)
    && typeof f.argsHash === 'string' && HEX64_RE.test(f.argsHash)
    && typeof f.nonce === 'string' && NONCE_RE.test(f.nonce)
    && Number.isSafeInteger(f.exp) && f.exp > 0
    && typeof f.approver === 'string' && APPROVER_RE.test(f.approver);
}

/** The exact bytes the HMAC covers, or null when any field is not in its
 *  canonical form (so nothing malformed is ever MAC'd). */
export function canonicalTapMessage(f: TapMacFields): string | null {
  if (!fieldsAreCanonical(f)) return null;
  return [
    APPROVE_TAP_MAC_PREFIX,
    `actionId=${f.actionId}`,
    `argsHash=${f.argsHash}`,
    `nonce=${f.nonce}`,
    `exp=${String(f.exp)}`,
    `approver=${f.approver}`,
  ].join('\n');
}

/** Lowercase hex HMAC-SHA256 of the canonical message, or null. The bridge
 *  computes exactly this. */
export function computeTapHmac(key: Buffer | string, f: TapMacFields): string | null {
  const msg = canonicalTapMessage(f);
  if (msg === null) return null;
  return createHmac('sha256', key).update(msg, 'utf8').digest('hex');
}

function hexEqualConstantTime(a: string, b: string): boolean {
  const left = Buffer.from(a, 'utf8');
  const right = Buffer.from(b, 'utf8');
  if (left.length !== right.length) return false;
  return timingSafeEqual(left, right);
}

// ── Terminal-only classification ──────────────────────────────────────────

export type TerminalOnlyReason = 'self-protection-floor' | 'catastrophic' | 'unscanned' | 'unknown-signal' | 'signals-incomplete';

/**
 * Why a denial with these signals may only be approved from a terminal, or
 * null when a tap may answer it. Fail closed: an unknown or redacted signal,
 * an empty list, or a list long enough to have been cut by the store all
 * refuse, because none of them proves the floor is absent.
 */
export function tapTerminalOnlyReason(signals: readonly unknown[] | undefined): TerminalOnlyReason | null {
  if (!Array.isArray(signals) || signals.length === 0 || signals.length >= RETRY_ROW_SIGNAL_CAP) {
    return 'signals-incomplete';
  }
  const list = signals.map((s) => (typeof s === 'string' ? s : ''));
  if (list.some((s) => GUARD_SELF_PROTECTION_SIGNALS.includes(s))) return 'self-protection-floor';
  if (list.some((s) => CATASTROPHIC_SIGNALS.includes(s))) return 'catastrophic';
  if (list.some((s) => UNSCANNED_SIGNALS.includes(s))) return 'unscanned';
  if (list.some((s) => !/^[a-z0-9][a-z0-9-]{0,63}$/.test(s) || s === 'redacted-signal')) return 'unknown-signal';
  return null;
}

function describeTerminalOnly(reason: TerminalOnlyReason): string {
  switch (reason) {
    case 'self-protection-floor':
      return 'This action touches ShieldCortex\'s own approvals, config or guard switches, so it can only be '
        + 'approved from a terminal on that machine.';
    case 'catastrophic':
      return 'This action is in the catastrophic tier, so it can only be approved from a terminal on that machine.';
    case 'unscanned':
      return 'The guard could not fully read this action, so it can only be approved from a terminal on that machine.';
    case 'unknown-signal':
    case 'signals-incomplete':
    default:
      return 'The guard cannot show that this action is outside the catastrophic and self-protection tiers, so it '
        + 'can only be approved from a terminal on that machine.';
  }
}

// ── Nonce store ───────────────────────────────────────────────────────────

interface TapNonceRecord {
  /** sha256(nonce) hex. The nonce itself is never written. */
  id: string;
  actionId: string;
  argsHash: string;
  rowId: string;
  epoch: number;
  mintedAt: number;
  exp: number;
  usedAt?: number;
}

interface TapNonceFile {
  version: 1;
  nonces: TapNonceRecord[];
}

export interface TapStoreOptions {
  home?: string;
  now?: number;
}

export function approveTapNoncePath(home?: string): string {
  return join(approvalsDir(home), 'approve-tap-nonces.json');
}

function noncesLockPath(home?: string): string {
  return join(approvalsDir(home), 'approve-tap-nonces.lock');
}

function nonceId(nonce: string): string {
  return createHash('sha256').update(`approve-tap-nonce:${nonce}`, 'utf8').digest('hex');
}

function isRecord(raw: unknown): raw is TapNonceRecord {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return false;
  const r = raw as Record<string, unknown>;
  return typeof r.id === 'string' && HEX64_RE.test(r.id)
    && typeof r.actionId === 'string' && ACTION_ID_RE.test(r.actionId)
    && typeof r.argsHash === 'string' && HEX64_RE.test(r.argsHash)
    && typeof r.rowId === 'string' && ROW_ID_RE.test(r.rowId)
    && Number.isSafeInteger(r.epoch) && (r.epoch as number) >= 0
    && Number.isSafeInteger(r.mintedAt) && Number.isSafeInteger(r.exp)
    && (r.usedAt === undefined || Number.isSafeInteger(r.usedAt));
}

function readNonces(home?: string): TapNonceFile {
  try {
    const p = approveTapNoncePath(home);
    if (!existsSync(p)) return { version: 1, nonces: [] };
    const parsed = JSON.parse(readFileSync(p, 'utf8')) as Partial<TapNonceFile>;
    if (!parsed || !Array.isArray(parsed.nonces)) return { version: 1, nonces: [] };
    // Bounded work on a hostile file; junk rows are dropped, never repaired.
    return { version: 1, nonces: parsed.nonces.slice(-MAX_LIVE_TAP_NONCES * 4).filter(isRecord) };
  } catch {
    // Corrupt reads as EMPTY: every nonce is then unknown — the refusal side.
    return { version: 1, nonces: [] };
  }
}

function writeNonces(file: TapNonceFile, home?: string): boolean {
  try {
    mkdirSecure(approvalsDir(home));
    const target = approveTapNoncePath(home);
    const tmp = `${target}.${process.pid}.tmp`;
    writeFileSync(tmp, `${JSON.stringify(file, null, 2)}\n`, { mode: 0o600 });
    renameSync(tmp, target);
    return true;
  } catch {
    return false;
  }
}

const LOCK_ATTEMPTS = 100;
const LOCK_SLEEP_MS = 20;
const LOCK_STALE_MS = 10_000;

function sleepSync(ms: number): void {
  try {
    Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms);
    return;
  } catch {
    /* fall through to a bounded spin */
  }
  const until = Date.now() + ms;
  while (Date.now() < until) { /* bounded spin */ }
}

interface NonceLock {
  path: string;
  token: string;
}

/**
 * An exclusive mkdir with a random owner token inside, bounded spin, stale
 * takeover. Failing to lock is failing CLOSED.
 *
 * A stale lock is taken over by RENAMING it to a unique tombstone (only one
 * contender's rename can succeed) rather than rmdir-then-mkdir, and every
 * write re-checks the token (`stillHeld`) first: if another process ever did
 * take the lock over while we held it, we refuse instead of writing over its
 * update.
 */
function acquireNonceLock(home?: string): NonceLock | null {
  const p = noncesLockPath(home);
  try {
    mkdirSecure(approvalsDir(home));
  } catch {
    return null;
  }
  const token = randomBytes(16).toString('hex');
  for (let attempt = 0; attempt < LOCK_ATTEMPTS; attempt += 1) {
    try {
      mkdirSync(p, { mode: 0o700 });
      try {
        writeFileSync(join(p, 'owner'), token, { mode: 0o600, flag: 'wx' });
      } catch {
        try { rmdirSync(p); } catch { /* leave it to go stale */ }
        return null;
      }
      return { path: p, token };
    } catch (err) {
      if ((err as NodeJS.ErrnoException)?.code !== 'EEXIST') return null;
      try {
        if (Date.now() - statSync(p).mtimeMs > LOCK_STALE_MS) {
          const tomb = `${p}.stale-${process.pid}-${randomBytes(4).toString('hex')}`;
          try {
            renameSync(p, tomb);
            rmSync(tomb, { recursive: true, force: true });
          } catch { /* another contender won the takeover */ }
          continue;
        }
      } catch {
        continue;
      }
      sleepSync(LOCK_SLEEP_MS);
    }
  }
  return null;
}

function stillHeld(lock: NonceLock): boolean {
  try {
    return readFileSync(join(lock.path, 'owner'), 'utf8') === lock.token;
  } catch {
    return false;
  }
}

function releaseNonceLock(lock: NonceLock | null): void {
  if (!lock || !stillHeld(lock)) return; // never remove a lock we no longer own
  try { rmSync(join(lock.path, 'owner'), { force: true }); } catch { /* ignore */ }
  try { rmdirSync(lock.path); } catch { /* ignore */ }
}

// ── Mint ──────────────────────────────────────────────────────────────────

export type TapMintFailure =
  | 'not-armed' | 'bad-action-id' | 'bad-lifetime' | 'not-found' | 'terminal-only' | 'unscopeable'
  | 'suppressed' | 'too-many' | 'locked' | 'unwritable';

export type TapMintOutcome =
  | { ok: true; actionId: string; nonce: string; argsHash: string; exp: number; mintedAt: number }
  | { ok: false; reason: TapMintFailure; message: string; terminalOnly?: TerminalOnlyReason };

export interface TapMintOptions extends TapStoreOptions, TapArmingDeps {
  config: ApproveTapConfig;
  /** Mint to expiry. Default and maximum: 10 minutes. Outside
   *  [30 s, 10 min] the mint is refused, never clamped. */
  lifetimeMs?: number;
}

/**
 * Mint a single-use tap nonce for the denial card of `actionId`. Refuses —
 * mints nothing — unless the tap path is armed, the denial is on file and
 * scopeable, not silenced by the operator's own Deny, and not terminal-only.
 * The returned `nonce` exists only in this return value and on the card; the
 * store keeps its sha256.
 */
export function mintApproveTapNonce(input: { actionId: string }, opts: TapMintOptions): TapMintOutcome {
  const now = opts.now ?? Date.now();
  const arming = checkApproveTapArming(opts.config, opts);
  if (!arming.armed) return { ok: false, reason: 'not-armed', message: arming.message };
  const actionId = typeof input?.actionId === 'string' ? input.actionId : '';
  if (!ACTION_ID_RE.test(actionId)) {
    return { ok: false, reason: 'bad-action-id', message: 'That is not a ShieldCortex action id (act- plus 16 hex).' };
  }
  const lifetimeMs = opts.lifetimeMs ?? APPROVE_TAP_MAX_NONCE_LIFETIME_MS;
  if (!Number.isInteger(lifetimeMs) || lifetimeMs < APPROVE_TAP_MIN_NONCE_LIFETIME_MS
    || lifetimeMs > APPROVE_TAP_MAX_NONCE_LIFETIME_MS) {
    return { ok: false, reason: 'bad-lifetime', message: 'A tap button may live between 30 seconds and 10 minutes.' };
  }
  const row = lookupRetryRow({ actionId }, { home: opts.home, now });
  if (!row || !row.actionIds.includes(actionId)) {
    return { ok: false, reason: 'not-found', message: `No headless denial ${actionId} is on file.` };
  }
  const terminalOnly = tapTerminalOnlyReason(row.signals);
  if (terminalOnly) {
    return { ok: false, reason: 'terminal-only', terminalOnly, message: describeTerminalOnly(terminalOnly) };
  }
  if (!row.originScope?.cwd) {
    return { ok: false, reason: 'unscopeable', message: 'This denial has no recorded directory, so a tap cannot scope a retry.' };
  }
  if (suppressionIsLive(row, now)) {
    return { ok: false, reason: 'suppressed', message: 'You denied this action; it is silenced, so no tap button is offered.' };
  }

  const nonce = randomBytes(16).toString('hex');
  const exp = now + lifetimeMs;
  const lock = acquireNonceLock(opts.home);
  if (!lock) return { ok: false, reason: 'locked', message: 'The tap store is busy; no button was minted.' };
  try {
    const file = readNonces(opts.home);
    file.nonces = file.nonces.filter((n) => n.exp > now);
    if (file.nonces.length >= MAX_LIVE_TAP_NONCES) {
      return { ok: false, reason: 'too-many', message: 'Too many tap buttons are outstanding; no new one was minted.' };
    }
    file.nonces.push({
      id: nonceId(nonce), actionId, argsHash: row.hash, rowId: row.id, epoch: row.denyEpoch, mintedAt: now, exp,
    });
    if (!stillHeld(lock) || !writeNonces(file, opts.home)) {
      return { ok: false, reason: 'unwritable', message: 'The tap store could not be written; no button was minted.' };
    }
  } finally {
    releaseNonceLock(lock);
  }
  return { ok: true, actionId, nonce, argsHash: row.hash, exp, mintedAt: now };
}

// ── Verify ────────────────────────────────────────────────────────────────

export interface ApproveTapRequest {
  actionId: string;
  argsHash: string;
  nonce: string;
  exp: number;
  approver: string;
  hmac: string;
}

export type TapRefusal =
  | 'malformed' | 'not-armed' | 'bad-hmac' | 'wrong-approver' | 'expired' | 'unknown-nonce'
  | 'nonce-used' | 'nonce-mismatch' | 'nonce-too-long-lived' | 'args-mismatch' | 'unknown-action'
  | 'terminal-only' | 'locked' | 'unwritable' | 'grant-refused' | 'grant-refused-unspent';

export type TapVerifyOutcome =
  | { ok: true; message: string; actionId: string; approver: string; grant: RetryGrant; row: RetryRow }
  | { ok: false; reason: TapRefusal; message: string; detail?: string };

export interface TapVerifyOptions extends TapStoreOptions, TapArmingDeps {
  config: ApproveTapConfig;
  /** The approve secret's bytes, from `loadApproveTapSecret`. */
  key: Buffer;
  /** Spend window for the grant. Default: the #310 default (10 minutes). */
  grantTtlMs?: number;
}

const REQUEST_KEYS = ['actionId', 'approver', 'argsHash', 'exp', 'hmac', 'nonce'];

/** Strict shape: exactly the six keys, each in canonical form. */
export function parseApproveTapRequest(raw: unknown): ApproveTapRequest | null {
  if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return null;
  const r = raw as Record<string, unknown>;
  const keys = Object.keys(r).sort();
  if (keys.length !== REQUEST_KEYS.length || keys.some((k, i) => k !== REQUEST_KEYS[i])) return null;
  const req = r as unknown as ApproveTapRequest;
  if (!fieldsAreCanonical(req)) return null;
  if (typeof req.hmac !== 'string' || !HEX64_RE.test(req.hmac)) return null;
  return { actionId: req.actionId, argsHash: req.argsHash, nonce: req.nonce, exp: req.exp, approver: req.approver, hmac: req.hmac };
}

const REFUSAL_COPY: Record<TapRefusal, string> = {
  'malformed': 'The tap request was not in the expected form. Nothing was approved.',
  'not-armed': 'One-tap approve is not armed on this machine. Nothing was approved.',
  'bad-hmac': 'The tap was not signed with this machine\'s approve secret. Nothing was approved.',
  'wrong-approver': 'This tap did not come from the configured approver. Nothing was approved.',
  'expired': 'This button has expired (buttons last at most 10 minutes). Nothing was approved; use the terminal command.',
  'unknown-nonce': 'This button is not one this machine issued, or it has expired. Nothing was approved.',
  'nonce-used': 'This button has already been used. Nothing new was approved.',
  'nonce-mismatch': 'This button does not belong to that action. Nothing was approved.',
  'nonce-too-long-lived': 'This button claims a lifetime over 10 minutes, so it is refused. Nothing was approved.',
  'args-mismatch': 'The action has changed since the button was issued. Nothing was approved.',
  'unknown-action': 'That denial is no longer on file. Nothing was approved.',
  'terminal-only': 'This action can only be approved from a terminal on that machine. Nothing was approved.',
  'locked': 'The approvals store is busy; try the button again in a moment. Nothing was approved.',
  'unwritable': 'The approvals store could not be written. Nothing was approved.',
  'grant-refused': 'The retry could not be authorised. The button is now spent; use the terminal command if you still want it.',
  'grant-refused-unspent': 'The retry could not be authorised. Nothing was approved.',
};

function refusal(reason: TapRefusal, detail?: string): TapVerifyOutcome {
  return { ok: false, reason, message: detail ? `${REFUSAL_COPY[reason]} ${detail}` : REFUSAL_COPY[reason], ...(detail ? { detail } : {}) };
}

const GRANT_REFUSAL_DETAIL: Partial<Record<string, string>> = {
  'suppressed': 'You denied this action after the button was sent, and your Deny stands.',
  'epoch-stale': 'You denied this action after the button was sent, and your Deny stands.',
  'grant-live': 'A retry for this action is already authorised and not yet used.',
  'card-live': 'Another approval card for this action is still open; answer that one.',
  'unscopeable': 'This denial has no recorded directory, so a retry cannot be scoped.',
  'hash-mismatch': 'The action has changed since the button was issued.',
  'not-found': 'That denial is no longer on file.',
};

/**
 * Verify one tap and, only if every check passes, write the retry grant.
 * `authenticateApproveTap` (needs the key) then `applyAuthenticatedTap` (does
 * not). The endpoint runs the two in different processes; see
 * src/cli/approve-tap.ts.
 *
 * Order (each step refuses with a plain-English reason):
 *   1. shape — exactly six canonical fields;
 *   2. armed — same check as doctor/mint (same-UID, mode, approver set);
 *   3. HMAC — constant-time, over the canonical v1 message, approve secret;
 *   4. approver — equals `telegram:<configured uid>`; exp not yet passed;
 *   5. under the nonce lock: the nonce exists for this action, is unused,
 *      its stored and presented exp agree, exp - mint <= 10 min, not expired;
 *   6. argsHash equals both the nonce's and the denial's exact hash;
 *   7. the denial is not catastrophic / self-protection-floor / unscanned,
 *      and the grant store would take it (no Deny since the card went out,
 *      no retry already authorised, no other card open) — read-only;
 *   8. consume the nonce (written), then `grantRetry` with `auth.tap`.
 * Steps 1–7 write nothing. Only a change that lands between step 7 and the
 * grant's own lock (a Deny in that instant) can refuse after the nonce is
 * spent; a busy or unwritable retry store un-spends it.
 */
export function verifyApproveTap(raw: unknown, opts: TapVerifyOptions): TapVerifyOutcome {
  const auth = authenticateApproveTap(raw, opts);
  if (!auth.ok) return auth.refusal;
  return applyAuthenticatedTap(auth.request, opts);
}

export type TapAuthentication =
  | { ok: true; request: ApproveTapRequest }
  | { ok: false; refusal: Extract<TapVerifyOutcome, { ok: false }> };

/** Steps 1–4. Pure: reads the secret's metadata (arming) and nothing else. */
export function authenticateApproveTap(
  raw: unknown,
  opts: Omit<TapVerifyOptions, 'home' | 'grantTtlMs'>,
): TapAuthentication {
  const fail = (r: TapVerifyOutcome): TapAuthentication => ({ ok: false, refusal: r as Extract<TapVerifyOutcome, { ok: false }> });
  const now = opts.now ?? Date.now();
  const req = parseApproveTapRequest(raw);
  if (!req) return fail(refusal('malformed'));

  const arming = checkApproveTapArming(opts.config, opts);
  if (!arming.armed) return fail(refusal('not-armed', arming.message));
  if (!Buffer.isBuffer(opts.key) || opts.key.length < SECRET_MIN_CHARS) return fail(refusal('not-armed'));

  const expected = computeTapHmac(opts.key, req);
  if (expected === null || !hexEqualConstantTime(expected, req.hmac)) return fail(refusal('bad-hmac'));

  if (req.approver !== `telegram:${opts.config.approverTelegramUid}`) return fail(refusal('wrong-approver'));
  if (req.exp <= now) return fail(refusal('expired'));
  return { ok: true, request: req };
}

function grantIsLiveAt(grant: RetryGrant | undefined, now: number): boolean {
  return !!grant && !grant.consumedAt && now - grant.approvedAt < grant.ttlMs;
}

/**
 * Steps 5–8 for a request `authenticateApproveTap` has ALREADY accepted. It
 * holds no key and checks no MAC, so it must only ever be handed such a
 * request — in the endpoint it runs in a keyless child as the agent's user.
 * (A process of that user can write the grant store directly anyway; this
 * adds nothing it could not already do.)
 */
export function applyAuthenticatedTap(
  request: ApproveTapRequest,
  opts: TapStoreOptions & { grantTtlMs?: number },
): TapVerifyOutcome {
  const now = opts.now ?? Date.now();
  const req = parseApproveTapRequest(request);
  if (!req) return refusal('malformed');
  if (req.exp <= now) return refusal('expired');

  const lock = acquireNonceLock(opts.home);
  if (!lock) return refusal('locked');
  try {
    const file = readNonces(opts.home);
    const id = nonceId(req.nonce);
    const rec = file.nonces.find((n) => n.id === id);
    if (!rec) return refusal('unknown-nonce');
    if (rec.actionId !== req.actionId) return refusal('nonce-mismatch');
    if (rec.usedAt !== undefined) return refusal('nonce-used');
    if (rec.exp !== req.exp) return refusal('nonce-mismatch');
    const lifetime = rec.exp - rec.mintedAt;
    if (!(lifetime > 0) || lifetime > APPROVE_TAP_MAX_NONCE_LIFETIME_MS) return refusal('nonce-too-long-lived');
    if (rec.mintedAt > now + MINT_CLOCK_SKEW_MS) return refusal('nonce-mismatch');
    if (now >= rec.exp) return refusal('expired');
    if (rec.argsHash !== req.argsHash) return refusal('args-mismatch');

    const row = lookupRetryRow({ actionId: req.actionId }, { home: opts.home, now });
    if (!row || row.id !== rec.rowId || !row.actionIds.includes(req.actionId)) return refusal('unknown-action');
    if (row.hash !== req.argsHash) return refusal('args-mismatch');
    const terminalOnly = tapTerminalOnlyReason(row.signals);
    if (terminalOnly) return refusal('terminal-only', describeTerminalOnly(terminalOnly));
    // Read-only previews of what grantRetry would refuse, so that the
    // ordinary refusals spend nothing.
    if (suppressionIsLive(row, now) || row.denyEpoch !== rec.epoch) {
      return refusal('grant-refused-unspent', GRANT_REFUSAL_DETAIL.suppressed);
    }
    if (grantIsLiveAt(row.grant, now)) return refusal('grant-refused-unspent', GRANT_REFUSAL_DETAIL['grant-live']);
    if (row.claim && row.claim.expiresAt > now && !row.claim.grantedAt) {
      return refusal('grant-refused-unspent', GRANT_REFUSAL_DETAIL['card-live']);
    }
    if (!row.originScope?.cwd) return refusal('grant-refused-unspent', GRANT_REFUSAL_DETAIL.unscopeable);

    // Spend the nonce BEFORE the grant: a crash between the two leaves a
    // spent nonce and no grant (fail closed), never a grant and a live nonce.
    rec.usedAt = now;
    if (!stillHeld(lock) || !writeNonces(file, opts.home)) return refusal('unwritable');

    const granted = grantRetry(
      { id: row.id },
      { tap: { approver: req.approver, hash: req.argsHash, epoch: rec.epoch } },
      { home: opts.home, now, ttlMs: opts.grantTtlMs ?? DEFAULT_RETRY_GRANT_TTL_MS },
    );
    if (!granted.ok) {
      if (granted.reason === 'locked' || granted.reason === 'unwritable') {
        // No decision was taken and no grant was written: un-spend the nonce
        // (we still hold its lock) so the operator can tap again.
        delete rec.usedAt;
        if (stillHeld(lock)) writeNonces(file, opts.home);
        return refusal(granted.reason === 'locked' ? 'locked' : 'unwritable');
      }
      return refusal('grant-refused', GRANT_REFUSAL_DETAIL[granted.reason]);
    }
    const minutes = Math.max(1, Math.round(granted.grant.ttlMs / 60_000));
    return {
      ok: true,
      actionId: req.actionId,
      approver: req.approver,
      grant: granted.grant,
      row: granted.row,
      message: `Approved ONE retry of ${row.tool} (${req.actionId}) for the next ${minutes} minute(s), `
        + 'in the same directory. It is spent by the first matching call.',
    };
  } finally {
    releaseNonceLock(lock);
  }
}

// ── HTTP (loopback only) ──────────────────────────────────────────────────

/** 127.0.0.0/8, ::1 and their IPv4-mapped form. Nothing else. */
export function isLoopbackAddress(addr: string | undefined): boolean {
  if (typeof addr !== 'string') return false;
  if (addr === '::1') return true;
  const v4 = addr.startsWith('::ffff:') ? addr.slice(7) : addr;
  return /^127\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(v4);
}

/** What the HTTP layer needs from a verifier; a `TapVerifyOutcome` is one. */
export type TapHandlerAnswer =
  | { ok: true; message: string; approver: string }
  | { ok: false; reason: string; message: string };

export interface TapHandlerDeps {
  verify: (body: unknown) => TapHandlerAnswer;
  /** One line per request. Never receives the secret, the nonce or the HMAC. */
  log?: (line: string) => void;
}

function send(res: ServerResponse, status: number, body: Record<string, unknown>): void {
  const text = JSON.stringify(body);
  res.writeHead(status, {
    'content-type': 'application/json; charset=utf-8',
    'cache-control': 'no-store',
    'content-length': Buffer.byteLength(text),
  });
  res.end(text);
}

const STATUS_FOR: Partial<Record<string, number>> = {
  'malformed': 400,
  'not-armed': 503,
  'locked': 503,
  'unwritable': 503,
};

/**
 * The `POST /approve-tap` request handler. Refuses anything that is not a
 * loopback peer, not exactly that method and path, carries a browser
 * `Origin`, is not `application/json`, or is over 4 KiB — before reading a
 * byte of it. Responses never echo the request.
 */
export function createApproveTapHandler(deps: TapHandlerDeps): (req: IncomingMessage, res: ServerResponse) => void {
  const log = deps.log ?? (() => {});
  return (req, res) => {
    if (!isLoopbackAddress(req.socket?.remoteAddress)) {
      log('approve-tap: refused a non-loopback peer');
      send(res, 403, { ok: false, reason: 'loopback-only', message: 'This endpoint answers loopback callers only.' });
      req.destroy();
      return;
    }
    if (req.url !== APPROVE_TAP_PATH) {
      send(res, 404, { ok: false, reason: 'not-found', message: 'Not found.' });
      return;
    }
    if (req.method !== 'POST') {
      res.setHeader('allow', 'POST');
      send(res, 405, { ok: false, reason: 'method', message: 'Use POST.' });
      return;
    }
    // A browser on this box must not be able to reach this endpoint (DNS
    // rebinding / simple-request CSRF): browsers always send Origin on POST,
    // and a JSON content type forces a preflight we never answer.
    if (req.headers.origin !== undefined) {
      send(res, 403, { ok: false, reason: 'browser', message: 'Browser requests are refused.' });
      return;
    }
    const ctype = String(req.headers['content-type'] ?? '').split(';')[0].trim().toLowerCase();
    if (ctype !== 'application/json') {
      send(res, 415, { ok: false, reason: 'content-type', message: 'Send application/json.' });
      return;
    }
    const declared = Number(req.headers['content-length'] ?? '0');
    if (Number.isFinite(declared) && declared > MAX_TAP_BODY_BYTES) {
      send(res, 413, { ok: false, reason: 'too-large', message: 'Request too large.' });
      req.destroy();
      return;
    }
    const chunks: Buffer[] = [];
    let size = 0;
    let done = false;
    req.on('data', (chunk: Buffer) => {
      if (done) return;
      size += chunk.length;
      if (size > MAX_TAP_BODY_BYTES) {
        done = true;
        send(res, 413, { ok: false, reason: 'too-large', message: 'Request too large.' });
        req.destroy();
        return;
      }
      chunks.push(chunk);
    });
    req.on('end', () => {
      if (done) return;
      done = true;
      let body: unknown;
      try {
        body = JSON.parse(Buffer.concat(chunks).toString('utf8'));
      } catch {
        log('approve-tap: refused (malformed)');
        send(res, 400, { ok: false, reason: 'malformed', message: REFUSAL_COPY.malformed });
        return;
      }
      let outcome: TapHandlerAnswer;
      try {
        outcome = deps.verify(body);
      } catch {
        outcome = { ok: false, reason: 'unwritable', message: REFUSAL_COPY.unwritable };
      }
      // The action id is logged only once it is known to be canonical.
      const parsed = parseApproveTapRequest(body);
      const idTag = parsed ? ` ${parsed.actionId}` : '';
      if (outcome.ok) {
        log(`approve-tap: granted ONE retry${idTag} for ${outcome.approver}`);
        send(res, 200, { ok: true, message: outcome.message });
      } else {
        log(`approve-tap: refused${idTag} (${outcome.reason})`);
        send(res, STATUS_FOR[outcome.reason] ?? 403, { ok: false, reason: outcome.reason, message: outcome.message });
      }
    });
    req.on('error', () => {
      done = true;
    });
  };
}

// ── doctor ────────────────────────────────────────────────────────────────

export interface TapDoctorRow {
  status: 'warn' | 'info';
  message: string;
  fix?: string;
}

/**
 * The one doctor line for one-tap approve. Silent (null) unless the operator
 * turned it on: an install that never asked for taps hears nothing. When it
 * is on, the line is WARN when the tap path cannot arm (same-UID secret and
 * the rest, in plain English) and INFO when it can. Never FAIL — the terminal
 * approve still works, so a tap path that cannot arm is a missing convenience,
 * not a broken guard — and it writes nothing.
 */
export function approveTapDoctorRow(raw: unknown, deps: TapArmingDeps = {}): TapDoctorRow | null {
  const config = normaliseApproveTapConfig(raw);
  if (!config.enabled) return null;
  const arming = checkApproveTapArming(config, deps);
  if (arming.armed) {
    return {
      status: 'info',
      message: `${arming.message} The endpoint is \`shieldcortex guard approve-tap\` (loopback only); `
        + 'catastrophic and self-protection actions still need the terminal.',
    };
  }
  const fix = arming.reason === 'same-uid' || arming.reason === 'agent-is-root'
    ? 'Give the approve secret to the notify bridge\'s own user (chown <bridge-user> <path>; chmod 600 <path>) and run '
      + 'the agent as a different user, or use the #501 OS lock (`sudo shieldcortex protect`) and approve from a '
      + 'terminal: `shieldcortex approve --denial <actionId>`.'
    : arming.reason === 'secret-mode'
      ? 'chmod 600 the approve secret.'
      : undefined;
  return { status: 'warn', message: arming.message, ...(fix ? { fix } : {}) };
}
