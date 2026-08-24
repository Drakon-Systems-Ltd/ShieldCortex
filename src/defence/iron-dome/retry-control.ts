/**
 * ShieldCortex — operator retry control for headless denials (#310).
 *
 * Design: docs/design/2026-08-19-310-retry-control.md (v3-final) +
 * docs/design/ADR-2026-08-19-retry-control.md.
 *
 * ## The one principle
 *
 * **Mint on operator intent, not on denial.** A `denied_no_prompt_surface`
 * (DNP) outcome stays terminal: the call was refused and handed back to the
 * agent. What a denial produces here is a FINGERPRINT — a claim ticket with
 * nothing spendable in it. Only a human act (a tap on an authenticated card,
 * or `shieldcortex approve --denial <actionId>` in a real terminal) turns a
 * fingerprint into a grant, and a grant is atomic, origin-scoped, one-shot
 * and time-boxed.
 *
 * Nothing here is reachable by an agent that merely imports this module:
 * `grantRetry` demands either the 256-bit `claimNonce` minted at card launch
 * (which lives only on the waiter's inherited fd, never on disk in the clear,
 * never in an alert) or a caller that has already proven a human is driving
 * (`isInteractive` in src/cli/approve.ts).
 *
 * ## One lock plane
 *
 * Fingerprints, deny suppression, launch claims, the card budget, grants and
 * grant consumption all live in ONE file guarded by ONE lock
 * (`~/.shieldcortex/approvals/retry-control.json` + `.lock`). The #118
 * approvals store keeps its own last-writer-wins RMW and stays LIVE-HOLD
 * ONLY — this module never touches it, and the live-hold path never touches
 * this one. That split is why #118/#143 behaviour is byte-identical with
 * retry cards on or off.
 *
 * The lock is a lock DIRECTORY (`mkdir` is atomic on every filesystem this
 * ships to; Node exposes no `flock(2)`), with a bounded spin and a stale
 * takeover. Failing to take it is failing CLOSED: every mutating entry point
 * returns `{ ok: false, reason: 'locked' }`, which mints nothing, grants
 * nothing and spends nothing.
 *
 * ## Deny epochs
 *
 * `denyEpoch` advances ONLY on an operator deny, on a launch claim expiring
 * unanswered, or on an explicit clear. It does NOT advance on a remint: a
 * cron job that keeps flapping refreshes `lastDeniedAt` and nothing else, so
 * the card the operator is looking at stays valid for its whole lifetime
 * (v2's per-DNP generation bump broke exactly the case this feature exists
 * for). A live claim pins the epoch; a tap authorises the retry the card was
 * drawn for.
 *
 * ## What is NOT here
 *
 * No `allow-always`. No `reviewedScripts` minting or spending. No path for
 * the catastrophic tier (it hard-blocks long before any DNP exists). No
 * interceptor wiring — the OpenClaw-native unattended path is out of this
 * phase by ADR, for cards AND for consume.
 */

import { createHash, createHmac, randomBytes, timingSafeEqual } from 'node:crypto';
import {
  existsSync,
  mkdirSync,
  readFileSync,
  realpathSync,
  renameSync,
  rmSync,
  rmdirSync,
  statSync,
  writeFileSync,
} from 'node:fs';
import { homedir } from 'node:os';
import { isAbsolute, join, resolve as resolvePath } from 'node:path';

import { mkdirSecure } from '../../setup/state-permissions.js';
import { DEFAULT_DNP_DIGEST_WINDOW_MS } from './dnp-digest.js';

/** The hash every fingerprint, card and grant is bound to is the SAME #118
 *  canonical tool-call hash — re-exported so callers (the hook, the CLI) have
 *  exactly one implementation to reach for. */
export { hashToolCall } from './action-approvals.js';

// ── Clocks (design B6, "budgets and clocks, named and aligned") ────────────

/** Card lifetime — the OpenClaw gateway's own ceiling for a plugin approval. */
export const RETRY_CARD_LIFETIME_MS = 10 * 60 * 1000;
/** Default spend window for a granted retry, from the moment of the tap. */
export const DEFAULT_RETRY_GRANT_TTL_MS = 10 * 60 * 1000;
export const MIN_RETRY_GRANT_TTL_MS = 60 * 1000;
export const MAX_RETRY_GRANT_TTL_MS = 60 * 60 * 1000;
/** Deny suppression — windowed SILENCE, never "permanent". Defaults to the
 *  digest window so "deny" and "stop paging me" cover the same span. */
export const MIN_DENY_SUPPRESSION_MS = 60 * 1000;
export const MAX_DENY_SUPPRESSION_MS = 24 * 60 * 60 * 1000;
/** Fingerprint retention: the #118 pending-retention clock, rolling from the
 *  last DNP for that identity. */
export const RETRY_FINGERPRINT_RETENTION_MS = 60 * 60 * 1000;
/** Audit tail kept after a grant goes terminal (spent or expired). */
export const RETRY_GRANT_AUDIT_TAIL_MS = 24 * 60 * 60 * 1000;

/** Per-identity live cards. One epoch-pinned claim, never a second. */
export const CARD_BUDGET_PER_IDENTITY = 1;
/** Global cards per budget window. The window START is the digest window's,
 *  read by the caller in the same handler (R3 rule 7). */
export const CARD_BUDGET_PER_WINDOW = 3;
/** How many "this denial got no card" ids the operator copy carries. */
const MAX_LOST_ACTION_IDS = 10;
const MAX_ACTION_ID_ALIASES = 10;

// ── Shapes ────────────────────────────────────────────────────────────────

export interface RetryOriginScope {
  /** Canonicalised cwd (realpath, no trailing separator). Absent ⇒ the row is
   *  UNSCOPEABLE and can never be granted from a card. */
  cwd?: string;
  /** Diagnostic telemetry ONLY. Never AND-matched on spend (R3 rule 3): the
   *  next cron tick spawns a new Claude session with a fresh sessionKey, and
   *  fail-closing on that would break the primary use case. */
  sessionKey?: string;
}

export interface RetryClaim {
  /** HMAC of the launch nonce. The raw nonce is NEVER written here (R3 rule 4). */
  nonceHmac: string;
  epoch: number;
  claimedAt: number;
  expiresAt: number;
  actionId?: string;
  /** Set when this claim was converted into a grant. The claim is KEPT (not
   *  deleted) so a double tap from the same card still authenticates and is
   *  answered idempotently — and so a tap arriving after that grant was spent
   *  or expired is refused as `claim-spent` rather than silently minting a
   *  second grant from one ticket. */
  grantedAt?: number;
}

export interface RetryGrant {
  grantKind: 'retry';
  /** ALWAYS set. There is deliberately no recordPending-then-approve shape
   *  here — grant is ONE locked write. */
  approvedAt: number;
  ttlMs: number;
  epoch: number;
  via: 'card' | 'tty';
  /** The spend predicate: `{cwd, tool}` AND-matched (R3 rule 3). */
  origin: { cwd?: string; tool: string; anyOrigin?: boolean };
  consumedAt?: number;
  /** Set when the unspent-expiry sweeper has already told the operator. */
  expiryNotifiedAt?: number;
}

export interface RetrySuppression {
  at: number;
  until: number;
  via: 'card' | 'tty';
}

export interface RetryRow {
  /** Canonical identity: sha256(hash, canonical cwd). Rows upsert by
   *  (hash, originScope); `actionIds` is the secondary alias index, so one
   *  identity never splits its epoch across the actionIds of its remints. */
  id: string;
  hash: string;
  tool: string;
  denyEpoch: number;
  deniedAt: number;
  lastDeniedAt: number;
  originScope: RetryOriginScope;
  signals: string[];
  redactedSurface: string;
  actionIds: string[];
  suppression?: RetrySuppression;
  claim?: RetryClaim;
  grant?: RetryGrant;
}

export interface RetryCardBudget {
  windowStartMs: number;
  windowMs: number;
  cards: number;
  lostActionIds: string[];
}

interface RetryControlFile {
  version: 1;
  rows: RetryRow[];
  budget: RetryCardBudget | null;
}

export interface RetryStoreOptions {
  home?: string;
  now?: number;
}

/** One "your grant expired without being used" item for the operator copy. */
export interface ExpiredGrantNotice {
  actionId?: string;
  tool: string;
  shortHash: string;
  approvedAt: number;
  ttlMs: number;
}

// ── Config (normaliseNotifyConfig discipline: allowlist, bound, drop junk) ──

export interface RetryControlConfig {
  /** Master switch. FALSE unless the config says exactly `true` — this whole
   *  feature ships dark behind it (ADR rollout gate). */
  retryCards: boolean;
  retryGrantTtlMs: number;
  denySuppressionMs: number;
}

function boundedNumber(v: unknown, min: number, max: number): number | undefined {
  if (typeof v !== 'number' || !Number.isFinite(v)) return undefined;
  if (v < min || v > max) return undefined;
  return Math.floor(v);
}

/**
 * Total: every input, including junk, yields a usable config and never
 * throws. `retryCards` is strict-true only (a "true" string or a 1 must not
 * arm a new trust surface), and the two clocks fall back to their defaults
 * rather than being clamped to the nearest value we happen to understand.
 *
 * `denySuppressionMs` defaults to the DIGEST window, so "deny" silences an
 * action for exactly as long as the digest would have coalesced it — the
 * honest reading of "deny silences this action for N minutes".
 */
export function normaliseRetryControlConfig(
  raw: unknown,
  opts: { digestWindowMs?: number } = {},
): RetryControlConfig {
  const digestWindow =
    boundedNumber(opts.digestWindowMs, MIN_DENY_SUPPRESSION_MS, MAX_DENY_SUPPRESSION_MS)
    ?? DEFAULT_DNP_DIGEST_WINDOW_MS;
  const block =
    raw && typeof raw === 'object' && !Array.isArray(raw) ? (raw as Record<string, unknown>) : {};
  return {
    retryCards: block.retryCards === true,
    retryGrantTtlMs:
      boundedNumber(block.retryGrantTtlMs, MIN_RETRY_GRANT_TTL_MS, MAX_RETRY_GRANT_TTL_MS)
      ?? DEFAULT_RETRY_GRANT_TTL_MS,
    denySuppressionMs:
      boundedNumber(block.denySuppressionMs, MIN_DENY_SUPPRESSION_MS, MAX_DENY_SUPPRESSION_MS)
      ?? digestWindow,
  };
}

// ── Paths, identity, canonicalisation ─────────────────────────────────────

/** Beside the #118 approvals file: same directory, same 0700/0600 posture
 *  (`approvals` is already in SECURE_SUBDIRS), different file and lock. */
export function retryControlDir(home?: string): string {
  return join(home ?? homedir(), '.shieldcortex', 'approvals');
}

export function retryControlPath(home?: string): string {
  return join(retryControlDir(home), 'retry-control.json');
}

function retryLockPath(home?: string): string {
  return join(retryControlDir(home), 'retry-control.lock');
}

function retryKeyPath(home?: string): string {
  return join(retryControlDir(home), 'retry-control.key');
}

/**
 * The origin's cwd, canonicalised once so a match is a match: realpath
 * (symlinked worktrees, /tmp → /private/tmp on macOS) then trailing
 * separators stripped (R3 rule 3). A relative or unusable value yields
 * `undefined`, which reads downstream as UNSCOPEABLE — never as "matches
 * everything".
 */
export function canonicaliseCwd(raw: unknown): string | undefined {
  if (typeof raw !== 'string') return undefined;
  const trimmed = raw.trim();
  if (!trimmed || trimmed.length > 4096) return undefined;
  if (!isAbsolute(trimmed)) return undefined;
  let out: string;
  try {
    out = realpathSync(trimmed);
  } catch {
    out = resolvePath(trimmed);
  }
  const stripped = out.replace(/[/\\]+$/, '');
  return stripped.length > 0 ? stripped : '/';
}

/** Canonical row identity — (hash, originScope). */
export function fingerprintId(hash: string, cwd?: string): string {
  return createHash('sha256').update(`${String(hash)}\u0000${cwd ?? ''}`).digest('hex').slice(0, 32);
}

function shortHashOf(hash: string): string {
  return String(hash).slice(0, 12);
}

// ── HMAC key for claim nonces at rest ─────────────────────────────────────

/**
 * The key that turns a launch nonce into the `nonceHmac` the store keeps.
 * Created 0600 on first use, inside the already-0700 approvals dir. Null
 * means "no key", and no key means no card claims and no card grants — the
 * fail-closed direction.
 */
function retryHmacKey(home?: string): string | null {
  const p = retryKeyPath(home);
  try {
    const existing = readFileSync(p, 'utf8').trim();
    if (/^[0-9a-f]{64}$/i.test(existing)) return existing.toLowerCase();
  } catch {
    /* create below */
  }
  try {
    mkdirSecure(retryControlDir(home));
    const key = randomBytes(32).toString('hex');
    try {
      writeFileSync(p, `${key}\n`, { mode: 0o600, flag: 'wx' });
      return key;
    } catch {
      // Another process won wx. A same-tick read can still see an empty
      // or partial file on some hosts (macOS CI after #399); retry briefly
      // then fail closed — no key means no card claim.
      for (let attempt = 0; attempt < HMAC_KEY_REREAD_ATTEMPTS; attempt += 1) {
        try {
          const raced = readFileSync(p, 'utf8').trim();
          if (/^[0-9a-f]{64}$/i.test(raced)) return raced.toLowerCase();
        } catch {
          /* still missing */
        }
        sleepSync(HMAC_KEY_REREAD_SLEEP_MS);
      }
      return null;
    }
  } catch {
    return null;
  }
}

function hmacNonce(nonce: string, home?: string): string | null {
  const key = retryHmacKey(home);
  if (!key) return null;
  return createHmac('sha256', Buffer.from(key, 'hex')).update(`retry-claim:${nonce}`).digest('hex');
}

function constantTimeEquals(a: string, b: string): boolean {
  const left = Buffer.from(String(a));
  const right = Buffer.from(String(b));
  if (left.length !== right.length) return false;
  return timingSafeEqual(left, right);
}

// ── The lock plane ────────────────────────────────────────────────────────

const LOCK_ATTEMPTS = 60;
const LOCK_SLEEP_MS = 20;
/** After losing exclusive key create, how long we wait to observe the winner's 64-hex write (~40ms). */
const HMAC_KEY_REREAD_ATTEMPTS = 8;
const HMAC_KEY_REREAD_SLEEP_MS = 5;
/** A lock older than this is presumed abandoned (the holder is a one-shot
 *  hook process; every operation here is milliseconds of file IO). */
const LOCK_STALE_MS = 10_000;

function sleepSync(ms: number): void {
  try {
    Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, ms);
    return;
  } catch {
    /* SharedArrayBuffer / Atomics.wait unavailable — wall-clock wait */
  }
  const until = Date.now() + ms;
  while (Date.now() < until) {
    /* bounded spin so lock retries actually back off */
  }
}

function acquireLock(home?: string): string | null {
  const p = retryLockPath(home);
  try {
    mkdirSecure(retryControlDir(home));
  } catch {
    return null;
  }
  for (let attempt = 0; attempt < LOCK_ATTEMPTS; attempt += 1) {
    try {
      // Not `recursive` — that would succeed on an existing directory and
      // hand two processes the same "exclusive" lock.
      mkdirSync(p, { mode: 0o700 });
      try {
        writeFileSync(join(p, 'owner'), JSON.stringify({ pid: process.pid, at: Date.now() }), {
          mode: 0o600,
        });
      } catch {
        /* the directory IS the lock; the owner note is a breadcrumb */
      }
      return p;
    } catch (err) {
      if ((err as NodeJS.ErrnoException)?.code !== 'EEXIST') return null;
      try {
        const st = statSync(p);
        if (Date.now() - st.mtimeMs > LOCK_STALE_MS) {
          try { rmSync(join(p, 'owner'), { force: true }); } catch { /* ignore */ }
          try { rmdirSync(p); } catch { /* someone else got there first */ }
          continue;
        }
      } catch {
        continue; // vanished between EEXIST and stat — retry immediately
      }
      sleepSync(LOCK_SLEEP_MS);
    }
  }
  return null;
}

function releaseLock(p: string | null): void {
  if (!p) return;
  try { rmSync(join(p, 'owner'), { force: true }); } catch { /* ignore */ }
  try { rmdirSync(p); } catch { /* ignore */ }
}

function readStore(home?: string): RetryControlFile {
  try {
    const p = retryControlPath(home);
    if (!existsSync(p)) return { version: 1, rows: [], budget: null };
    const parsed = JSON.parse(readFileSync(p, 'utf8')) as Partial<RetryControlFile>;
    if (!parsed || !Array.isArray(parsed.rows)) return { version: 1, rows: [], budget: null };
    const rawBudget = parsed.budget as RetryCardBudget | null | undefined;
    const budget: RetryCardBudget | null =
      rawBudget && typeof rawBudget === 'object'
        ? {
            windowStartMs: Number(rawBudget.windowStartMs) || 0,
            windowMs: Number(rawBudget.windowMs) || 0,
            cards: Number(rawBudget.cards) || 0,
            lostActionIds: Array.isArray(rawBudget.lostActionIds)
              ? rawBudget.lostActionIds.map(String).slice(-MAX_LOST_ACTION_IDS)
              : [],
          }
        : null;
    return { version: 1, rows: parsed.rows.filter(isUsableRow), budget };
  } catch {
    // A corrupt store must never revive a stale card: it reads as EMPTY, so
    // there is no claim record, `grantRetry` fails its claimNonce check first,
    // and every consume finds nothing. Fail CLOSED — the only direction that
    // exists here.
    return { version: 1, rows: [], budget: null };
  }
}

function isUsableRow(row: unknown): row is RetryRow {
  if (!row || typeof row !== 'object') return false;
  const r = row as Partial<RetryRow>;
  return typeof r.id === 'string'
    && typeof r.hash === 'string'
    && typeof r.denyEpoch === 'number'
    && typeof r.lastDeniedAt === 'number'
    && Array.isArray(r.actionIds);
}

function writeStore(file: RetryControlFile, home?: string): boolean {
  try {
    mkdirSecure(retryControlDir(home));
    const target = retryControlPath(home);
    const tmp = `${target}.${process.pid}.tmp`;
    writeFileSync(tmp, `${JSON.stringify(file, null, 2)}\n`, { mode: 0o600 });
    renameSync(tmp, target);
    return true;
  } catch {
    return false;
  }
}

type LockedResult<T> = { ok: true; value: T } | { ok: false; reason: 'locked' | 'unwritable' };

/** Read-modify-write under the one lock. */
function withLock<T>(
  home: string | undefined,
  mutate: (file: RetryControlFile) => { value: T; commit: boolean },
): LockedResult<T> {
  const lock = acquireLock(home);
  if (!lock) return { ok: false, reason: 'locked' };
  try {
    const file = readStore(home);
    const { value, commit } = mutate(file);
    if (commit && !writeStore(file, home)) return { ok: false, reason: 'unwritable' };
    return { ok: true, value };
  } catch {
    return { ok: false, reason: 'unwritable' };
  } finally {
    releaseLock(lock);
  }
}

// ── Prune (R3 rule 1 — precedence) ────────────────────────────────────────

// Deliberately NOT type predicates: `x && !isLive(x)` would narrow `x` to
// `never` in the branch that has the most work to do (prune), and the
// resulting non-null assertions read worse than a plain boolean does.
function grantIsLive(grant: RetryGrant | undefined, now: number): boolean {
  return !!grant && !grant.consumedAt && now - grant.approvedAt < grant.ttlMs;
}

function claimIsLive(claim: RetryClaim | undefined, now: number): boolean {
  return !!claim && claim.expiresAt > now;
}

export function suppressionIsLive(row: RetryRow | undefined, now: number): boolean {
  return !!row?.suppression && row.suppression.until > now;
}

/**
 * Age the store. Precedence, in order, per R3 rule 1:
 *   1. A row with a LIVE claim or a LIVE unspent grant is never pruned — the
 *      fingerprint TTL yields to claim/grant terminality.
 *   2. A terminal grant (spent or expired) keeps a spend-TTL + 24h audit tail.
 *   3. A live suppression keeps its row — that is what makes deny stick.
 *   4. Otherwise the fingerprint prunes on the 60m rolling retention clock.
 * Rows that fall off are GONE: tap-after-prune finds nothing and is refused,
 * which is the intended answer, not a bug.
 *
 * Two side effects happen here and only here, so every entry point that takes
 * the lock gets them for free: a launch claim that expired unanswered advances
 * the deny epoch (a stale card can never be revalidated), and an unspent grant
 * that expired is reported ONCE for the operator copy.
 *
 * `report` is what makes "once" honest. Only callers that actually DELIVER the
 * notice (the DNP fingerprint write and the explicit sweeper) pass true; the
 * rest prune without claiming the notice, so a consume or a claim in between
 * cannot swallow the one telling the operator their grant went unused.
 */
function pruneInPlace(file: RetryControlFile, now: number, report = false): ExpiredGrantNotice[] {
  const notices: ExpiredGrantNotice[] = [];
  const kept: RetryRow[] = [];

  for (const row of file.rows) {
    if (row.claim && !claimIsLive(row.claim, now)) {
      // Claim expiry advances the epoch UNLESS the tap already landed as a
      // grant on that same epoch (in which case the claim simply retires).
      if (!row.grant || row.grant.epoch !== row.claim.epoch) row.denyEpoch += 1;
      delete row.claim;
    }
    if (row.suppression && row.suppression.until <= now) delete row.suppression;
    if (report && row.grant && !row.grant.consumedAt && now - row.grant.approvedAt >= row.grant.ttlMs) {
      if (!row.grant.expiryNotifiedAt) {
        row.grant.expiryNotifiedAt = now;
        notices.push({
          actionId: row.actionIds[row.actionIds.length - 1],
          tool: row.tool,
          shortHash: shortHashOf(row.hash),
          approvedAt: row.grant.approvedAt,
          ttlMs: row.grant.ttlMs,
        });
      }
    }

    if (claimIsLive(row.claim, now) || grantIsLive(row.grant, now)) {
      kept.push(row);
      continue;
    }
    if (row.grant) {
      if (now - row.grant.approvedAt < row.grant.ttlMs + RETRY_GRANT_AUDIT_TAIL_MS) kept.push(row);
      continue;
    }
    if (suppressionIsLive(row, now)) {
      kept.push(row);
      continue;
    }
    if (now - row.lastDeniedAt < RETRY_FINGERPRINT_RETENTION_MS) kept.push(row);
  }

  file.rows = kept;
  return notices;
}

// ── Lookup ────────────────────────────────────────────────────────────────

export interface RetryRowRef {
  /** Canonical identity (preferred). */
  id?: string;
  /** Secondary alias index — what `--denial` and the webhook copy carry. */
  actionId?: string;
  hash?: string;
  cwd?: string;
}

function findRow(rows: RetryRow[], ref: RetryRowRef): RetryRow | undefined {
  if (ref.id) {
    const byId = rows.find((r) => r.id === ref.id);
    if (byId) return byId;
  }
  if (ref.hash) {
    const cwd = ref.cwd === undefined ? undefined : canonicaliseCwd(ref.cwd);
    const wanted = fingerprintId(ref.hash, cwd);
    const byIdentity = rows.find((r) => r.id === wanted);
    if (byIdentity) return byIdentity;
  }
  if (ref.actionId) {
    const needle = String(ref.actionId).trim().toLowerCase();
    const matches = rows.filter((r) => r.actionIds.some((a) => a.toLowerCase() === needle));
    if (matches.length === 1) return matches[0];
    // Newest wins — the alias index exists so an operator can paste the id out
    // of the alert they are looking at.
    if (matches.length > 1) return [...matches].sort((a, b) => b.lastDeniedAt - a.lastDeniedAt)[0];
  }
  return undefined;
}

/** Read-only lookup for the CLI and for copy builders. */
export function getRetryRow(ref: RetryRowRef, opts: RetryStoreOptions = {}): RetryRow | undefined {
  return findRow(readStore(opts.home).rows, ref);
}

/** Everything still meaningful, newest denial first. Read-only. */
export function listRetryRows(opts: RetryStoreOptions = {}): RetryRow[] {
  const now = opts.now ?? Date.now();
  return readStore(opts.home).rows
    .filter((r) =>
      grantIsLive(r.grant, now)
      || claimIsLive(r.claim, now)
      || suppressionIsLive(r, now)
      || now - r.lastDeniedAt < RETRY_FINGERPRINT_RETENTION_MS)
    .sort((a, b) => b.lastDeniedAt - a.lastDeniedAt);
}

// ── 1. Fingerprint on denial ──────────────────────────────────────────────

export interface DenialFingerprintEntry {
  hash: string;
  tool: string;
  actionId?: string;
  signals?: string[];
  redactedSurface?: string;
  /** From the harness payload (same trust as sessionKey), NEVER from tool input. */
  cwd?: string;
  sessionKey?: string;
}

export interface DenialFingerprintResult {
  ok: boolean;
  reason?: 'locked' | 'unwritable';
  id?: string;
  row?: RetryRow;
  /** True when a live deny suppression covers this identity. The caller MUST
   *  order on this: suppression check → digest/budget → card (design B2). */
  suppressed?: boolean;
  suppressedUntilMs?: number;
}

/**
 * Record that a DNP happened for this exact (hash, origin). Idempotent by
 * identity: a remint refreshes `lastDeniedAt` and appends the new actionId to
 * the alias index, and NEVER advances the deny epoch — that is what keeps a
 * live card valid while the job flaps.
 *
 * Runs for suppressed events too: suppression buys silence, not amnesia
 * (audit truth preserved).
 */
export function recordDenialFingerprint(
  entry: DenialFingerprintEntry,
  opts: RetryStoreOptions = {},
): DenialFingerprintResult {
  const now = opts.now ?? Date.now();
  const hash = String(entry.hash ?? '').trim().toLowerCase();
  if (!/^[0-9a-f]{64}$/.test(hash)) return { ok: false, reason: 'unwritable' };
  const cwd = canonicaliseCwd(entry.cwd);
  const id = fingerprintId(hash, cwd);

  const result = withLock(opts.home, (file) => {
    // Prune WITHOUT claiming the unspent-expiry notice: "reported once" has to
    // mean "delivered once", and this write is not a delivery. The hook calls
    // `pruneRetryControl` on the path that actually sends (and so does the
    // CLI), which is where the notice is claimed.
    pruneInPlace(file, now);
    let row = file.rows.find((r) => r.id === id);
    if (!row) {
      row = {
        id,
        hash,
        tool: String(entry.tool ?? 'tool').slice(0, 64),
        denyEpoch: 0,
        deniedAt: now,
        lastDeniedAt: now,
        originScope: {
          ...(cwd ? { cwd } : {}),
          ...(entry.sessionKey ? { sessionKey: String(entry.sessionKey).slice(0, 64) } : {}),
        },
        signals: (entry.signals ?? []).map((s) => String(s)).slice(0, 8),
        redactedSurface: String(entry.redactedSurface ?? '').slice(0, 300),
        actionIds: [],
      };
      file.rows.push(row);
    } else {
      // Remint: refresh recency and display fields only. NOT the epoch.
      row.lastDeniedAt = now;
      row.tool = String(entry.tool ?? row.tool).slice(0, 64);
      if (entry.signals?.length) row.signals = entry.signals.map((s) => String(s)).slice(0, 8);
      if (entry.redactedSurface) row.redactedSurface = String(entry.redactedSurface).slice(0, 300);
      // sessionKey is diagnostic; keep the most recent one that reached us.
      if (entry.sessionKey) row.originScope.sessionKey = String(entry.sessionKey).slice(0, 64);
    }
    const actionId = typeof entry.actionId === 'string' ? entry.actionId.trim() : '';
    if (actionId && !row.actionIds.includes(actionId)) {
      row.actionIds.push(actionId);
      while (row.actionIds.length > MAX_ACTION_ID_ALIASES) row.actionIds.shift();
    }
    return { value: { row: { ...row } }, commit: true };
  });

  if (!result.ok) return { ok: false, reason: result.reason };
  const row = result.value.row;
  return {
    ok: true,
    id,
    row,
    suppressed: suppressionIsLive(row, now),
    suppressedUntilMs: row.suppression?.until,
  };
}

/** Is this identity currently silenced by an operator deny? Read-only. */
export function isDenySuppressed(
  ref: RetryRowRef,
  opts: RetryStoreOptions = {},
): { suppressed: boolean; untilMs?: number } {
  const now = opts.now ?? Date.now();
  const row = findRow(readStore(opts.home).rows, ref);
  if (!row || !suppressionIsLive(row, now)) return { suppressed: false };
  return { suppressed: true, untilMs: row.suppression!.until };
}

// ── 2. Deny suppression ───────────────────────────────────────────────────

export type DenySuppressionOutcome =
  | { ok: true; untilMs: number; revokedGrant: boolean; epoch: number }
  | { ok: false; reason: 'not-found' | 'locked' | 'unwritable' };

/**
 * The operator said no. Three things happen in ONE locked write, because any
 * two of them apart would be a window:
 *   - a suppression window opens (windowed silence — never "permanent"),
 *   - the deny epoch advances, retiring any live card,
 *   - an UNSPENT grant is revoked (R3 rule 6 — deny always beats an approve
 *     that has not been spent; a spent grant is history and is left alone).
 */
export function recordDenySuppression(
  ref: RetryRowRef,
  opts: RetryStoreOptions & { suppressionMs?: number; via?: 'card' | 'tty' } = {},
): DenySuppressionOutcome {
  const now = opts.now ?? Date.now();
  const suppressionMs =
    boundedNumber(opts.suppressionMs, MIN_DENY_SUPPRESSION_MS, MAX_DENY_SUPPRESSION_MS)
    ?? DEFAULT_DNP_DIGEST_WINDOW_MS;
  const via = opts.via === 'tty' ? 'tty' : 'card';

  const result = withLock(opts.home, (file) => {
    pruneInPlace(file, now);
    const row = findRow(file.rows, ref);
    if (!row) return { value: null, commit: false };
    let revokedGrant = false;
    if (row.grant && !row.grant.consumedAt) {
      delete row.grant;
      revokedGrant = true;
    }
    delete row.claim;
    row.denyEpoch += 1;
    row.suppression = { at: now, until: now + suppressionMs, via };
    return {
      value: { untilMs: row.suppression.until, revokedGrant, epoch: row.denyEpoch },
      commit: true,
    };
  });

  if (!result.ok) return { ok: false, reason: result.reason };
  if (!result.value) return { ok: false, reason: 'not-found' };
  return { ok: true, ...result.value };
}

// ── 3. Launch claim (atomic with the card budget debit) ───────────────────

export type LaunchClaimFailure =
  | 'not-found' | 'suppressed' | 'unscopeable' | 'already-claimed' | 'grant-live'
  | 'budget-exhausted' | 'locked' | 'unwritable' | 'no-key';

export type LaunchClaimOutcome =
  | { ok: true; id: string; nonce: string; epoch: number; expiresAt: number; row: RetryRow }
  | { ok: false; reason: LaunchClaimFailure; lostActionIds?: string[] };

export interface LaunchClaimOptions extends RetryStoreOptions {
  /** Digest window start, read by the caller in the SAME handler (R3 rule 7).
   *  The card budget shares it — no independent first-event windows. */
  windowStartMs: number;
  windowMs: number;
  cardLifetimeMs?: number;
  actionId?: string;
}

interface ClaimAttempt {
  failed?: LaunchClaimFailure;
  lostActionIds?: string[];
  granted?: { row: RetryRow; epoch: number; expiresAt: number };
}

/**
 * Claim the right to raise ONE card for this identity, debiting the budget in
 * the same locked write. Refuses — mints nothing — when the identity is
 * suppressed, unscopeable, already holds a live claim (per-identity budget of
 * 1, epoch-pinned), already holds a LIVE UNSPENT grant (R3 rule 5:
 * consume-before-card), or the global window budget is spent.
 *
 * The returned `nonce` is the ONLY spendable artifact this call produces, it
 * exists for the lifetime of the waiter process, and the store keeps only its
 * HMAC. It never touches denials.jsonl, a webhook body, or an audit row.
 */
export function claimCardLaunch(ref: RetryRowRef, opts: LaunchClaimOptions): LaunchClaimOutcome {
  const now = opts.now ?? Date.now();
  const cardLifetimeMs =
    boundedNumber(opts.cardLifetimeMs, 1_000, MAX_RETRY_GRANT_TTL_MS) ?? RETRY_CARD_LIFETIME_MS;
  const nonce = randomBytes(32).toString('hex');
  const nonceHmac = hmacNonce(nonce, opts.home);
  if (!nonceHmac) return { ok: false, reason: 'no-key' };

  const result = withLock<ClaimAttempt>(opts.home, (file) => {
    pruneInPlace(file, now);
    const row = findRow(file.rows, ref);
    if (!row) return { value: { failed: 'not-found' }, commit: true };
    if (suppressionIsLive(row, now)) return { value: { failed: 'suppressed' }, commit: true };
    if (!row.originScope.cwd) return { value: { failed: 'unscopeable' }, commit: true };
    // Grant first: a live unspent grant is the more informative refusal, and
    // it is the one R3 rule 5 names (consume-before-card ordering — the retry
    // the operator already authorised has not been taken yet).
    if (grantIsLive(row.grant, now)) return { value: { failed: 'grant-live' }, commit: true };
    // A live UNANSWERED claim blocks a second card (two cards, one identity —
    // never). A claim whose tap already produced a grant blocks only while
    // that grant is itself live: once spent or expired, the claim is inert
    // history and the next DNP may card again (SOL R-impl blocker 1 — the
    // post-spend card blackout fought the flapping-retry case this exists
    // for). Epoch pinning is unaffected: a NEW claim gets the CURRENT epoch.
    if (claimIsLive(row.claim, now) && !(row.claim?.grantedAt && !grantIsLive(row.grant, now))) {
      return { value: { failed: 'already-claimed' }, commit: true };
    }

    if (
      !file.budget
      || file.budget.windowStartMs !== opts.windowStartMs
      || file.budget.windowMs !== opts.windowMs
    ) {
      file.budget = {
        windowStartMs: opts.windowStartMs,
        windowMs: opts.windowMs,
        cards: 0,
        // Carried, not cleared: a denial that lost its card near the end of a
        // window has almost certainly been COALESCED by the digest, so the
        // operator copy naming it only goes out on the next window's first
        // notify. Dropping the ids on reset would lose exactly the events the
        // operator most needs to see.
        lostActionIds: file.budget?.lostActionIds ?? [],
      };
    }
    if (file.budget.cards >= CARD_BUDGET_PER_WINDOW) {
      const lost = opts.actionId ?? row.actionIds[row.actionIds.length - 1];
      if (lost && !file.budget.lostActionIds.includes(lost)) {
        file.budget.lostActionIds.push(lost);
        while (file.budget.lostActionIds.length > MAX_LOST_ACTION_IDS) file.budget.lostActionIds.shift();
      }
      return {
        value: { failed: 'budget-exhausted', lostActionIds: [...file.budget.lostActionIds] },
        commit: true,
      };
    }

    file.budget.cards += 1;
    row.claim = {
      nonceHmac,
      epoch: row.denyEpoch,
      claimedAt: now,
      expiresAt: now + cardLifetimeMs,
      ...(opts.actionId ? { actionId: opts.actionId } : {}),
    };
    return {
      value: { granted: { row: { ...row }, epoch: row.denyEpoch, expiresAt: row.claim.expiresAt } },
      commit: true,
    };
  });

  if (!result.ok) return { ok: false, reason: result.reason };
  const attempt = result.value;
  if (attempt.failed) {
    return {
      ok: false,
      reason: attempt.failed,
      ...(attempt.lostActionIds ? { lostActionIds: attempt.lostActionIds } : {}),
    };
  }
  const granted = attempt.granted!;
  return {
    ok: true,
    id: granted.row.id,
    nonce,
    epoch: granted.epoch,
    expiresAt: granted.expiresAt,
    row: granted.row,
  };
}

/**
 * The card never went out (spawn failed). Release the slot: drop the claim and
 * refund the budget debit, in one locked write. The epoch does NOT advance —
 * nothing was ever shown to a human, so there is nothing to retire.
 */
export function releaseCardLaunch(ref: RetryRowRef, opts: RetryStoreOptions = {}): { ok: boolean } {
  const result = withLock(opts.home, (file) => {
    const row = findRow(file.rows, ref);
    if (!row || !row.claim) return { value: false, commit: false };
    if (row.grant && row.grant.epoch === row.claim.epoch) return { value: false, commit: false };
    delete row.claim;
    if (file.budget && file.budget.cards > 0) file.budget.cards -= 1;
    return { value: true, commit: true };
  });
  return { ok: result.ok && result.value === true };
}

// ── 4. Grant ──────────────────────────────────────────────────────────────

export interface GrantRetryAuth {
  /** The card path. Required unless `isInteractive` is true. */
  nonce?: string;
  /** The TTY path — pass the live `isInteractive` value from src/cli/approve.ts. */
  isInteractive?: boolean;
  /** TTY only, off by default: grant with no cwd binding ("ANY local process
   *  may spend this"). Cards can never set it. */
  anyOrigin?: boolean;
  /** TTY only: grant despite a live deny suppression. Cards can never set it. */
  overrideDeny?: boolean;
}

export type GrantRetryFailure =
  | 'not-found' | 'suppressed' | 'unscopeable' | 'claim-missing' | 'claim-expired'
  | 'claim-spent' | 'epoch-stale' | 'bad-nonce' | 'not-authenticated' | 'locked'
  | 'unwritable' | 'no-key';

export type GrantRetryOutcome =
  | { ok: true; alreadyGranted?: boolean; grant: RetryGrant; row: RetryRow; id: string }
  | { ok: false; reason: GrantRetryFailure; suppressedUntilMs?: number };

interface GrantAttempt {
  failed?: GrantRetryFailure;
  suppressedUntilMs?: number;
  alreadyGranted?: boolean;
  row?: RetryRow;
  grant?: RetryGrant;
}

/**
 * Turn a fingerprint into a grant. ONE locked write, `approvedAt` always set —
 * there is deliberately no recordPending-then-approve shape here, because the
 * window between those two writes is a row that looks grantable and was never
 * granted.
 *
 * Authentication is not optional and has exactly two forms:
 *   - card: the `claimNonce` minted at launch, HMAC-matched against a claim
 *     that is still live AND still on the current epoch. A corrupt/reset store
 *     has no claim record, so a stale card fails here before anything else.
 *   - TTY: `isInteractive` — the same gate `shieldcortex approve` has always
 *     used. A same-user process that merely imports this module has neither.
 *
 * Deny beats an in-flight approve: a tap that lands after the operator already
 * denied is refused (`suppressed`) and audited, never honoured. Only the TTY
 * path can override that, and only behind an explicit confirmation upstream.
 */
export function grantRetry(
  ref: RetryRowRef,
  auth: GrantRetryAuth,
  opts: RetryStoreOptions & { ttlMs?: number; tool?: string } = {},
): GrantRetryOutcome {
  const now = opts.now ?? Date.now();
  const ttlMs =
    boundedNumber(opts.ttlMs, MIN_RETRY_GRANT_TTL_MS, MAX_RETRY_GRANT_TTL_MS)
    ?? DEFAULT_RETRY_GRANT_TTL_MS;
  const viaCard = typeof auth.nonce === 'string' && auth.nonce.length > 0;
  // Card authentication is EXCLUSIVE: a caller presenting a nonce is the
  // waiter, and the waiter never carries TTY privileges. Hard-drop the
  // interactive flag and both wideners the moment a nonce is present, so a
  // confused (or malicious) caller supplying nonce + isInteractive cannot
  // smuggle --any-origin / --override-deny onto a card grant (SOL R-impl
  // blocker 2; spec B4 — the trust boundary is THIS function, not its
  // callers).
  const viaTty = !viaCard && auth.isInteractive === true;
  if (viaCard) {
    auth = { ...auth, isInteractive: false, anyOrigin: false, overrideDeny: false };
  }
  if (!viaCard && !viaTty) return { ok: false, reason: 'not-authenticated' };

  let presentedHmac: string | null = null;
  if (viaCard) {
    presentedHmac = hmacNonce(auth.nonce as string, opts.home);
    if (!presentedHmac) return { ok: false, reason: 'no-key' };
  }

  const result = withLock<GrantAttempt>(opts.home, (file) => {
    pruneInPlace(file, now);
    const row = findRow(file.rows, ref);
    if (!row) return { value: { failed: 'not-found' }, commit: true };

    if (viaCard) {
      // Claim checks FIRST: on a fresh/corrupt store there is no claim, so a
      // replayed card dies here rather than on any later condition.
      if (!row.claim) return { value: { failed: 'claim-missing' }, commit: true };
      if (!claimIsLive(row.claim, now)) return { value: { failed: 'claim-expired' }, commit: true };
      if (row.claim.epoch !== row.denyEpoch) return { value: { failed: 'epoch-stale' }, commit: true };
      if (!constantTimeEquals(row.claim.nonceHmac, presentedHmac as string)) {
        return { value: { failed: 'bad-nonce' }, commit: true };
      }
    }

    const suppressed = suppressionIsLive(row, now);
    if (suppressed && !(viaTty && auth.overrideDeny === true)) {
      return {
        value: { failed: 'suppressed', suppressedUntilMs: row.suppression!.until },
        commit: true,
      };
    }

    const anyOrigin = viaTty && auth.anyOrigin === true;
    if (!row.originScope.cwd && !anyOrigin) {
      // Cards NEVER get here (claimCardLaunch already refused an unscopeable
      // identity); this is the TTY path without --any-origin.
      return { value: { failed: 'unscopeable' }, commit: true };
    }

    if (grantIsLive(row.grant, now)) {
      // Double tap. Idempotent by construction: the FIRST grant stands, its
      // TTL is not extended, and the caller is told it was already granted.
      return {
        value: { alreadyGranted: true, row: { ...row }, grant: { ...row.grant! } },
        commit: false,
      };
    }

    if (viaCard && row.claim?.grantedAt) {
      // This ticket already became a grant, and that grant is no longer live —
      // it was spent, or it expired. One claim, one grant: a late tap on the
      // same card must not mint a second.
      return { value: { failed: 'claim-spent' }, commit: true };
    }

    if (suppressed && viaTty && auth.overrideDeny === true) {
      // The operator explicitly overrode their own deny — the silence ends
      // with it, or the very retry they just authorised would be muted for the
      // rest of the window.
      delete row.suppression;
    }

    const grant: RetryGrant = {
      grantKind: 'retry',
      approvedAt: now,
      ttlMs,
      epoch: row.denyEpoch,
      via: viaCard ? 'card' : 'tty',
      origin: {
        ...(anyOrigin ? { anyOrigin: true } : {}),
        ...(row.originScope.cwd && !anyOrigin ? { cwd: row.originScope.cwd } : {}),
        tool: String(opts.tool ?? row.tool ?? 'tool').slice(0, 64),
      },
    };
    row.grant = grant;
    // The claim is KEPT and marked: it is what lets a double tap authenticate
    // and be answered idempotently, and what makes a third tap `claim-spent`.
    if (row.claim) row.claim.grantedAt = now;
    return { value: { row: { ...row }, grant: { ...grant } }, commit: true };
  });

  if (!result.ok) return { ok: false, reason: result.reason };
  const attempt = result.value;
  if (attempt.failed) {
    return {
      ok: false,
      reason: attempt.failed,
      ...(typeof attempt.suppressedUntilMs === 'number'
        ? { suppressedUntilMs: attempt.suppressedUntilMs }
        : {}),
    };
  }
  return {
    ok: true,
    ...(attempt.alreadyGranted ? { alreadyGranted: true } : {}),
    grant: attempt.grant!,
    row: attempt.row!,
    id: attempt.row!.id,
  };
}

// ── 5. Consume (locked RMW in the same plane — R3 rule 5) ─────────────────

export interface ConsumeRetryOrigin {
  /** Caller-computed, from the hook's own context. Canonicalised here. */
  cwd?: string;
  tool: string;
}

export type ConsumedRetryGrant = RetryGrant & { hash: string; id: string; actionId?: string };

/**
 * Spend a retry grant for this exact call, if one is live and the origin
 * AND-matches. Returns the consumed grant (for auditing) or null.
 *
 * The predicate is `{cwd, tool}` and nothing else (R3 rule 3): sessionKey is
 * diagnostic, because the next cron tick is a NEW Claude session with a fresh
 * sessionKey and fail-closing on that would break the case this exists for.
 * `--any-origin` grants (TTY-only, confirmed) skip the cwd leg and match tool
 * alone.
 *
 * Consumption is a locked read-modify-write in the one plane, so two racing
 * tool calls cannot both spend the same grant: exactly one sees it unspent.
 */
export function consumeRetryGrant(
  args: { hash: string; origin: ConsumeRetryOrigin },
  opts: RetryStoreOptions = {},
): ConsumedRetryGrant | null {
  const now = opts.now ?? Date.now();
  const hash = String(args.hash ?? '').trim().toLowerCase();
  if (!/^[0-9a-f]{64}$/.test(hash)) return null;
  const tool = String(args.origin?.tool ?? '').trim();
  if (!tool) return null;
  const cwd = canonicaliseCwd(args.origin?.cwd);

  const result = withLock<ConsumedRetryGrant | null>(opts.home, (file) => {
    // Snapshotted so a no-op consume — the overwhelming majority, since every
    // guarded call on a retry-cards host asks — writes NOTHING. An install
    // that never had a denial keeps an empty footprint, and the live-hold path
    // stays byte-identical rather than merely equivalent.
    const before = JSON.stringify(file);
    pruneInPlace(file, now);
    const row = file.rows.find((r) => {
      if (r.hash !== hash) return false;
      if (!grantIsLive(r.grant, now)) return false;
      if (suppressionIsLive(r, now)) return false; // deny beats a live grant
      const origin = r.grant!.origin;
      if (origin.tool !== tool) return false;
      if (origin.anyOrigin === true) return true; // TTY-only, confirmed
      if (!origin.cwd) return false; // unscopeable never matches
      return origin.cwd === cwd;
    });
    if (!row) return { value: null, commit: JSON.stringify(file) !== before };
    row.grant!.consumedAt = now;
    return {
      value: {
        ...row.grant!,
        hash: row.hash,
        id: row.id,
        actionId: row.actionIds[row.actionIds.length - 1],
      },
      commit: true,
    };
  });

  if (!result.ok) return null;
  return result.value;
}

// ── 6. Opportunistic sweeper ──────────────────────────────────────────────

/**
 * Prune + report. There is no daemon: this runs on every DNP event and on
 * every `shieldcortex approve` invocation, so worst case the "your grant
 * expired unspent" notice rides the next guard event or the next time the
 * operator looks. That is stated plainly in the ADR rather than dressed up as
 * a timer.
 */
export function pruneRetryControl(
  opts: RetryStoreOptions = {},
): { ok: boolean; expired: ExpiredGrantNotice[] } {
  const now = opts.now ?? Date.now();
  const result = withLock(opts.home, (file) => {
    const expired = pruneInPlace(file, now, true);
    return { value: expired, commit: true };
  });
  return result.ok ? { ok: true, expired: result.value } : { ok: false, expired: [] };
}

/**
 * Take the "these denials got no card" ids for delivery, clearing them in the
 * same locked write. Called ONLY on a path that is actually about to send: an
 * id that is drained and then not delivered is an id the operator never hears
 * about, so draining is deliberately coupled to sending.
 */
export function drainLostActionIds(opts: RetryStoreOptions = {}): string[] {
  const result = withLock<string[]>(opts.home, (file) => {
    const lost = file.budget?.lostActionIds ?? [];
    if (lost.length === 0) return { value: [], commit: false };
    file.budget!.lostActionIds = [];
    return { value: [...lost], commit: true };
  });
  return result.ok ? result.value : [];
}

/**
 * Put drained ids BACK when the delivery they were drained for did not
 * happen (Grok/SOL R-impl shared nit — an id drained and then dropped on a
 * failed send is an operator who never hears about a lost card). Deduped;
 * a redelivery in between cannot double them.
 */
export function restoreLostActionIds(ids: string[], opts: RetryStoreOptions = {}): void {
  const clean = [...new Set(ids.filter((i) => typeof i === 'string' && i.length > 0))];
  if (clean.length === 0) return;
  withLock<void>(opts.home, (file) => {
    if (!file.budget) return { value: undefined, commit: false };
    const merged = [...new Set([...(file.budget.lostActionIds ?? []), ...clean])];
    file.budget.lostActionIds = merged.slice(0, 50);
    return { value: undefined, commit: true };
  });
}

/** Card budget as it stands, for the operator copy. Read-only. */
export function readCardBudget(opts: RetryStoreOptions = {}): RetryCardBudget | null {
  return readStore(opts.home).budget;
}

// ── 7. Operator copy ──────────────────────────────────────────────────────

/** OpenClaw's own caps. A request rejected for length is a card that never
 *  reached the operator, so we stay inside them rather than discover them. */
const CARD_TITLE_MAX = 80;
const CARD_DESCRIPTION_MAX = 256;

function isSecretEgress(signals: string[]): boolean {
  return signals.some((s) => {
    const t = String(s).toLowerCase();
    return t.includes('secret') || t.includes('credential');
  });
}

/** Last two path segments, bounded — enough for an operator to recognise the
 *  job without spending the description budget on a deep path. */
export function scopeTail(cwd?: string): string {
  if (!cwd) return 'unscoped';
  const parts = cwd.split(/[/\\]+/).filter(Boolean);
  const tail = parts.slice(-2).join('/');
  const out = tail || cwd;
  return out.length <= 40 ? out : `…${out.slice(-39)}`;
}

export interface RetryCardCopyInput {
  tool: string;
  signals: string[];
  redactedSurface: string;
  cwd?: string;
  ttlMs: number;
  /** When the schedule that produced this denial fires less often than the
   *  grant can be spent, the card must SAY so (design: card copy). */
  cronIntervalMs?: number;
}

export interface RetryCardFields {
  title: string;
  description: string;
  /** True when the redacted surface was dropped entirely (secret egress) or
   *  truncated to fit — the trust copy is never the thing that gives way. */
  surfaceWithheld: boolean;
  surfaceTruncated: boolean;
}

/**
 * The 256-character budget, spent in a fixed order (design: "Card copy"):
 *   1. the mandatory TRUST copy — held headless, ONE retry, the TTL, the
 *      scope — which is never truncated, because it is the whole reason a tap
 *      is safe to make;
 *   2. the cron-interval caveat, when the schedule outruns the spend TTL;
 *   3. whatever is left goes to the redacted surface, which truncates LAST.
 * A secret-egress class withholds the surface outright — the same discipline
 * as #173/#192: the thing that tripped the guard must not be forwarded to a
 * chat surface. The hash and the full surface live in the webhook alert and
 * the audit row: the card is the CONTROL, the webhook is the RECORD.
 */
export function buildRetryCardFields(input: RetryCardCopyInput): RetryCardFields {
  const tool = String(input.tool || 'tool').slice(0, 32);
  const topSignal = String(input.signals?.[0] ?? 'action-guard').slice(0, 32);
  const rawTitle = `Approve once? ${tool} · ${topSignal}`;
  const title = rawTitle.length <= CARD_TITLE_MAX ? rawTitle : `${rawTitle.slice(0, CARD_TITLE_MAX - 1)}…`;

  const minutes = Math.max(1, Math.round(input.ttlMs / 60_000));
  const trust = `held headless — Approve = ONE retry (${minutes}m, ${scopeTail(input.cwd)})`;
  const cronCaveat =
    typeof input.cronIntervalMs === 'number'
    && Number.isFinite(input.cronIntervalMs)
    && input.cronIntervalMs > input.ttlMs
      ? ' · schedule is slower than this TTL — use `approve --denial <id> --ttl`'
      : '';

  const withheld = isSecretEgress(input.signals ?? []);
  let description = `${trust}${cronCaveat}`;
  let surfaceTruncated = false;
  if (!withheld) {
    const remaining = CARD_DESCRIPTION_MAX - description.length - 3; // " · "
    const surface = String(input.redactedSurface ?? '').replace(/\s+/g, ' ').trim();
    if (surface && remaining > 4) {
      const fitted = surface.length <= remaining ? surface : `${surface.slice(0, remaining - 1)}…`;
      surfaceTruncated = fitted !== surface;
      description = `${description} · ${fitted}`;
    } else if (surface) {
      surfaceTruncated = true;
    }
  }

  return {
    title,
    // Trust copy is short by construction (bounded tool/scope), so this cap
    // only bites if someone widens it — and by then the SURFACE is already
    // gone, per the order above.
    description: description.slice(0, CARD_DESCRIPTION_MAX),
    surfaceWithheld: withheld,
    surfaceTruncated,
  };
}

/** The exact gateway request the waiter will place. Built here so tests can
 *  pin what the operator is offered without spawning anything. `allow-always`
 *  is deliberately not offered: durable trust is a config decision, and this
 *  path can never mint or spend `reviewedScripts`. */
export function buildRetryCardParams(input: RetryCardCopyInput): Record<string, unknown> {
  const { title, description } = buildRetryCardFields(input);
  return {
    pluginId: 'shieldcortex',
    title,
    description,
    severity: 'warning',
    allowedDecisions: ['allow-once', 'deny'],
    timeoutMs: RETRY_CARD_LIFETIME_MS,
  };
}

/** Operator copy for a denial that got NO card because the window budget was
 *  spent. It carries the ids that lost out and the command that still works —
 *  this belongs on the digest/webhook, not in an audit row nobody opens. */
export function formatBudgetExhaustedNotice(lostActionIds: string[]): string {
  const ids = lostActionIds.filter(Boolean).slice(-MAX_LOST_ACTION_IDS);
  const list = ids.length > 0 ? ids.join(', ') : 'none recorded';
  return [
    `budget_exhausted: ${ids.length || 'further'} denial(s) got no retry card in this window (cap ${CARD_BUDGET_PER_WINDOW}).`,
    `No card: ${list}`,
    'Authorise one from YOUR terminal: shieldcortex approve --denial <actionId>',
  ].join('\n');
}

/** Operator copy for grants that expired without ever being spent. */
export function formatUnspentExpiryNotice(expired: ExpiredGrantNotice[]): string {
  if (expired.length === 0) return '';
  const lines = expired.slice(0, MAX_LOST_ACTION_IDS).map((e) => {
    const mins = Math.max(1, Math.round(e.ttlMs / 60_000));
    return `  ${e.actionId ?? e.shortHash} (${e.tool}) — approved, never retried, expired after ${mins}m`;
  });
  return [
    `retry grant expired UNSPENT (${expired.length}): the job did not run again inside the window.`,
    ...lines,
    'Re-authorise from YOUR terminal: shieldcortex approve --denial <actionId> --ttl <minutes>',
  ].join('\n');
}
