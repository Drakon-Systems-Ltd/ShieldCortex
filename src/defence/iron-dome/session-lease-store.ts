/**
 * Iron Dome — Session Action Lease, fs layer (#227 completion).
 *
 * Turns the pure lease arithmetic in session-lease.ts into an actual control:
 * a real ledger location, a real per-scope lease store with acquire/refresh/
 * release and crash recovery, and ONE entry point — `evaluateToolCallLease` —
 * that both enforcement planes call (the Claude Code PreToolUse hook lazy-
 * loads this from dist; the OpenClaw interceptor receives it injected via the
 * defence module, the same route `evaluateToolCall` travels).
 *
 * STORAGE IS FLAT JSON, NOT SQLITE — deliberately. The Claude Code hook has no
 * DB on its hot path (the native binding breaking is a documented fleet
 * failure mode, and the guard must outlive it). A lease store one plane cannot
 * read is a plane that silently does not bind — the exact capability
 * dishonesty this PR was blocked over. Pattern follows action-approvals.ts:
 * atomic tmp+rename writes (0o600), TTL discipline, corrupt store read as
 * empty.
 *
 * CONCURRENCY, honestly (do not overclaim — a security module must not): the
 * lease file gives BEST-EFFORT coordination between HONEST sessions, not true
 * mutual exclusion. Acquire is read → atomic-rename → re-read-verify, but two
 * processes that both read the scope free can each rename and each then see
 * their own token, so a tight race CAN double-hold (last-writer-wins on the
 * file; both may believe they won). This is acceptable because the LEASE is
 * the soft half: it produces the "another session is doing X, wait" nicety.
 * The FREEZE — the hard control, the thing 10 Aug actually needed — lives in
 * DECISIONS.md, is checked before any lease logic, and is unaffected by this
 * race. True mutual exclusion would need SQLite BEGIN IMMEDIATE, which cannot
 * serve the Claude Code hook plane (no DB on its hot path); binding both
 * planes best-effort beats binding one plane perfectly. Stated so it is a
 * decision, not a surprise.
 *
 * FREEZE > LEASE, everywhere: the ledger check runs before any lease logic
 * and a refused action acquires nothing.
 *
 * TAMPER EVIDENCE, not proof: the ledger hash below detects an out-of-band
 * ledger edit — but it lives in the same owner-writable tree, so the same
 * out-of-band actor can update the hash to match and erase the evidence. It
 * catches accident and casual tampering, not a determined same-uid attacker;
 * a separate append-only/owner-only sink would be stronger and is future work.
 */

import { createHash, randomBytes } from 'crypto';
import fs from 'fs';
import os from 'os';
import path from 'path';

import {
  checkSessionLease,
  scopeForToolCall,
  DEFAULT_LEASE_TTL_MS,
  type LeaseDecision,
  type LeaseRecord,
  type LeaseScope,
} from './session-lease.js';

// ── Paths ───────────────────────────────────────────────────────────────────

/** Honours SHIELDCORTEX_CONFIG_DIR like cloud/config.ts's getConfigDir. */
export function resolveStateDir(env: NodeJS.ProcessEnv = process.env): string {
  return env.SHIELDCORTEX_CONFIG_DIR || path.join(os.homedir(), '.shieldcortex');
}

export function decisionsLedgerPath(dir: string = resolveStateDir()): string {
  return path.join(dir, 'DECISIONS.md');
}

function leasesDir(dir: string): string {
  return path.join(dir, 'leases');
}

function leasesPath(dir: string): string {
  return path.join(leasesDir(dir), 'leases.json');
}

// ── Ledger ──────────────────────────────────────────────────────────────────

/**
 * Read the decisions ledger. THREE-STATE by design:
 *   - '' (empty)  — the file does not exist: nothing was ever frozen. Allow-shaped.
 *   - text        — readable ledger content.
 *   - null        — the file EXISTS but cannot be read (EACCES/EIO/...): refuse-shaped.
 * "Cannot know" and "nothing is frozen" must never collapse into each other.
 */
export function readDecisionsLedger(dir: string = resolveStateDir()): string | null {
  try {
    return fs.readFileSync(decisionsLedgerPath(dir), 'utf-8');
  } catch (err) {
    const code = (err as NodeJS.ErrnoException).code;
    if (code === 'ENOENT' || code === 'ENOTDIR') return '';
    return null;
  }
}

// ── Lease store ─────────────────────────────────────────────────────────────

interface StoredLease extends LeaseRecord {
  token?: string;
}

interface LeaseFile {
  leases: Partial<Record<string, StoredLease>>;
  /** sha256 of the ledger at last evaluation — tamper evidence, not proof. */
  ledgerHash?: string;
}

function readLeaseFile(dir: string): LeaseFile {
  try {
    const parsed = JSON.parse(fs.readFileSync(leasesPath(dir), 'utf-8')) as LeaseFile;
    if (parsed && typeof parsed === 'object' && parsed.leases && typeof parsed.leases === 'object') {
      return parsed;
    }
  } catch {
    // Corrupt or absent store reads as empty. For MUTUAL EXCLUSION that is the
    // open direction — accepted: the lease is best-effort coordination between
    // honest sessions. The FREEZE (the hard control) never lives here.
  }
  return { leases: {} };
}

function writeLeaseFile(dir: string, file: LeaseFile): void {
  const target = leasesPath(dir);
  fs.mkdirSync(path.dirname(target), { recursive: true, mode: 0o700 });
  const tmp = `${target}.${process.pid}.${randomBytes(4).toString('hex')}.tmp`;
  fs.writeFileSync(tmp, JSON.stringify(file, null, 2), { mode: 0o600 });
  fs.renameSync(tmp, target);
}

function liveRecord(rec: StoredLease | undefined, nowMs: number): StoredLease | null {
  if (!rec || typeof rec.holder !== 'string') return null;
  const expiry =
    rec.expiresAtMs ?? (rec.acquiredAtMs != null ? rec.acquiredAtMs + DEFAULT_LEASE_TTL_MS : null);
  if (expiry == null || nowMs > expiry) return null;
  return rec;
}

export interface AcquireInput {
  dir?: string;
  scope: LeaseScope;
  self: string;
  nowMs?: number;
  ttlMs?: number;
  reason?: string;
}

export interface AcquireResult {
  acquired: boolean;
  /** The live record after the attempt — ours on success, the winner's on loss. */
  record: StoredLease | null;
}

/**
 * Acquire a free/expired lease, or refresh one this identity already holds.
 * Write-then-verify: after the atomic rename the file is re-read, and only an
 * exact holder+token match counts as ownership — a lost race reads as a loss.
 */
export function acquireOrRefreshLease(input: AcquireInput): AcquireResult {
  const dir = input.dir ?? resolveStateDir();
  const nowMs = input.nowMs ?? Date.now();
  const ttlMs = input.ttlMs ?? DEFAULT_LEASE_TTL_MS;

  try {
    const file = readLeaseFile(dir);
    const current = liveRecord(file.leases[input.scope], nowMs);
    if (current && current.holder !== input.self) {
      return { acquired: false, record: current };
    }

    const token = `${nowMs.toString(36)}-${randomBytes(6).toString('hex')}`;
    const record: StoredLease = {
      holder: input.self,
      pid: process.pid,
      reason: input.reason,
      acquiredAtMs: current?.holder === input.self ? (current.acquiredAtMs ?? nowMs) : nowMs,
      expiresAtMs: nowMs + ttlMs,
      token,
    };
    file.leases[input.scope] = record;
    writeLeaseFile(dir, file);

    // Verify: the rename is atomic, so whatever is on disk now is some
    // process's complete write. Ownership is ours only if it is OUR write.
    const after = readLeaseFile(dir).leases[input.scope];
    if (after && after.holder === input.self && after.token === token) {
      return { acquired: true, record: after };
    }
    return { acquired: false, record: liveRecord(after, nowMs) };
  } catch {
    // A store that cannot be written coordinates nothing — report not-acquired
    // with no record so the caller's decision logic sees a free-but-unprovable
    // slot. The freeze path is unaffected (it reads the ledger, not this file).
    return { acquired: false, record: null };
  }
}

export interface ReleaseInput {
  dir?: string;
  scope: LeaseScope;
  self: string;
}

/** Release a lease held by this identity. Another identity's lease is not
 *  releasable — a session must not be able to free its rival's slot. */
export function releaseLease(input: ReleaseInput): boolean {
  const dir = input.dir ?? resolveStateDir();
  try {
    const file = readLeaseFile(dir);
    const rec = file.leases[input.scope];
    if (!rec || rec.holder !== input.self) return false;
    delete file.leases[input.scope];
    writeLeaseFile(dir, file);
    return true;
  } catch {
    return false;
  }
}

/** List current lease records (expired ones included — display decides). */
export function listLeases(dir: string = resolveStateDir()): Partial<Record<string, StoredLease>> {
  return readLeaseFile(dir).leases;
}

// ── The single gate entry point ─────────────────────────────────────────────

export interface LeaseGateResult {
  scope: LeaseScope;
  decision: LeaseDecision;
  /** True when THIS call minted/refreshed the lease (verdict was allow). The
   *  caller releases it if a later stage — the guard's own block verdict —
   *  means the action will not actually run, so a refused action does not
   *  leave a 10-minute hold blocking honest sessions on that scope. */
  acquired?: boolean;
  /** Set when the ledger's content hash changed since the last evaluation —
   *  tamper EVIDENCE for the audit trail, not tamper proof. */
  ledgerChanged?: { fromHash: string; toHash: string };
}

export interface LeaseGateOptions {
  self: string;
  dir?: string;
  nowMs?: number;
  ttlMs?: number;
}

function sha256(text: string): string {
  return createHash('sha256').update(text, 'utf-8').digest('hex');
}

/**
 * The one function both enforcement planes call, AFTER the guard verdict and
 * BEFORE any approval affordance (a freeze that can be one-click-approved
 * around is not a freeze).
 *
 * Returns null for the overwhelmingly common case — a tool call exercising no
 * lease scope — without touching disk. For scoped calls: freeze first, then
 * mutual exclusion, then acquire-on-allow so the next session sees the hold.
 * Never throws.
 */
export function evaluateToolCallLease(
  toolName: string,
  args: Record<string, unknown> | null | undefined,
  opts: LeaseGateOptions,
): LeaseGateResult | null {
  try {
    const scope = scopeForToolCall(toolName, args ?? {});
    if (scope == null) return null;

    const dir = opts.dir ?? resolveStateDir();
    const nowMs = opts.nowMs ?? Date.now();
    // A blank identity never participates as itself: it gets a stable-ish
    // per-process fallback so records are attributable, and the pure core
    // separately refuses blank-on-blank re-entrancy.
    const self = (opts.self ?? '').trim() || `anon-pid-${process.pid}`;

    const ledger = readDecisionsLedger(dir);

    // Tamper evidence: note a ledger content change since the last scoped
    // evaluation. Detection, not prevention — same-uid writes cannot be
    // prevented from userspace, and pretending otherwise would be the
    // "reports protection it does not have" failure this PR was blocked over.
    let ledgerChanged: LeaseGateResult['ledgerChanged'];
    try {
      const file = readLeaseFile(dir);
      const toHash = ledger == null ? 'unreadable' : sha256(ledger);
      if (file.ledgerHash && file.ledgerHash !== toHash) {
        ledgerChanged = { fromHash: file.ledgerHash, toHash };
      }
      if (file.ledgerHash !== toHash) {
        file.ledgerHash = toHash;
        writeLeaseFile(dir, file);
      }
    } catch {
      // Evidence recording must never affect the decision.
    }

    const held = liveRecord(readLeaseFile(dir).leases[scope] as StoredLease | undefined, nowMs);
    const decision = checkSessionLease({ scope, ledger, held, self, nowMs });

    if (decision.verdict === 'allow') {
      const acquired = acquireOrRefreshLease({ dir, scope, self, nowMs, ttlMs: opts.ttlMs });
      if (!acquired.acquired && acquired.record && acquired.record.holder !== self) {
        // Lost a race between check and acquire — re-decide with the winner.
        const raced = checkSessionLease({ scope, ledger, held: acquired.record, self, nowMs });
        return { scope, decision: raced, ledgerChanged };
      }
      return { scope, decision, acquired: acquired.acquired, ledgerChanged };
    }

    return { scope, decision, ledgerChanged };
  } catch {
    return null;
  }
}

/**
 * Release a lease this session acquired via evaluateToolCallLease, when a later
 * stage refuses the action anyway (the guard's own block verdict). Best-effort
 * and never throws — worst case the hold self-heals at its TTL.
 */
export function releaseToolCallLease(
  toolName: string,
  args: Record<string, unknown> | null | undefined,
  opts: LeaseGateOptions,
): void {
  try {
    const scope = scopeForToolCall(toolName, args ?? {});
    if (scope == null) return;
    const self = (opts.self ?? '').trim() || `anon-pid-${process.pid}`;
    releaseLease({ dir: opts.dir ?? resolveStateDir(), scope, self });
  } catch {
    /* best-effort */
  }
}
