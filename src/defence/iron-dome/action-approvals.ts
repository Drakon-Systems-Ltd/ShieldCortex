/**
 * ShieldCortex — one-shot exact-command approvals for the Action Guard (issue #118).
 *
 * The dangerous tier returns `require_approval`. On a harness with a native
 * permission card that becomes a prompt; in hook mode it is operationally a
 * hard denial, so the guard's own hint ("approve this exact command") promised
 * something no code implemented. This module is that mechanism.
 *
 * Shape:
 *   - The guard hook RECORDS a pending request keyed by a hash of the exact
 *     (tool, input) pair it just refused.
 *   - The operator runs `shieldcortex approve <hash>` in a real terminal.
 *   - The next evaluation of that EXACT pair consumes the approval and passes.
 *     Single-use, time-limited, and audited on both sides.
 *
 * Threat model — the agent is inside the blast radius. An agent that can run
 * shell commands can also run `shieldcortex approve`, which would make this a
 * self-service bypass of the very guard it is gating. Two properties stop that:
 *
 *   1. `approveRequest()` refuses unless stdin AND stdout are TTYs. A tool call
 *      spawned by an agent harness has piped stdio, so it cannot self-approve.
 *      This is enforced by the CLI layer via `assertInteractive`.
 *   2. Approvals are bound to an exact input hash, expire (default 10 minutes),
 *      and are consumed on first use — so a stolen/replayed hash buys nothing
 *      beyond the single command the operator actually read and approved.
 *
 * Storage is a single JSON file under ~/.shieldcortex/approvals/. It is small,
 * rewritten atomically, and self-pruning: expired and consumed records are
 * dropped on every write.
 */

import { createHash } from 'crypto';
import { mkdirSecure } from '../../setup/state-permissions.js';
import { existsSync, mkdirSync, readFileSync, renameSync, writeFileSync } from 'fs';
import { homedir } from 'os';
import { join } from 'path';

import { classifyFamily } from './tool-action-guard.js';

/** Default lifetime of an operator approval before it must be re-granted. */
export const DEFAULT_APPROVAL_TTL_MS = 10 * 60 * 1000;

/** How long an un-approved pending request is kept for `approve --list`. */
export const PENDING_RETENTION_MS = 60 * 60 * 1000;

export interface ApprovalRecord {
  /** Full sha256 of the canonical (tool, input) pair. */
  hash: string;
  /** Tool the guard refused, e.g. "Bash". */
  tool: string;
  /** Human-readable one-liner of what was refused (bounded). */
  summary: string;
  /** Signals from the verdict, for the operator to see what tripped. */
  signals: string[];
  /** ms epoch the guard recorded the request. */
  requestedAt: number;
  /** ms epoch the operator approved it; absent while pending. */
  approvedAt?: number;
  /** ms epoch the operator denied it (#143); absent unless denied. Denial is
   *  terminal — a denied record is removed from the store in the same call
   *  that sets this, so it is never read back from disk. Present only on the
   *  in-memory record `denyRequest` hands back to its caller, for audit. */
  deniedAt?: number;
  /** ms epoch the approval was spent; absent while unused. */
  consumedAt?: number;
  /** Lifetime granted at approval time. */
  ttlMs?: number;
}

interface ApprovalFile {
  version: 1;
  records: ApprovalRecord[];
}

const EMPTY: ApprovalFile = { version: 1, records: [] };

/** Short, operator-facing form of a hash — enough to be unambiguous in practice. */
export function shortHash(hash: string): string {
  return hash.slice(0, 12);
}

/**
 * Advisory fields on an EXEC tool call (#201). A Claude-harness Bash call
 * carries `description` (a free-text label the model re-words on every
 * attempt) and `timeout` — neither changes what executes, but hashing them
 * minted a fresh approval id per ATTEMPT, so `shieldcortex approve` could
 * never land: the operator approved hash A and the identical retry presented
 * hash B. Stripped for exec-family tools only: on any other tool a
 * `description` may be payload (an issue body, a PR description), where
 * approving one text must not release another.
 *
 * Deliberately NOT stripped: `dangerouslyDisableSandbox`, `run_in_background`
 * — they change confinement/supervision, so an approval for the sandboxed
 * form must not release the unsandboxed one.
 */
const EXEC_ADVISORY_KEYS = new Set(['description', 'timeout']);

/**
 * Reviewed non-exec tool contracts where `description` and `timeout` are
 * advisory to the named command field. This must stay an exact allowlist:
 * `extractCommand` deliberately treats broad keys such as `code` and `input`
 * as detection surfaces, but those keys are payload on many non-exec tools.
 * Using that heuristic here would let one approval cover changed payload.
 */
const NON_EXEC_COMMAND_FIELDS: ReadonlyMap<string, ReadonlySet<string>> = new Map([
  ['workflow', new Set(['script'])],
]);

function hasReviewedCommandSurface(tool: string, input: Record<string, unknown>): boolean {
  // Matched on the RAW tool name, deliberately NOT `normaliseToolName` (which
  // classifyFamily above uses). Normalising would map `mcp__evil__workflow`
  // onto this entry, letting any MCP server claim a relief that was reviewed
  // for exactly one first-party tool contract. Only an exact name qualifies;
  // a namespaced look-alike keeps its full input bound.
  const fields = NON_EXEC_COMMAND_FIELDS.get(tool.trim().toLowerCase());
  if (!fields) return false;
  return [...fields].some((field) => typeof input[field] === 'string' && input[field].length > 0);
}

function projectForHash(tool: string, input: unknown): unknown {
  if (!input || typeof input !== 'object' || Array.isArray(input)) return input;
  const record = input as Record<string, unknown>;
  // Unknown tools fail closed: keep their full input bound to the approval.
  if (classifyFamily(tool) !== 'exec' && !hasReviewedCommandSurface(tool, record)) return input;
  const out: Record<string, unknown> = {};
  for (const key of Object.keys(record)) {
    if (!EXEC_ADVISORY_KEYS.has(key)) out[key] = record[key];
  }
  return out;
}

/**
 * Canonical hash of the exact call. Stable across processes: object keys are
 * sorted and everything is JSON with no formatting. String values are
 * BYTE-EXACT: whitespace is meaningful in shell (`foo bar` is one command,
 * `foo\nbar` is two), so any textual difference is a different call and needs
 * its own approval. The old whitespace-collapse "equivalent retry" affordance
 * let a space→newline mutation append a second command while keeping the
 * granted hash — a grant for one command must never release another (#451
 * review). Cost of byte-exactness is a re-approve on a reformatted retry;
 * that fails toward the operator, never toward the attacker. Exec-tool
 * advisory fields are still excluded (#201) so the hash is per COMMAND, not
 * per attempt.
 */
export function hashToolCall(tool: string, input: unknown): string {
  const canonical = JSON.stringify([tool, canonicalise(projectForHash(tool, input))]);
  return createHash('sha256').update(canonical).digest('hex');
}

function canonicalise(value: unknown): unknown {
  if (typeof value === 'string') return value;
  if (Array.isArray(value)) return value.map(canonicalise);
  if (value && typeof value === 'object') {
    const out: Record<string, unknown> = {};
    for (const key of Object.keys(value as Record<string, unknown>).sort()) {
      out[key] = canonicalise((value as Record<string, unknown>)[key]);
    }
    return out;
  }
  return value ?? null;
}

/** Directory holding the approvals file. Resolved per-call so tests can swap HOME. */
export function approvalsDir(home?: string): string {
  return join(home ?? homedir(), '.shieldcortex', 'approvals');
}

function approvalsPath(home?: string): string {
  return join(approvalsDir(home), 'approvals.json');
}

function readFile(home?: string): ApprovalFile {
  try {
    const p = approvalsPath(home);
    if (!existsSync(p)) return { ...EMPTY, records: [] };
    const parsed = JSON.parse(readFileSync(p, 'utf-8')) as ApprovalFile;
    if (!parsed || !Array.isArray(parsed.records)) return { ...EMPTY, records: [] };
    return { version: 1, records: parsed.records };
  } catch {
    // A corrupt store must not wedge the guard: treat it as empty, which means
    // "nothing is approved" — the fail-CLOSED direction.
    return { ...EMPTY, records: [] };
  }
}

function writeFileAtomic(file: ApprovalFile, home?: string): void {
  const dir = approvalsDir(home);
  mkdirSecure(dir);
  const target = approvalsPath(home);
  const tmp = `${target}.tmp`;
  writeFileSync(tmp, JSON.stringify(file, null, 2), { mode: 0o600 });
  renameSync(tmp, target);
}

/** Drop records that can no longer be used: consumed, expired, or stale pending. */
function prune(records: ApprovalRecord[], now: number): ApprovalRecord[] {
  return records.filter((r) => {
    if (r.consumedAt) return false;
    if (r.approvedAt) return now - r.approvedAt < (r.ttlMs ?? DEFAULT_APPROVAL_TTL_MS);
    return now - r.requestedAt < PENDING_RETENTION_MS;
  });
}

/**
 * Record that the guard refused this exact call, so the operator has something
 * to approve. Idempotent: re-refusing the same call refreshes its timestamp
 * rather than piling up duplicates, and NEVER resurrects an approval.
 */
export function recordPending(
  entry: { tool: string; input: unknown; summary: string; signals: string[] },
  opts: { home?: string; now?: number } = {},
): ApprovalRecord {
  const now = opts.now ?? Date.now();
  const hash = hashToolCall(entry.tool, entry.input);
  const file = readFile(opts.home);
  const records = prune(file.records, now);
  const existing = records.find((r) => r.hash === hash);

  if (existing) {
    // Leave an approved record untouched — refreshing it here would let a
    // repeated refusal extend an approval the operator time-boxed.
    if (!existing.approvedAt) existing.requestedAt = now;
    writeFileAtomic({ version: 1, records }, opts.home);
    return existing;
  }

  const record: ApprovalRecord = {
    hash,
    tool: entry.tool,
    summary: entry.summary.replace(/\s+/g, ' ').trim().slice(0, 300),
    signals: entry.signals.slice(0, 8),
    requestedAt: now,
  };
  records.push(record);
  writeFileAtomic({ version: 1, records }, opts.home);
  return record;
}

export type ApproveOutcome =
  | { ok: true; record: ApprovalRecord }
  | { ok: false; reason: 'not-found' | 'already-approved' };

export type DenyOutcome =
  | { ok: true; record: ApprovalRecord }
  | { ok: false; reason: 'not-found' | 'already-approved' };

/**
 * Mark a pending request approved. Matches on the full hash or any unambiguous
 * prefix (operators paste the short form). Callers MUST have established that a
 * human is driving — see `assertInteractive` in the CLI layer.
 */
export function approveRequest(
  hashOrPrefix: string,
  opts: { home?: string; now?: number; ttlMs?: number } = {},
): ApproveOutcome {
  const now = opts.now ?? Date.now();
  const file = readFile(opts.home);
  const records = prune(file.records, now);
  const needle = hashOrPrefix.trim().toLowerCase();
  const matches = records.filter((r) => r.hash.startsWith(needle));

  if (matches.length !== 1) return { ok: false, reason: 'not-found' };
  const record = matches[0];
  if (record.approvedAt) return { ok: false, reason: 'already-approved' };

  record.approvedAt = now;
  record.ttlMs = opts.ttlMs ?? DEFAULT_APPROVAL_TTL_MS;
  writeFileAtomic({ version: 1, records }, opts.home);
  return { ok: true, record };
}

/**
 * Mark a pending request DENIED (#143). The sibling of `approveRequest` on the
 * same one-shot record — not a second approval concept. Deny is deliberately
 * as cheap as approve (one call, one match-by-hash-or-prefix) because a
 * notification transport that makes "no" harder to tap than "yes" biases
 * every ambiguous reply toward release.
 *
 * A deny is TERMINAL, not a hold: the record is removed from the store in the
 * same call (mirrors how `consumeApproval` removes a spent approval), so a
 * later `approveRequest` for the same hash finds nothing rather than a stale
 * grantable record — a delayed or replayed "approve" arriving after a human
 * already said no must not resurrect the request it was answering.
 *
 * An already-approved record refuses the deny outright (`already-approved`)
 * rather than revoking it: the human already spoke, and a late or duplicate
 * "no" (e.g. two channels both got a reply) must not undo a decision already
 * made, especially one the guard may have already acted on.
 */
export function denyRequest(
  hashOrPrefix: string,
  opts: { home?: string; now?: number } = {},
): DenyOutcome {
  const now = opts.now ?? Date.now();
  const file = readFile(opts.home);
  const records = prune(file.records, now);
  const needle = hashOrPrefix.trim().toLowerCase();
  const matches = records.filter((r) => r.hash.startsWith(needle));

  if (matches.length !== 1) return { ok: false, reason: 'not-found' };
  const record = matches[0];
  if (record.approvedAt) return { ok: false, reason: 'already-approved' };

  const denied: ApprovalRecord = { ...record, deniedAt: now };
  const remaining = records.filter((r) => r.hash !== record.hash);
  writeFileAtomic({ version: 1, records: remaining }, opts.home);
  return { ok: true, record: denied };
}

/**
 * Spend an approval for this exact call, if one is live. Returns the consumed
 * record (for auditing) or null. Consumption is a write — a second identical
 * call finds nothing and is refused again, which is the whole point.
 */
export function consumeApproval(
  tool: string,
  input: unknown,
  opts: { home?: string; now?: number } = {},
): ApprovalRecord | null {
  const now = opts.now ?? Date.now();
  const hash = hashToolCall(tool, input);
  const file = readFile(opts.home);
  const records = prune(file.records, now);
  const record = records.find((r) => r.hash === hash && r.approvedAt);
  if (!record) {
    // Still persist the prune so expired rows don't accumulate.
    if (records.length !== file.records.length) writeFileAtomic({ version: 1, records }, opts.home);
    return null;
  }

  record.consumedAt = now;
  const consumed: ApprovalRecord = { ...record };
  // prune() drops consumed records, so this write also removes it.
  writeFileAtomic({ version: 1, records: prune(records, now) }, opts.home);
  return consumed;
}

/** Everything currently on file, newest first — pending and approved. */
export function listApprovals(opts: { home?: string; now?: number } = {}): ApprovalRecord[] {
  const now = opts.now ?? Date.now();
  return prune(readFile(opts.home).records, now).sort((a, b) => b.requestedAt - a.requestedAt);
}
