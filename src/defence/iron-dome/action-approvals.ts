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

import { REACH_ANSWER_WINDOW_MS, newReachAttemptId, recordApprovalReach } from './guard-readiness.js';

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
  /** #509: correlation id of the latest delivery attempt for this request.
   *  Re-minted on every refusal, so an answer binds to one attempt and the
   *  attempts before it keep their own (expired) outcome. */
  reachAttemptId?: string;
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
 * Advisory fields on a first-party exec call (#201). A Claude Code Bash call
 * carries `description` (a free-text label the model re-words on every
 * attempt) and `timeout` — neither changes what executes, but hashing them
 * minted a fresh approval id per ATTEMPT, so `shieldcortex approve` could
 * never land: the operator approved hash A and the identical retry presented
 * hash B. Stripped only for the reviewed contracts in
 * `FIRST_PARTY_EXEC_TOOLS` and `NON_EXEC_COMMAND_FIELDS`: on any other tool a
 * `description` may be payload (an issue body, a PR description, an invoice
 * memo), where approving one text must not release another.
 *
 * Deliberately NOT stripped: `dangerouslyDisableSandbox`, `run_in_background`
 * — they change confinement/supervision, so an approval for the sandboxed
 * form must not release the unsandboxed one.
 */
const EXEC_ADVISORY_KEYS = new Set(['description', 'timeout']);

/**
 * First-party exec tool contracts whose advisory fields may be left out of an
 * approval binding (#201, #815 B7). Matched against the raw tool name byte
 * for byte (no trimming, no case folding): never `normaliseToolName`, never
 * `classifyFamily`.
 *
 * `classifyFamily` is a risk heuristic, not a contract registry. Its exec
 * pattern matches SUBSTRINGS (`run`, `process`, `exec`, `script`, `command`,
 * …) of the LAST segment of a namespaced name, so `mcp__acme__process_invoice`,
 * `mcp__jira__run` and `mcp__evil__exec` all read as exec. Gating on it let
 * any MCP server whose tool name contains one of those words have its
 * `description` (on such a tool, possibly the payload: "pay vendor B 10000")
 * dropped from both the approval hash and the exact tap digest, so an approval
 * for one text released another. Only a contract a human reviewed qualifies;
 * every other name, including a namespaced look-alike of a listed one
 * (`mcp__evil__Bash`) and a differently cased one (`bash`), keeps every field
 * bound.
 *
 * `Bash`: Claude Code's shell tool, the only exec tool the guard hook sees by
 * a first-party name. Its `description` is a label and its `timeout` a
 * supervision bound; neither reaches the command.
 */
const FIRST_PARTY_EXEC_TOOLS: ReadonlySet<string> = new Set(['Bash']);

/**
 * Reviewed non-exec tool contracts where `description` and `timeout` are
 * advisory to the named command field. Keys are lowercase; a tool name is
 * looked up after trimming and lowercasing it, so `Workflow` and ` workflow `
 * match this entry and a namespaced name never does. This must stay an
 * allowlist of whole names:
 * `extractCommand` deliberately treats broad keys such as `code` and `input`
 * as detection surfaces, but those keys are payload on many non-exec tools.
 * Using that heuristic here would let one approval cover changed payload.
 */
const NON_EXEC_COMMAND_FIELDS: ReadonlyMap<string, ReadonlySet<string>> = new Map([
  ['workflow', new Set(['script'])],
]);

function hasReviewedCommandSurface(tool: string, input: Record<string, unknown>): boolean {
  // Matched on the raw tool name, only trimmed and lowercased; deliberately
  // NOT `normaliseToolName`. Normalising would map `mcp__evil__workflow` onto
  // this entry (it strips the namespace), letting any MCP server claim a
  // relief that was reviewed for exactly one first-party tool contract. Only
  // the whole name `workflow`, in any case, qualifies; a namespaced
  // look-alike keeps its full input bound. (`Bash`, above, is stricter: byte
  // for byte.)
  const fields = NON_EXEC_COMMAND_FIELDS.get(tool.trim().toLowerCase());
  if (!fields) return false;
  return [...fields].some((field) => typeof input[field] === 'string' && input[field].length > 0);
}

/**
 * The ONE gate both projections below share (#815 B7): may this call's
 * advisory fields be left out of its binding at all? Only for a reviewed
 * first-party contract. Kept in one place so the tolerant hash and the exact
 * digest cannot drift onto different tool sets again.
 */
function hasReviewedAdvisoryFields(tool: string, input: Record<string, unknown>): boolean {
  return FIRST_PARTY_EXEC_TOOLS.has(tool) || hasReviewedCommandSurface(tool, input);
}

/**
 * A fresh object for a projection or canonical form, and the only way a key
 * is put on one (#815 B8). `JSON.parse` gives a JSON key named `__proto__`
 * an ordinary own property, but `out[key] = value` on a plain `{}` runs
 * `Object.prototype`'s `__proto__` setter instead: no own property is
 * created, `JSON.stringify` never sees the key, and its whole subtree drops
 * out of the binding. Two calls differing only under `__proto__` (an
 * invoice's payee and amount) then shared one approval hash and one exact
 * digest, so a tap grant for one was spent by the other. A null-prototype
 * object has no such setter, and `defineProperty` creates an own data
 * property whatever the key; together every own key of the input survives.
 */
function emptyRecord(): Record<string, unknown> {
  return Object.create(null) as Record<string, unknown>;
}

function setOwn(out: Record<string, unknown>, key: string, value: unknown): void {
  Object.defineProperty(out, key, { value, enumerable: true, writable: true, configurable: true });
}

function projectForHash(tool: string, input: unknown): unknown {
  if (!input || typeof input !== 'object' || Array.isArray(input)) return input;
  const record = input as Record<string, unknown>;
  // Unknown and namespaced tools fail closed: their full input stays bound.
  if (!hasReviewedAdvisoryFields(tool, record)) return input;
  const out = emptyRecord();
  for (const key of Object.keys(record)) {
    if (!EXEC_ADVISORY_KEYS.has(key)) setOwn(out, key, record[key]);
  }
  return out;
}

/**
 * Canonical hash of the exact call. Stable across processes: object keys are
 * sorted, whitespace in string values is collapsed, and everything else is
 * JSON with no formatting. Two textually different-but-equivalent commands
 * (extra spaces) hash the same; a different command never does. Advisory
 * fields of a reviewed first-party contract are excluded (#201) so the hash
 * is per COMMAND, not per attempt.
 */
export function hashToolCall(tool: string, input: unknown): string {
  const canonical = JSON.stringify([tool, canonicalise(projectForHash(tool, input))]);
  return createHash('sha256').update(canonical).digest('hex');
}

/** Version of `exactCallDigest`'s form. A digest recorded under another
 *  version never matches; bump it whenever the form below changes.
 *  v2 (#815 B7): `description` is excluded only for the reviewed first-party
 *  contracts, no longer for every name `classifyFamily` reads as exec.
 *  v3 (#815 B8): a JSON key named `__proto__` is bound like any other key.
 *  The v2 form dropped it with its subtree, so a v2 digest can stand for
 *  several different calls; it is never spent again. */
export const EXACT_CALL_DIGEST_VERSION = 3;
const EXACT_CALL_DIGEST_DOMAIN = 'shieldcortex-exact-call/v3';

/**
 * Reviewed exclusions for the exact digest: `description` only, and only on
 * a reviewed first-party contract (`hasReviewedAdvisoryFields`). There it is
 * prose shown to the user; it never reaches what runs. (`timeout` is NOT
 * excluded here: it changes how long the action may run.)
 */
const EXACT_DIGEST_ADVISORY_KEYS = new Set(['description']);

function projectForExactDigest(tool: string, input: unknown): unknown {
  if (!input || typeof input !== 'object' || Array.isArray(input)) return input;
  const record = input as Record<string, unknown>;
  if (!hasReviewedAdvisoryFields(tool, record)) return input;
  const out = emptyRecord();
  for (const key of Object.keys(record)) {
    if (!EXACT_DIGEST_ADVISORY_KEYS.has(key)) setOwn(out, key, record[key]);
  }
  return out;
}

/** Sorted keys (key order carries no meaning in a JSON tool input); every
 *  own key kept, `__proto__` included (#815 B8); every string, number and
 *  the tool name taken exactly as given. */
function canonicaliseExact(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(canonicaliseExact);
  if (value && typeof value === 'object') {
    const out = emptyRecord();
    for (const key of Object.keys(value as Record<string, unknown>).sort()) {
      setOwn(out, key, canonicaliseExact((value as Record<string, unknown>)[key]));
    }
    return out;
  }
  return value ?? null;
}

/**
 * Exact, versioned digest of a tool call (#815 B). Unlike `hashToolCall`,
 * which is deliberately tolerant so that one approval survives cosmetic
 * re-spellings, this binds every byte of every execution-relevant field:
 * any change to the tool name, a path, a payload or the command text gives a
 * different digest. Used where a binding must hold exactly — the one-tap
 * approve grant. The only exclusion is `EXACT_DIGEST_ADVISORY_KEYS`.
 */
export function exactCallDigest(tool: string, input: unknown): string {
  const canonical = JSON.stringify([tool, canonicaliseExact(projectForExactDigest(tool, input))]);
  return createHash('sha256').update(`${EXACT_CALL_DIGEST_DOMAIN}\n${canonical}`, 'utf8').digest('hex');
}

function canonicalise(value: unknown): unknown {
  if (typeof value === 'string') return value.replace(/\s+/g, ' ').trim();
  if (Array.isArray(value)) return value.map(canonicalise);
  if (value && typeof value === 'object') {
    // Every own key kept, `__proto__` included (#815 B8): see `setOwn`.
    const out = emptyRecord();
    for (const key of Object.keys(value as Record<string, unknown>).sort()) {
      setOwn(out, key, canonicalise((value as Record<string, unknown>)[key]));
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
    if (!existing.approvedAt) {
      existing.requestedAt = now;
      existing.reachAttemptId = newReachAttemptId();
    }
    writeFileAtomic({ version: 1, records }, opts.home);
    return existing;
  }

  const record: ApprovalRecord = {
    hash,
    tool: entry.tool,
    summary: entry.summary.replace(/\s+/g, ' ').trim().slice(0, 300),
    signals: entry.signals.slice(0, 8),
    requestedAt: now,
    reachAttemptId: newReachAttemptId(),
  };
  records.push(record);
  writeFileAtomic({ version: 1, records }, opts.home);
  return record;
}

export type ApproveOutcome =
  | { ok: true; record: ApprovalRecord }
  | { ok: false; reason: 'not-found' | 'already-approved' | 'stale-attempt' };

export type DenyOutcome =
  | { ok: true; record: ApprovalRecord }
  | { ok: false; reason: 'not-found' | 'already-approved' | 'stale-attempt' };

/**
 * #509 R4-2: which delivered attempt an answer is for. A channel answer (card
 * tap, a reply to a notice) names the attempt it was shown; it binds only when
 * that is the record's CURRENT attempt, compared exactly. An answer to an
 * earlier attempt — expired and replaced by a newer delivery of the same
 * command — grants nothing and is evidence for nobody.
 *
 * `undefined` is the #118 terminal path (`shieldcortex approve <hash>` typed at
 * a TTY): it acts on the current attempt, as it always has, but it is NOT a
 * reach through the channel, so it records no reachability evidence.
 *
 * #509 r5 (finding 4a): an explicit attempt also has a lifetime. An answer
 * arriving more than {@link REACH_ANSWER_WINDOW_MS} after that attempt was
 * delivered is the same as an answer to a superseded one — the channel
 * already counted it as a timeout — so it grants nothing either.
 */
function attemptMatches(record: ApprovalRecord, attemptId: string | undefined, now: number): boolean | 'terminal' {
  if (attemptId === undefined) return 'terminal';
  if (!(typeof record.reachAttemptId === 'string'
    && record.reachAttemptId.length > 0
    && attemptId === record.reachAttemptId)) return false;
  const age = now - record.requestedAt;
  return Number.isFinite(age) && age >= 0 && age <= REACH_ANSWER_WINDOW_MS;
}

/**
 * Mark a pending request approved. Matches on the full hash or any unambiguous
 * prefix (operators paste the short form). Callers MUST have established that a
 * human is driving — see `assertInteractive` in the CLI layer.
 */
export function approveRequest(
  hashOrPrefix: string,
  opts: { home?: string; now?: number; ttlMs?: number; attemptId?: string } = {},
): ApproveOutcome {
  const now = opts.now ?? Date.now();
  const file = readFile(opts.home);
  const records = prune(file.records, now);
  const needle = hashOrPrefix.trim().toLowerCase();
  const matches = records.filter((r) => r.hash.startsWith(needle));

  if (matches.length !== 1) return { ok: false, reason: 'not-found' };
  const record = matches[0];
  // r5 (finding 4b): the attempt is validated BEFORE `already-approved`, so an
  // answer to a superseded attempt reads as stale — and records no reach —
  // even after the current attempt was approved.
  const bound = attemptMatches(record, opts.attemptId, now);
  if (bound === false) return { ok: false, reason: 'stale-attempt' };
  if (record.approvedAt) return { ok: false, reason: 'already-approved' };

  record.approvedAt = now;
  record.ttlMs = opts.ttlMs ?? DEFAULT_APPROVAL_TTL_MS;
  writeFileAtomic({ version: 1, records }, opts.home);
  // #509: a human answered THIS attempt through the channel. Evidence for
  // approval reachability, bound to the attempt the answer named. A terminal
  // hash-only answer (R4-2) is not a channel reach and records nothing.
  if (bound === true) {
    recordApprovalReach({ hash: record.hash, attemptId: record.reachAttemptId, phase: 'answer', answer: 'approve', origin: 'approval-store' }, { home: opts.home, now });
  }
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
  opts: { home?: string; now?: number; attemptId?: string } = {},
): DenyOutcome {
  const now = opts.now ?? Date.now();
  const file = readFile(opts.home);
  const records = prune(file.records, now);
  const needle = hashOrPrefix.trim().toLowerCase();
  const matches = records.filter((r) => r.hash.startsWith(needle));

  if (matches.length !== 1) return { ok: false, reason: 'not-found' };
  const record = matches[0];
  const bound = attemptMatches(record, opts.attemptId, now);
  if (bound === false) return { ok: false, reason: 'stale-attempt' };
  if (record.approvedAt) return { ok: false, reason: 'already-approved' };

  const denied: ApprovalRecord = { ...record, deniedAt: now };
  const remaining = records.filter((r) => r.hash !== record.hash);
  writeFileAtomic({ version: 1, records: remaining }, opts.home);
  // #509: a "no" is a human answer too — it reached someone (same binding).
  if (bound === true) {
    recordApprovalReach({ hash: record.hash, attemptId: record.reachAttemptId, phase: 'answer', answer: 'deny', origin: 'approval-store' }, { home: opts.home, now });
  }
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
