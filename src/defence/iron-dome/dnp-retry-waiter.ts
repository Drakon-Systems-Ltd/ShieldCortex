/**
 * ShieldCortex — the detached card owner for DNP RETRY control (#310).
 *
 * Spawned by scripts/pre-tool-hook.mjs on a `denied_no_prompt_surface` event
 * when `actionGuard.retryCards` is on. Like the #143 waiter, it exists because
 * the gateway scopes a pending approval to the CONNECTION that requested it,
 * so the request and the wait for the tap must live on ONE long-lived
 * `openclaw gateway call plugin.approval.request` — which cannot be the hook
 * (one process per tool call, exits immediately).
 *
 * ## Why this is a NEW file and not a branch inside the #143 waiter
 *
 * The #143 waiter translates a tap onto the #118 live-hold store
 * (`approveRequest`/`denyRequest`), whose whole semantics are "a call is being
 * HELD and a human answer decides it". A DNP has no held call: it was already
 * refused and handed back to the agent. Calling `approveRequest` here would
 * mint a live-hold approval for a request nothing is waiting on — the exact
 * confusion the ADR forbids. So the decision mapping is different, and it is
 * total:
 *
 *   'allow-once'  → grantRetry(fingerprint, claimNonce)  — atomic, scoped, one-shot
 *   'deny'        → recordDenySuppression(fingerprint)   — windowed silence
 *   anything else → NOTHING
 *
 * "Anything else" is load-bearing, same as #143: a timed-out card comes back
 * as `decision: null`, and silence from a human is not a "no" — the
 * fingerprint simply ages out on its own retention. A gateway error, an
 * unparseable response, or an unknown decision string ('allow-always' was
 * never offered) all end this process without touching the store.
 *
 * #853 — "without touching the store" is not "without telling anyone". Every
 * way a card ends WITHOUT an Approve (expired unanswered, denied, transport
 * failed after `requesting`, an unreadable answer, an Approve
 * the store refused) writes one `retry_card_expired` / `retry_denied` /
 * `retry_card_failed` / `retry_grant_failed` row, retires this waiter's own
 * claim (nobody can answer the card any more), and sends one no-button
 * "nothing ran" follow-up (held-follow-up.ts). A failure before
 * `requesting` sends nothing: no card was shown, and the hook — which polls
 * the receipt — reports that denial as card-less instead.
 *
 * `createOpenClawApprovalChannel` is deliberately NOT reused either: its
 * `send()` refuses `denied_no_prompt_surface` by design ("interactive-only —
 * this guard outcome has no decision left to offer"), which was true before
 * this feature and is the reason this one had to be built rather than
 * borrowed.
 *
 * ## The nonce
 *
 * The card grant is authenticated by a 256-bit `claimNonce` minted inside the
 * launch claim (see retry-control.ts). It reaches this process on an INHERITED
 * FD (`--nonce-fd 3`, an already-unlinked 0600 temp file the hook opened), so
 * it is not visible in `/proc/<pid>/cmdline` to other local processes. The
 * `--nonce <hex>` argv form is a documented fallback for platforms/harnesses
 * where fd inheritance is unavailable; it is the same trust level as the rest
 * of this process's argv and no worse than the status quo (which had no
 * authentication at all), but the fd path is what ships by default.
 *
 * ## Ack follows the store (R3 rule 8)
 *
 * Nothing tells the operator "granted" until `grantRetry` has RETURNED ok. The
 * ack is a receipt phase plus an operator-visible row in the same
 * `denials.jsonl` they already read — deliberately NOT a new gateway route,
 * because this codebase has not verified one exists (the same call
 * openclaw-approval-channel.ts made). A grant that fails writes `grant_failed`
 * and points the operator at `shieldcortex approve --denial <actionId>`.
 *
 * Exits 0 in every case: a detached waiter has nobody to report to, and its
 * outcome is legible where it matters — in the store and in denials.jsonl.
 */
import { execFile } from 'node:child_process';
import { closeSync, constants, fstatSync, mkdirSync, openSync, readSync, rmSync, writeFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { dirname, join } from 'node:path';

import {
  HELD_FOLLOW_UP_OUTCOMES,
  appendRetryOutcomeRow,
  deliverHeldFollowUp,
  type HeldFollowUpStatus,
} from './held-follow-up.js';
import {
  DEFAULT_RETRY_GRANT_TTL_MS,
  RETRY_CARD_LIFETIME_MS,
  closeCardClaim,
  grantRetry,
  recordDenySuppression,
} from './retry-control.js';

/** The waiter's own call deadline must outlast the card's expiry to hear it. */
export const RETRY_WAIT_DECISION_TIMEOUT_MS = RETRY_CARD_LIFETIME_MS + 15_000;

export interface RetryWaiterArgs {
  paramsB64: string;
  /** Canonical fingerprint id (retry-control.ts `fingerprintId`). */
  fingerprint: string;
  /** Alias for the operator copy — never used to authenticate anything. */
  actionId?: string;
  /** The hook's safe tool label, for the follow-up copy only. */
  tool?: string;
  openclawBin: string;
  receiptPath: string;
  /** Exactly one of these two is set by `parseRetryWaiterArgs`. */
  nonce?: string;
  nonceFd?: number;
  ttlMs: number;
  suppressionMs: number;
}

export type RetryWaiterReceipt =
  | { phase: 'requesting' }
  /** `requested` — the failure came AFTER `requesting`, so a card may have
   *  been shown: the hook must not re-label this denial as card-less. */
  | { phase: 'failed'; reason: string; requested?: boolean }
  | { phase: 'granted'; actionId?: string }
  | { phase: 'grant_failed'; reason: string; actionId?: string }
  | { phase: 'denied'; untilMs: number; actionId?: string };

export type RetryWaiterOutcome =
  | { acted: 'granted'; id: string }
  | { acted: 'denied'; untilMs: number }
  | { acted: 'nothing'; reason: string };

function positiveInt(value: string | null, fallback: number): number {
  const n = Number(value);
  return Number.isFinite(n) && n > 0 ? Math.floor(n) : fallback;
}

export function parseRetryWaiterArgs(argv: string[]): RetryWaiterArgs | null {
  const get = (flag: string): string | null => {
    const i = argv.indexOf(flag);
    return i >= 0 && i + 1 < argv.length ? argv[i + 1] : null;
  };
  const paramsB64 = get('--params-b64');
  const fingerprint = get('--fingerprint');
  const openclawBin = get('--openclaw-bin');
  const receiptPath = get('--receipt');
  if (!paramsB64 || !fingerprint || !openclawBin || !receiptPath) return null;
  // The fingerprint is about to be matched against the store — refuse anything
  // that does not look like one rather than forward surprises.
  if (!/^[0-9a-f]{16,64}$/i.test(fingerprint)) return null;

  const nonceRaw = get('--nonce');
  const nonceFdRaw = get('--nonce-fd');
  const nonceFd = nonceFdRaw !== null ? Number(nonceFdRaw) : NaN;
  const nonce = nonceRaw && /^[0-9a-f]{64}$/i.test(nonceRaw) ? nonceRaw.toLowerCase() : undefined;
  const hasFd = Number.isInteger(nonceFd) && nonceFd >= 3 && nonceFd <= 1024;
  // No nonce by either route means no card grant is possible — refuse to start
  // rather than raise a card whose tap could never be honoured.
  if (!nonce && !hasFd) return null;

  const actionId = get('--action-id');
  const tool = get('--tool');
  return {
    paramsB64,
    fingerprint: fingerprint.toLowerCase(),
    ...(actionId && /^act-[a-f0-9]{16}$/.test(actionId) ? { actionId } : {}),
    ...(tool && /^[A-Za-z0-9_.:-]{1,64}$/.test(tool) ? { tool } : {}),
    openclawBin,
    receiptPath,
    ...(nonce ? { nonce } : {}),
    ...(hasFd ? { nonceFd } : {}),
    ttlMs: positiveInt(get('--ttl-ms'), DEFAULT_RETRY_GRANT_TTL_MS),
    suppressionMs: positiveInt(get('--suppress-ms'), 15 * 60 * 1000),
  };
}

/** Read the nonce off the inherited fd, then close it. The file it points at
 *  was already unlinked by the hook, so this is the only way to read it and
 *  the only copy dies with this process. */
export function readNonceFromFd(fd: number): string | null {
  try {
    const st = fstatSync(fd);
    if (!st.isFile() || st.size > 4_096) return null;
    const buf = Buffer.alloc(st.size);
    let read = 0;
    while (read < st.size) {
      const n = readSync(fd, buf, read, st.size - read, read);
      if (n <= 0) break;
      read += n;
    }
    const text = buf.subarray(0, read).toString('utf8').trim();
    return /^[0-9a-f]{64}$/i.test(text) ? text.toLowerCase() : null;
  } catch {
    return null;
  } finally {
    try { closeSync(fd); } catch { /* already gone */ }
  }
}

function writeReceipt(path: string, receipt: RetryWaiterReceipt): void {
  try {
    mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
    writeFileSync(path, JSON.stringify(receipt), { mode: 0o600 });
  } catch {
    /* a receipt that cannot be written degrades the report, not the decision */
  }
}

function clearReceipt(path: string): void {
  try { rmSync(path, { force: true }); } catch { /* best-effort */ }
}

// The denials.jsonl row writer lives with the #853 follow-up code (one
// writer, no import cycle); re-exported here for its existing callers.
export { appendRetryOutcomeRow } from './held-follow-up.js';

export interface RetryWaiterDeps {
  execFileImpl?: typeof execFile;
  grantImpl?: typeof grantRetry;
  suppressImpl?: typeof recordDenySuppression;
  appendOutcomeImpl?: typeof appendRetryOutcomeRow;
  readNonceImpl?: (fd: number) => string | null;
  /** #853 — the "nothing ran" follow-up sender. */
  followUpImpl?: typeof deliverHeldFollowUp;
  /** #853 — retires this waiter's own claim once its card is over. */
  closeClaimImpl?: typeof closeCardClaim;
  waitTimeoutMs?: number;
  home?: string;
  now?: number;
}

/**
 * Own the card: request, wait, translate. Injectable seams for tests; the
 * strictness lives here, not in `main()`.
 */
export async function runRetryWaiter(
  args: RetryWaiterArgs,
  deps: RetryWaiterDeps = {},
): Promise<RetryWaiterOutcome> {
  const execFileImpl = deps.execFileImpl ?? execFile;
  const grantImpl = deps.grantImpl ?? grantRetry;
  const suppressImpl = deps.suppressImpl ?? recordDenySuppression;
  const appendOutcome = deps.appendOutcomeImpl ?? appendRetryOutcomeRow;
  const readNonce = deps.readNonceImpl ?? readNonceFromFd;
  const waitTimeoutMs = deps.waitTimeoutMs ?? RETRY_WAIT_DECISION_TIMEOUT_MS;
  const followUp = deps.followUpImpl ?? deliverHeldFollowUp;
  const closeClaim = deps.closeClaimImpl ?? closeCardClaim;
  const tool = args.tool ?? 'tool';
  const ref = { id: args.fingerprint, ...(args.actionId ? { actionId: args.actionId } : {}) };
  // Set once the claim nonce is read; `reportNothingRan` only runs after that.
  let nonce: string | null = null;

  /** #853 — one terminal row + one no-button follow-up for a card that ended
   *  without a grant, after retiring this waiter's own (unanswered) claim.
   *  Never throws; never touches a grant, a suppression or the budget. */
  const reportNothingRan = async (
    kind: 'expired' | 'denied' | 'failed' | 'grant_failed',
    reason: string,
    extra: Record<string, unknown> = {},
  ): Promise<HeldFollowUpStatus> => {
    // No waiter will answer this card any more: retire its claim first, so a
    // remint is not deduped onto it and `approve --denial` is not refused as
    // `card-live`. Best effort; at worst it lapses at `expiresAt` as before.
    if (nonce) {
      try { closeClaim(ref, { nonce }, { home: deps.home, now: deps.now }); } catch { /* lapses at expiresAt */ }
    }
    let status: HeldFollowUpStatus = 'dropped';
    try {
      status = await followUp(
        { kind, tool, at: deps.now ?? Date.now(), ...(args.actionId ? { actionId: args.actionId } : {}) },
        { home: deps.home },
      );
    } catch {
      status = 'dropped';
    }
    appendOutcome(
      {
        event: 'action_guard_denial',
        outcome: HELD_FOLLOW_UP_OUTCOMES[kind],
        origin: 'claude-code-hook',
        tool,
        reason,
        ...(kind === 'failed' || kind === 'grant_failed' ? { nextStep: `shieldcortex approve --denial ${args.actionId ?? '<actionId>'}` } : {}),
        ...extra,
        followUp: status,
        ...(args.actionId ? { actionId: args.actionId } : {}),
      },
      { home: deps.home },
    );
    return status;
  };

  let paramsJson: string;
  try {
    paramsJson = Buffer.from(args.paramsB64, 'base64').toString('utf8');
    JSON.parse(paramsJson); // shape is the gateway's problem; parseability is ours
  } catch {
    writeReceipt(args.receiptPath, { phase: 'failed', reason: 'unparseable card params' });
    return { acted: 'nothing', reason: 'unparseable card params' };
  }

  // Read the nonce BEFORE dialling: a card we could never honour must not be
  // shown to a human at all.
  nonce = args.nonce ?? (typeof args.nonceFd === 'number' ? readNonce(args.nonceFd) : null);
  if (!nonce) {
    writeReceipt(args.receiptPath, { phase: 'failed', reason: 'no claim nonce' });
    return { acted: 'nothing', reason: 'no claim nonce' };
  }

  writeReceipt(args.receiptPath, { phase: 'requesting' });

  let stdout: string;
  try {
    stdout = await new Promise<string>((resolvePromise, rejectPromise) => {
      execFileImpl(
        args.openclawBin,
        [
          'gateway', 'call', 'plugin.approval.request',
          '--json',
          '--expect-final',
          '--params', paramsJson,
          '--timeout', String(waitTimeoutMs),
        ],
        { timeout: waitTimeoutMs + 10_000, killSignal: 'SIGKILL', maxBuffer: 256 * 1024 },
        (err, out) => (err ? rejectPromise(err) : resolvePromise(String(out))),
      );
    });
  } catch (err) {
    const reason = `request failed: ${err instanceof Error ? err.message : String(err)}`;
    // Deliberately NOT cleared: the launcher's poll window is short, and a
    // fast failure must still be readable when it looks.
    writeReceipt(args.receiptPath, { phase: 'failed', reason, requested: true });
    await reportNothingRan('failed', 'the held retry card could not be delivered or answered (gateway call failed); nothing ran');
    return { acted: 'nothing', reason };
  }

  let decision: unknown;
  try {
    decision = (JSON.parse(stdout) as { decision?: unknown })?.decision;
  } catch {
    clearReceipt(args.receiptPath);
    await reportNothingRan('failed', 'the held retry card returned an unreadable answer; nothing ran');
    return { acted: 'nothing', reason: 'unparseable decision response' };
  }

  if (decision === 'allow-once') {
    const outcome = grantImpl(ref, { nonce }, { home: deps.home, now: deps.now, ttlMs: args.ttlMs });
    if (!outcome.ok) {
      // NO ack. The operator tapped Approve and the store said no — telling
      // them "granted" here is the one lie this path must never tell.
      writeReceipt(args.receiptPath, {
        phase: 'grant_failed',
        reason: outcome.reason,
        ...(args.actionId ? { actionId: args.actionId } : {}),
      });
      // #853 — and tell them, once, with no buttons: an Allow that produced no
      // grant must not sit in their chat reading as a yes.
      await reportNothingRan(
        'grant_failed',
        `retry grant refused (${outcome.reason}) after an operator Approve; nothing ran — authorise from a terminal instead`,
      );
      return { acted: 'nothing', reason: `grant_failed:${outcome.reason}` };
    }
    // Ack follows the store, never precedes it.
    writeReceipt(args.receiptPath, {
      phase: 'granted',
      ...(args.actionId ? { actionId: args.actionId } : {}),
    });
    appendOutcome(
      {
        event: 'action_guard_denial',
        outcome: 'retry_granted',
        origin: 'claude-code-hook',
        tool: outcome.grant.origin.tool,
        // #853 — approved is not run: nothing has run until the SAME call runs
        // again (a one-shot worker must be re-launched).
        reason: `operator authorised ONE retry (${Math.max(1, Math.round(outcome.grant.ttlMs / 60_000))}m, scoped); approved, not run: nothing runs until the same call is retried`,
        ...(args.actionId ? { actionId: args.actionId } : {}),
      },
      { home: deps.home },
    );
    return { acted: 'granted', id: outcome.id };
  }

  if (decision === 'deny') {
    const outcome = suppressImpl(ref, {
      home: deps.home,
      now: deps.now,
      suppressionMs: args.suppressionMs,
      via: 'card',
    });
    if (!outcome.ok) {
      writeReceipt(args.receiptPath, {
        phase: 'failed',
        reason: `suppression failed: ${outcome.reason}`,
        requested: true,
      });
      // The operator said no and nothing ran; only the silence could not be
      // recorded. Report the Deny honestly rather than as a transport failure.
      await reportNothingRan('denied', `operator denied the retry; nothing ran (silence could not be recorded: ${outcome.reason})`);
      return { acted: 'nothing', reason: `suppress_failed:${outcome.reason}` };
    }
    writeReceipt(args.receiptPath, {
      phase: 'denied',
      untilMs: outcome.untilMs,
      ...(args.actionId ? { actionId: args.actionId } : {}),
    });
    await reportNothingRan(
      'denied',
      `operator denied the retry; nothing ran; this action is silenced until ${new Date(outcome.untilMs).toISOString()}${outcome.revokedGrant ? ' (an unspent grant was revoked)' : ''}`,
    );
    return { acted: 'denied', untilMs: outcome.untilMs };
  }

  clearReceipt(args.receiptPath);
  if (decision === null || decision === undefined || decision === 'timeout') {
    await reportNothingRan('expired', 'the held retry card expired unanswered; nothing ran');
  } else {
    // Never guess what an unknown answer meant: nothing was granted.
    await reportNothingRan('failed', 'the held retry card returned an unrecognised decision; nothing ran');
  }
  return {
    acted: 'nothing',
    reason: `no actionable decision (${decision === null ? 'card expired unanswered' : String(decision)})`,
  };
}

/** Detached entrypoint:
 *  `node dnp-retry-waiter.js --params-b64 … --fingerprint … --nonce-fd 3 …` */
async function main(): Promise<void> {
  const args = parseRetryWaiterArgs(process.argv.slice(2));
  if (!args) process.exit(0);
  try {
    await runRetryWaiter(args);
  } catch {
    // A waiter that dies is a card whose tap goes unheard — the terminal
    // `shieldcortex approve --denial <actionId>` path is unchanged.
  }
  process.exit(0);
}

// Only run as a script when invoked directly, never on import — mirrors the
// convention used by the #143 waiter; tests import the exports above.
const invokedDirectly = (() => {
  try {
    const entry = process.argv[1];
    return typeof entry === 'string' && /dnp-retry-waiter\.(js|ts|mjs|cjs)$/.test(entry);
  } catch {
    return false;
  }
})();
if (invokedDirectly) void main();
