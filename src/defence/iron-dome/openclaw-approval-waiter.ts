/**
 * ShieldCortex — the detached card owner for OpenClaw approvals (#143).
 *
 * Spawned by openclaw-approval-channel.ts, this process owns the approval
 * card end-to-end: the gateway scopes a pending approval to the connection
 * that requested it, so the request and the wait for the human's tap must
 * live on ONE long-lived `openclaw gateway call plugin.approval.request`
 * invocation — which cannot be the hook (one process per tool call) and so
 * is this. It is the moral equivalent of the operator typing `shieldcortex
 * approve <hash>` — with the human-is-driving property established not by a
 * TTY check (there is no TTY here) but by the gateway's own approver
 * authentication: only a resolved approver (the owner identities in the
 * gateway config) can tap the card, the same bar `/approve` in the
 * operator's chat clears.
 *
 * The decision mapping is strict and total:
 *
 *   'allow-once'      → approveRequest(hash)   (single use, normal TTL)
 *   'deny'            → denyRequest(hash)      (terminal, record removed)
 *   anything else     → NOTHING
 *
 * "Anything else" is load-bearing. The gateway reports a timed-out card as
 * `decision: null` — and silence from a human is not a "no", it is silence:
 * the pending record stays and expires on the store's own retention,
 * exactly as if no card had ever been sent. Likewise a gateway error, an
 * unparseable response, an unknown decision string ('allow-always' was
 * never offered — honouring it would grant under a label the operator never
 * saw), or a dead gateway all end this process without touching the store.
 *
 * The receipt file is the channel's only view of this process: written as
 * `{"phase":"requesting"}` BEFORE dialling, rewritten `{"phase":"failed"}`
 * on any fast failure, deleted on the way out. It never carries a decision
 * — two phases, both of them pre-decision, by construction.
 *
 * Exits 0 in every case — a detached waiter has nobody to report to, and
 * its outcome is legible where it matters: in the store (a record now
 * approved/denied) and in the guard's own audit of the eventual retry.
 *
 * #509: silence and failure are also evidence. A card that expires
 * unanswered or a request the gateway refused appends an `approval_reach`
 * answer row (`timeout` / `unreached`) — approval reachability counts it as
 * NOT reaching a human. An answered card is recorded by the store itself
 * (approveRequest / denyRequest), so it is counted exactly once.
 */
import { execFile } from 'node:child_process';
import { mkdirSync, rmSync, writeFileSync } from 'node:fs';
import { dirname } from 'node:path';
import { approveRequest, denyRequest } from './action-approvals.js';
import { recordApprovalReach } from './guard-readiness.js';
import { WAIT_DECISION_TIMEOUT_MS } from './openclaw-approval-channel.js';

export interface WaiterArgs {
  paramsB64: string;
  hash: string;
  openclawBin: string;
  receiptPath: string;
}

export function parseWaiterArgs(argv: string[]): WaiterArgs | null {
  const get = (flag: string): string | null => {
    const i = argv.indexOf(flag);
    return i >= 0 && i + 1 < argv.length ? argv[i + 1] : null;
  };
  const paramsB64 = get('--params-b64');
  const hash = get('--hash');
  const openclawBin = get('--openclaw-bin');
  const receiptPath = get('--receipt');
  if (!paramsB64 || !hash || !openclawBin || !receiptPath) return null;
  // The hash is about to be matched against the store — refuse anything that
  // does not look like one rather than forward surprises.
  if (!/^[0-9a-f]{12,64}$/i.test(hash)) return null;
  return { paramsB64, hash, openclawBin, receiptPath };
}

export type WaiterOutcome =
  | { acted: 'approved' | 'denied'; ok: boolean }
  | { acted: 'nothing'; reason: string };

function writeReceipt(path: string, receipt: { phase: 'requesting' } | { phase: 'failed'; reason: string }): void {
  try {
    mkdirSync(dirname(path), { recursive: true, mode: 0o700 });
    writeFileSync(path, JSON.stringify(receipt), { mode: 0o600 });
  } catch {
    /* a receipt that cannot be written degrades the channel's report, not the decision path */
  }
}

function clearReceipt(path: string): void {
  try {
    rmSync(path, { force: true });
  } catch {
    /* best-effort */
  }
}

/**
 * Own the card: request, wait, translate. Injectable seams for tests; the
 * strictness lives here, not in main().
 */
export async function runWaiter(
  args: WaiterArgs,
  deps: {
    execFileImpl?: typeof execFile;
    approveImpl?: typeof approveRequest;
    denyImpl?: typeof denyRequest;
    recordReachImpl?: typeof recordApprovalReach;
    waitTimeoutMs?: number;
  } = {},
): Promise<WaiterOutcome> {
  const execFileImpl = deps.execFileImpl ?? execFile;
  const approveImpl = deps.approveImpl ?? approveRequest;
  const denyImpl = deps.denyImpl ?? denyRequest;
  const recordReach = (input: Parameters<typeof recordApprovalReach>[0]): void => {
    try { (deps.recordReachImpl ?? recordApprovalReach)(input); } catch { /* evidence is best-effort */ }
  };
  const waitTimeoutMs = deps.waitTimeoutMs ?? WAIT_DECISION_TIMEOUT_MS;

  let paramsJson: string;
  try {
    paramsJson = Buffer.from(args.paramsB64, 'base64').toString('utf8');
    JSON.parse(paramsJson); // shape is the gateway's problem; parseability is ours
  } catch {
    writeReceipt(args.receiptPath, { phase: 'failed', reason: 'unparseable card params' });
    clearReceipt(args.receiptPath);
    return { acted: 'nothing', reason: 'unparseable card params' };
  }

  writeReceipt(args.receiptPath, { phase: 'requesting' });

  const call = await callApprovalGateway(execFileImpl, args.openclawBin, paramsJson, waitTimeoutMs);
  if (!call.ok && call.stage === 'request') {
    writeReceipt(args.receiptPath, { phase: 'failed', reason: call.reason });
    // Deliberately NOT cleared: the channel's poll window is short, and a
    // fast failure must still be readable when it looks. The receipt dir is
    // tmp — the OS owns its lifecycle.
    recordReach({ hash: args.hash, phase: 'answer', answer: 'unreached', reason: 'gateway request failed', origin: 'approval-waiter' });
    return { acted: 'nothing', reason: call.reason };
  }

  clearReceipt(args.receiptPath);

  if (!call.ok) {
    recordReach({ hash: args.hash, phase: 'answer', answer: 'unreached', reason: call.reason, origin: 'approval-waiter' });
    return { acted: 'nothing', reason: call.reason };
  }
  const decision = call.decision;

  if (decision === 'allow-once') {
    const outcome = approveImpl(args.hash);
    // The store records the reach on success; a tap that found no record
    // (already answered elsewhere, expired) still proves a human was reached.
    if (!outcome.ok) recordReach({ hash: args.hash, phase: 'answer', answer: 'approve', origin: 'approval-waiter' });
    return { acted: 'approved', ok: outcome.ok };
  }
  if (decision === 'deny') {
    const outcome = denyImpl(args.hash);
    if (!outcome.ok) recordReach({ hash: args.hash, phase: 'answer', answer: 'deny', origin: 'approval-waiter' });
    return { acted: 'denied', ok: outcome.ok };
  }
  recordReach({
    hash: args.hash,
    phase: 'answer',
    answer: decision === null ? 'timeout' : 'unreached',
    reason: decision === null ? 'card expired unanswered' : 'unrecognised decision',
    origin: 'approval-waiter',
  });
  return {
    acted: 'nothing',
    reason: `no actionable decision (${decision === null ? 'card expired unanswered' : String(decision)})`,
  };
}

/**
 * One `plugin.approval.request` round-trip on ONE connection: request the
 * card, block until the gateway reports the tap (or its expiry). Returns the
 * raw decision value, which callers map — this function grants nothing.
 * Shared with `shieldcortex guard test-approval` (#509), whose synthetic card
 * must travel the exact path a real one does.
 */
export async function callApprovalGateway(
  execFileImpl: typeof execFile,
  openclawBin: string,
  paramsJson: string,
  waitTimeoutMs: number,
): Promise<{ ok: true; decision: unknown } | { ok: false; stage: 'request' | 'parse'; reason: string }> {
  let stdout: string;
  try {
    stdout = await new Promise<string>((resolvePromise, rejectPromise) => {
      execFileImpl(
        openclawBin,
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
    return { ok: false, stage: 'request', reason: `request failed: ${err instanceof Error ? err.message : String(err)}` };
  }
  try {
    const parsed = JSON.parse(stdout) as { decision?: unknown };
    return { ok: true, decision: parsed?.decision };
  } catch {
    return { ok: false, stage: 'parse', reason: 'unparseable decision response' };
  }
}

/** Detached entrypoint:
 *  `node openclaw-approval-waiter.js --params-b64 … --hash … --openclaw-bin … --receipt …` */
async function main(): Promise<void> {
  const args = parseWaiterArgs(process.argv.slice(2));
  if (!args) process.exit(0);
  try {
    await runWaiter(args);
  } catch {
    // A waiter that dies is a card whose tap goes unheard — the terminal
    // hash fallback (printed with the refusal) remains the working path.
  }
  process.exit(0);
}

// Only run as a script when invoked directly, never on import — mirrors the
// convention used by scripts/ entries; tests import the exports above.
const invokedDirectly = (() => {
  try {
    const entry = process.argv[1];
    return typeof entry === 'string' && /openclaw-approval-waiter\.(js|ts|mjs|cjs)$/.test(entry);
  } catch {
    return false;
  }
})();
if (invokedDirectly) void main();
