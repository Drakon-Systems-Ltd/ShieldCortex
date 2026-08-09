/**
 * ShieldCortex — the detached decision waiter for OpenClaw approval cards (#143).
 *
 * Spawned by openclaw-approval-channel.ts after a card is delivered, this is
 * the courier that carries the operator's tap from the OpenClaw gateway to
 * the #118 one-shot approval store. It is the moral equivalent of the
 * operator typing `shieldcortex approve <hash>` — with the human-is-driving
 * property established not by a TTY check (there is no TTY here) but by the
 * gateway's own approver authentication: `plugin.approval.resolve` only
 * accepts a decision from a resolved approver (the owner identities in the
 * gateway config), the same bar `/approve` in the operator's chat clears.
 *
 * The mapping is strict and total:
 *
 *   'allow-once'      → approveRequest(hash)   (single use, normal TTL)
 *   'deny'            → denyRequest(hash)      (terminal, record removed)
 *   anything else     → NOTHING
 *
 * "Anything else" is load-bearing. The gateway resolves a timed-out card
 * with `decision: null` — and silence from a human is not a "no", it is
 * silence: the pending record stays and expires on the store's own
 * retention, exactly as if no card had ever been sent. Likewise a gateway
 * error, an unparseable response, an unknown decision string, or a dead
 * gateway all end this process without touching the store. The only two
 * bytes of the outside world that can move the store are the two decision
 * strings this process itself offered on the card.
 *
 * Exits 0 in every case — a detached waiter has nobody to report to, and
 * its outcome is legible where it matters: in the store (a record now
 * approved/denied) and in the guard's own audit of the eventual retry.
 */
import { execFile } from 'node:child_process';
import { approveRequest, denyRequest } from './action-approvals.js';
import { WAIT_DECISION_TIMEOUT_MS } from './openclaw-approval-channel.js';

interface WaiterArgs {
  id: string;
  hash: string;
  openclawBin: string;
}

export function parseWaiterArgs(argv: string[]): WaiterArgs | null {
  const get = (flag: string): string | null => {
    const i = argv.indexOf(flag);
    return i >= 0 && i + 1 < argv.length ? argv[i + 1] : null;
  };
  const id = get('--id');
  const hash = get('--hash');
  const openclawBin = get('--openclaw-bin');
  if (!id || !hash || !openclawBin) return null;
  // The hash is about to be matched against the store; the id goes back to
  // the gateway that minted it. Neither should ever look like anything but
  // what it is — refuse rather than forward surprises.
  if (!/^[0-9a-f]{12,64}$/i.test(hash)) return null;
  return { id, hash, openclawBin };
}

export type WaiterOutcome =
  | { acted: 'approved' | 'denied'; ok: boolean }
  | { acted: 'nothing'; reason: string };

/**
 * Wait for the card's decision and translate it onto the store. Injectable
 * seams for tests; the strictness lives here, not in main().
 */
export async function runWaiter(
  args: WaiterArgs,
  deps: {
    execFileImpl?: typeof execFile;
    approveImpl?: typeof approveRequest;
    denyImpl?: typeof denyRequest;
    waitTimeoutMs?: number;
  } = {},
): Promise<WaiterOutcome> {
  const execFileImpl = deps.execFileImpl ?? execFile;
  const approveImpl = deps.approveImpl ?? approveRequest;
  const denyImpl = deps.denyImpl ?? denyRequest;
  const waitTimeoutMs = deps.waitTimeoutMs ?? WAIT_DECISION_TIMEOUT_MS;

  let stdout: string;
  try {
    stdout = await new Promise<string>((resolvePromise, rejectPromise) => {
      execFileImpl(
        args.openclawBin,
        [
          'gateway', 'call', 'plugin.approval.waitDecision',
          '--json',
          '--params', JSON.stringify({ id: args.id }),
          '--timeout', String(waitTimeoutMs),
        ],
        { timeout: waitTimeoutMs + 10_000, killSignal: 'SIGKILL', maxBuffer: 256 * 1024 },
        (err, out) => (err ? rejectPromise(err) : resolvePromise(String(out))),
      );
    });
  } catch (err) {
    return { acted: 'nothing', reason: `waitDecision failed: ${err instanceof Error ? err.message : String(err)}` };
  }

  let decision: unknown;
  try {
    const parsed = JSON.parse(stdout) as { decision?: unknown };
    decision = parsed?.decision;
  } catch {
    return { acted: 'nothing', reason: 'unparseable waitDecision response' };
  }

  // Strict equality against the two decisions the card offered. NOTE:
  // 'allow-always' is intentionally absent — the card never offers it
  // (openclaw-approval-channel.ts), and if a gateway reported it anyway,
  // honouring it here would grant a durable-sounding decision one single-use
  // pass under a label the operator never saw. Unknown means untouched.
  if (decision === 'allow-once') {
    const outcome = approveImpl(args.hash);
    return { acted: 'approved', ok: outcome.ok };
  }
  if (decision === 'deny') {
    const outcome = denyImpl(args.hash);
    return { acted: 'denied', ok: outcome.ok };
  }
  return { acted: 'nothing', reason: `no actionable decision (${decision === null ? 'card expired unanswered' : String(decision)})` };
}

/** Detached entrypoint: `node openclaw-approval-waiter.js --id … --hash … --openclaw-bin …` */
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
