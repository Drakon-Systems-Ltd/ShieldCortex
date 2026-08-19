/**
 * `shieldcortex approve` — grant a one-shot Action Guard approval.
 *
 * Usage:
 *   shieldcortex approve                    # list what the guard has refused recently
 *   shieldcortex approve <hash>             # approve that exact HELD call, once, for 10 minutes
 *   shieldcortex approve <hash> --ttl 2     # ...for 2 minutes instead
 *
 *   shieldcortex approve --denial           # list headless denials awaiting a retry decision (#310)
 *   shieldcortex approve --denial <actionId>              # authorise ONE retry, scoped to cwd+tool
 *   shieldcortex approve --denial <actionId> --ttl 20     # ...with a 20-minute spend window
 *   shieldcortex approve --denial <actionId> --any-origin # ...unscoped (confirmed, dangerous)
 *   shieldcortex approve --denial <actionId> --override-deny  # ...despite your own earlier Deny
 *
 * Two different things live behind one verb, deliberately: `<hash>` answers a
 * call that is still HELD (#118), `--denial` authorises a RETRY of one that was
 * already refused on a promptless box (#310). Both are operator-only — they
 * refuse to run unless stdin and stdout are both TTYs, so an agent shelling out
 * cannot approve its own blocked command. There is no env-var escape hatch: one
 * would be indistinguishable from the bypass this exists to prevent.
 */

import { existsSync, readSync } from 'node:fs';

import {
  approveRequest,
  listApprovals,
  shortHash,
  DEFAULT_APPROVAL_TTL_MS,
  type ApprovalRecord,
} from '../defence/iron-dome/action-approvals.js';
import {
  DEFAULT_RETRY_GRANT_TTL_MS,
  MAX_RETRY_GRANT_TTL_MS,
  MIN_RETRY_GRANT_TTL_MS,
  formatUnspentExpiryNotice,
  grantRetry,
  listRetryRows,
  pruneRetryControl,
  retryControlPath,
  scopeTail,
  type RetryRow,
} from '../defence/iron-dome/retry-control.js';

const BOLD = '\x1b[1m';
const DIM = '\x1b[2m';
const GREEN = '\x1b[32m';
const YELLOW = '\x1b[33m';
const RED = '\x1b[31m';
const RESET = '\x1b[0m';

/** True only when a human is plausibly at the keyboard. */
export function isInteractive(streams: { stdin?: { isTTY?: boolean }; stdout?: { isTTY?: boolean } } = process): boolean {
  return Boolean(streams.stdin?.isTTY && streams.stdout?.isTTY);
}

function age(ms: number): string {
  const s = Math.max(0, Math.round(ms / 1000));
  if (s < 60) return `${s}s ago`;
  if (s < 3600) return `${Math.round(s / 60)}m ago`;
  return `${Math.round(s / 3600)}h ago`;
}

function renderList(records: ApprovalRecord[], now: number, retryRows: RetryRow[] = []): string {
  if (records.length === 0) {
    const lines = [`${DIM}No pending Action Guard approvals.${RESET}`];
    if (retryRows.length > 0) {
      lines.push(
        `${DIM}${retryRows.length} headless denial(s) on file — list with: shieldcortex approve --denial${RESET}`,
      );
    }
    return `${lines.join('\n')}\n`;
  }
  const lines: string[] = [`${BOLD}Action Guard — recent refusals${RESET}\n`];
  for (const r of records) {
    const live = r.approvedAt
      ? `${GREEN}approved${RESET} ${DIM}(expires in ${Math.max(
          0,
          Math.round(((r.ttlMs ?? DEFAULT_APPROVAL_TTL_MS) - (now - r.approvedAt)) / 1000),
        )}s)${RESET}`
      : `${YELLOW}pending${RESET}`;
    lines.push(`  ${BOLD}${shortHash(r.hash)}${RESET}  ${r.tool}  ${live}`);
    lines.push(`     ${r.summary}`);
    lines.push(`     ${DIM}${r.signals.join(', ') || 'no signals'} · seen ${age(now - r.requestedAt)}${RESET}`);
    lines.push('');
  }
  lines.push(`${DIM}Approve one with: shieldcortex approve <hash>${RESET}\n`);
  return lines.join('\n');
}

/** #310 — the headless-denial list. A separate rendering from the held-call
 *  list above because the two answer different questions: this one is "a job
 *  DIED; do you want to authorise one retry?", never "should this run?". */
function renderDenialList(rows: RetryRow[], now: number): string {
  if (rows.length === 0) {
    return `${DIM}No headless denials on file (nothing to retry).${RESET}\n`;
  }
  const lines: string[] = [`${BOLD}Action Guard — headless denials (already refused)${RESET}\n`];
  for (const r of rows) {
    const actionId = r.actionIds[r.actionIds.length - 1] ?? `(no actionId, hash ${shortHash(r.hash)})`;
    const state = r.grant && !r.grant.consumedAt && now - r.grant.approvedAt < r.grant.ttlMs
      ? `${GREEN}retry authorised${RESET} ${DIM}(expires in ${Math.max(0, Math.round((r.grant.ttlMs - (now - r.grant.approvedAt)) / 1000))}s)${RESET}`
      : r.suppression && r.suppression.until > now
        ? `${RED}denied${RESET} ${DIM}(silenced for ${Math.max(1, Math.round((r.suppression.until - now) / 60_000))}m more)${RESET}`
        : r.claim && r.claim.expiresAt > now
          ? `${YELLOW}card out${RESET} ${DIM}(awaiting a tap)${RESET}`
          : `${YELLOW}denied, no decision${RESET}`;
    lines.push(`  ${BOLD}${actionId}${RESET}  ${r.tool}  ${state}`);
    lines.push(`     ${r.redactedSurface || '(no surface recorded)'}`);
    lines.push(
      `     ${DIM}${r.signals.join(', ') || 'no signals'} · scope ${r.originScope.cwd ?? 'UNSCOPEABLE'} · last denied ${age(now - r.lastDeniedAt)}${RESET}`,
    );
    lines.push('');
  }
  lines.push(`${DIM}Authorise ONE retry with: shieldcortex approve --denial <actionId>${RESET}\n`);
  return lines.join('\n');
}

/**
 * A blocking yes/no on the real terminal. Only ever reached after the TTY gate
 * has already passed, and only for the two flags that widen a grant beyond its
 * default — an operator who is about to hand out something unusual reads the
 * sentence and types the word.
 */
function defaultConfirm(question: string): boolean {
  try {
    process.stdout.write(`${question}\nType "yes" to continue: `);
    const buf = Buffer.alloc(64);
    const n = readSync(0, buf, 0, 64, null);
    return buf.subarray(0, n).toString('utf8').trim().toLowerCase() === 'yes';
  } catch {
    // No readable stdin means no confirmation — which means no grant.
    return false;
  }
}

export interface ApproveDeps {
  now?: number;
  home?: string;
  interactive?: boolean;
  log?: (msg: string) => void;
  error?: (msg: string) => void;
  /** Injected by tests; the real one reads a line from the operator's TTY. */
  confirm?: (question: string) => boolean;
}

/**
 * Returns the process exit code: 0 on success, 1 on a refusal the operator
 * needs to see. Never throws for ordinary "no such hash" outcomes.
 */
export function runApprove(argv: string[], deps: ApproveDeps = {}): number {
  const now = deps.now ?? Date.now();
  const home = deps.home;
  const log = deps.log ?? ((m: string) => console.log(m));
  const err = deps.error ?? ((m: string) => console.error(m));

  const args = argv.filter((a) => a !== '--');
  const ttlIndex = args.findIndex((a) => a === '--ttl');
  let ttlMs = DEFAULT_APPROVAL_TTL_MS;
  let ttlGiven = false;
  if (ttlIndex >= 0) {
    const minutes = Number(args[ttlIndex + 1]);
    if (!Number.isFinite(minutes) || minutes <= 0) {
      err('--ttl expects a positive number of minutes, e.g. --ttl 2');
      return 1;
    }
    ttlMs = minutes * 60 * 1000;
    ttlGiven = true;
    args.splice(ttlIndex, 2);
  }

  const anyOrigin = args.includes('--any-origin');
  const overrideDeny = args.includes('--override-deny');
  const denialIndex = args.indexOf('--denial');
  const positional = args.filter((a) => !a.startsWith('-'));

  // #310 opportunistic sweeper. No daemon exists, so the "your retry grant
  // expired unspent" notice rides the next guard event OR the next time an
  // operator looks — this is the second of those two triggers. Skipped
  // entirely when the store has never been written, so an install that never
  // switched retry cards on is untouched.
  if (existsSync(retryControlPath(home))) {
    const swept = pruneRetryControl({ home, now });
    if (swept.expired.length > 0) log(`${YELLOW}${formatUnspentExpiryNotice(swept.expired)}${RESET}\n`);
  }

  if (denialIndex >= 0) {
    return runDenialRetry(
      { actionId: positional[0], ttlMs: ttlGiven ? ttlMs : DEFAULT_RETRY_GRANT_TTL_MS, anyOrigin, overrideDeny },
      { now, home, log, err, interactive: deps.interactive, confirm: deps.confirm ?? defaultConfirm },
    );
  }

  if (anyOrigin || overrideDeny) {
    err('--any-origin and --override-deny only apply to `shieldcortex approve --denial <actionId>`.');
    return 1;
  }

  const hash = positional[0];

  if (!hash) {
    log(renderList(listApprovals({ home, now }), now, listRetryRows({ home, now })));
    return 0;
  }

  // Listing is harmless; granting is not.
  const interactive = deps.interactive ?? isInteractive();
  if (!interactive) {
    err('shieldcortex approve must be run by a human in an interactive terminal.');
    err('Refusing: stdin/stdout are not TTYs, so this could be the agent approving its own blocked command.');
    return 1;
  }

  const outcome = approveRequest(hash, { home, now, ttlMs });
  if (!outcome.ok) {
    if (outcome.reason === 'already-approved') {
      err(`Approval ${hash} is already granted and still live — just re-run the command.`);
    } else {
      err(`No pending approval matches "${hash}".`);
      err('Run `shieldcortex approve` with no arguments to see what is outstanding.');
    }
    return 1;
  }

  const r = outcome.record;
  log(`${GREEN}✓${RESET} Approved ${BOLD}${shortHash(r.hash)}${RESET} (${r.tool}) for ${Math.round(ttlMs / 60000)} minute(s) from now.`);
  log(`  ${r.summary}`);
  log(`${DIM}  Single use — the next run of this exact command passes, then it is spent.${RESET}`);
  return 0;
}

interface DenialRetryArgs {
  actionId?: string;
  ttlMs: number;
  anyOrigin: boolean;
  overrideDeny: boolean;
}

interface DenialRetryDeps {
  now: number;
  home?: string;
  log: (msg: string) => void;
  err: (msg: string) => void;
  interactive?: boolean;
  confirm: (question: string) => boolean;
}

/**
 * `shieldcortex approve --denial <actionId>` (#310).
 *
 * The TTY half of retry control, and the ONLY half that can widen a grant:
 * `--any-origin` drops the cwd binding and `--override-deny` overrules the
 * operator's own earlier Deny. Both are off by default and both require a
 * typed confirmation that names, in plain words, what is being handed out — a
 * card can set neither, ever.
 */
function runDenialRetry(args: DenialRetryArgs, deps: DenialRetryDeps): number {
  const { now, home, log, err } = deps;

  // Bounded HERE rather than silently defaulted downstream: an operator who
  // typed `--ttl 120` and got a 10-minute grant would have been told one thing
  // and handed another.
  if (args.ttlMs < MIN_RETRY_GRANT_TTL_MS || args.ttlMs > MAX_RETRY_GRANT_TTL_MS) {
    err(
      `--ttl for a retry must be between ${MIN_RETRY_GRANT_TTL_MS / 60_000} and `
      + `${MAX_RETRY_GRANT_TTL_MS / 60_000} minutes (a retry grant is a short window, not standing trust).`,
    );
    return 1;
  }

  if (!args.actionId) {
    log(renderDenialList(listRetryRows({ home, now }), now));
    return 0;
  }

  const interactive = deps.interactive ?? isInteractive();
  if (!interactive) {
    err('shieldcortex approve --denial must be run by a human in an interactive terminal.');
    err('Refusing: stdin/stdout are not TTYs, so this could be the agent authorising its own retry.');
    return 1;
  }

  const row = listRetryRows({ home, now }).find((r) => r.actionIds.includes(args.actionId as string))
    ?? listRetryRows({ home, now }).find((r) => r.id === args.actionId);
  if (!row) {
    err(`No headless denial matches "${args.actionId}".`);
    err('Run `shieldcortex approve --denial` with no id to see what is on file.');
    return 1;
  }

  if (args.anyOrigin) {
    const ok = deps.confirm(
      `${RED}--any-origin removes the directory binding from this grant.${RESET}\n`
      + `ANY local process, in ANY directory, may spend it once within ${Math.round(args.ttlMs / 60_000)} minute(s).`,
    );
    if (!ok) {
      err('Not confirmed — nothing was granted.');
      return 1;
    }
  }

  const suppressedUntil = row.suppression && row.suppression.until > now ? row.suppression.until : null;
  if (suppressedUntil && !args.overrideDeny) {
    err(`You denied this action at ${new Date(row.suppression!.at).toISOString()}; it is silenced until ${new Date(suppressedUntil).toISOString()}.`);
    err('Re-run with --override-deny to overrule your own Deny, or wait for the window to end.');
    return 1;
  }
  if (suppressedUntil && args.overrideDeny) {
    const ok = deps.confirm(
      `${RED}You are overriding your OWN deny from ${new Date(row.suppression!.at).toISOString()}.${RESET}\n`
      + 'That deny silenced this action; approving now cancels the silence and authorises one retry.',
    );
    if (!ok) {
      err('Not confirmed — the deny stands and nothing was granted.');
      return 1;
    }
  }

  const outcome = grantRetry(
    { id: row.id, actionId: args.actionId },
    { isInteractive: true, anyOrigin: args.anyOrigin, overrideDeny: args.overrideDeny },
    { home, now, ttlMs: args.ttlMs },
  );

  if (!outcome.ok) {
    if (outcome.reason === 'unscopeable') {
      err('This denial has no recorded working directory, so a scoped grant is impossible.');
      err('Re-run with --any-origin if you accept that ANY local process may spend it.');
    } else if (outcome.reason === 'suppressed') {
      err(`This action is silenced by your own Deny until ${new Date(outcome.suppressedUntilMs ?? now).toISOString()}.`);
      err('Re-run with --override-deny to overrule it.');
    } else if (outcome.reason === 'locked') {
      err('The retry-control store is busy (another guard event holds the lock). Try again in a moment.');
    } else {
      err(`Could not authorise a retry for "${args.actionId}" (${outcome.reason}).`);
    }
    return 1;
  }

  const grant = outcome.grant;
  const minutes = Math.max(1, Math.round(grant.ttlMs / 60_000));
  if (outcome.alreadyGranted) {
    const remaining = Math.max(0, Math.round((grant.approvedAt + grant.ttlMs - now) / 1000));
    log(`${GREEN}✓${RESET} Already authorised — one retry is live for another ${remaining}s (approved at ${new Date(grant.approvedAt).toISOString()}).`);
    log(`${DIM}  Re-approving does NOT extend it; the original window stands.${RESET}`);
    return 0;
  }

  log(`${GREEN}✓${RESET} Authorised ONE retry of ${BOLD}${row.tool}${RESET} (${args.actionId}).`);
  log(`  ${row.redactedSurface || '(no surface recorded)'}`);
  log(
    grant.origin.anyOrigin
      ? `${DIM}  Scope: ANY directory (--any-origin), tool ${grant.origin.tool}.${RESET}`
      : `${DIM}  Scope: ${grant.origin.cwd} (${scopeTail(grant.origin.cwd)}), tool ${grant.origin.tool}.${RESET}`,
  );
  log(
    `${DIM}  Spend window: ${minutes} minute(s) from now (expires ${new Date(grant.approvedAt + grant.ttlMs).toISOString()}).${RESET}`,
  );
  log(`${DIM}  Single use — the first matching call inside that window passes, then it is spent. Nothing else changes.${RESET}`);
  return 0;
}
