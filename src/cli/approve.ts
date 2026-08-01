/**
 * `shieldcortex approve` — grant a one-shot, exact-command Action Guard approval.
 *
 * Usage:
 *   shieldcortex approve            # list what the guard has refused recently
 *   shieldcortex approve <hash>     # approve that exact call, once, for 10 minutes
 *   shieldcortex approve <hash> --ttl 2   # ...for 2 minutes instead
 *
 * This is deliberately operator-only: it refuses to run unless stdin and stdout
 * are both TTYs, so an agent shelling out cannot approve its own blocked
 * command (issue #118 threat model). There is no env-var escape hatch — one
 * would be indistinguishable from the bypass this exists to prevent.
 */

import {
  approveRequest,
  listApprovals,
  shortHash,
  DEFAULT_APPROVAL_TTL_MS,
  type ApprovalRecord,
} from '../defence/iron-dome/action-approvals.js';

const BOLD = '\x1b[1m';
const DIM = '\x1b[2m';
const GREEN = '\x1b[32m';
const YELLOW = '\x1b[33m';
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

function renderList(records: ApprovalRecord[], now: number): string {
  if (records.length === 0) {
    return `${DIM}No pending Action Guard approvals.${RESET}\n`;
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

export interface ApproveDeps {
  now?: number;
  home?: string;
  interactive?: boolean;
  log?: (msg: string) => void;
  error?: (msg: string) => void;
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
  if (ttlIndex >= 0) {
    const minutes = Number(args[ttlIndex + 1]);
    if (!Number.isFinite(minutes) || minutes <= 0) {
      err('--ttl expects a positive number of minutes, e.g. --ttl 2');
      return 1;
    }
    ttlMs = minutes * 60 * 1000;
    args.splice(ttlIndex, 2);
  }

  const hash = args.find((a) => !a.startsWith('-'));

  if (!hash) {
    log(renderList(listApprovals({ home, now }), now));
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
  log(`${GREEN}✓${RESET} Approved ${BOLD}${shortHash(r.hash)}${RESET} (${r.tool}) for ${Math.round(ttlMs / 60000)} minute(s).`);
  log(`  ${r.summary}`);
  log(`${DIM}  Single use — the next run of this exact command passes, then it is spent.${RESET}`);
  return 0;
}
