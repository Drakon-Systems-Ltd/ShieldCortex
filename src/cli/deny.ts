/**
 * `shieldcortex deny` — reject a pending Action Guard approval request (#143).
 *
 * Usage:
 *   shieldcortex deny            # list what the guard has refused recently
 *   shieldcortex deny <hash>     # deny that exact call, once and for all
 *
 * The sibling of `shieldcortex approve` (#118): same store, same hash, same
 * TTY gate. It exists because a notification transport that only offers an
 * "approve" affordance biases every ambiguous reply toward release — deny
 * must be exactly as cheap as approve (design doc, #143 acceptance criteria).
 *
 * Interactive-only for the same reason `approve` is: an agent that could deny
 * its own pending request non-interactively could quietly wipe a suspicious
 * refusal from the operator's queue before they ever saw it. There is no
 * env-var escape hatch, matching approve.ts.
 */

import {
  denyRequest,
  listApprovals,
  shortHash,
  type ApprovalRecord,
} from '../defence/iron-dome/action-approvals.js';
import { isInteractive } from './approve.js';

const BOLD = '\x1b[1m';
const DIM = '\x1b[2m';
const RED = '\x1b[31m';
const YELLOW = '\x1b[33m';
const RESET = '\x1b[0m';

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
    const live = r.approvedAt ? `${YELLOW}already approved${RESET}` : `${YELLOW}pending${RESET}`;
    lines.push(`  ${BOLD}${shortHash(r.hash)}${RESET}  ${r.tool}  ${live}`);
    lines.push(`     ${r.summary}`);
    lines.push(`     ${DIM}${r.signals.join(', ') || 'no signals'} · seen ${age(now - r.requestedAt)}${RESET}`);
    lines.push('');
  }
  lines.push(`${DIM}Deny one with: shieldcortex deny <hash>${RESET}\n`);
  return lines.join('\n');
}

export interface DenyDeps {
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
export function runDeny(argv: string[], deps: DenyDeps = {}): number {
  const now = deps.now ?? Date.now();
  const home = deps.home;
  const log = deps.log ?? ((m: string) => console.log(m));
  const err = deps.error ?? ((m: string) => console.error(m));

  const args = argv.filter((a) => a !== '--');
  const hash = args.find((a) => !a.startsWith('-'));

  if (!hash) {
    log(renderList(listApprovals({ home, now }), now));
    return 0;
  }

  // Listing is harmless; denying (like approving) is a decision, so it needs
  // a human at the keyboard.
  const interactive = deps.interactive ?? isInteractive();
  if (!interactive) {
    err('shieldcortex deny must be run by a human in an interactive terminal.');
    err('Refusing: stdin/stdout are not TTYs, so this could be the agent denying its own pending request.');
    return 1;
  }

  const outcome = denyRequest(hash, { home, now });
  if (!outcome.ok) {
    if (outcome.reason === 'already-approved') {
      err(`Approval ${hash} was already granted — it cannot be denied after the fact.`);
      err('If this was a mistake, let the approval expire; it is single-use.');
    } else {
      err(`No pending approval matches "${hash}".`);
      err('Run `shieldcortex deny` with no arguments to see what is outstanding.');
    }
    return 1;
  }

  const r = outcome.record;
  log(`${RED}✕${RESET} Denied ${BOLD}${shortHash(r.hash)}${RESET} (${r.tool}).`);
  log(`  ${r.summary}`);
  log(`${DIM}  This exact command will be refused again if the agent retries it.${RESET}`);
  return 0;
}
