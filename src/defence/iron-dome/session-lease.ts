/**
 * Iron Dome — Session Action Lease
 *
 * WHY THIS EXISTS (10 Aug 2026, and it is not hypothetical)
 * ---------------------------------------------------------
 * A single agent identity routinely runs as many concurrent processes: the
 * interactive session, ~20 isolated cron agents, sub-agents. They share a
 * filesystem and a name but cannot read each other's context. On 10 Aug that
 * cost one operator, in four hours:
 *
 *   - 11:14Z  a package published to the public npm registry, unauthorised and
 *             irreversible, by one session while another was still debating
 *             whether it could be installed internally
 *   - 11:29Z  a session announced to the fleet: nobody installs this until an
 *             independent review
 *   - 11:30Z  a DIFFERENT session installed it on two machines — 77 seconds
 *             after that freeze, having never seen it
 *
 * Nobody defied anything. The freeze lived in one context window, and a
 * commitment no other process can read binds nobody.
 *
 * The guard already answers "should this action proceed?" for content and
 * privilege. This adds the two questions a context window cannot answer:
 *
 *   1. Is a standing FREEZE in force for this class of action?
 *   2. Is another live session already holding it?
 *
 * DESIGN
 * ------
 * Pure decision, injected state. Nothing here touches disk: callers supply the
 * ledger text and the lease record, so every branch is testable and the same
 * logic serves both enforcement surfaces (the OpenClaw interceptor and the
 * Claude Code hook) without a shared runtime.
 *
 * FAILS CLOSED on an unreadable ledger. "I could not read the freezes" and
 * "nothing is frozen" must never produce the same behaviour — that equivalence
 * is precisely how a guard becomes decoration.
 */

/** Action classes worth serialising across sessions. Each is something that
 *  changed the world on 10 Aug without a second session knowing. */
export type LeaseScope =
  | 'npm-publish'
  | 'install'
  | 'gateway-restart'
  | 'security-config'
  | 'fleet-broadcast';

/**
 * Keywords that mean each scope, declared EXPLICITLY.
 *
 * An earlier stem-matching version let `install` sail past a freeze written
 * `installing` (guard silently off), then matched `instruction` to the same
 * freeze (guard fires on the wrong thing). Both failures are worse than a list
 * a human can read and audit, so the list is the design.
 */
export const SCOPE_KEYWORDS: Record<LeaseScope, readonly string[]> = {
  'npm-publish': ['publish', 'npm', 'registry'],
  install: ['install', 'upgrad'],
  'gateway-restart': ['gateway restart', 'restart the gateway', 'gateway restarts'],
  'security-config': ['security compon', 'trust key', 'guard posture', 'operatorpubkey'],
  'fleet-broadcast': ['broadcast', 'fleet directive'],
};

export interface LeaseRecord {
  holder: string;
  pid?: number | null;
  reason?: string;
  acquiredAtMs?: number;
  expiresAtMs?: number;
}

export interface LeaseCheckInput {
  scope: LeaseScope;
  /** Raw DECISIONS.md text, or null when it could not be read. */
  ledger: string | null;
  /** The lease currently on disk for this scope, or null when free. */
  held: LeaseRecord | null;
  /** Identity of the session asking — a holder may re-enter its own lease. */
  self: string;
  nowMs: number;
}

export type LeaseVerdict = 'allow' | 'frozen' | 'held' | 'unknown';

export interface LeaseDecision {
  verdict: LeaseVerdict;
  /** Operator-facing explanation. Never bare "denied": a refusal that does not
   *  say WHY, and who can lift it, is a refusal that gets routed around. */
  reason: string;
  /** The freeze record quoted verbatim, when one applies. */
  freeze?: string;
}

/**
 * Split DECISIONS.md into logical records.
 *
 * Records wrap across physical lines. A line-by-line version read only the
 * first fragment of every freeze and so never saw "gateway restarts", which sat
 * on a continuation line — the freeze was live, formatted innocently, and
 * silently unenforced. Blank lines separate records; everything else is joined.
 */
export function parseFreezeRecords(ledger: string): string[] {
  return ledger
    .split(/\n\s*\n/)
    .map((block) => block.split(/\s+/).join(' ').trim())
    .filter((record) => record.includes('| FROZEN |'));
}

/** The first freeze record naming this scope, or null. */
export function findFreeze(ledger: string, scope: LeaseScope): string | null {
  const keywords = SCOPE_KEYWORDS[scope] ?? [];
  for (const record of parseFreezeRecords(ledger)) {
    const lowered = record.toLowerCase();
    if (keywords.some((k) => lowered.includes(k))) return record;
  }
  return null;
}

/**
 * Decide whether this session may take the action.
 *
 * Order matters: a FREEZE outranks lease availability. An unheld lease on a
 * frozen scope is still a refusal — otherwise the first session to arrive after
 * a freeze would sail through, which is exactly the 11:30 install.
 */
export function checkSessionLease(input: LeaseCheckInput): LeaseDecision {
  const { scope, ledger, held, self, nowMs } = input;

  if (ledger == null) {
    return {
      verdict: 'unknown',
      reason:
        `cannot read the decisions ledger, so cannot know whether ${scope} is frozen — ` +
        `refusing rather than assuming it is clear`,
    };
  }

  const freeze = findFreeze(ledger, scope);
  if (freeze) {
    return {
      verdict: 'frozen',
      freeze,
      reason:
        `${scope} is FROZEN by a standing decision: "${freeze.slice(0, 180)}". ` +
        `A freeze is lifted by the operator editing DECISIONS.md — never by an agent ` +
        `deciding it does not apply to this case.`,
    };
  }

  if (held) {
    // An expired lease is not a held one; a crashed session must not wedge the
    // fleet forever, which is why every lease carries a TTL.
    const expired = held.expiresAtMs != null && nowMs > held.expiresAtMs;
    if (!expired) {
      // Re-entrancy: the holder may continue its own work. Without this a
      // multi-step action (acquire, then several tool calls) would deadlock
      // against itself and teach operators to disable the gate.
      if (held.holder === self) {
        return { verdict: 'allow', reason: `${scope} lease already held by this session` };
      }
      const ageSec = held.acquiredAtMs != null ? Math.round((nowMs - held.acquiredAtMs) / 1000) : null;
      return {
        verdict: 'held',
        reason:
          `${scope} is held by another session (${held.holder}` +
          (held.pid != null ? `, pid ${held.pid}` : '') +
          (ageSec != null ? `, ${ageSec}s ago` : '') +
          `)${held.reason ? `: ${held.reason}` : ''}. Wait for it to finish or expire — do not force it.`,
      };
    }
  }

  return { verdict: 'allow', reason: `${scope} is neither frozen nor held` };
}

/** Whether a verdict permits the action. Single definition so no caller can
 *  invent its own idea of which verdicts are safe. */
export function leasePermits(decision: LeaseDecision): boolean {
  return decision.verdict === 'allow';
}
