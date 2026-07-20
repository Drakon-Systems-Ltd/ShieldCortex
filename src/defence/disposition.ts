/**
 * P1/WS4 (issue #61) — the single verdict→disposition mapping shared by EVERY
 * memory capture path (store.ts:addMemory and the Claude Code hook's
 * save-memory.mjs). Before this, the two paths forked: the hook routed purely
 * on `firewall.result` and neither applied the sub-agent trust-band hold nor
 * held a BLOCK, so a high-confidence poisoning write could be disposed of
 * differently depending on which runtime captured it. One function, one policy,
 * so the runtimes cannot drift.
 *
 * Consumed from TypeScript (store.ts) directly and from the `.mjs` hook via a
 * dynamic import of the compiled `dist/defence/disposition.js`.
 */

/** The sub-agent auto-quarantine trust band: an ALLOW verdict whose source
 *  trust falls in [MIN, MAX) is HELD for parent approval, never stored live. */
export const SUBAGENT_QUARANTINE_MIN = 0.5;
export const SUBAGENT_QUARANTINE_MAX = 0.7;

export interface DispositionInput {
  /** Pipeline `result.allowed`. */
  allowed: boolean;
  /** Pipeline `result.firewall.result` ('ALLOW' | 'BLOCK' | 'QUARANTINE'). */
  firewallResult: string;
  /** Pipeline `result.trust.score`. */
  trustScore: number;
  /** Pipeline `result.firewall.reason`. */
  reason: string;
}

export interface Disposition {
  /** 'store' → write to memories; 'quarantine' → hold in the quarantine table. */
  action: 'store' | 'quarantine';
  /** The verdict to record on the held row (BLOCK is preserved with its flag). */
  firewallResult: 'ALLOW' | 'BLOCK' | 'QUARANTINE';
  reason: string;
  /** True when an ALLOW was flipped to a hold by the sub-agent trust band —
   *  the caller may need to sync the (now-held) content it would otherwise not. */
  subAgentHold: boolean;
}

/**
 * Resolve where a scanned write goes. High-confidence poisoning ⇒ held
 * (quarantine) on every path; a BLOCK is held with its flag (forensically
 * preserved, auto-rejected at review — never silently dropped, never stored);
 * a QUARANTINE awaits parent approval; an ALLOW in the sub-agent trust band is
 * held; everything else stores.
 */
export function resolveDisposition(input: DispositionInput): Disposition {
  if (input.allowed && input.trustScore >= SUBAGENT_QUARANTINE_MIN && input.trustScore < SUBAGENT_QUARANTINE_MAX) {
    return {
      action: 'quarantine',
      firewallResult: 'QUARANTINE',
      reason: `Sub-agent write (trust=${input.trustScore.toFixed(3)}) requires parent approval`,
      subAgentHold: true,
    };
  }
  if (!input.allowed) {
    const fw = input.firewallResult === 'ALLOW' ? 'BLOCK' : (input.firewallResult as 'BLOCK' | 'QUARANTINE');
    return { action: 'quarantine', firewallResult: fw, reason: input.reason, subAgentHold: false };
  }
  return { action: 'store', firewallResult: 'ALLOW', reason: input.reason, subAgentHold: false };
}
