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

// ═══════════════════════ #402 Phase 1 — multi-way valve ═══════════════════════
//
// The binary store|quarantine disposition becomes a 6-way valve layered ON TOP
// of resolveDisposition: everything that quarantines today still quarantines
// (the base decision is computed first and only ever refined, never relaxed).
// The v2 kinds map onto storage actions:
//   admit           → store; injectable if the read-time gate agrees
//   admit-low-trust → store with trust clamped below the inject floor;
//                     reaches packs only after operator promotion/pin
//   inert           → store, content_form 'directive'|'mixed'|'unknown' keeps
//                     it out of packs via the form key (B1: never injectable)
//   quarantine      → quarantine table hold (parent/operator review)
//   escalate        → quarantine table hold flagged for OPERATOR review — a
//                     fact-shaped write the firewall still flagged (boundary
//                     case a human should adjudicate, not auto-expire)
//   reject          → quarantine table hold with BLOCK preserved forensically
//                     (auto-rejected at review), exactly today's BLOCK path.

export type ContentFormLabel = 'fact' | 'directive' | 'mixed' | 'unknown';

export type DispositionKind =
  | 'admit'
  | 'admit-low-trust'
  | 'inert'
  | 'quarantine'
  | 'reject'
  | 'escalate';

/** Trust stamp ceiling for admit-low-trust rows: strictly below the 0.5
 *  read-time inject trust floor, so a low-trust admit can NEVER reach a pack
 *  until an operator promotes it. */
export const LOW_TRUST_CLAMP = 0.45;

/** ALLOW trust floor below which a work-fact is admitted low-trust (thin
 *  provenance). Matches the inject-pack trust floor. */
export const ADMIT_TRUST_FLOOR = 0.5;

export interface DispositionInputV2 extends DispositionInput {
  /** classifyContentForm(content); omitted/invalid ⇒ treated as 'unknown'
   *  (fail-closed — never auto-admit on a missing classification). */
  contentForm?: ContentFormLabel | null;
  /** Pipeline threat indicators (soft signals demote admit → admit-low-trust). */
  threatIndicators?: readonly unknown[];
  /** Pipeline anomaly score (soft signal, same demotion). */
  anomalyScore?: number;
  /** B1 lock: attestation is channel identity, NEVER trust — accepted here
   *  only so callers can pass their full context; it grants nothing. */
  sourceAttested?: boolean;
}

export interface DispositionV2 extends Disposition {
  kind: DispositionKind;
  /** The content form the decision was made on (normalized, fail-closed). */
  contentForm: ContentFormLabel;
  /** Write-time injectability stamp. The live read gate (two-key) still
   *  applies at pack build — this alone never puts a row in a pack. */
  injectable: boolean;
  /** For admit-low-trust: the ceiling to clamp the stored trust_score to. */
  trustClamp?: number;
}

function normalizeForm(form: unknown): ContentFormLabel {
  return form === 'fact' || form === 'directive' || form === 'mixed' ? form : 'unknown';
}

/** Soft-signal test: an ALLOWED write that still tripped indicators or scored
 *  anomalous is admitted low-trust rather than clean-admitted. */
function hasSoftSignals(input: DispositionInputV2): boolean {
  if (Array.isArray(input.threatIndicators) && input.threatIndicators.length > 0) return true;
  return typeof input.anomalyScore === 'number' && input.anomalyScore >= 0.3;
}

/**
 * Resolve the 6-way disposition. Refines resolveDisposition — never relaxes it:
 * base 'quarantine' stays a hold (kind reject/escalate/quarantine); base
 * 'store' splits into admit / admit-low-trust / inert on form + soft signals.
 */
export function resolveDispositionV2(input: DispositionInputV2): DispositionV2 {
  const base = resolveDisposition(input);
  const contentForm = normalizeForm(input.contentForm);

  if (base.action === 'quarantine') {
    let kind: DispositionKind;
    if (base.firewallResult === 'BLOCK') {
      kind = 'reject';
    } else if (base.subAgentHold) {
      kind = 'quarantine'; // parent-approval flow, not operator escalation
    } else if (contentForm === 'fact') {
      // Fact-shaped content the firewall still flagged: boundary case —
      // hold it flagged for a human, don't let it auto-expire unseen. The
      // reason prefix is the operator-review flag recorded on the held row.
      kind = 'escalate';
      return {
        ...base,
        kind,
        contentForm,
        injectable: false,
        reason: `escalate: operator review required — ${base.reason}`,
      };
    } else {
      kind = 'quarantine';
    }
    return { ...base, kind, contentForm, injectable: false };
  }

  // base.action === 'store'
  if (contentForm !== 'fact') {
    // directive / mixed / unknown ⇒ INERT: stored for forensics + operator
    // promotion (re-scan on promote), never injectable (B1 fail-closed).
    return {
      ...base,
      kind: 'inert',
      contentForm,
      injectable: false,
      reason: base.reason
        ? `${base.reason}; inert: content form '${contentForm}' is not a work-fact`
        : `inert: content form '${contentForm}' is not a work-fact`,
    };
  }

  if (input.trustScore < ADMIT_TRUST_FLOOR || hasSoftSignals(input)) {
    return {
      ...base,
      kind: 'admit-low-trust',
      contentForm,
      injectable: false,
      trustClamp: Math.min(input.trustScore, LOW_TRUST_CLAMP),
    };
  }

  return { ...base, kind: 'admit', contentForm, injectable: true };
}
