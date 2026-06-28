/**
 * Overseer Guard — manipulation-signal detectors.
 *
 * Each detector scans the approval text (action + justification) for one family
 * of tactics aimed at the human approver, returning operator-facing signals.
 * Provenance mismatch is structural and lives in `provenanceSignal()`.
 */
import type { ApprovalContext, ApprovalRiskSignal, Severity } from './types.js';

interface Rule {
  re: RegExp;
  severity: Severity;
  reason: string;
}

function firstHit(text: string, rules: Rule[], signal: ApprovalRiskSignal['signal']): ApprovalRiskSignal | null {
  for (const r of rules) {
    const m = r.re.exec(text);
    if (m) {
      return { signal, severity: r.severity, reason: r.reason, evidence: m[0].trim().slice(0, 160) };
    }
  }
  return null;
}

// "your admin requires this", "as per security policy", "the owner said to"
const AUTHORITY_RULES: Rule[] = [
  {
    re: /\b(your|the)\s+(admin(istrator)?|owner|manager|boss|security\s+team|it\s+(team|department)|compliance)\s+(requires?|requests?|demands?|instructed?|authoris(es|ed)|says?|told\s+you|wants?\s+you)/i,
    severity: 'high',
    reason: 'Invokes an authority the user never granted to pressure approval',
  },
  {
    re: /\bas\s+(per|required\s+by|mandated\s+by)\s+(policy|compliance|the\s+security\s+team|regulations?)/i,
    severity: 'high',
    reason: 'Claims a policy/compliance mandate to justify the action',
  },
  {
    re: /\bon\s+behalf\s+of\s+(the\s+)?(admin(istrator)?|owner|security|management)/i,
    severity: 'high',
    reason: 'Asserts it is acting on a third party’s authority',
  },
  {
    re: /\byou\s+are\s+(required|obligated|authoris(ed)?|instructed)\s+to\b/i,
    severity: 'medium',
    reason: 'Frames the action as a non-negotiable obligation',
  },
];

const URGENCY_RULES: Rule[] = [
  {
    re: /\b(immediately|urgent(ly)?|right\s+now|asap|without\s+delay|time[-\s]?sensitive|this\s+can('?t|not)\s+wait)\b/i,
    severity: 'medium',
    reason: 'Uses urgency to discourage careful review',
  },
  {
    re: /\bbefore\s+(it('?s|\s+is)\s+too\s+late|the\s+deadline|anyone\s+(notices|finds\s+out)|the\s+window\s+closes)/i,
    severity: 'medium',
    reason: 'Manufactures a closing-window deadline',
  },
  {
    re: /\b(critical|emergency)\b[^.]{0,30}\b(approv|confirm|action|act\s+now)/i,
    severity: 'medium',
    reason: 'Frames approval as an emergency',
  },
];

const COERCION_RULES: Rule[] = [
  {
    re: /\b(tell|ask|instruct|get)\s+(your|the)\s+(user|operator|human|owner|approver)\s+to\s+(approve|confirm|allow|say\s+yes)/i,
    severity: 'high',
    reason: 'Directs the agent to push the human into approving',
  },
  {
    re: /\b(auto[-\s]?(approve|confirm)|approve\s+automatically|pre[-\s]?approved)/i,
    severity: 'high',
    reason: 'Seeks automatic approval, bypassing the human',
  },
  {
    re: /\b(do\s*n'?t|do\s+not|no\s+need\s+to|there'?s\s+no\s+need\s+to)\s+(ask|bother|confirm\s+with|check\s+with|consult|notify)\s+(the\s+)?(user|operator|human|owner)/i,
    severity: 'high',
    reason: 'Tells the agent not to consult the operator',
  },
  {
    re: /\bskip\s+(the\s+)?(confirmation|approval|review|verification)/i,
    severity: 'high',
    reason: 'Asks to skip the confirmation/approval step',
  },
  {
    re: /\b(just|simply)\s+(approve|confirm|click\s+(yes|allow|approve)|say\s+yes)\b/i,
    severity: 'medium',
    reason: 'Nudges toward a thoughtless approval',
  },
];

// Minimising language — only meaningful when the action actually carries impact.
const RISK_HIDING_RULES: Rule[] = [
  {
    re: /\b(just|only|merely|simply)\s+a\s+(quick|small|minor|routine|harmless|tiny)\b/i,
    severity: 'medium',
    reason: 'Downplays the action as trivial',
  },
  {
    re: /\b((completely|totally|perfectly)\s+)?(safe|harmless|benign)\b/i,
    severity: 'medium',
    reason: 'Asserts safety to pre-empt scrutiny',
  },
  {
    re: /\b(nothing\s+to\s+worry\s+about|no\s+risk|zero\s+risk|won'?t\s+(cause|do)\s+any\s+harm)\b/i,
    severity: 'medium',
    reason: 'Explicitly denies any risk',
  },
];

function combinedText(ctx: ApprovalContext): string {
  return `${ctx.action || ''}\n${ctx.justification || ''}`;
}

export function authoritySignal(ctx: ApprovalContext): ApprovalRiskSignal | null {
  return firstHit(combinedText(ctx), AUTHORITY_RULES, 'authority_spoofing');
}

export function urgencySignal(ctx: ApprovalContext): ApprovalRiskSignal | null {
  return firstHit(combinedText(ctx), URGENCY_RULES, 'urgency_pressure');
}

export function coercionSignal(ctx: ApprovalContext): ApprovalRiskSignal | null {
  return firstHit(combinedText(ctx), COERCION_RULES, 'approval_coercion');
}

export function riskHidingSignal(ctx: ApprovalContext): ApprovalRiskSignal | null {
  // Minimising a genuinely low-impact action isn't manipulation — require impact.
  const impactful = ctx.impact === 'medium' || ctx.impact === 'high' || ctx.impact === 'catastrophic';
  if (!impactful) return null;
  const hit = firstHit(combinedText(ctx), RISK_HIDING_RULES, 'risk_hiding');
  if (hit && (ctx.impact === 'high' || ctx.impact === 'catastrophic')) hit.severity = 'high';
  return hit;
}

/**
 * Structural signal: the action is driven by external content, not the user.
 * "the page said do X; the user never asked for X" — the central overseer trap.
 */
export function provenanceSignal(ctx: ApprovalContext): ApprovalRiskSignal | null {
  if (ctx.origin !== 'external') return null;
  if (ctx.userRequested === true) return null; // user genuinely asked — not a mismatch
  const where = ctx.originDetail ? ` (${ctx.originDetail})` : '';
  const highImpact = ctx.impact === 'high' || ctx.impact === 'catastrophic';
  if (ctx.userRequested === false) {
    return {
      signal: 'provenance_mismatch',
      severity: highImpact ? 'high' : 'medium',
      reason: `Action originates from external content${where}, not a user request`,
      evidence: ctx.originDetail || 'external origin',
    };
  }
  // unknown whether the user asked — flag, but softer
  return {
    signal: 'provenance_mismatch',
    severity: highImpact ? 'medium' : 'low',
    reason: `Action came from external content${where}; not confirmed the user asked for it`,
    evidence: ctx.originDetail || 'external origin',
  };
}

export function detectAllSignals(ctx: ApprovalContext): ApprovalRiskSignal[] {
  return [
    provenanceSignal(ctx),
    authoritySignal(ctx),
    urgencySignal(ctx),
    coercionSignal(ctx),
    riskHidingSignal(ctx),
  ].filter((s): s is ApprovalRiskSignal => s !== null);
}
