/**
 * Overseer Guard — types.
 *
 * The fourth front. Iron Dome guards what the agent *does*; the Overseer Guard
 * guards what the human *approves*. When an action reaches the approval boundary
 * it is analysed for manipulation tactics aimed at the human approver, so the
 * operator never becomes "the last exploited parser in the chain"
 * (docs/agent-trap-gap-analysis.md §3.6, §7.6).
 *
 * Advisory by default: this produces a report to surface, it does not block.
 */

/** A class of manipulation aimed at the human approver. */
export type ManipulationSignal =
  | 'provenance_mismatch' // action driven by external content, not the user's request
  | 'authority_spoofing' // invokes authority the user never granted ("your admin requires")
  | 'urgency_pressure' // time pressure engineered to skip scrutiny
  | 'approval_coercion' // tries to obtain auto-approval or silence the operator
  | 'risk_hiding'; // minimising language masking a high-impact action

export type Severity = 'low' | 'medium' | 'high';

/** One detected manipulation signal, operator-facing. */
export interface ApprovalRiskSignal {
  signal: ManipulationSignal;
  severity: Severity;
  /** Plain-English explanation shown to the operator. */
  reason: string;
  /** The exact snippet that triggered it (empty for structural signals). */
  evidence: string;
}

/** What the operator is being asked to approve, plus where it came from. */
export interface ApprovalContext {
  /** The action requiring approval, e.g. "Bash: rm -rf /tmp/cache". */
  action: string;
  /** The stated reason for the action (agent's or external content's words). */
  justification?: string;
  /** Where the request originated. `external` = a page/email/tool result, etc. */
  origin?: 'user' | 'external' | 'unknown';
  /** Human-readable provenance, e.g. "fetched page evil.com" / "user message". */
  originDetail?: string;
  /** Did the user explicitly ask for THIS action? Undefined = unknown. */
  userRequested?: boolean;
  /** Iron Dome's impact rating for the action, if known. */
  impact?: 'low' | 'medium' | 'high' | 'catastrophic';
}

export type RiskLevel = 'clean' | 'caution' | 'high';

/** The advisory report surfaced at the approval boundary. */
export interface ApprovalRiskReport {
  /** Aggregate manipulation risk, 0..1. */
  score: number;
  level: RiskLevel;
  signals: ApprovalRiskSignal[];
  /** One-line operator headline. */
  summary: string;
}
