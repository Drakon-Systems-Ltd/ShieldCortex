/**
 * Overseer Guard — public API.
 *
 * `analyzeApprovalRisk(ctx)` runs the manipulation-signal detectors over an
 * approval request and returns an advisory risk report for the operator. It
 * never blocks; the caller decides what to do with the report (surface it,
 * raise the approval bar, etc.). The fourth ShieldCortex front:
 *   Memory protects what the agent stores · Iron Dome what it does ·
 *   Environment Firewall what it sees · Overseer Guard what the human approves.
 */
import type { ApprovalContext, ApprovalRiskReport, ApprovalRiskSignal, RiskLevel } from './types.js';
import { detectAllSignals } from './detector.js';

export type { ApprovalContext, ApprovalRiskReport, ApprovalRiskSignal, ManipulationSignal, RiskLevel, Severity } from './types.js';
export { detectAllSignals } from './detector.js';

const WEIGHT: Record<ApprovalRiskSignal['severity'], number> = { low: 0.15, medium: 0.3, high: 0.5 };

function levelFor(score: number, signals: ApprovalRiskSignal[]): RiskLevel {
  if (signals.some((s) => s.severity === 'high') || score >= 0.6) return 'high';
  if (signals.length > 0 || score >= 0.25) return 'caution';
  return 'clean';
}

function summarise(level: RiskLevel, signals: ApprovalRiskSignal[]): string {
  if (level === 'clean') return 'No manipulation signals — approval request looks operator-driven.';
  const names: Record<string, string> = {
    provenance_mismatch: 'driven by external content, not your request',
    authority_spoofing: 'invokes authority you never granted',
    urgency_pressure: 'uses urgency to rush approval',
    approval_coercion: 'tries to bypass your confirmation',
    risk_hiding: 'downplays a high-impact action',
  };
  const phrases = signals.map((s) => names[s.signal] ?? s.signal);
  const head = level === 'high' ? '⚠️ High manipulation risk' : 'Caution';
  return `${head}: this approval ${phrases.join('; ')}.`;
}

/** Analyse an approval request for manipulation of the human approver. Advisory. */
export function analyzeApprovalRisk(ctx: ApprovalContext): ApprovalRiskReport {
  const signals = detectAllSignals(ctx);
  const score = Math.min(1, signals.reduce((acc, s) => acc + WEIGHT[s.severity], 0));
  const level = levelFor(score, signals);
  return {
    score: Number(score.toFixed(2)),
    level,
    signals,
    summary: summarise(level, signals),
  };
}
