/**
 * #361 — which conversation-scan summaries may raise session taint.
 *
 * Session taint escalates Action Guard. Only concrete detections may do that.
 * Uncertainty ("unknown"), unavailable scanners, and empty noise must not.
 */

export type TaintMarkSeverity = 'low' | 'medium' | 'high' | 'critical' | 'unknown';

export function isTaintingScanSummary(summary: string | undefined | null): boolean {
  if (!summary || typeof summary !== 'string') return false;
  const s = summary.trim();
  if (!s) return false;
  const lower = s.toLowerCase();
  if (lower === 'unknown' || lower === 'none' || lower === 'clean') return false;
  if (lower.includes('scan unavailable') || lower.includes('unscanned')) return false;
  if (/\b(critical|high|medium|low)\b/i.test(s)) return true;
  if (/\bthreat\b/i.test(s)) return true;
  if (/\bdetections?\b/i.test(s) && /\d+/.test(s)) return true;
  return false;
}

export function severityFromScanSummary(summary: string): TaintMarkSeverity {
  const s = summary.toLowerCase();
  if (/\bcritical\b/.test(s)) return 'critical';
  if (/\bhigh\b/.test(s)) return 'high';
  if (/\bmedium\b/.test(s)) return 'medium';
  if (/\blow\b/.test(s)) return 'low';
  return 'medium';
}
