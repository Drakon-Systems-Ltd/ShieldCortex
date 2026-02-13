/**
 * Audit Types
 *
 * Shared types for the `shieldcortex audit` command — a comprehensive
 * security scanner for AI agent environments.
 */

// ── Severity ──

export type AuditSeverity = 'critical' | 'high' | 'medium' | 'low' | 'info';

// ── Finding ──

export interface AuditFinding {
  /** Scanner that produced this finding */
  scanner: string;
  /** Severity of the finding */
  severity: AuditSeverity;
  /** Short human-readable title */
  title: string;
  /** Detailed description of the finding */
  description: string;
  /** File path where the finding was located (if applicable) */
  filePath?: string;
  /** Matched text snippet (truncated) */
  matchedText?: string;
  /** URL to learn more about this finding category */
  learnMoreUrl?: string;
}

// ── Scanner Result ──

export interface ScannerResult {
  /** Scanner name for display */
  name: string;
  /** Number of items scanned */
  itemsScanned: number;
  /** Findings from this scanner */
  findings: AuditFinding[];
  /** Duration in milliseconds */
  durationMs: number;
  /** Whether the scanner was skipped (e.g., no files found) */
  skipped?: boolean;
  /** Reason for skipping */
  skipReason?: string;
}

// ── Full Audit Report ──

export type AuditGrade = 'A' | 'B' | 'C' | 'D' | 'F';

export interface AuditReport {
  /** Security grade (A-F) */
  grade: AuditGrade;
  /** Total number of findings */
  totalFindings: number;
  /** Findings by severity */
  bySeverity: Record<AuditSeverity, number>;
  /** Results from each scanner */
  scanners: ScannerResult[];
  /** All findings sorted by severity */
  findings: AuditFinding[];
  /** Duration of the full audit in milliseconds */
  durationMs: number;
  /** Timestamp of the audit */
  timestamp: string;
  /** ShieldCortex version */
  version: string;
}

/**
 * Calculate grade from findings.
 *
 * A = no findings above info
 * B = only low/info findings
 * C = medium findings present
 * D = high findings present
 * F = critical findings present
 */
export function calculateGrade(bySeverity: Record<AuditSeverity, number>): AuditGrade {
  if (bySeverity.critical > 0) return 'F';
  if (bySeverity.high > 0) return 'D';
  if (bySeverity.medium > 0) return 'C';
  if (bySeverity.low > 0) return 'B';
  return 'A';
}
