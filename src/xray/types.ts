/**
 * X-Ray Types
 *
 * Core type definitions for the ShieldCortex X-Ray scanner —
 * package, file, and directory risk inspection.
 */

// ── Categories ──────────────────────────────────────────────

export type XRayCategory =
  | 'prompt-injection'
  | 'eval-exec'
  | 'shell-execution'
  | 'network-beacon'
  | 'obfuscation'
  | 'steganography'
  | 'unicode-trick'
  | 'metadata-exploit'
  | 'persistence-hook'
  | 'covert-channel'
  | 'dependency-risk'
  | 'ai-directive';

// ── Target ──────────────────────────────────────────────────

export interface XRayTarget {
  type: 'npm' | 'dir' | 'file';
  path: string;
}

// ── Finding ─────────────────────────────────────────────────

export interface XRayFinding {
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  category: XRayCategory;
  title: string;
  description: string;
  file?: string;
  line?: number;
  evidence?: string;
}

// ── Result ──────────────────────────────────────────────────

export interface XRayResult {
  target: string;
  trustScore: number;
  riskLevel: 'CRITICAL' | 'HIGH' | 'MEDIUM' | 'LOW' | 'SAFE';
  findings: XRayFinding[];
  filesScanned: number;
  scannedAt: Date;
  deepScan: boolean;
}

// ── Actionable Findings ──────────────────────────────────────

export type FindingStatus = 'new' | 'reviewed' | 'ignored' | 'resolved' | 'quarantined';

export interface ActionableXRayFinding extends XRayFinding {
  /** Unique ID for this finding instance */
  id: string;
  /** Which scan/watch session produced this finding */
  sourceId: string;
  /** Source type: manual scan or watch detection */
  sourceKind: 'scan' | 'watch';
  /** Full path to the target that was scanned */
  target: string;
  /** Current lifecycle status */
  status: FindingStatus;
  /** When the finding was first detected */
  detectedAt: string;
  /** When status was last changed */
  updatedAt: string;
  /** Optional note from user when resolving/ignoring */
  resolutionNote?: string;
}
