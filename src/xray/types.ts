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
