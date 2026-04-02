/**
 * X-Ray Memory Guard
 *
 * Synchronous, fast content scanner for memory pipeline integration.
 * Checks content destined for memory storage against X-Ray pattern
 * detection, returning an allow/deny decision with findings.
 *
 * No file I/O, no network — pure in-memory analysis.
 */

import type { XRayFinding } from './types.js';
import { detectPatterns, detectFilenameDirectives } from './patterns.js';
import { calculateTrustScore } from './trust-score.js';

// ── Public API ──────────────────────────────────────────────

export interface MemoryGuardResult {
  allowed: boolean;
  findings: XRayFinding[];
  riskLevel: string;
}

/**
 * Scan content destined for memory storage.
 *
 * @param content - The memory content to scan
 * @param title - Optional title/name for the memory entry
 * @returns { allowed, findings, riskLevel }
 *   - allowed: true if trust score >= 40 (MEDIUM or better)
 *   - findings: all detected X-Ray findings
 *   - riskLevel: SAFE | LOW | MEDIUM | HIGH | CRITICAL
 */
export function xrayMemoryContent(
  content: string,
  title?: string,
): MemoryGuardResult {
  const findings: XRayFinding[] = [];

  // Scan the content body
  findings.push(...detectPatterns(content));

  // Scan the title for filename-style directives
  if (title) {
    findings.push(...detectFilenameDirectives(title));
  }

  const { score, riskLevel } = calculateTrustScore(findings);

  return {
    allowed: score >= 40,
    findings,
    riskLevel,
  };
}
