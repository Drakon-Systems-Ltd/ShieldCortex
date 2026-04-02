/**
 * Trust Score Calculator
 *
 * Computes a 0–100 trust score from X-Ray findings and maps it to a risk level.
 */

import type { XRayFinding, XRayResult } from './types.js';

// ── Penalty weights ─────────────────────────────────────────

const SEVERITY_PENALTY: Record<XRayFinding['severity'], number> = {
  critical: 60,
  high: 35,
  medium: 15,
  low: 5,
  info: 0,
};

// ── Risk level thresholds ───────────────────────────────────

function riskLevelFromScore(score: number): XRayResult['riskLevel'] {
  if (score >= 80) return 'SAFE';
  if (score >= 60) return 'LOW';
  if (score >= 40) return 'MEDIUM';
  if (score >= 20) return 'HIGH';
  return 'CRITICAL';
}

// ── Public API ──────────────────────────────────────────────

export function calculateTrustScore(findings: XRayFinding[]): {
  score: number;
  riskLevel: XRayResult['riskLevel'];
} {
  let score = 100;

  for (const finding of findings) {
    score -= SEVERITY_PENALTY[finding.severity];
  }

  score = Math.max(0, score);

  return {
    score,
    riskLevel: riskLevelFromScore(score),
  };
}
