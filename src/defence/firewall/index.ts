/**
 * Memory Firewall
 *
 * Orchestrates all detection modules to scan memory writes for threats.
 * Combines instruction detection, privilege escalation detection,
 * encoding obfuscation detection, and anomaly scoring into a single
 * firewall analysis result.
 */

import type {
  FirewallAnalysis,
  FirewallResult,
  DefenceSource,
  DefenceConfig,
  ThreatIndicator,
} from '../types.js';

import { detectInstructions } from './instruction-detector.js';
import type { InstructionDetectionResult } from './instruction-detector.js';

import { detectPrivilegeEscalation } from './privilege-detector.js';
import type { PrivilegeDetectionResult } from './privilege-detector.js';

import { detectEncoding } from './encoding-detector.js';
import type { EncodingDetectionResult } from './encoding-detector.js';

import { scoreAnomaly } from './anomaly-scorer.js';

// Re-exports
export { detectInstructions } from './instruction-detector.js';
export type { InstructionDetectionResult } from './instruction-detector.js';
export { detectPrivilegeEscalation } from './privilege-detector.js';
export type { PrivilegeDetectionResult } from './privilege-detector.js';
export { detectEncoding } from './encoding-detector.js';
export type { EncodingDetectionResult } from './encoding-detector.js';
export { scoreAnomaly } from './anomaly-scorer.js';

/**
 * Run the full firewall analysis pipeline on memory content.
 */
export function analyzeFirewall(
  content: string,
  title: string,
  source: DefenceSource,
  trustScore: number,
  config: DefenceConfig,
): FirewallAnalysis {
  const instructions = detectInstructions(content);
  const privilege = detectPrivilegeEscalation(content);
  const encoding = detectEncoding(content);
  const anomaly = scoreAnomaly(content, title);

  // Collect threat indicators
  const threatIndicators: ThreatIndicator[] = [];
  const blockedPatterns: string[] = [];

  if (instructions.detected) {
    threatIndicators.push('instruction_injection');
    blockedPatterns.push(...instructions.patterns);
  }

  if (privilege.detected) {
    if (privilege.indicators.includes('credential_reference')) {
      threatIndicators.push('credential_leak');
    }
    if (privilege.indicators.includes('external_url')) {
      threatIndicators.push('external_url');
    }
    if (privilege.indicators.includes('system_access') ||
        privilege.indicators.includes('destructive_filesystem') ||
        privilege.indicators.includes('network_exfiltration')) {
      threatIndicators.push('privilege_escalation');
    }
  }

  if (encoding.detected) {
    threatIndicators.push('encoding_obfuscation');
    blockedPatterns.push(...encoding.encodingTypes);
  }

  // Determine result based on mode
  const { result, reason } = determineResult(
    config.mode,
    instructions,
    privilege,
    encoding,
    anomaly,
    trustScore,
    threatIndicators,
  );

  return {
    result,
    reason,
    threatIndicators,
    anomalyScore: anomaly,
    blockedPatterns,
  };
}

function determineResult(
  mode: DefenceConfig['mode'],
  instructions: InstructionDetectionResult,
  privilege: PrivilegeDetectionResult,
  encoding: EncodingDetectionResult,
  anomalyScore: number,
  trustScore: number,
  threatIndicators: ThreatIndicator[],
): { result: FirewallResult; reason: string } {
  const lowTrust = trustScore < 0.5;
  const detectionCount = threatIndicators.length;

  // ── Strict mode: any detection blocks ──
  if (mode === 'strict') {
    if (detectionCount > 0) {
      return {
        result: 'BLOCK',
        reason: `Strict mode: detected ${threatIndicators.join(', ')}`,
      };
    }
    if (anomalyScore > 0.7) {
      return {
        result: 'BLOCK',
        reason: `Strict mode: high anomaly score (${anomalyScore})`,
      };
    }
    return { result: 'ALLOW', reason: 'No threats detected' };
  }

  // ── Permissive mode: always allow, but populate indicators ──
  if (mode === 'permissive') {
    const reason = detectionCount > 0
      ? `Permissive mode: allowing despite ${threatIndicators.join(', ')}`
      : 'No threats detected';
    return { result: 'ALLOW', reason };
  }

  // ── Balanced mode ──

  // Instruction injection → quarantine
  if (instructions.detected) {
    const result: FirewallResult = lowTrust ? 'BLOCK' : 'QUARANTINE';
    return {
      result,
      reason: `Instruction injection detected (confidence: ${instructions.confidence})${lowTrust ? ', low trust source' : ''}`,
    };
  }

  // High severity privilege escalation → quarantine
  if (privilege.detected && privilege.severity === 'high') {
    const result: FirewallResult = lowTrust ? 'BLOCK' : 'QUARANTINE';
    return {
      result,
      reason: `High severity privilege escalation: ${privilege.indicators.join(', ')}${lowTrust ? ', low trust source' : ''}`,
    };
  }

  // Encoding combined with another detection → quarantine
  if (encoding.detected && detectionCount >= 2) {
    return {
      result: 'QUARANTINE',
      reason: `Encoding obfuscation combined with ${threatIndicators.filter((t) => t !== 'encoding_obfuscation').join(', ')}`,
    };
  }

  // Low trust bumps medium-severity detections to quarantine
  if (lowTrust && detectionCount > 0) {
    return {
      result: 'QUARANTINE',
      reason: `Low trust source (${trustScore}) with detections: ${threatIndicators.join(', ')}`,
    };
  }

  // Single low-severity detection → allow with warning
  if (detectionCount > 0) {
    return {
      result: 'ALLOW',
      reason: `Low severity detections: ${threatIndicators.join(', ')}`,
    };
  }

  // High anomaly score alone
  if (anomalyScore > 0.7 && lowTrust) {
    return {
      result: 'QUARANTINE',
      reason: `High anomaly score (${anomalyScore}) from low trust source`,
    };
  }

  return { result: 'ALLOW', reason: 'No threats detected' };
}
