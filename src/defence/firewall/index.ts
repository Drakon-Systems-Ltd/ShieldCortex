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
import type { SanitisationCategory } from '../input-sanitisation/index.js';

import { detectInstructions } from './instruction-detector.js';
import type { InstructionDetectionResult } from './instruction-detector.js';

import { detectPrivilegeEscalation } from './privilege-detector.js';
import type { PrivilegeDetectionResult } from './privilege-detector.js';

import { detectCredentialExfil } from './credential-exfil-detector.js';

import { detectEncoding } from './encoding-detector.js';
import type { EncodingDetectionResult } from './encoding-detector.js';

import { detectMarkdownImageExfil } from './markdown-image-detector.js';

import { scoreAnomaly } from './anomaly-scorer.js';

import { detectSkillThreats } from '../skill-scanner/patterns.js';
import { scanForCredentials } from '../credential-leak/index.js';

// Re-exports
export { detectInstructions } from './instruction-detector.js';
export type { InstructionDetectionResult } from './instruction-detector.js';
export { detectPrivilegeEscalation } from './privilege-detector.js';
export type { PrivilegeDetectionResult } from './privilege-detector.js';
export { detectEncoding } from './encoding-detector.js';
export type { EncodingDetectionResult } from './encoding-detector.js';
export { detectMarkdownImageExfil } from './markdown-image-detector.js';
export type { MarkdownImageExfilResult } from './markdown-image-detector.js';
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
  /**
   * Categories stripped by Layer 1 sanitisation BEFORE this content arrived.
   * The sanitiser removes zero-width/bidi bytes, so the encoding detector below
   * never sees them. Preserve that evidence for strict blocking, low-trust and
   * harmful corroboration checks; bidi still quarantines on its own. Benign
   * zero-width-only content can remain ALLOW at normal trust in balanced mode.
   */
  preSanitisationStrips?: SanitisationCategory[],
): FirewallAnalysis {
  const instructions = detectInstructions(content);
  const privilege = detectPrivilegeEscalation(content);
  const credentialExfil = detectCredentialExfil(content);
  const encoding = detectEncoding(content);
  const markdownImage = detectMarkdownImageExfil(content);
  const anomaly = scoreAnomaly(content, title);

  // Preserve pre-strip evidence for strict blocking and balanced corroboration.
  // Reuse the detector's encoding types: sanitisation and direct detection are
  // the same signal, not two independent reasons to escalate benign text.
  if (preSanitisationStrips?.includes('zero_width') &&
      !encoding.encodingTypes.includes('zero_width_chars')) {
    encoding.encodingTypes.push('zero_width_chars');
    encoding.detected = true;
  }
  if (preSanitisationStrips?.includes('bidi_override') &&
      !encoding.encodingTypes.includes('rtl_override')) {
    encoding.encodingTypes.push('rtl_override');
    encoding.detected = true;
  }

  // Skill scanner patterns — catches tool injection, scope escalation,
  // data exfiltration, persistence, supply chain, agent manipulation,
  // and stealth instructions in memory content (not just skill files).
  const skillThreats = detectSkillThreats(content);

  // Collect threat indicators
  const threatIndicators: ThreatIndicator[] = [];
  const blockedPatterns: string[] = [];

  if (instructions.detected) {
    threatIndicators.push('instruction_injection');
    blockedPatterns.push(...instructions.patterns);
  }

  // Credential exfiltration is a first-class classification (v4.47.2): credential
  // material access COMBINED WITH external outbound movement. When it fires it
  // OWNS the verdict — it must NOT also be reported as generic privilege_escalation
  // (fleet finding, Edith case e). Either half alone stays on the normal paths.
  if (credentialExfil.detected) {
    threatIndicators.push('credential_exfil');
  }

  if (privilege.detected) {
    if (privilege.indicators.includes('credential_reference')) {
      threatIndicators.push('credential_leak');
    }
    if (privilege.indicators.includes('external_url')) {
      threatIndicators.push('external_url');
    }
    if (!credentialExfil.detected &&
        (privilege.indicators.includes('system_access') ||
        privilege.indicators.includes('destructive_filesystem') ||
        privilege.indicators.includes('network_exfiltration'))) {
      threatIndicators.push('privilege_escalation');
    }
  }

  if (encoding.detected) {
    threatIndicators.push('encoding_obfuscation');
    blockedPatterns.push(...encoding.encodingTypes);
  }

  // Markdown-image exfiltration — a rendered image URL that smuggles data to an
  // attacker. Keep the public external_url indicator, but preserve the harmful
  // image signal separately: an ordinary link is not encoding corroboration.
  if (markdownImage.detected) {
    if (!threatIndicators.includes('external_url')) {
      threatIndicators.push('external_url');
    }
    blockedPatterns.push('markdown_image_exfil');
  }

  // Skill-level threats in memory content (tool injection, scope escalation, etc.)
  if (skillThreats.detected) {
    for (const threat of skillThreats.threats) {
      if (!threatIndicators.includes(threat as ThreatIndicator)) {
        threatIndicators.push(threat as ThreatIndicator);
      }
    }
    blockedPatterns.push(...skillThreats.threats.map(t => `skill:${t}`));
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
    skillThreats,
    markdownImage.detected,
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
  skillThreats?: { detected: boolean; threats: string[]; confidence: number },
  markdownImageExfil: boolean = false,
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

  // Credential exfiltration (dangerous tier) → BLOCK. Credential material bound
  // for an external host is never recoverable once it leaves; unlike a quarantine
  // there is nothing safe to review later, so it hard-blocks in enforce regardless
  // of trust. This is the v4.47.2 first-class `credential_exfil` verdict.
  if (threatIndicators.includes('credential_exfil')) {
    return {
      result: 'BLOCK',
      reason: 'Credential exfiltration: credential material bound for an external host',
    };
  }

  // Instruction injection → quarantine
  if (instructions.detected) {
    const result: FirewallResult = lowTrust ? 'BLOCK' : 'QUARANTINE';
    return {
      result,
      reason: `Instruction injection detected (confidence: ${instructions.confidence})${lowTrust ? ', low trust source' : ''}`,
    };
  }

  // Skill-level threats (tool injection, scope escalation, agent manipulation, etc.)
  if (skillThreats?.detected && skillThreats.confidence >= 0.8) {
    const result: FirewallResult = lowTrust ? 'BLOCK' : 'QUARANTINE';
    return {
      result,
      reason: `Skill-level threat detected: ${skillThreats.threats.join(', ')} (confidence: ${skillThreats.confidence})${lowTrust ? ', low trust source' : ''}`,
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

  // Re-scan decoded content even beside an ordinary URL. Do this before generic
  // corroboration so it cannot mask a decoded credential/exfiltration BLOCK.
  if (encoding.detected && encoding.decodedSnippets.length > 0) {
    for (const snippet of encoding.decodedSnippets) {
      if (detectCredentialExfil(snippet).detected) {
        return {
          result: 'BLOCK',
          reason: `Encoded content contains credential exfiltration (${encoding.encodingTypes.join(', ')})`,
        };
      }

      // Check for instruction injection in decoded content
      const decodedInstructions = detectInstructions(snippet);
      if (decodedInstructions.detected) {
        const result: FirewallResult = lowTrust ? 'BLOCK' : 'QUARANTINE';
        return {
          result,
          reason: `Encoded content contains instruction injection (${encoding.encodingTypes.join(', ')})`,
        };
      }

      // Check for privilege escalation in decoded content
      const decodedPrivilege = detectPrivilegeEscalation(snippet);
      if (decodedPrivilege.detected && decodedPrivilege.severity === 'high') {
        const result: FirewallResult = lowTrust ? 'BLOCK' : 'QUARANTINE';
        return {
          result,
          reason: `Encoded content contains privilege escalation: ${decodedPrivilege.indicators.join(', ')} (${encoding.encodingTypes.join(', ')})`,
        };
      }

      // Check for credential leaks in decoded content
      const decodedCredentials = scanForCredentials(snippet);
      if (decodedCredentials.findings.some(f => f.action === 'blocked')) {
        return {
          result: 'BLOCK',
          reason: `Encoded content contains credential leak (${encoding.encodingTypes.join(', ')})`,
        };
      }

      // Check for skill-level threats in decoded content
      const decodedSkill = detectSkillThreats(snippet);
      if (decodedSkill.detected && decodedSkill.confidence >= 0.8) {
        const result: FirewallResult = lowTrust ? 'BLOCK' : 'QUARANTINE';
        return {
          result,
          reason: `Encoded content contains skill threat: ${decodedSkill.threats.join(', ')} (${encoding.encodingTypes.join(', ')})`,
        };
      }

      // A URL alone is not harmful, but decoded outbound movement or a rendered
      // data-bearing image must not lose the old encoding corroboration floor.
      if (decodedPrivilege.indicators.includes('network_exfiltration') ||
          detectMarkdownImageExfil(snippet).detected) {
        return {
          result: 'QUARANTINE',
          reason: `Encoded content contains ${decodedPrivilege.indicators.includes('network_exfiltration') ? 'network exfiltration' : 'markdown_image_exfil'} (${encoding.encodingTypes.join(', ')})`,
        };
      }

      // Check anomaly score of decoded content
      const decodedAnomaly = scoreAnomaly(snippet, '');
      if (decodedAnomaly > 0.6) {
        return {
          result: 'QUARANTINE',
          reason: `Encoded content has high anomaly score (${decodedAnomaly.toFixed(2)})`,
        };
      }
    }
  }

  // Encoding needs an independent harmful signal, not merely an ordinary URL.
  // Keep all indicators for audit/strict/low-trust policy; only corroboration
  // excludes bare links. A data-bearing markdown image is still corroboration.
  const corroborating: string[] = threatIndicators.filter(t => t !== 'encoding_obfuscation' && t !== 'external_url');
  if (markdownImageExfil) corroborating.push('markdown_image_exfil');
  if (encoding.detected && corroborating.length > 0) {
    return {
      result: 'QUARANTINE',
      reason: `Encoding obfuscation combined with ${corroborating.join(', ')}`,
    };
  }

  // Bidi override alone still quarantines. Mixed-script and ordinary zero-width
  // text need corroboration, hostile decoded content, or low trust; otherwise
  // keep their encoding indicator without denying benign prose.
  if (encoding.detected && encoding.encodingTypes.includes('rtl_override')) {
    return {
      result: 'QUARANTINE',
      reason: `Suspicious encoding: ${encoding.encodingTypes.join(', ')}`,
    };
  }

  // Low trust bumps medium-severity detections to quarantine
  if (lowTrust && detectionCount > 0) {
    return {
      result: 'QUARANTINE',
      reason: `Low trust source (${trustScore}) with detections: ${threatIndicators.join(', ')}`,
    };
  }

  // Only low-severity detections remain (possibly encoding + URL) → warn/allow
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
