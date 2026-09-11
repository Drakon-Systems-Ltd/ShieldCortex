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
  ProvenanceLabel,
} from '../types.js';
import type { SanitisationCategory } from '../input-sanitisation/index.js';

import { detectInstructions } from './instruction-detector.js';
import type { InstructionDetectionResult } from './instruction-detector.js';
import { detectNonAuthoritativeInstruction } from './provenance-policy.js';
import type { NonAuthoritativeInstructionResult } from './provenance-policy.js';

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
export {
  describeProvenance,
  detectNonAuthoritativeInstruction,
  isProvenanceLabel,
  isTrustedProvenance,
  isUntrustedDataOrigin,
  NAI_PATTERN,
  PROVENANCE_LABELS,
  TRUSTED_PROVENANCE_SOURCES,
  UNTRUSTED_DATA_ORIGIN_SOURCES,
} from './provenance-policy.js';
export type { NonAuthoritativeInstructionResult, NonAuthoritativePattern } from './provenance-policy.js';

/**
 * Run the full firewall analysis pipeline on memory content.
 */
export function analyzeFirewall(
  content: string,
  title: string,
  source: DefenceSource | { type: ProvenanceLabel; identifier: string },
  trustScore: number,
  config: DefenceConfig,
  /**
   * Categories stripped by Layer 1 sanitisation BEFORE this content arrived.
   * The sanitiser removes zero-width/bidi bytes, so the encoding detector below
   * never sees them — feeding the strip signal back in lets the verdict reflect
   * the smuggling attempt instead of silently allowing the cleaned content.
   */
  preSanitisationStrips?: SanitisationCategory[],
): FirewallAnalysis {
  const instructions = detectInstructions(content);
  const privilege = detectPrivilegeEscalation(content);
  const credentialExfil = detectCredentialExfil(content);
  const encoding = detectEncoding(content);
  const markdownImage = detectMarkdownImageExfil(content);
  const anomaly = scoreAnomaly(content, title);
  const nonAuthoritative = detectNonAuthoritativeInstruction(content, source.type);

  // Fold pre-sanitisation zero-width/bidi strips into the encoding signal so
  // determineResult escalates (quarantine in balanced, block in strict). We map
  // them onto the SAME encodingTypes the detector emits ('zero_width_chars' /
  // 'rtl_override') so the existing "suspicious encoding → quarantine" rule and
  // the strict-mode detection count both fire without any extra branches.
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

  if (nonAuthoritative.detected) {
    threatIndicators.push('non_authoritative_instruction');
    blockedPatterns.push(...nonAuthoritative.patterns);
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
  // attacker. Reported as external_url so determineResult treats it the same as
  // any other off-host link: low-severity alone, but it escalates the verdict
  // when it co-occurs with another detection (encoding combined with >=2, etc.).
  if (markdownImage.detected && !threatIndicators.includes('external_url')) {
    threatIndicators.push('external_url');
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
    nonAuthoritative,
  );

  return {
    result,
    reason,
    threatIndicators,
    anomalyScore: anomaly,
    blockedPatterns,
  };
}

/**
 * Verdict assembly, with the L2 floor applied MONOTONICALLY.
 *
 * The provenance floor is an additive layer, so the one thing it must never do
 * is answer a question an earlier layer already answered more severely. Before
 * this the L2 branch sat above the skill-threat / privilege / encoding branches
 * in balanced mode and returned QUARANTINE unconditionally, so appending a
 * memory-persistence sentence to text that already reached the low-trust
 * privilege BLOCK *downgraded* the verdict: adding an indicator made the
 * product safer on paper and weaker in fact.
 *
 * So the base verdict is computed as if L2 had never fired — its indicator is
 * withheld from the balanced count as well, because "the L1 verdict" must not
 * be a function of the L2 hit either — and L2 may then escalate ALLOW →
 * QUARANTINE. A base BLOCK or QUARANTINE stands, carrying the L2 indicator and
 * pattern names beside its own (both are collected in `analyzeFirewall`, which
 * is unconditional and therefore unaffected by this ordering).
 *
 * Strict and permissive keep the FULL indicator list and are untouched: strict
 * already blocks on any detection (escalation only, by construction) and
 * permissive allows everything by definition. Adding a quarantine there would
 * be a posture change, which this round is explicitly not making.
 */
function determineResult(
  mode: DefenceConfig['mode'],
  instructions: InstructionDetectionResult,
  privilege: PrivilegeDetectionResult,
  encoding: EncodingDetectionResult,
  anomalyScore: number,
  trustScore: number,
  threatIndicators: ThreatIndicator[],
  skillThreats?: { detected: boolean; threats: string[]; confidence: number },
  nonAuthoritative?: NonAuthoritativeInstructionResult,
): { result: FirewallResult; reason: string } {
  const balanced = mode !== 'strict' && mode !== 'permissive';
  const baseIndicators = balanced && nonAuthoritative?.detected
    ? threatIndicators.filter((t) => t !== 'non_authoritative_instruction')
    : threatIndicators;

  const base = determineBaseResult(
    mode,
    instructions,
    privilege,
    encoding,
    anomalyScore,
    trustScore,
    baseIndicators,
    skillThreats,
  );

  if (!balanced || !nonAuthoritative?.detected) return base;
  // Never weaken: only a verdict L1 left at ALLOW is L2's to raise.
  if (base.result !== 'ALLOW') return base;
  return {
    result: 'QUARANTINE',
    reason: 'Non-authoritative instruction from untrusted data origin',
  };
}

function determineBaseResult(
  mode: DefenceConfig['mode'],
  instructions: InstructionDetectionResult,
  privilege: PrivilegeDetectionResult,
  encoding: EncodingDetectionResult,
  anomalyScore: number,
  trustScore: number,
  threatIndicators: ThreatIndicator[],
  skillThreats?: { detected: boolean; threats: string[]; confidence: number },
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

  // The L2 provenance floor is NOT a branch here: it is applied by the caller
  // AFTER this function returns, so it can only raise an ALLOW. See
  // determineResult().

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

  // Encoding combined with another detection → quarantine
  if (encoding.detected && detectionCount >= 2) {
    return {
      result: 'QUARANTINE',
      reason: `Encoding obfuscation combined with ${threatIndicators.filter((t) => t !== 'encoding_obfuscation').join(', ')}`,
    };
  }

  // Encoding-only: run FULL pipeline on decoded content (not just instruction detection)
  if (encoding.detected && encoding.decodedSnippets.length > 0) {
    for (const snippet of encoding.decodedSnippets) {
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

  // Zero-width chars / RTL override are always suspicious → quarantine
  if (encoding.detected && (
    encoding.encodingTypes.includes('zero_width_chars') ||
    encoding.encodingTypes.includes('rtl_override') ||
    encoding.encodingTypes.includes('unicode_homoglyph')
  )) {
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
