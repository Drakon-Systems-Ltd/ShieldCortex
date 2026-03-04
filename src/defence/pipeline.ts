/**
 * Defence Pipeline Orchestrator
 *
 * Runs all 6 defence layers in sequence and returns a unified result.
 * Fail-closed: if any layer throws, the pipeline defaults to BLOCK for security.
 */

import type {
  DefenceConfig,
  DefencePipelineResult,
  DefencePipelineResultWithVerify,
  DefenceSource,
  FirewallAnalysis,
  FragmentationAnalysis,
  SensitivityClassification,
  TrustScore,
} from './types.js';
import { DEFAULT_DEFENCE_CONFIG } from './types.js';

import { scoreSource } from './trust/index.js';
import { analyzeFirewall } from './firewall/index.js';
import { classifySensitivity } from './sensitivity/index.js';
import { analyzeFragmentation } from './fragmentation/index.js';
import { scanForCredentials, type CredentialScanResult } from './credential-leak/index.js';
import { logAudit, createContentHash } from './audit/index.js';
import { persistEvent } from '../api/events.js';
import { syncToCloud } from '../cloud/sync.js';
import { syncQuarantineToCloud } from '../cloud/quarantine-sync.js';
import { isFeatureEnabled } from '../license/gate.js';
import { getDefenceMode } from '../cloud/config.js';
import { isDatabaseInitialized } from '../database/init.js';

export function runDefencePipeline(
  content: string,
  title: string,
  source: DefenceSource,
  config?: DefenceConfig,
  project?: string,
): DefencePipelineResult {
  const cfg = config ?? { ...DEFAULT_DEFENCE_CONFIG, mode: getDefenceMode() };
  const startTime = performance.now();

  try {
    // 1. Score trust
    const trust: TrustScore = scoreSource(source);

    // 2. Run firewall
    const firewall: FirewallAnalysis = analyzeFirewall(
      content,
      title,
      source,
      trust.score,
      cfg,
    );

    // 3. Classify sensitivity
    const sensitivity: SensitivityClassification = classifySensitivity(content, title);

    // 4. Run fragmentation detection (if enabled and firewall didn't block)
    let fragmentation: FragmentationAnalysis | null = null;
    if (cfg.enableFragmentationDetection && firewall.result !== 'BLOCK') {
      fragmentation = analyzeFragmentation(content, title, cfg);
    }

    // 5. Run credential leak detection (Layer 6)
    const credentialScan: CredentialScanResult = scanForCredentials(content);

    // 6. Determine final decision
    let allowed: boolean;
    let reason: string;

    // Check if credential scan produced any blocked findings
    const credentialBlocked = credentialScan.findings.some(f => f.action === 'blocked');

    if (firewall.result === 'BLOCK') {
      allowed = false;
      reason = firewall.reason;
    } else if (credentialBlocked) {
      allowed = false;
      const blockedTypes = credentialScan.findings
        .filter(f => f.action === 'blocked')
        .map(f => f.provider ? `${f.provider} ${f.type}` : f.type);
      reason = `Blocked: credential leak detected (${blockedTypes.join(', ')})`;
      // Also update firewall result to reflect the block
      firewall.result = 'BLOCK';
      if (!firewall.threatIndicators.includes('credential_leak')) {
        firewall.threatIndicators.push('credential_leak');
      }
    } else if (firewall.result === 'QUARANTINE') {
      allowed = false;
      reason = `Quarantined: ${firewall.reason}`;
    } else if (
      fragmentation !== null &&
      fragmentation.score > cfg.autoQuarantineThreshold
    ) {
      allowed = false;
      reason = `Quarantined: fragmentation score ${fragmentation.score} exceeds threshold ${cfg.autoQuarantineThreshold}`;
      firewall.result = 'QUARANTINE';
      firewall.reason = reason;
    } else if (sensitivity.level === 'RESTRICTED') {
      allowed = false;
      reason = `Blocked: content classified as RESTRICTED (${sensitivity.detectedPatterns.join(', ')})`;
      firewall.result = 'BLOCK';
      firewall.reason = reason;
      if (!firewall.threatIndicators.includes('restricted_content')) {
        firewall.threatIndicators.push('restricted_content');
      }
    } else {
      allowed = true;
      reason = firewall.reason;
    }

    // 6b. Apply custom firewall rules (Pro feature, additive only — can tighten, never weaken)
    if (allowed && isFeatureEnabled('custom_firewall_rules') && isDatabaseInitialized()) {
      try {
        const { getEnabledFirewallRules } = require('./custom-rules/store.js');
        const customRules = getEnabledFirewallRules();
        for (const rule of customRules) {
          try {
            const regex = new RegExp(rule.condition_value, 'gi');
            if (regex.test(content) || regex.test(title)) {
              if (rule.action === 'block') {
                allowed = false;
                reason = `Blocked by custom rule: ${rule.name}`;
                firewall.result = 'BLOCK';
                if (!firewall.threatIndicators.includes('custom_rule')) {
                  firewall.threatIndicators.push('custom_rule');
                }
                break; // Block is final
              } else if (rule.action === 'quarantine' && firewall.result !== 'BLOCK') {
                allowed = false;
                reason = `Quarantined by custom rule: ${rule.name}`;
                firewall.result = 'QUARANTINE';
                if (!firewall.threatIndicators.includes('custom_rule')) {
                  firewall.threatIndicators.push('custom_rule');
                }
              }
              // 'allow' action: no-op — custom rules cannot weaken built-in decisions
            }
          } catch {
            // Skip invalid regex in custom rules
          }
        }
      } catch {
        // Custom rules store not available — skip silently
      }
    }

    // 6c. Apply custom injection patterns (Pro feature, additive)
    if (allowed && isFeatureEnabled('custom_injection_patterns') && isDatabaseInitialized()) {
      try {
        const { getEnabledCustomPatterns } = require('./custom-patterns/store.js');
        const customPatterns = getEnabledCustomPatterns();
        for (const pattern of customPatterns) {
          try {
            const regex = new RegExp(pattern.regex, 'gi');
            if (regex.test(content) || regex.test(title)) {
              if (pattern.severity === 'critical' || pattern.severity === 'high') {
                allowed = false;
                reason = `Blocked by custom pattern: ${pattern.name} (${pattern.severity})`;
                firewall.result = 'BLOCK';
              } else {
                allowed = false;
                reason = `Quarantined by custom pattern: ${pattern.name} (${pattern.severity})`;
                firewall.result = 'QUARANTINE';
              }
              if (!firewall.threatIndicators.includes('custom_pattern')) {
                firewall.threatIndicators.push('custom_pattern');
              }
              break;
            }
          } catch {
            // Skip invalid regex in custom patterns
          }
        }
      } catch {
        // Custom patterns store not available — skip silently
      }
    }

    // Keep top-level reason and firewall.reason consistent for downstream callers.
    firewall.reason = reason;

    // Add credential_leak to threat indicators if any findings (even non-blocking)
    if (credentialScan.leaked && !firewall.threatIndicators.includes('credential_leak')) {
      firewall.threatIndicators.push('credential_leak');
    }

    const durationMs = Math.round(performance.now() - startTime);

    // 6. Log audit
    const _contentHash = createContentHash(content);
    const auditId = logAudit({
      memory_id: null,
      project: project ?? null,
      timestamp: new Date().toISOString(),
      source_type: source.type,
      source_identifier: source.identifier,
      trust_score: trust.score,
      sensitivity_level: sensitivity.level,
      firewall_result: firewall.result,
      anomaly_score: firewall.anomalyScore,
      threat_indicators: JSON.stringify(firewall.threatIndicators),
      blocked_patterns: JSON.stringify(firewall.blockedPatterns),
      reason,
      fragmentation_score: fragmentation?.score ?? null,
      pipeline_duration_ms: durationMs,
    });

    // 7. Emit defence event for real-time dashboard alerts (BLOCK/QUARANTINE only)
    if (firewall.result !== 'ALLOW') {
      try {
        persistEvent('defence_event', {
          source_type: source.type,
          source_identifier: source.identifier,
          firewall_result: firewall.result,
          trust_score: trust.score,
          anomaly_score: firewall.anomalyScore,
          reason,
          threat_indicators: JSON.stringify(firewall.threatIndicators),
          timestamp: new Date().toISOString(),
        });
      } catch {
        // Event persistence is best-effort
      }
    }

    const pipelineResult: DefencePipelineResult = {
      allowed,
      firewall,
      fragmentation,
      sensitivity,
      trust,
      credentialScan: credentialScan.leaked ? credentialScan : undefined,
      auditId,
    };

    // 8. Sync audit data to cloud (fire-and-forget, never blocks)
    if (isFeatureEnabled('cloud_sync')) {
      try {
        syncToCloud(pipelineResult, source, durationMs);
      } catch {
        // Cloud sync must never affect local pipeline
      }
    }

    // 9. Sync quarantine content to cloud (fire-and-forget)
    if (isFeatureEnabled('cloud_sync') && firewall.result === 'QUARANTINE') {
      try {
        const indicators = firewall.threatIndicators.map(t =>
          typeof t === 'string' ? t : (t as { pattern?: string }).pattern ?? String(t)
        );
        syncQuarantineToCloud({
          original_content: content,
          original_title: title,
          source_type: source.type,
          source_identifier: source.identifier,
          reason,
          threat_indicators: indicators,
          anomaly_score: firewall.anomalyScore,
          firewall_result: firewall.result,
        });
      } catch {
        // Quarantine sync must never affect local pipeline
      }
    }

    return pipelineResult;
  } catch (err) {
    // FAIL-CLOSED: on error, default to BLOCK for security
    const durationMs = Math.round(performance.now() - startTime);
    console.error('[defence] Pipeline error, failing closed:', err);

    const auditId = logAudit({
      memory_id: null,
      project: project ?? null,
      timestamp: new Date().toISOString(),
      source_type: source.type,
      source_identifier: source.identifier,
      trust_score: 0,
      sensitivity_level: 'RESTRICTED',
      firewall_result: 'BLOCK',
      anomaly_score: 1.0,
      threat_indicators: '["pipeline_error"]',
      blocked_patterns: '[]',
      reason: `Pipeline error (fail-closed): ${err instanceof Error ? err.message : String(err)}`,
      fragmentation_score: null,
      pipeline_duration_ms: durationMs,
    });

    return {
      allowed: false,
      firewall: {
        result: 'BLOCK',
        reason: 'Pipeline error — fail-closed for security',
        threatIndicators: ['pipeline_error'],
        anomalyScore: 1.0,
        blockedPatterns: [],
      },
      fragmentation: null,
      sensitivity: {
        level: 'RESTRICTED',
        confidence: 0,
        detectedPatterns: [],
        redactionRequired: true,
      },
      trust: {
        score: 0,
        source,
        hierarchy: [],
      },
      auditId,
    };
  }
}

/**
 * Async pipeline wrapper with optional LLM verification.
 *
 * Runs the synchronous defence pipeline, then optionally submits content
 * for cloud-based LLM verification (Tier 2).
 *
 * Advisory mode: fire-and-forget (returns immediately with pending status)
 * Enforce mode: awaits result, may upgrade QUARANTINE → BLOCK
 * Fail-OPEN: if verification fails/times out, original verdict stands.
 */
export async function runDefencePipelineWithVerify(
  content: string,
  title: string,
  source: DefenceSource,
  config?: DefenceConfig,
  project?: string,
): Promise<DefencePipelineResultWithVerify> {
  const result = runDefencePipeline(content, title, source, config, project);

  // Lazy import to avoid circular dependencies and keep sync pipeline clean
  const { getCloudConfig, getVerifyConfig } = await import('../cloud/config.js');
  const verifyConfig = getVerifyConfig();
  const cloudConfig = getCloudConfig();

  // Check if verification should trigger
  if (!cloudConfig.cloudEnabled || !cloudConfig.cloudApiKey || !verifyConfig.verifyEnabled) {
    return result;
  }

  if (!verifyConfig.verifyTriggers.includes(result.firewall.result)) {
    return result;
  }

  // Submit for verification
  const { submitVerification } = await import('../cloud/verify.js');
  const verifyResult = await submitVerification(content, title, result, source);

  if (!verifyResult) {
    return { ...result, verification: { id: 0, status: 'skipped', mode: verifyConfig.verifyMode } };
  }

  const verification: DefencePipelineResultWithVerify['verification'] = {
    id: verifyResult.id,
    status: verifyResult.status as 'pending' | 'completed' | 'failed',
    verdict: verifyResult.verdict,
    confidence: verifyResult.confidence,
    threats_detected: verifyResult.threats_detected,
    action: verifyResult.action,
    mode: verifyConfig.verifyMode,
  };

  // In enforce mode, upgrade QUARANTINE → BLOCK if LLM says THREAT with high confidence
  if (
    verifyConfig.verifyMode === 'enforce' &&
    verifyResult.status === 'completed' &&
    verifyResult.verdict === 'THREAT' &&
    (verifyResult.confidence ?? 0) >= 0.7 &&
    result.firewall.result === 'QUARANTINE'
  ) {
    verification.originalFirewallResult = result.firewall.result;
    return {
      ...result,
      allowed: false,
      firewall: {
        ...result.firewall,
        result: 'BLOCK',
        reason: `${result.firewall.reason} [LLM verified: THREAT, confidence ${verifyResult.confidence}]`,
      },
      verification,
    };
  }

  return { ...result, verification };
}
