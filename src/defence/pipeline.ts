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

import { sanitiseInput } from './input-sanitisation/index.js';
import { scoreSource } from './trust/index.js';
import { analyzeFirewall } from './firewall/index.js';
import { classifySensitivity } from './sensitivity/index.js';
import { analyzeFragmentation } from './fragmentation/index.js';
import { scanForCredentials, type CredentialScanResult } from './credential-leak/index.js';
import { logAudit } from './audit/index.js';
import { persistEvent } from '../api/events.js';
import { syncToCloud } from '../cloud/sync.js';
import { syncQuarantineToCloud } from '../cloud/quarantine-sync.js';
import { isFeatureEnabled } from '../license/gate.js';
import { getDefenceMode } from '../cloud/config.js';
import { isDatabaseInitialized } from '../database/init.js';
import { getEnabledFirewallRules, ruleMatches } from './custom-rules/store.js';
import { getEnabledCustomPatterns } from './custom-patterns/store.js';

// The rule/pattern stores are imported statically. Safe at module-eval time:
// there is no import cycle on these edges — custom-rules/store and
// custom-patterns/store import only getDatabase and types, never back into the
// pipeline — and they do no work at import (no top-level DB access). They are
// only called inside runDefencePipeline. The surrounding try/catch below stays:
// getEnabledFirewallRules()/getEnabledCustomPatterns() throw if the DB is
// uninitialised, and that must still fail closed rather than weaken a decision.

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
    // 1. Input sanitisation (Layer 1) — strip dangerous bytes before analysis
    const sanitisation = sanitiseInput(content);
    const cleanContent = sanitisation.sanitised;

    // 2. Score trust
    const trust: TrustScore = scoreSource(source);

    // 3. Run firewall (on sanitised content). Pass the strip categories so the
    // firewall can account for zero-width/bidi bytes the sanitiser already
    // removed — otherwise its encoding detector never sees them and the
    // "zero-width/RTL → quarantine" rule can't fire.
    const firewall: FirewallAnalysis = analyzeFirewall(
      cleanContent,
      title,
      source,
      trust.score,
      cfg,
      sanitisation.strippedCategories,
    );

    // Carry forward any sanitisation threat indicators (deduped — the firewall
    // may already have added 'encoding_obfuscation' from the strip signal above)
    for (const indicator of sanitisation.threatIndicators) {
      if (!firewall.threatIndicators.includes(indicator)) {
        firewall.threatIndicators.push(indicator);
      }
    }

    // 4. Classify sensitivity
    const sensitivity: SensitivityClassification = classifySensitivity(cleanContent, title);

    // 5. Run fragmentation detection (if enabled and firewall didn't block)
    let fragmentation: FragmentationAnalysis | null = null;
    if (cfg.enableFragmentationDetection && firewall.result !== 'BLOCK') {
      fragmentation = analyzeFragmentation(cleanContent, title, cfg);
    }

    // 6. Run credential leak detection
    const credentialScan: CredentialScanResult = scanForCredentials(cleanContent);

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
      Math.round(fragmentation.score * 1000) > Math.round(cfg.autoQuarantineThreshold * 1000)
    ) {
      allowed = false;
      reason = `Quarantined: fragmentation score ${fragmentation.score.toFixed(2)} exceeds threshold ${cfg.autoQuarantineThreshold}`;
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
      if (firewall.result !== 'ALLOW') {
        allowed = false;
        reason = `Unexpected firewall result: ${firewall.result}`;
      } else {
        allowed = true;
        reason = firewall.reason;
      }
    }

    // 6b. Apply firewall rules (built-in rules always evaluated; user-added
    // custom rules require the Pro `custom_firewall_rules` feature). Both
    // are additive only — can tighten, never weaken.
    if (allowed && isDatabaseInitialized()) {
      try {
        const userRulesAllowed = isFeatureEnabled('custom_firewall_rules');
        const allRules = getEnabledFirewallRules();
        for (const rule of allRules) {
          if (!rule.built_in && !userRulesAllowed) continue;
          try {
            // Honour the rule's condition_type: keyword = literal substring,
            // domain = hostname match, regex = compiled pattern.
            if (ruleMatches(rule, cleanContent, title)) {
              const indicator = rule.built_in ? 'builtin_rule' : 'custom_rule';
              if (rule.action === 'block') {
                allowed = false;
                reason = `Blocked by ${rule.built_in ? 'built-in' : 'custom'} rule: ${rule.name}`;
                firewall.result = 'BLOCK';
                if (!firewall.threatIndicators.includes(indicator)) {
                  firewall.threatIndicators.push(indicator);
                }
                break; // Block is final
              } else if (rule.action === 'quarantine' && firewall.result !== 'BLOCK') {
                allowed = false;
                reason = `Quarantined by ${rule.built_in ? 'built-in' : 'custom'} rule: ${rule.name}`;
                firewall.result = 'QUARANTINE';
                if (!firewall.threatIndicators.includes(indicator)) {
                  firewall.threatIndicators.push(indicator);
                }
              }
              // 'allow' action: no-op — rules cannot weaken built-in decisions
            }
          } catch {
            // Skip invalid regex in rules
          }
        }
      } catch {
        // Rules store not available — skip silently
      }
    }

    // 6c. Apply custom injection patterns (Pro feature, additive)
    if (allowed && isFeatureEnabled('custom_injection_patterns') && isDatabaseInitialized()) {
      try {
        const customPatterns = getEnabledCustomPatterns();
        for (const pattern of customPatterns) {
          try {
            const regex = new RegExp(pattern.regex, 'gi');
            if (regex.test(cleanContent) || regex.test(title)) {
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

    // 8. Sync audit data to cloud (fire-and-forget, never blocks).
    // Gated on `cloud_audit_sync` (Free tier) — metadata only, no content.
    if (isFeatureEnabled('cloud_audit_sync')) {
      try {
        syncToCloud(pipelineResult, source, durationMs);
      } catch {
        // Cloud sync must never affect local pipeline
      }
    }

    // 9. Sync quarantine *content* to cloud (fire-and-forget). Gated on
    // `cloud_sync` (Team tier) because this sends original content + title.
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
          project: project ?? null,
          sensitivity_level: sensitivity.level,
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
  let result: DefencePipelineResultWithVerify = runDefencePipeline(content, title, source, config, project);

  // Semantic-similarity layer (LOCAL, async-path only). Runs regardless of the
  // cloud-verify gate below. Lazy-imported so the sync pipeline never pulls in
  // the embedding worker. Degrades gracefully: when the model is unavailable
  // `available` is false and we do nothing (no escalation, no field). When it
  // flags, the escalation is ADDITIVE — it can lift ALLOW/QUARANTINE up to at
  // least QUARANTINE, but it never downgrades an existing BLOCK.
  try {
    const { analyzeSemanticSimilarity } = await import('./semantic/index.js');
    const semantic = await analyzeSemanticSimilarity(content);
    if (semantic.available) {
      result = {
        ...result,
        semanticSimilarity: {
          maxSimilarity: semantic.maxSimilarity,
          matchedPhrase: semantic.matchedPhrase,
        },
      };

      if (semantic.flagged && result.firewall.result !== 'BLOCK') {
        const threatIndicators = result.firewall.threatIndicators.includes('semantic_similarity')
          ? result.firewall.threatIndicators
          : [...result.firewall.threatIndicators, 'semantic_similarity' as const];
        const reason = `Quarantined: semantic similarity to known attack phrasing (${semantic.maxSimilarity.toFixed(2)})`;
        result = {
          ...result,
          allowed: false,
          firewall: {
            ...result.firewall,
            result: 'QUARANTINE',
            reason,
            threatIndicators,
          },
        };
      }
    }
  } catch {
    // Semantic layer must never affect the local verdict on failure — keep the
    // sync result as-is (the sync pipeline already fails closed on real errors).
  }

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
