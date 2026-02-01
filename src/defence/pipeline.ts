/**
 * Defence Pipeline Orchestrator
 *
 * Runs all 5 defence layers in sequence and returns a unified result.
 * Fail-open: if any layer throws, the pipeline defaults to ALLOW with a warning.
 */

import type {
  DefenceConfig,
  DefencePipelineResult,
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
import { logAudit, createContentHash } from './audit/index.js';

export function runDefencePipeline(
  content: string,
  title: string,
  source: DefenceSource,
  config?: DefenceConfig,
): DefencePipelineResult {
  const cfg = config ?? DEFAULT_DEFENCE_CONFIG;
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

    // 5. Determine final decision
    let allowed: boolean;
    let reason: string;

    if (firewall.result === 'BLOCK') {
      allowed = false;
      reason = firewall.reason;
    } else if (firewall.result === 'QUARANTINE') {
      allowed = false;
      reason = `Quarantined: ${firewall.reason}`;
    } else if (
      fragmentation !== null &&
      fragmentation.score > cfg.autoQuarantineThreshold
    ) {
      allowed = false;
      reason = `Quarantined: fragmentation score ${fragmentation.score} exceeds threshold ${cfg.autoQuarantineThreshold}`;
    } else if (sensitivity.level === 'RESTRICTED') {
      allowed = false;
      reason = `Blocked: content classified as RESTRICTED (${sensitivity.detectedPatterns.join(', ')})`;
    } else {
      allowed = true;
      reason = firewall.reason;
    }

    const durationMs = Math.round(performance.now() - startTime);

    // 6. Log audit
    const _contentHash = createContentHash(content);
    const auditId = logAudit({
      memory_id: null,
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

    return {
      allowed,
      firewall,
      fragmentation,
      sensitivity,
      trust,
      auditId,
    };
  } catch (err) {
    // Fail-open: log warning and allow
    const durationMs = Math.round(performance.now() - startTime);
    console.error('[defence] Pipeline error, failing open:', err);

    const auditId = logAudit({
      memory_id: null,
      timestamp: new Date().toISOString(),
      source_type: source.type,
      source_identifier: source.identifier,
      trust_score: 0,
      sensitivity_level: 'PUBLIC',
      firewall_result: 'ALLOW',
      anomaly_score: 0,
      threat_indicators: '[]',
      blocked_patterns: '[]',
      reason: `Pipeline error (fail-open): ${err instanceof Error ? err.message : String(err)}`,
      fragmentation_score: null,
      pipeline_duration_ms: durationMs,
    });

    return {
      allowed: true,
      firewall: {
        result: 'ALLOW',
        reason: 'Pipeline error — fail-open default',
        threatIndicators: [],
        anomalyScore: 0,
        blockedPatterns: [],
      },
      fragmentation: null,
      sensitivity: {
        level: 'PUBLIC',
        confidence: 0,
        detectedPatterns: [],
        redactionRequired: false,
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
