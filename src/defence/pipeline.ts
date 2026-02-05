/**
 * Defence Pipeline Orchestrator
 *
 * Runs all 5 defence layers in sequence and returns a unified result.
 * Fail-closed: if any layer throws, the pipeline defaults to BLOCK for security.
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
import { persistEvent } from '../api/events.js';

export function runDefencePipeline(
  content: string,
  title: string,
  source: DefenceSource,
  config?: DefenceConfig,
  project?: string,
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

    return {
      allowed,
      firewall,
      fragmentation,
      sensitivity,
      trust,
      auditId,
    };
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
