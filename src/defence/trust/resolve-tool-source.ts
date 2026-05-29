/**
 * Resolve and harden the source of an MCP tool call.
 *
 * MCP callers can self-declare any source they like. This module:
 * 1. Always computes the environment-inferred trust ceiling first.
 * 2. Clamps any over-claimed declared source down to that ceiling.
 * 3. Writes a `SOURCE_ELEVATION_BLOCKED` row to defence_audit when a clamp
 *    happens, so operators can spot prompt-injection trying to escalate
 *    its own trust.
 * 4. Writes a `SOURCE_MISSING` row when no source was declared, preserving
 *    the existing visibility into unconfigured callers.
 */

import type { DefenceSource } from '../types.js';
import { clampSourceToCeiling } from './env-detector.js';
import { logAudit } from '../audit/logger.js';

export interface ResolveToolSourceOptions {
  /** Tool name (e.g. 'remember', 'recall') — recorded in the audit reason. */
  toolName: string;
  /** Active project scope, recorded on the audit row. */
  project: string | null;
}

/**
 * Resolve the effective source for an MCP tool call.
 *
 * Returns the source the rest of the pipeline should use. When a caller
 * over-claims trust the declared source is dropped, an audit row is written,
 * and the env-inferred source is returned instead.
 */
export function resolveToolSource(
  declaredSource: DefenceSource | undefined,
  options: ResolveToolSourceOptions,
): DefenceSource {
  const clampResult = clampSourceToCeiling(declaredSource);
  const { source, clamped, declaredScore, ceilingScore, detection } = clampResult;

  if (clamped && declaredSource) {
    try {
      logAudit({
        memory_id: null,
        project: options.project,
        timestamp: new Date().toISOString(),
        source_type: source.type,
        source_identifier: source.identifier,
        trust_score: ceilingScore,
        sensitivity_level: 'PUBLIC',
        firewall_result: 'BLOCK',
        anomaly_score: 0,
        threat_indicators: JSON.stringify(['privilege_escalation']),
        blocked_patterns: '[]',
        reason:
          `SOURCE_ELEVATION_BLOCKED: tool=${options.toolName}, ` +
          `declared=${declaredSource.type}:${declaredSource.identifier} (score=${declaredScore}), ` +
          `clamped=${source.type}:${source.identifier} (score=${ceilingScore}) ` +
          `via ${detection.method} (confidence: ${detection.confidence})`,
        fragmentation_score: null,
        pipeline_duration_ms: null,
      });
    } catch {
      // Audit logging must never break tool execution.
    }
    return source;
  }

  // No declared source — inferred from environment. Preserve the existing
  // SOURCE_MISSING visibility so operators see unconfigured callers.
  if (!declaredSource) {
    try {
      logAudit({
        memory_id: null,
        project: options.project,
        timestamp: new Date().toISOString(),
        source_type: source.type,
        source_identifier: source.identifier,
        trust_score: 0,
        sensitivity_level: 'PUBLIC',
        firewall_result: 'ALLOW',
        anomaly_score: 0,
        threat_indicators: '[]',
        blocked_patterns: '[]',
        reason:
          `SOURCE_MISSING: tool=${options.toolName}, ` +
          `inferred=${source.type}:${source.identifier} ` +
          `via ${detection.method} (confidence: ${detection.confidence})`,
        fragmentation_score: null,
        pipeline_duration_ms: null,
      });
    } catch {
      // Audit logging must never break tool execution.
    }
  }

  return source;
}
