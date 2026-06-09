/**
 * Tool Response Scanner
 *
 * Lightweight defence scanner for MCP tool outputs (read-path).
 * Runs injection detection + credential leak scanning (2 of 6 layers).
 * Skips fragmentation, sensitivity, and trust scoring (write-path concerns).
 *
 * Advisory by default: logs threats but never blocks tool responses.
 */

import { scanForInjection } from './iron-dome/injection-scanner.js';
import { scanForCredentials } from './credential-leak/index.js';
import { logAudit } from './audit/logger.js';
import { isDatabaseInitialized } from '../database/init.js';
import { getToolResponseScanConfig } from '../cloud/config.js';
import type { ThreatIndicator, ToolResponseScanResult } from './types.js';
import { persistEvent } from '../api/events.js';

// ../api/events.js is imported statically. ESM tolerates the cycle because
// persistEvent is only called inside scanToolResponse (function-level use,
// resolved at call time), and the events module is lightweight (EventEmitter +
// getDatabase, no server/ws stack). The try/catch below stays — dashboard event
// persistence is best-effort and must never affect tool-response delivery.

// Tools that return memory/knowledge content (worth scanning)
const HIGH_RISK_TOOLS = new Set([
  'recall',
  'get_context',
  'get_memory',
  'get_related',
  'graph_query',
  'graph_explain',
  'graph_entities',
  'export_memories',
  'detect_contradictions',
]);

// Tools that only return metadata/stats (not worth scanning)
const METADATA_ONLY_TOOLS = new Set([
  'memory_stats',
  'defence_stats',
  'iron_dome_status',
  'get_project',
  'audit_query',
]);

/**
 * Check if a tool's response should be scanned.
 * Unknown tools (e.g. external MCP servers) default to scanned.
 */
export function shouldScanToolResponse(toolName: string): boolean {
  if (HIGH_RISK_TOOLS.has(toolName)) return true;
  if (METADATA_ONLY_TOOLS.has(toolName)) return false;
  return true;
}

/**
 * Scan a tool response for threats.
 *
 * Runs injection scanning (40+ patterns) + credential leak detection (25+ providers).
 * In advisory mode, threats are logged but the response is never blocked.
 */
export function scanToolResponse(
  toolName: string,
  content: string,
  mode?: 'advisory' | 'enforce',
): ToolResponseScanResult {
  const startTime = performance.now();
  const resolvedMode = mode ?? getToolResponseScanConfig().toolResponseMode;

  // Skip tiny responses (confirmations, error messages)
  if (!content || content.length < 20) {
    return {
      clean: true,
      mode: resolvedMode,
      toolName,
      injection: { clean: true, riskLevel: 'NONE', detections: [], textLength: content?.length ?? 0, summary: 'No patterns detected.' },
      credentials: { leaked: false, findings: [] },
      threatIndicators: [],
      summary: `Tool response from "${toolName}" skipped (too short)`,
      durationMs: Math.round(performance.now() - startTime),
      auditId: -1,
    };
  }

  // 1. Injection scan (Iron Dome patterns)
  const injection = scanForInjection(content);

  // 2. Credential leak scan
  const credentials = scanForCredentials(content);

  // 3. Collect threat indicators
  const threatIndicators: ThreatIndicator[] = [];
  if (!injection.clean) {
    threatIndicators.push('instruction_injection');
    const categories = new Set(injection.detections.map(d => d.category));
    if (categories.has('credential_extraction')) {
      threatIndicators.push('credential_leak');
    }
    if (categories.has('encoding_trick')) {
      threatIndicators.push('encoding_obfuscation');
    }
  }
  if (credentials.leaked && !threatIndicators.includes('credential_leak')) {
    threatIndicators.push('credential_leak');
  }

  const clean = injection.clean && !credentials.leaked;
  const durationMs = Math.round(performance.now() - startTime);

  // 4. Build summary
  let summary: string;
  if (clean) {
    summary = `Tool response from "${toolName}" is clean (${durationMs}ms)`;
  } else {
    const parts: string[] = [];
    if (!injection.clean) parts.push(`injection: ${injection.summary}`);
    if (credentials.leaked) parts.push(`credentials: ${credentials.findings.length} finding(s)`);
    summary = `THREAT in "${toolName}" response: ${parts.join('; ')} (${durationMs}ms)`;
  }

  // 5. Audit log (threats only)
  let auditId = -1;
  if (!clean && isDatabaseInitialized()) {
    try {
      auditId = logAudit({
        memory_id: null,
        project: null,
        timestamp: new Date().toISOString(),
        source_type: 'tool_response',
        source_identifier: toolName,
        trust_score: 0.5,
        sensitivity_level: credentials.leaked ? 'CONFIDENTIAL' : 'PUBLIC',
        firewall_result: resolvedMode === 'enforce' ? 'BLOCK' : 'ALLOW',
        anomaly_score: injection.clean ? 0 : (injection.riskLevel === 'CRITICAL' ? 1.0 : 0.7),
        threat_indicators: JSON.stringify(threatIndicators),
        blocked_patterns: JSON.stringify(injection.detections.map(d => d.pattern)),
        reason: summary,
        fragmentation_score: null,
        pipeline_duration_ms: durationMs,
      });
    } catch {
      // Audit logging must never affect tool response delivery
    }

    // 6. Dashboard real-time event
    try {
      persistEvent('defence_event', {
        source_type: 'tool_response',
        source_identifier: toolName,
        firewall_result: resolvedMode === 'enforce' ? 'BLOCK' : 'ALLOW',
        trust_score: 0.5,
        anomaly_score: injection.clean ? 0 : 0.7,
        reason: summary,
        threat_indicators: JSON.stringify(threatIndicators),
        timestamp: new Date().toISOString(),
      });
    } catch {
      // Event persistence is best-effort
    }
  }

  return {
    clean,
    mode: resolvedMode,
    toolName,
    injection,
    credentials,
    threatIndicators,
    summary,
    durationMs,
    auditId,
  };
}
