/**
 * Iron Dome — Audit Logging
 *
 * Uses the existing ShieldCortex audit system to log Iron Dome events.
 */

import type { DefenceSource } from '../types.js';
import { logAudit } from '../audit/logger.js';

export interface IronDomeAuditEvent {
  action: string;
  channel?: string;
  actionType?: string;
  allowed: boolean;
  reason: string;
  source?: DefenceSource;
}

/**
 * Log an Iron Dome event to the defence audit table.
 * Fire-and-forget safe: errors are caught and logged, never thrown.
 */
export function logIronDomeAudit(event: IronDomeAuditEvent): void {
  try {
    logAudit({
      memory_id: null,
      project: null,
      timestamp: new Date().toISOString(),
      source_type: event.source?.type ?? 'cli',
      source_identifier: event.source?.identifier ?? 'iron-dome',
      trust_score: 0,
      sensitivity_level: 'PUBLIC',
      firewall_result: event.allowed ? 'ALLOW' : 'BLOCK',
      anomaly_score: 0,
      threat_indicators: '[]',
      blocked_patterns: '[]',
      reason: `[iron-dome:${event.action}] ${event.reason}`,
      fragmentation_score: null,
      pipeline_duration_ms: null,
    });
  } catch (err) {
    console.error('[iron-dome] Failed to log audit event:', err);
  }
}
