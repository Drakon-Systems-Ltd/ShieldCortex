/**
 * Iron Dome — Audit Logging
 *
 * Uses the existing ShieldCortex audit system to log Iron Dome events.
 */

import type { DefenceSource } from '../types.js';
import { attestedFlag, logAudit } from '../audit/logger.js';

export interface IronDomeAuditEvent {
  action: string;
  channel?: string;
  actionType?: string;
  allowed: boolean;
  reason: string;
  source?: DefenceSource;
  /**
   * Attestation for the row. Omit for the default cli:iron-dome identity — a
   * code constant, attested by construction. If you supply your OWN `source`
   * (e.g. a resolved caller), you MUST state attestation too: an unstated
   * source falls to NULL (fail-safe), never silently attested.
   */
  attested?: boolean;
}

/**
 * Log an Iron Dome event to the defence audit table.
 * Fire-and-forget safe: errors are caught and logged, never thrown.
 */
export function logIronDomeAudit(event: IronDomeAuditEvent): void {
  try {
    // No source ⇒ the code-constant cli:iron-dome identity ⇒ attested by
    // construction. A supplied source with no stated attestation fails safe to
    // NULL (a resolved caller identity is only attested if the resolver said so).
    const attested = event.attested ?? (event.source ? undefined : true);
    logAudit({
      memory_id: null,
      project: null,
      timestamp: new Date().toISOString(),
      source_type: event.source?.type ?? 'cli',
      source_identifier: event.source?.identifier ?? 'iron-dome',
      trust_score: 0,
      sensitivity_level: 'PUBLIC',
      firewall_result: event.allowed ? 'ALLOW' : 'BLOCK',
      operation: null, // iron-dome kill-switch / defence event, not a memory read/write/delete
      anomaly_score: 0,
      threat_indicators: '[]',
      blocked_patterns: '[]',
      reason: `[iron-dome:${event.action}] ${event.reason}`,
      fragmentation_score: null,
      pipeline_duration_ms: null,
      source_attested: attestedFlag(attested),
    });
  } catch (err) {
    console.error('[iron-dome] Failed to log audit event:', err);
  }
}
