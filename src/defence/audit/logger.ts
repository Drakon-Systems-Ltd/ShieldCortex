/**
 * Audit logger — records all memory operations for forensic analysis
 */

import { createHash } from 'crypto';
import { getDatabase } from '../../database/init.js';
import type { AuditEntry } from '../types.js';

/**
 * Log an audit entry to the defence_audit table.
 * Fire-and-forget safe: errors are caught and logged, never thrown.
 */
export function logAudit(entry: Omit<AuditEntry, 'id'>): number {
  try {
    const db = getDatabase();
    const stmt = db.prepare(`
      INSERT INTO defence_audit (
        memory_id, timestamp, source_type, source_identifier,
        trust_score, sensitivity_level, firewall_result,
        anomaly_score, threat_indicators, blocked_patterns,
        reason, fragmentation_score, pipeline_duration_ms
      ) VALUES (
        @memory_id, @timestamp, @source_type, @source_identifier,
        @trust_score, @sensitivity_level, @firewall_result,
        @anomaly_score, @threat_indicators, @blocked_patterns,
        @reason, @fragmentation_score, @pipeline_duration_ms
      )
    `);

    const result = stmt.run({
      memory_id: entry.memory_id ?? null,
      timestamp: entry.timestamp ?? new Date().toISOString(),
      source_type: entry.source_type,
      source_identifier: entry.source_identifier,
      trust_score: entry.trust_score,
      sensitivity_level: entry.sensitivity_level,
      firewall_result: entry.firewall_result,
      anomaly_score: entry.anomaly_score ?? 0,
      threat_indicators: entry.threat_indicators ?? '[]',
      blocked_patterns: entry.blocked_patterns ?? '[]',
      reason: entry.reason ?? null,
      fragmentation_score: entry.fragmentation_score ?? null,
      pipeline_duration_ms: entry.pipeline_duration_ms ?? null,
    });

    return Number(result.lastInsertRowid);
  } catch (err) {
    console.error('[audit] Failed to log audit entry:', err);
    return -1;
  }
}

/**
 * Create a SHA-256 hash of content for integrity verification.
 */
export function createContentHash(content: string): string {
  return createHash('sha256').update(content, 'utf-8').digest('hex');
}
