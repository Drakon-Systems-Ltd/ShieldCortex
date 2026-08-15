/**
 * Audit logger — records all memory operations for forensic analysis
 */

import { createHash } from 'crypto';
import { getDatabase, isDatabaseInitialized } from '../../database/init.js';
import type { AuditEntry } from '../types.js';

/**
 * Map an attestation intent to the `source_attested` ledger value.
 *
 * The one place the boolean→column mapping lives, so every writer that plumbs
 * attestation agrees on it: `true`→1, `false`→0, and `undefined`→NULL — the
 * last meaning "this writer does not derive attestation", which the risk model
 * reads conservatively as un-attested. A writer must never pass a literal
 * `false` as a placeholder for "not plumbed yet": an explicit 0 under a real
 * identity is what mutes that source's trust modifier (risk.ts latest-non-null).
 */
export function attestedFlag(attested: boolean | undefined): number | null {
  return attested === undefined ? null : attested ? 1 : 0;
}

/**
 * Log an audit entry to the defence_audit table.
 * Fire-and-forget safe: errors are caught and logged, never thrown.
 */
export function logAudit(entry: Omit<AuditEntry, 'id'>): number {
  if (!isDatabaseInitialized()) return -1;

  try {
    const db = getDatabase();
    const stmt = db.prepare(`
      INSERT INTO defence_audit (
        memory_id, project, timestamp, source_type, source_identifier,
        trust_score, sensitivity_level, firewall_result, operation, content_hash,
        anomaly_score, threat_indicators, blocked_patterns,
        reason, fragmentation_score, pipeline_duration_ms,
        source_attested, risk_modifier
      ) VALUES (
        @memory_id, @project, @timestamp, @source_type, @source_identifier,
        @trust_score, @sensitivity_level, @firewall_result, @operation, @content_hash,
        @anomaly_score, @threat_indicators, @blocked_patterns,
        @reason, @fragmentation_score, @pipeline_duration_ms,
        @source_attested, @risk_modifier
      )
    `);

    const result = stmt.run({
      memory_id: entry.memory_id ?? null,
      project: entry.project ?? null,
      timestamp: entry.timestamp ?? new Date().toISOString(),
      source_type: entry.source_type,
      source_identifier: entry.source_identifier,
      trust_score: entry.trust_score,
      sensitivity_level: entry.sensitivity_level,
      firewall_result: entry.firewall_result,
      operation: entry.operation ?? null,
      content_hash: entry.content_hash ?? null,
      anomaly_score: entry.anomaly_score ?? 0,
      threat_indicators: entry.threat_indicators ?? '[]',
      blocked_patterns: entry.blocked_patterns ?? '[]',
      reason: entry.reason ?? null,
      fragmentation_score: entry.fragmentation_score ?? null,
      pipeline_duration_ms: entry.pipeline_duration_ms ?? null,
      source_attested: entry.source_attested ?? null,
      risk_modifier: entry.risk_modifier ?? null,
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
