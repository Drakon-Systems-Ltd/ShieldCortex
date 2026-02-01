/**
 * Forensic query helpers for the defence audit log
 */

import { getDatabase } from '../../database/init.js';
import type { AuditEntry, FirewallResult } from '../types.js';

// ── Interfaces ──

export interface AuditQueryOptions {
  startTime?: string;
  endTime?: string;
  operation?: 'write' | 'read' | 'delete' | 'update';
  source?: string;
  firewallResult?: FirewallResult;
  memoryId?: number;
  limit?: number;
}

export interface AuditStats {
  totalOperations: number;
  allowedCount: number;
  blockedCount: number;
  quarantinedCount: number;
  topSources: { source: string; count: number }[];
  threatBreakdown: Record<string, number>;
}

// ── Query Functions ──

/**
 * Query audit logs with flexible filters.
 */
export function queryAuditLogs(options: AuditQueryOptions = {}): AuditEntry[] {
  const db = getDatabase();
  const conditions: string[] = [];
  const params: Record<string, unknown> = {};

  if (options.startTime) {
    conditions.push('timestamp >= @startTime');
    params.startTime = options.startTime;
  }
  if (options.endTime) {
    conditions.push('timestamp <= @endTime');
    params.endTime = options.endTime;
  }
  if (options.firewallResult) {
    conditions.push('firewall_result = @firewallResult');
    params.firewallResult = options.firewallResult;
  }
  if (options.source) {
    conditions.push('source_type = @source');
    params.source = options.source;
  }
  if (options.memoryId !== undefined) {
    conditions.push('memory_id = @memoryId');
    params.memoryId = options.memoryId;
  }

  const where = conditions.length > 0 ? `WHERE ${conditions.join(' AND ')}` : '';
  const limit = options.limit ?? 50;

  const sql = `SELECT * FROM defence_audit ${where} ORDER BY timestamp DESC LIMIT @limit`;
  params.limit = limit;

  return db.prepare(sql).all(params) as AuditEntry[];
}

/**
 * Get aggregate audit statistics for a time range.
 */
export function getAuditStats(timeRange: '24h' | '7d' | '30d'): AuditStats {
  const db = getDatabase();

  const hoursMap = { '24h': 24, '7d': 168, '30d': 720 };
  const hours = hoursMap[timeRange];
  const since = new Date(Date.now() - hours * 3600_000).toISOString();

  // Counts by firewall result
  const counts = db.prepare(`
    SELECT firewall_result, COUNT(*) as cnt
    FROM defence_audit
    WHERE timestamp >= ?
    GROUP BY firewall_result
  `).all(since) as { firewall_result: string; cnt: number }[];

  let totalOperations = 0;
  let allowedCount = 0;
  let blockedCount = 0;
  let quarantinedCount = 0;

  for (const row of counts) {
    totalOperations += row.cnt;
    if (row.firewall_result === 'ALLOW') allowedCount = row.cnt;
    else if (row.firewall_result === 'BLOCK') blockedCount = row.cnt;
    else if (row.firewall_result === 'QUARANTINE') quarantinedCount = row.cnt;
  }

  // Top sources
  const topSources = db.prepare(`
    SELECT source_type as source, COUNT(*) as count
    FROM defence_audit
    WHERE timestamp >= ?
    GROUP BY source_type
    ORDER BY count DESC
    LIMIT 10
  `).all(since) as { source: string; count: number }[];

  // Threat indicator breakdown
  const rows = db.prepare(`
    SELECT threat_indicators
    FROM defence_audit
    WHERE timestamp >= ? AND threat_indicators != '[]'
  `).all(since) as { threat_indicators: string }[];

  const threatBreakdown: Record<string, number> = {};
  for (const row of rows) {
    try {
      const indicators: string[] = JSON.parse(row.threat_indicators);
      for (const indicator of indicators) {
        threatBreakdown[indicator] = (threatBreakdown[indicator] ?? 0) + 1;
      }
    } catch {
      // Skip malformed JSON
    }
  }

  return {
    totalOperations,
    allowedCount,
    blockedCount,
    quarantinedCount,
    topSources,
    threatBreakdown,
  };
}
