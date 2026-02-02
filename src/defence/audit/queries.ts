/**
 * Forensic query helpers for the defence audit log
 */

import { getDatabase } from '../../database/init.js';
import type { AuditEntry, FirewallResult } from '../types.js';

// ── Agent Interfaces ──

export interface AgentInfo {
  source_type: string;
  source_identifier: string;
  operation_count: number;
  last_seen: string;
  avg_trust_score: number;
  min_trust_score: number;
  max_trust_score: number;
  flagged_count: number;
}

export interface AgentTimelinePoint {
  timestamp: string;
  trust_score: number;
  firewall_result: string;
  anomaly_score: number;
}

// ── Interfaces ──

export interface AuditQueryOptions {
  startTime?: string;
  endTime?: string;
  operation?: 'write' | 'read' | 'delete' | 'update';
  source?: string;
  firewallResult?: FirewallResult;
  memoryId?: number;
  project?: string;
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
    conditions.push('da.timestamp >= @startTime');
    params.startTime = options.startTime;
  }
  if (options.endTime) {
    conditions.push('da.timestamp <= @endTime');
    params.endTime = options.endTime;
  }
  if (options.firewallResult) {
    conditions.push('da.firewall_result = @firewallResult');
    params.firewallResult = options.firewallResult;
  }
  if (options.source) {
    conditions.push('da.source_type = @source');
    params.source = options.source;
  }
  if (options.memoryId !== undefined) {
    conditions.push('da.memory_id = @memoryId');
    params.memoryId = options.memoryId;
  }

  if (options.project) {
    conditions.push('da.project = @project');
    params.project = options.project;
  }

  const where = conditions.length > 0 ? `WHERE ${conditions.join(' AND ')}` : '';
  const limit = options.limit ?? 50;

  const sql = `SELECT da.* FROM defence_audit da ${where} ORDER BY da.timestamp DESC LIMIT @limit`;
  params.limit = limit;

  return db.prepare(sql).all(params) as AuditEntry[];
}

/**
 * Get aggregate audit statistics for a time range.
 */
export function getAuditStats(timeRange: '24h' | '7d' | '30d', project?: string): AuditStats {
  const db = getDatabase();

  const hoursMap = { '24h': 24, '7d': 168, '30d': 720 };
  const hours = hoursMap[timeRange];
  const since = new Date(Date.now() - hours * 3600_000).toISOString();

  const projectCond = project ? 'AND da.project = ?' : '';
  const baseParams = project ? [since, project] : [since];

  // Counts by firewall result
  const counts = db.prepare(`
    SELECT da.firewall_result, COUNT(*) as cnt
    FROM defence_audit da
    WHERE da.timestamp >= ? ${projectCond}
    GROUP BY da.firewall_result
  `).all(...baseParams) as { firewall_result: string; cnt: number }[];

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
    SELECT da.source_type as source, COUNT(*) as count
    FROM defence_audit da
    WHERE da.timestamp >= ? ${projectCond}
    GROUP BY da.source_type
    ORDER BY count DESC
    LIMIT 10
  `).all(...baseParams) as { source: string; count: number }[];

  // Threat indicator breakdown
  const rows = db.prepare(`
    SELECT da.threat_indicators
    FROM defence_audit da
    WHERE da.timestamp >= ? ${projectCond} AND da.threat_indicators != '[]'
  `).all(...baseParams) as { threat_indicators: string }[];

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

// ── Agent Query Functions ──

/**
 * Get distinct agents aggregated from audit logs.
 */
export function queryAgentRegistry(timeRange: '24h' | '7d' | '30d' = '24h', project?: string): AgentInfo[] {
  const db = getDatabase();
  const hoursMap = { '24h': 24, '7d': 168, '30d': 720 };
  const since = new Date(Date.now() - hoursMap[timeRange] * 3600_000).toISOString();

  const projectCond = project ? 'AND project = ?' : '';
  const params = project ? [since, project] : [since];

  return db.prepare(`
    SELECT source_type, source_identifier,
      COUNT(*) as operation_count,
      MAX(timestamp) as last_seen,
      AVG(trust_score) as avg_trust_score,
      MIN(trust_score) as min_trust_score,
      MAX(trust_score) as max_trust_score,
      SUM(CASE WHEN firewall_result != 'ALLOW' THEN 1 ELSE 0 END) as flagged_count
    FROM defence_audit
    WHERE timestamp >= ? ${projectCond}
    GROUP BY source_type, source_identifier
    ORDER BY operation_count DESC
  `).all(...params) as AgentInfo[];
}

/**
 * Get trust score timeline for a specific agent.
 */
export function queryAgentTimeline(
  identifier: string,
  timeRange: '24h' | '7d' | '30d' = '24h',
  project?: string,
): AgentTimelinePoint[] {
  const db = getDatabase();
  const hoursMap = { '24h': 24, '7d': 168, '30d': 720 };
  const since = new Date(Date.now() - hoursMap[timeRange] * 3600_000).toISOString();

  const projectCond = project ? 'AND project = ?' : '';
  const params = project ? [identifier, since, project] : [identifier, since];

  return db.prepare(`
    SELECT timestamp, trust_score, firewall_result, anomaly_score
    FROM defence_audit
    WHERE source_identifier = ? AND timestamp >= ? ${projectCond}
    ORDER BY timestamp ASC
  `).all(...params) as AgentTimelinePoint[];
}

/**
 * Get paginated audit entries for a specific agent.
 */
export function queryAgentOperations(
  identifier: string,
  options: { limit?: number; offset?: number; firewallResult?: FirewallResult; project?: string } = {},
): AuditEntry[] {
  const db = getDatabase();
  const conditions: string[] = ['source_identifier = @identifier'];
  const params: Record<string, unknown> = { identifier };

  if (options.firewallResult) {
    conditions.push('firewall_result = @firewallResult');
    params.firewallResult = options.firewallResult;
  }
  if (options.project) {
    conditions.push('project = @project');
    params.project = options.project;
  }

  const limit = options.limit ?? 50;
  const offset = options.offset ?? 0;
  params.limit = limit;
  params.offset = offset;

  return db.prepare(`
    SELECT * FROM defence_audit
    WHERE ${conditions.join(' AND ')}
    ORDER BY timestamp DESC
    LIMIT @limit OFFSET @offset
  `).all(params) as AuditEntry[];
}
