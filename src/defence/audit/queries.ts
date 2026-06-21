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

export interface IncidentReplayOptions {
  startTime?: string;
  endTime?: string;
  project?: string;
  sourceIdentifier?: string;
  memoryId?: number;
  limit?: number;
}

export interface IncidentReplayEntry {
  timestamp: string;
  type: 'audit' | 'quarantine' | 'event';
  eventType: string;
  severity: 'info' | 'warning' | 'critical';
  summary: string;
  details?: string | null;
  source?: string;
  memoryId?: number | null;
  auditId?: number | null;
  quarantineId?: number | null;
  metadata?: Record<string, unknown>;
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
  if (options.operation) {
    conditions.push('da.operation = @operation');
    params.operation = options.operation;
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

// ── Lifetime Stats ──

export interface LifetimeStats {
  totalScans: number;
  threatsBlocked: number;
  quarantined: number;
  credentialLeaks: number;
  memoriesProtected: number;
}

/**
 * Get all-time aggregate stats.
 *
 * defence_audit is now retention-bounded (see src/defence/audit/retention.ts):
 * old rows are periodically purged so the table can't grow until it bricks the
 * DB at the 100MB hard limit. To keep these lifetime totals correct, every purge
 * first rolls the to-be-deleted rows' contributions into the single-row
 * `audit_aggregates` table. So the lifetime total is `aggregate + scan(live)` —
 * the aggregate carries the purged history and the COUNT scan covers the
 * (bounded) rows still on disk. This guarantees totals never go backwards after
 * a purge. The credential LIKE scan is over a bounded table now, so it's fine.
 */
export function getLifetimeStats(): LifetimeStats {
  const db = getDatabase();

  // Counts by firewall result (live, retention-bounded rows)
  const counts = db.prepare(`
    SELECT firewall_result, COUNT(*) as cnt
    FROM defence_audit
    GROUP BY firewall_result
  `).all() as { firewall_result: string; cnt: number }[];

  let totalScans = 0;
  let threatsBlocked = 0;
  let quarantined = 0;
  let memoriesProtected = 0;

  for (const row of counts) {
    totalScans += row.cnt;
    if (row.firewall_result === 'BLOCK') threatsBlocked = row.cnt;
    else if (row.firewall_result === 'QUARANTINE') quarantined = row.cnt;
    else if (row.firewall_result === 'ALLOW') memoriesProtected = row.cnt;
  }

  // Credential leaks: threat_indicators contains 'credential' (case-insensitive)
  const credRow = db.prepare(`
    SELECT COUNT(*) as cnt
    FROM defence_audit
    WHERE LOWER(threat_indicators) LIKE '%credential%'
  `).get() as { cnt: number };

  let credentialLeaks = credRow?.cnt ?? 0;

  // Add the cumulative aggregate of all rows already purged by retention. The
  // table may not exist on very old DBs mid-migration — treat absence as zero.
  try {
    const agg = db.prepare(`
      SELECT total_scans, threats_blocked, quarantined, memories_protected, credential_leaks
      FROM audit_aggregates WHERE id = 1
    `).get() as
      | {
          total_scans: number;
          threats_blocked: number;
          quarantined: number;
          memories_protected: number;
          credential_leaks: number;
        }
      | undefined;

    if (agg) {
      totalScans += agg.total_scans;
      threatsBlocked += agg.threats_blocked;
      quarantined += agg.quarantined;
      memoriesProtected += agg.memories_protected;
      credentialLeaks += agg.credential_leaks;
    }
  } catch {
    // No aggregate row / table yet — lifetime == live counts.
  }

  return {
    totalScans,
    threatsBlocked,
    quarantined,
    credentialLeaks,
    memoriesProtected,
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

function extractReplayMemoryId(data: unknown): number | null {
  if (!data || typeof data !== 'object') return null;
  const record = data as Record<string, unknown>;
  if (typeof record.memoryId === 'number') return record.memoryId;
  if (record.memory && typeof record.memory === 'object' && record.memory) {
    const nested = record.memory as Record<string, unknown>;
    if (typeof nested.id === 'number') return nested.id;
  }
  return null;
}

function extractReplayProject(data: unknown): string | null {
  if (!data || typeof data !== 'object') return null;
  const record = data as Record<string, unknown>;
  if (typeof record.project === 'string') return record.project;
  if (record.memory && typeof record.memory === 'object' && record.memory) {
    const nested = record.memory as Record<string, unknown>;
    if (typeof nested.project === 'string') return nested.project;
  }
  return null;
}

function buildEventSummary(type: string, data: unknown): string {
  if (!data || typeof data !== 'object') return type;
  const record = data as Record<string, unknown>;

  switch (type) {
    case 'memory_created':
    case 'memory_updated':
      return `Memory ${type === 'memory_created' ? 'created' : 'updated'}: ${String((record.memory as Record<string, unknown> | undefined)?.title ?? 'Untitled')}`;
    case 'memory_deleted':
      return `Memory deleted: ${String(record.title ?? `ID ${record.memoryId ?? 'unknown'}`)}`;
    case 'memory_accessed':
      return `Memory accessed: ${String((record.memory as Record<string, unknown> | undefined)?.title ?? `ID ${record.memoryId ?? 'unknown'}`)}`;
    case 'defence_event':
      return `Defence event: ${String(record.firewall_result ?? 'UNKNOWN')} from ${String(record.source_type ?? 'unknown')}:${String(record.source_identifier ?? 'unknown')}`;
    case 'consolidation_complete':
      return `Consolidation complete: ${String(record.consolidated ?? 0)} promoted, ${String(record.deleted ?? 0)} deleted`;
    case 'kill_switch_activated':
      return 'Kill switch activated';
    case 'kill_switch_deactivated':
      return 'Kill switch deactivated';
    default:
      return type.replace(/_/g, ' ');
  }
}

export function queryIncidentReplay(options: IncidentReplayOptions = {}): IncidentReplayEntry[] {
  const db = getDatabase();
  const startTime = options.startTime ?? new Date(Date.now() - 24 * 60 * 60 * 1000).toISOString();
  const endTime = options.endTime ?? new Date().toISOString();
  const limit = options.limit ?? 200;
  const entries: IncidentReplayEntry[] = [];

  const auditConditions = ['timestamp >= @startTime', 'timestamp <= @endTime'];
  const auditParams: Record<string, unknown> = { startTime, endTime, limit };

  if (options.project) {
    auditConditions.push('project = @project');
    auditParams.project = options.project;
  }
  if (options.sourceIdentifier) {
    auditConditions.push('source_identifier = @sourceIdentifier');
    auditParams.sourceIdentifier = options.sourceIdentifier;
  }
  if (options.memoryId !== undefined) {
    auditConditions.push('memory_id = @memoryId');
    auditParams.memoryId = options.memoryId;
  }

  const auditRows = db.prepare(`
    SELECT *
    FROM defence_audit
    WHERE ${auditConditions.join(' AND ')}
    ORDER BY timestamp DESC
    LIMIT @limit
  `).all(auditParams) as AuditEntry[];

  entries.push(...auditRows.map((row) => {
    const severity: IncidentReplayEntry['severity'] =
      row.firewall_result === 'BLOCK' ? 'critical' : row.firewall_result === 'QUARANTINE' ? 'warning' : 'info';

    return {
      timestamp: row.timestamp,
      type: 'audit' as const,
      eventType: row.firewall_result.toLowerCase(),
      severity,
      summary: `${row.firewall_result} ${row.source_type}:${row.source_identifier}`,
      details: row.reason,
      source: `${row.source_type}:${row.source_identifier}`,
      memoryId: row.memory_id,
      auditId: row.id,
      metadata: {
        threatIndicators: row.threat_indicators,
        blockedPatterns: row.blocked_patterns,
        trustScore: row.trust_score,
        anomalyScore: row.anomaly_score,
        sensitivityLevel: row.sensitivity_level,
      },
    };
  }));

  const quarantineConditions = ['q.created_at >= @startTime', 'q.created_at <= @endTime'];
  const quarantineParams: Record<string, unknown> = { startTime, endTime, limit };

  if (options.project) {
    quarantineConditions.push('q.project = @project');
    quarantineParams.project = options.project;
  }
  if (options.sourceIdentifier) {
    quarantineConditions.push('q.source_identifier = @sourceIdentifier');
    quarantineParams.sourceIdentifier = options.sourceIdentifier;
  }
  if (options.memoryId !== undefined) {
    quarantineConditions.push('da.memory_id = @memoryId');
    quarantineParams.memoryId = options.memoryId;
  }

  const quarantineRows = db.prepare(`
    SELECT q.*, da.memory_id
    FROM quarantine q
    LEFT JOIN defence_audit da ON da.id = q.audit_id
    WHERE ${quarantineConditions.join(' AND ')}
    ORDER BY q.created_at DESC
    LIMIT @limit
  `).all(quarantineParams) as Array<Record<string, unknown>>;

  entries.push(...quarantineRows.map((row) => {
    const severity: IncidentReplayEntry['severity'] = row.status === 'pending' ? 'warning' : 'info';

    return {
      timestamp: String(row.created_at),
      type: 'quarantine' as const,
      eventType: `quarantine_${String(row.status)}`,
      severity,
      summary: `Quarantine ${String(row.status)}: ${String(row.original_title ?? 'Untitled')}`,
      details: String(row.reason ?? ''),
      source: `${String(row.source_type ?? 'unknown')}:${String(row.source_identifier ?? 'unknown')}`,
      memoryId: typeof row.memory_id === 'number' ? row.memory_id : null,
      auditId: typeof row.audit_id === 'number' ? row.audit_id : null,
      quarantineId: row.id as number,
      metadata: {
        reviewedAt: row.reviewed_at ?? null,
        reviewedBy: row.reviewed_by ?? null,
        firewallResult: row.firewall_result ?? null,
        anomalyScore: row.anomaly_score ?? null,
        threatIndicators: row.threat_indicators ?? '[]',
      },
    };
  }));

  const eventRows = db.prepare(`
    SELECT id, type, data, timestamp
    FROM events
    WHERE timestamp >= @startTime AND timestamp <= @endTime
    ORDER BY timestamp DESC
    LIMIT @limit
  `).all({ startTime, endTime, limit }) as Array<{ id: number; type: string; data: string | null; timestamp: string }>;

  for (const row of eventRows) {
    const parsed = row.data ? JSON.parse(row.data) : null;
    const eventMemoryId = extractReplayMemoryId(parsed);
    const eventProject = extractReplayProject(parsed);

    if (options.memoryId !== undefined && eventMemoryId !== options.memoryId) continue;
    if (options.project && eventProject && eventProject !== options.project) continue;
    if (options.sourceIdentifier && row.type !== 'defence_event') continue;
    if (options.sourceIdentifier && parsed && typeof parsed === 'object') {
      const record = parsed as Record<string, unknown>;
      if (record.source_identifier !== options.sourceIdentifier) continue;
    }

    entries.push({
      timestamp: row.timestamp,
      type: 'event',
      eventType: row.type,
      severity: row.type.includes('kill_switch') ? 'critical' : row.type === 'defence_event' ? 'warning' : 'info',
      summary: buildEventSummary(row.type, parsed),
      details: null,
      memoryId: eventMemoryId,
      metadata: parsed && typeof parsed === 'object' ? parsed as Record<string, unknown> : undefined,
    });
  }

  return entries
    .sort((a, b) => new Date(a.timestamp).getTime() - new Date(b.timestamp).getTime())
    .slice(0, limit);
}
