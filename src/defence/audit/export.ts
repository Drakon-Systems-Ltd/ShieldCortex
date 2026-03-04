/**
 * Audit log export — JSON and CSV formats (Pro feature).
 */

import { getDatabase } from '../../database/init.js';

interface AuditRow {
  id: number;
  memory_id: number | null;
  project: string | null;
  timestamp: string;
  source_type: string;
  source_identifier: string;
  trust_score: number;
  sensitivity_level: string;
  firewall_result: string;
  anomaly_score: number;
  threat_indicators: string;
  blocked_patterns: string;
  reason: string | null;
  fragmentation_score: number | null;
  pipeline_duration_ms: number | null;
}

function queryLogs(startTime?: string, endTime?: string): AuditRow[] {
  const db = getDatabase();
  const conditions: string[] = [];
  const params: unknown[] = [];

  if (startTime) {
    conditions.push('timestamp >= ?');
    params.push(startTime);
  }
  if (endTime) {
    conditions.push('timestamp <= ?');
    params.push(endTime);
  }

  const where = conditions.length > 0 ? `WHERE ${conditions.join(' AND ')}` : '';
  return db.prepare(`SELECT * FROM defence_audit ${where} ORDER BY timestamp DESC`).all(...params) as AuditRow[];
}

export function exportAuditJSON(startTime?: string, endTime?: string): string {
  const logs = queryLogs(startTime, endTime);
  return JSON.stringify({ exported_at: new Date().toISOString(), count: logs.length, logs }, null, 2);
}

export function exportAuditCSV(startTime?: string, endTime?: string): string {
  const logs = queryLogs(startTime, endTime);
  const headers = [
    'id', 'memory_id', 'project', 'timestamp', 'source_type', 'source_identifier',
    'trust_score', 'sensitivity_level', 'firewall_result', 'anomaly_score',
    'threat_indicators', 'blocked_patterns', 'reason', 'fragmentation_score', 'pipeline_duration_ms',
  ];

  const escapeCSV = (val: unknown): string => {
    if (val === null || val === undefined) return '';
    const str = String(val);
    if (str.includes(',') || str.includes('"') || str.includes('\n')) {
      return `"${str.replace(/"/g, '""')}"`;
    }
    return str;
  };

  const rows = logs.map(row =>
    headers.map(h => escapeCSV(row[h as keyof AuditRow])).join(',')
  );

  return [headers.join(','), ...rows].join('\n');
}
