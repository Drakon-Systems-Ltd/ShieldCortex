/**
 * Retroactive Memory Scanner
 *
 * Scans existing memories in the database for signs of poisoning,
 * injection attacks, or sensitive data stored in plain text.
 * "Is Your AI Agent Compromised?"
 */

import { getDatabase } from '../../database/init.js';
import { analyzeFirewall } from '../firewall/index.js';
import { classifySensitivity } from '../sensitivity/index.js';
import type {
  DefenceConfig,
  DefenceSource,
  ThreatIndicator,
} from '../types.js';
import { DEFAULT_DEFENCE_CONFIG } from '../types.js';

// ── Types ──

export interface ScanOptions {
  project?: string;
  limit?: number;
  config?: DefenceConfig;
}

export interface ThreatFinding {
  memoryId: number;
  title: string;
  severity: 'low' | 'medium' | 'high' | 'critical';
  threatType: ThreatIndicator;
  details: string;
  content_preview: string;
}

export interface ScanReport {
  totalScanned: number;
  cleanCount: number;
  suspiciousCount: number;
  threatsFound: ThreatFinding[];
  scanDuration: number;
  summary: string;
}

// ── Internal types ──

interface MemoryRow {
  id: number;
  title: string;
  content: string;
  project: string | null;
  trust_score: number | null;
  sensitivity_level: string | null;
  source: string | null;
}

const BATCH_SIZE = 100;

/**
 * Parse a source string like "user:direct" into a DefenceSource.
 */
function parseSource(raw: string | null): DefenceSource {
  if (!raw || !raw.includes(':')) {
    return { type: 'user', identifier: 'direct' };
  }
  const [type, ...rest] = raw.split(':');
  const validTypes = new Set(['user', 'email', 'web', 'agent', 'file', 'api']);
  return {
    type: (validTypes.has(type) ? type : 'user') as DefenceSource['type'],
    identifier: rest.join(':') || 'direct',
  };
}

/**
 * Map firewall result + threat indicators to a severity level.
 */
function deriveSeverity(
  firewallResult: string,
  indicators: ThreatIndicator[],
): 'low' | 'medium' | 'high' | 'critical' {
  if (firewallResult === 'BLOCK') {
    if (indicators.includes('instruction_injection') || indicators.includes('credential_leak')) {
      return 'critical';
    }
    return 'high';
  }
  if (firewallResult === 'QUARANTINE') {
    if (indicators.includes('instruction_injection')) {
      return 'high';
    }
    return 'medium';
  }
  return 'low';
}

/**
 * Scan existing memories for signs of poisoning or sensitive data exposure.
 */
export function scanExistingMemories(options?: ScanOptions): ScanReport {
  const startTime = Date.now();
  const config = options?.config ?? DEFAULT_DEFENCE_CONFIG;
  const limit = options?.limit ?? 1000;
  const project = options?.project;

  const db = getDatabase();

  // Build query
  let query = 'SELECT id, title, content, project, trust_score, sensitivity_level, source FROM memories';
  const params: unknown[] = [];

  if (project) {
    query += ' WHERE project = ?';
    params.push(project);
  }

  query += ' ORDER BY id ASC LIMIT ?';
  params.push(limit);

  const allRows = db.prepare(query).all(...params) as MemoryRow[];

  const threatsFound: ThreatFinding[] = [];

  // Process in batches
  for (let i = 0; i < allRows.length; i += BATCH_SIZE) {
    const batch = allRows.slice(i, i + BATCH_SIZE);

    for (const row of batch) {
      const source = parseSource(row.source);
      const trustScore = row.trust_score ?? 1.0;
      const preview = row.content.slice(0, 100);

      // Run firewall analysis
      const firewall = analyzeFirewall(
        row.content,
        row.title,
        source,
        trustScore,
        config,
      );

      // Collect threats from firewall
      if (firewall.result === 'BLOCK' || firewall.result === 'QUARANTINE') {
        for (const indicator of firewall.threatIndicators) {
          threatsFound.push({
            memoryId: row.id,
            title: row.title,
            severity: deriveSeverity(firewall.result, firewall.threatIndicators),
            threatType: indicator,
            details: firewall.reason,
            content_preview: preview,
          });
        }

        // If no specific indicators but still blocked/quarantined (e.g. high anomaly)
        if (firewall.threatIndicators.length === 0) {
          threatsFound.push({
            memoryId: row.id,
            title: row.title,
            severity: firewall.result === 'BLOCK' ? 'high' : 'medium',
            threatType: 'instruction_injection', // fallback indicator
            details: firewall.reason,
            content_preview: preview,
          });
        }
      }

      // Run sensitivity classification
      const sensitivity = classifySensitivity(row.content, row.title);

      // Flag RESTRICTED content stored in plain text
      if (sensitivity.level === 'RESTRICTED') {
        threatsFound.push({
          memoryId: row.id,
          title: row.title,
          severity: 'high',
          threatType: 'credential_leak',
          details: `RESTRICTED sensitivity content stored in plain text. Detected patterns: ${sensitivity.detectedPatterns.join(', ')}`,
          content_preview: preview,
        });
      }
    }
  }

  const totalScanned = allRows.length;
  // Count unique memory IDs with threats
  const suspiciousIds = new Set(threatsFound.map((t) => t.memoryId));
  const suspiciousCount = suspiciousIds.size;
  const cleanCount = totalScanned - suspiciousCount;

  // Build severity counts for summary
  const severityCounts = { critical: 0, high: 0, medium: 0, low: 0 };
  for (const t of threatsFound) {
    severityCounts[t.severity]++;
  }

  const summary =
    `Scanned ${totalScanned} memories. Found ${threatsFound.length} threats ` +
    `(${severityCounts.critical} critical, ${severityCounts.high} high, ` +
    `${severityCounts.medium} medium, ${severityCounts.low} low). ` +
    `${cleanCount} clean.`;

  return {
    totalScanned,
    cleanCount,
    suspiciousCount,
    threatsFound,
    scanDuration: Date.now() - startTime,
    summary,
  };
}
