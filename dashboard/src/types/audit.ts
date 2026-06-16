/**
 * Audit / defence response types — the snake_case contract the API serialises.
 *
 * Single source of truth for the dashboard side of `/api/v1/audit`. This shape
 * mirrors the server-side `AuditEntry` in `src/defence/types.ts` (the producer);
 * they live in separate TypeScript builds, so this is the one canonical copy the
 * dashboard imports — previously it was redefined in useDefence.ts AND
 * useActivityTrend.ts, which let the two drift.
 */

export type FirewallResult = 'ALLOW' | 'BLOCK' | 'QUARANTINE';

export interface AuditEntry {
  id: number;
  memory_id: number | null;
  project: string | null;
  timestamp: string;
  source_type: string;
  source_identifier: string;
  trust_score: number;
  sensitivity_level: string;
  firewall_result: FirewallResult;
  anomaly_score: number;
  threat_indicators: string; // JSON array
  blocked_patterns: string; // JSON array
  reason: string | null;
  fragmentation_score: number | null;
  pipeline_duration_ms: number | null;
}
