// plugins/openclaw/audit-entry.ts
// Canonical audit-entry builder for the OpenClaw plugin's cloud egress.
// Mirrors the SaaS ingestSchema (ShieldCortex-internal/src/routes/v1/audit.ts).
// Privacy: callers pass METADATA only — this never reads content/preview.

export type FirewallResult = 'ALLOW' | 'BLOCK' | 'QUARANTINE';

export interface CanonicalAuditEntry {
  source_type: string;
  source_identifier: string;
  trust_score: number;
  sensitivity_level: string;
  firewall_result: FirewallResult;
  anomaly_score: number;
  threat_indicators: string[];
  fragmentation_score?: number | null;
  reason: string;
  pipeline_duration_ms: number;
  timestamp: string;
}

export type InterceptInput = {
  kind: 'intercept';
  tool?: string; firewallResult?: string; threats?: string[]; anomalyScore?: number;
  trustScore?: number; sensitivityLevel?: string; fragmentationScore?: number | null;
  outcome?: string; action?: string; pipelineDurationMs?: number; ts?: string;
};
export type RealtimeInput = {
  kind: 'realtime';
  hook?: string; sessionId?: string; model?: string; reason?: string; ts?: string;
};

function clamp01(n: unknown): number {
  const v = typeof n === 'number' && Number.isFinite(n) ? n : 0;
  return Math.max(0, Math.min(1, v));
}
function normalizeFirewallResult(raw: unknown, fallback: FirewallResult): FirewallResult {
  const s = String(raw ?? '').toUpperCase();
  if (s === 'ALLOW' || s === 'BLOCK' || s === 'QUARANTINE') return s;
  if (s === 'DENY' || s === 'DENIED' || s === 'AUTO_DENIED' || s === 'BLOCKED') return 'BLOCK';
  return fallback;
}
function isoTimestamp(raw: unknown): string {
  const c = typeof raw === 'string' ? raw : '';
  const t = c ? new Date(c).getTime() : NaN;
  return Number.isNaN(t) ? new Date().toISOString() : new Date(t).toISOString();
}

export function toAuditEntry(input: InterceptInput | RealtimeInput): CanonicalAuditEntry | null {
  if (!input) return null;
  const timestamp = isoTimestamp(input.ts);
  if (input.kind === 'intercept') {
    const anomaly = clamp01(input.anomalyScore);
    return {
      source_type: 'openclaw-interceptor',
      source_identifier: input.tool || 'openclaw',
      trust_score: input.trustScore != null ? clamp01(input.trustScore) : clamp01(1 - anomaly),
      sensitivity_level: input.sensitivityLevel || 'INTERNAL',
      firewall_result: normalizeFirewallResult(input.firewallResult, 'QUARANTINE'),
      anomaly_score: anomaly,
      threat_indicators: Array.isArray(input.threats) ? input.threats.map(String) : [],
      fragmentation_score: input.fragmentationScore == null ? null : clamp01(input.fragmentationScore),
      reason: `OpenClaw intercept: ${input.tool ?? 'tool'} → ${input.outcome ?? input.action ?? 'logged'}`,
      pipeline_duration_ms: Math.max(0, Math.trunc(input.pipelineDurationMs ?? 0)),
      timestamp,
    };
  }
  const reason = input.reason || 'OpenClaw realtime threat';
  return {
    source_type: input.hook || 'openclaw-realtime',
    source_identifier: input.model || input.sessionId || 'openclaw',
    trust_score: 0.5,
    sensitivity_level: 'INTERNAL',
    firewall_result: 'QUARANTINE',
    anomaly_score: 0,
    threat_indicators: [reason],
    fragmentation_score: null,
    reason,
    pipeline_duration_ms: 0,
    timestamp,
  };
}
