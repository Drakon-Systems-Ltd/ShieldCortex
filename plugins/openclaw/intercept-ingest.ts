// plugins/openclaw/intercept-ingest.ts
import { toAuditEntry } from './audit-entry.js';
import type { InterceptAuditEntry } from './interceptor.js';

interface CloudConfig {
  cloudApiKey: string;
  cloudBaseUrl: string;
  cloudEnabled: boolean;
}

export function syncInterceptEvent(event: InterceptAuditEntry, config: CloudConfig): void {
  if (!config.cloudEnabled || !config.cloudApiKey) return;

  // Privacy: build a canonical audit entry from METADATA only — the content
  // preview never leaves the machine (ClawScan finding: previews may contain
  // credentials or confidential data). The local audit JSONL retains the
  // preview for triage. toAuditEntry has no notion of preview/content.
  const entry = toAuditEntry({
    kind: 'intercept',
    tool: event.tool,
    firewallResult: event.firewallResult,
    threats: event.threats,
    anomalyScore: event.anomalyScore,
    trustScore: event.trustScore,
    sensitivityLevel: event.sensitivityLevel,
    fragmentationScore: event.fragmentationScore,
    outcome: event.outcome,
    action: event.action,
    pipelineDurationMs: event.pipelineDurationMs,
    ts: event.ts,
  });
  if (!entry) return;

  // SaaS /v1/audit/ingest requires { entries: [<canonical snake_case entry>] }
  // (zod ingestSchema). The old { events: [...] } shape was rejected 400 and
  // every interceptor POST was silently dropped.
  fetch(`${config.cloudBaseUrl}/v1/audit/ingest`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${config.cloudApiKey}`,
    },
    body: JSON.stringify({ entries: [entry] }),
    signal: AbortSignal.timeout(5_000),
  }).catch(() => {
    // Fire-and-forget — never block on cloud sync failure
  });
}
