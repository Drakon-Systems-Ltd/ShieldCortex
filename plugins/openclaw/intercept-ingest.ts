// plugins/openclaw/intercept-ingest.ts
import type { InterceptAuditEntry } from './interceptor.js';

interface CloudConfig {
  cloudApiKey: string;
  cloudBaseUrl: string;
  cloudEnabled: boolean;
}

export function syncInterceptEvent(event: InterceptAuditEntry, config: CloudConfig): void {
  if (!config.cloudEnabled || !config.cloudApiKey) return;

  const url = `${config.cloudBaseUrl}/v1/audit/ingest`;

  // Privacy: forward audit METADATA only — strip the content preview so raw memory
  // text never leaves the machine (ClawScan finding: previews may contain credentials
  // or confidential data). The local audit JSONL retains the preview for triage.
  const metadata: Record<string, unknown> = { ...event };
  delete metadata.preview;

  fetch(url, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${config.cloudApiKey}`,
    },
    body: JSON.stringify({
      events: [{ ...metadata, source: 'openclaw-interceptor' }],
    }),
    signal: AbortSignal.timeout(5_000),
  }).catch(() => {
    // Fire-and-forget — never block on cloud sync failure
  });
}
