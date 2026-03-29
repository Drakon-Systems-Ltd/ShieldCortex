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

  fetch(url, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${config.cloudApiKey}`,
    },
    body: JSON.stringify({
      events: [{ ...event, source: 'openclaw-interceptor' }],
    }),
    signal: AbortSignal.timeout(5_000),
  }).catch(() => {
    // Fire-and-forget — never block on cloud sync failure
  });
}
