import { getCloudConfig, getDeviceId, getDeviceName } from './config.js';
import { enqueueFailedQuarantineSync } from './sync-queue.js';

/**
 * Fire-and-forget: sends quarantined content to ShieldCortex cloud.
 * Never blocks, never throws. Failed requests are logged and queued for retry.
 */
export function syncQuarantineToCloud(entry: {
  original_content: string;
  original_title?: string;
  source_type: string;
  source_identifier: string;
  reason: string;
  threat_indicators: string[];
  anomaly_score: number;
  firewall_result: string;
}): void {
  const config = getCloudConfig();
  if (!config.cloudEnabled || !config.cloudApiKey) return;

  const payload = {
    ...entry,
    device_id: getDeviceId(),
    device_name: getDeviceName(),
    timestamp: new Date().toISOString(),
  };

  const url = `${config.cloudBaseUrl}/v1/quarantine/ingest`;
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 10_000);

  fetch(url, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      Authorization: `Bearer ${config.cloudApiKey}`,
    },
    body: JSON.stringify(payload),
    signal: controller.signal,
  })
    .then((res) => {
      if (!res?.ok) {
        console.error(`[shieldcortex] Quarantine sync failed: HTTP ${res.status}`);
        try { enqueueFailedQuarantineSync(payload); } catch { /* non-critical */ }
      }
    })
    .catch((e: unknown) => {
      console.error('[shieldcortex] Quarantine sync failed:', e instanceof Error ? e.message : String(e));
      try { enqueueFailedQuarantineSync(payload); } catch { /* non-critical */ }
    })
    .finally(() => clearTimeout(timeout));
}
