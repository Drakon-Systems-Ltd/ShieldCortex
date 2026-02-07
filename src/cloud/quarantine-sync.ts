import { getCloudConfig, getDeviceId, getDeviceName } from './config.js';

/**
 * Fire-and-forget: sends quarantined content to ShieldCortex cloud.
 * Never blocks, never throws. Silently swallows all errors.
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
    .catch(() => {})
    .finally(() => clearTimeout(timeout));
}
