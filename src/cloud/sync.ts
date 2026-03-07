import { getCloudConfig, getDeviceId, getDeviceName, updateLastSyncAt } from './config.js';
import { enqueueFailedSync } from './sync-queue.js';
import type { DefencePipelineResult, DefenceSource } from '../defence/types.js';

/**
 * Fire-and-forget: sends a heartbeat to ShieldCortex cloud so the
 * device shows as "Online" even when idle (no scans triggering syncToCloud).
 * Called by BrainWorker every 5 minutes.
 */
export function sendHeartbeat(): void {
  const config = getCloudConfig();
  if (!config.cloudEnabled || !config.cloudApiKey) return;

  const payload = {
    device_id: getDeviceId(),
    device_name: getDeviceName(),
    platform: `${process.platform}/${process.arch}`,
  };

  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), 10_000);

  fetch(`${config.cloudBaseUrl}/v1/devices/heartbeat`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${config.cloudApiKey}`,
    },
    body: JSON.stringify(payload),
    signal: controller.signal,
  })
    .then(() => { clearTimeout(timeoutId); })
    .catch(() => { clearTimeout(timeoutId); });
}

/**
 * Fire-and-forget: sends audit data to ShieldCortex cloud.
 * Never blocks, never throws. Failed requests are logged and queued for retry.
 * Sends audit metadata ONLY — no content or titles.
 */
export function syncToCloud(
  result: DefencePipelineResult,
  source: DefenceSource,
  durationMs: number,
): void {
  const config = getCloudConfig();

  // Bail immediately if cloud sync is not configured
  if (!config.cloudEnabled || !config.cloudApiKey) return;

  const entry = {
    source_type: source.type,
    source_identifier: source.identifier,
    trust_score: result.trust.score,
    sensitivity_level: result.sensitivity.level,
    firewall_result: result.firewall.result,
    anomaly_score: result.firewall.anomalyScore,
    threat_indicators: result.firewall.threatIndicators.map(t =>
      typeof t === 'string' ? t : (t as { pattern?: string }).pattern ?? String(t)
    ),
    reason: result.firewall.reason,
    pipeline_duration_ms: durationMs,
    device_id: getDeviceId(),
    device_name: getDeviceName(),
    platform: `${process.platform}/${process.arch}`,
    timestamp: new Date().toISOString(),
  };

  // Abort after 10 seconds to prevent pending fetch accumulation
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), 10_000);

  // Fire-and-forget — no await, catch all errors silently
  fetch(`${config.cloudBaseUrl}/v1/audit/ingest`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${config.cloudApiKey}`,
    },
    body: JSON.stringify({ entries: [entry] }),
    signal: controller.signal,
  })
    .then((res) => {
      clearTimeout(timeoutId);
      if (!res?.ok) {
        try { enqueueFailedSync(entry); } catch { /* truly silent */ }
      } else {
        try { updateLastSyncAt(); } catch { /* truly silent */ }
      }
    })
    .catch((e: unknown) => {
      clearTimeout(timeoutId);
      console.error('[shieldcortex] Cloud sync failed:', e instanceof Error ? e.message : String(e));
      try { enqueueFailedSync(entry); } catch { /* truly silent */ }
    });
}

/**
 * Fire-and-forget: sends a kill switch alert to ShieldCortex cloud.
 * Shaped as a normal audit ingest entry so the SaaS API accepts it.
 */
export function sendKillSwitchAlert(meta: {
  source: string;
  phrase?: string;
  reason?: string;
  memoryCountAtTrigger?: number;
  triggeredAt: string;
}): void {
  const config = getCloudConfig();
  if (!config.cloudEnabled || !config.cloudApiKey) return;

  const entry = {
    source_type: 'kill_switch',
    source_identifier: meta.source,
    trust_score: 0,
    sensitivity_level: 'RESTRICTED',
    firewall_result: 'BLOCK',
    anomaly_score: 1,
    threat_indicators: ['kill_switch'],
    reason: `Kill switch activated. Source: ${meta.source}.${meta.phrase ? ` Phrase: "${meta.phrase}".` : ''}${meta.reason ? ` ${meta.reason}` : ''}`,
    pipeline_duration_ms: 0,
    device_id: getDeviceId(),
    device_name: getDeviceName(),
    platform: `${process.platform}/${process.arch}`,
    timestamp: meta.triggeredAt,
  };

  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), 10_000);

  fetch(`${config.cloudBaseUrl}/v1/audit/ingest`, {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json',
      'Authorization': `Bearer ${config.cloudApiKey}`,
    },
    body: JSON.stringify({ entries: [entry] }),
    signal: controller.signal,
  })
    .then(() => { clearTimeout(timeoutId); })
    .catch(() => { clearTimeout(timeoutId); });
}
