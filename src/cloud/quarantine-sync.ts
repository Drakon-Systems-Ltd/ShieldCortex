import {
  getCloudConfig,
  getCloudSyncControls,
  getDeviceId,
  getDeviceName,
  isSensitiveLevel,
  shouldSyncProject,
} from './config.js';
import { enqueueFailedQuarantineSync } from './sync-queue.js';
import { redactCredentials } from '../defence/credential-leak/index.js';

/**
 * Fire-and-forget: sends quarantined content to ShieldCortex cloud.
 * Never blocks, never throws. Failed requests are logged and queued for retry.
 *
 * IMPORTANT: Quarantine holds the most sensitive payloads, so it applies the
 * SAME CloudSyncControls gating as memory-sync (see shouldSyncRecord /
 * applyContentMode in memory-sync.ts) BEFORE any content leaves the device:
 *   - project filter (`shouldSyncProject`) — excluded projects never sync
 *   - `excludeSensitive` — CONFIDENTIAL+ items are dropped entirely
 *   - `contentMode: 'metadata'` — content/title are redacted to a placeholder
 * On top of that, credentials/secrets are always redacted with
 * [REDACTED-{type}] placeholders to prevent secret leakage.
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
  /** Project the quarantined write belongs to (for the project filter). */
  project?: string | null;
  /** Sensitivity classification of the content (for `excludeSensitive`). */
  sensitivity_level?: string | null;
}): void {
  const config = getCloudConfig();
  if (!config.cloudEnabled || !config.cloudApiKey) return;

  // Apply the user's CloudSyncControls (parity with memory-sync).
  const controls = getCloudSyncControls();
  if (!shouldSyncProject(entry.project ?? null, controls)) return;
  if (controls.excludeSensitive && isSensitiveLevel(entry.sensitivity_level ?? null)) return;

  const metadataOnly = controls.contentMode === 'metadata';

  // Always redact credentials; metadata-only mode replaces content entirely.
  const safeContent = metadataOnly
    ? '[ShieldCortex] Quarantine content redacted by local sync policy.'
    : redactCredentials(entry.original_content);
  const safeTitle = metadataOnly
    ? '[Metadata only]'
    : entry.original_title
      ? redactCredentials(entry.original_title)
      : entry.original_title;

  const payload = {
    ...entry,
    original_content: safeContent,
    original_title: safeTitle,
    content_redacted: metadataOnly,
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
