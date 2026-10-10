import {
  getCloudConfig,
  getCloudSyncControls,
  getDeviceId,
  getDeviceName,
  isSensitiveLevel,
  shouldSyncProject,
  type CloudSyncControls,
} from './config.js';
import { enqueueFailedQuarantineSync } from './sync-queue.js';
import { redactCredentials } from '../defence/credential-leak/index.js';
import { classifySensitivity } from '../defence/sensitivity/index.js';

/** A quarantine entry as presented to the cloud sync gate. */
export interface QuarantineSyncEntry {
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
}

/** The exact body POSTed to `/v1/quarantine/ingest` after gating + redaction. */
export interface QuarantineSyncPayload extends QuarantineSyncEntry {
  original_content: string;
  original_title: string | undefined;
  content_redacted: boolean;
  device_id: string;
  device_name: string;
  timestamp: string;
}

/**
 * Build the quarantine row → cloud payload, applying the user's
 * CloudSyncControls and credential redaction BEFORE any content leaves the
 * device. Returns `null` when the entry must NOT be sent at all.
 *
 * This is the SINGLE gate for quarantine content. Every path that ships
 * quarantine content to the cloud — the automatic fire-and-forget sync below
 * AND the dashboard bulk "sync pending to cloud" route — must go through it,
 * so the `CONFIDENTIAL+ excluded by default` promise cannot be bypassed by
 * choosing a different entry point.
 *
 *   - project filter (`shouldSyncProject`) — excluded projects never sync
 *   - `excludeSensitive` — CONFIDENTIAL+ items are dropped entirely
 *   - `contentMode: 'metadata'` — content/title are redacted to a placeholder
 *   - credentials/secrets are always redacted with [REDACTED-{type}]
 */
export function prepareQuarantineSyncPayload(
  entry: QuarantineSyncEntry,
  controls: CloudSyncControls = getCloudSyncControls(),
): QuarantineSyncPayload | null {
  if (!shouldSyncProject(entry.project ?? null, controls)) return null;
  if (controls.excludeSensitive && isSensitiveLevel(entry.sensitivity_level ?? null)) return null;

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

  return {
    ...entry,
    original_content: safeContent,
    original_title: safeTitle,
    content_redacted: metadataOnly,
    device_id: getDeviceId(),
    device_name: getDeviceName(),
    timestamp: new Date().toISOString(),
  };
}

/**
 * Map a persisted `quarantine` table row to a sync entry.
 *
 * The table does not store a sensitivity level (the automatic path gets it
 * from the live pipeline classification), so the stored content is
 * re-classified with the SAME classifier the pipeline uses. This keeps the
 * `excludeSensitive` gate meaningful for rows synced after the fact.
 */
export function quarantineRowToSyncEntry(row: Record<string, unknown>): QuarantineSyncEntry {
  const content = typeof row.original_content === 'string' ? row.original_content : '';
  const title = typeof row.original_title === 'string' ? row.original_title : undefined;
  const indicators: string[] = (() => {
    try {
      const parsed = JSON.parse((row.threat_indicators as string) ?? '[]');
      return Array.isArray(parsed) ? parsed.map(String) : [];
    } catch { return []; }
  })();

  return {
    original_content: content,
    original_title: title,
    source_type: typeof row.source_type === 'string' ? row.source_type : 'unknown',
    source_identifier: typeof row.source_identifier === 'string' ? row.source_identifier : 'unknown',
    reason: typeof row.reason === 'string' ? row.reason : 'Unknown reason',
    threat_indicators: indicators,
    anomaly_score: typeof row.anomaly_score === 'number' ? row.anomaly_score : 0,
    firewall_result: typeof row.firewall_result === 'string' ? row.firewall_result : 'QUARANTINE',
    project: typeof row.project === 'string' ? row.project : null,
    sensitivity_level: classifySensitivity(content, title ?? '').level,
  };
}

/**
 * Fire-and-forget: sends quarantined content to ShieldCortex cloud.
 * Never blocks, never throws. Failed requests are logged and queued for retry.
 *
 * Gating + redaction live in `prepareQuarantineSyncPayload` (shared with the
 * dashboard bulk route) — see that function for the rules applied.
 */
export function syncQuarantineToCloud(entry: QuarantineSyncEntry): void {
  const config = getCloudConfig();
  if (!config.cloudEnabled || !config.cloudApiKey) return;

  const payload = prepareQuarantineSyncPayload(entry);
  if (!payload) return;

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
