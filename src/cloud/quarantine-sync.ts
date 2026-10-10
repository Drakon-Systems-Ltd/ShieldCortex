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
import { getDatabase, isDatabaseInitialized } from '../database/init.js';
import { redactCredentials } from '../defence/credential-leak/index.js';
import { sanitiseInput } from '../defence/input-sanitisation/index.js';
import { classifySensitivity, hasRedactionToken, redactForPersistence } from '../defence/sensitivity/index.js';
import type { SensitivityLevel } from '../defence/types.js';

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
 *   - #510: PII identifiers (and the contact details beside them) are redacted
 *     with `[REDACTED:<kind>]` by the same write-time redactor every
 *     persistence boundary uses. The automatic callers hand over the LIVE
 *     pipeline text, not the write-redacted row, so this stage is what keeps
 *     an NI number / SSN / salary out of the outbound body and out of the
 *     local retry queue. It honours the redactor's own explicit opt-out
 *     (`SHIELDCORTEX_PII_REDACTION=off`); opting IN to sensitive sync
 *     (`excludeSensitive: false`) is not a PII-redaction opt-out.
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
  // #510: PII identifiers never leave the device either — run the persistence
  // redactor FIRST, then credential redaction over what it returns.
  const pii = redactForPersistence({ title: entry.original_title, content: entry.original_content }).fields;
  const safeContent = metadataOnly
    ? '[ShieldCortex] Quarantine content redacted by local sync policy.'
    : redactCredentials(pii.content ?? '');
  const safeTitle = metadataOnly
    ? '[Metadata only]'
    : pii.title
      ? redactCredentials(pii.title)
      : pii.title;

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

const LEVEL_RANK: Record<SensitivityLevel, number> = { PUBLIC: 0, INTERNAL: 1, CONFIDENTIAL: 2, RESTRICTED: 3 };
const LEVELS: SensitivityLevel[] = ['PUBLIC', 'INTERNAL', 'CONFIDENTIAL', 'RESTRICTED'];

/**
 * Rank a stored level string. Unknown but non-empty values are ranked as
 * CONFIDENTIAL — `isSensitiveLevel` already treats them as sensitive, so the
 * gate and the payload agree. Empty/missing → null (no information).
 */
function rankLevel(level: unknown): number | null {
  if (typeof level !== 'string') return null;
  const normalised = level.trim().toUpperCase();
  if (normalised.length === 0) return null;
  return normalised in LEVEL_RANK ? LEVEL_RANK[normalised as SensitivityLevel] : LEVEL_RANK.CONFIDENTIAL;
}

/**
 * The live classification recorded for a quarantined write, when the row is
 * linked to its `defence_audit` entry. `null` when the row has no link, the
 * linked entry is gone, or the database is not available — callers must then
 * fall back to the conservative reconstruction, never to "PUBLIC".
 */
function readAuditSensitivity(auditId: unknown): string | null {
  if (typeof auditId !== 'number' || !Number.isInteger(auditId)) return null;
  try {
    if (!isDatabaseInitialized()) return null;
    const row = getDatabase()
      .prepare('SELECT sensitivity_level FROM defence_audit WHERE id = ?')
      .get(auditId) as { sensitivity_level?: unknown } | undefined;
    return typeof row?.sensitivity_level === 'string' ? row.sensitivity_level : null;
  } catch {
    return null;
  }
}

/**
 * Reconstruct the sensitivity level the live pipeline would have assigned to
 * a persisted `quarantine` row. The table stores no level of its own, and the
 * stored text is NOT what the pipeline classified:
 *
 *   - the pipeline classifies the SANITISED content (NFKC, zero-width / bidi
 *     controls stripped — `sanitiseInput`), so a zero-width-split sort code or
 *     a fullwidth `＠` that classifies PUBLIC raw is CONFIDENTIAL live;
 *   - persistence (#510) replaces identifiers with `[REDACTED:<kind>]`
 *     tokens, so the stored text can classify lower than the identifier did.
 *
 * The result is the HIGHEST of: the live level recorded on the linked
 * `defence_audit` row (trusted provenance, when the row has one), the
 * classification of the stored text as-is, the classification of the
 * sanitised text, and a CONFIDENTIAL floor when the stored text carries a
 * write-time redaction token (an identifier was present at persistence, and
 * identifier-grade PII is at least CONFIDENTIAL). Legacy rows without an
 * audit link get everything except provenance. Nothing here can lower the
 * level the original classification produced.
 */
export function reconstructQuarantineSensitivity(row: Record<string, unknown>): SensitivityLevel {
  const content = typeof row.original_content === 'string' ? row.original_content : '';
  const title = typeof row.original_title === 'string' ? row.original_title : '';

  let rank = LEVEL_RANK[classifySensitivity(content, title).level];
  rank = Math.max(rank, LEVEL_RANK[classifySensitivity(sanitiseInput(content).sanitised, sanitiseInput(title).sanitised).level]);
  if (hasRedactionToken(content) || hasRedactionToken(title)) rank = Math.max(rank, LEVEL_RANK.CONFIDENTIAL);
  const provenance = rankLevel(readAuditSensitivity(row.audit_id));
  if (provenance !== null) rank = Math.max(rank, provenance);

  return LEVELS[rank];
}

/**
 * Map a persisted `quarantine` table row to a sync entry.
 *
 * The sensitivity level comes from `reconstructQuarantineSensitivity`: the
 * live level when the row carries its audit link, and never lower than what
 * the stored text (raw or sanitised) or its redaction evidence implies. The
 * entry carries the stored text as-is; `prepareQuarantineSyncPayload` applies
 * the PII + credential redaction before anything leaves the device.
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
    sensitivity_level: reconstructQuarantineSensitivity(row),
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
