/**
 * Cloud Sync Retry Queue
 *
 * Replaces fire-and-forget cloud sync with a queue that retries failed syncs.
 * Supports both audit metadata sync and quarantine content sync payloads.
 * Uses SQLite sync_queue table with exponential backoff.
 */

import { getDatabase } from '../database/init.js';
import { getCloudConfig, getDeviceId, getDeviceName, updateLastSyncAt } from './config.js';
import type { SyncedMemoryRecord } from './memory-sync.js';
import type { GraphSyncEnvelope } from './graph-sync.js';

export interface SyncEntry {
  source_type: string;
  source_identifier: string;
  trust_score: number;
  sensitivity_level: string;
  firewall_result: string;
  anomaly_score: number;
  threat_indicators: string[];
  reason: string | null;
  pipeline_duration_ms: number;
  device_id: string;
  device_name: string;
  platform: string;
  timestamp: string;
}

export interface QuarantineSyncEntry {
  original_content: string;
  original_title?: string;
  source_type: string;
  source_identifier: string;
  reason: string;
  threat_indicators: string[];
  anomaly_score: number;
  firewall_result: string;
  device_id: string;
  device_name: string;
  timestamp: string;
}

type QueuePayload =
  | { kind: 'audit'; entry: SyncEntry }
  | { kind: 'quarantine'; entry: QuarantineSyncEntry }
  | { kind: 'graph'; entry: GraphSyncEnvelope }
  | {
      kind: 'memory';
      entry: {
        record: SyncedMemoryRecord;
        device_id: string;
        device_name: string;
        platform: string;
      };
    };

export interface QueueStats {
  pending: number;
  failed: number;
  synced: number;
  byKind: Record<'audit' | 'quarantine' | 'memory' | 'graph' | 'unknown', {
    pending: number;
    failed: number;
    synced: number;
  }>;
  oldestPendingAt: string | null;
  nextRetryAt: string | null;
  lastError: string | null;
  lastErrorKind: 'audit' | 'quarantine' | 'memory' | 'graph' | 'unknown' | null;
  latestFailureAt: string | null;
}

export interface SyncQueueResult {
  processed: number;
  succeeded: number;
  failed: number;
  permanentlyFailed: number;
}

export interface ReconcileQueueResult {
  removed: number;
}

/**
 * Enqueue a failed sync entry for later retry.
 * INSERT into sync_queue with exponential backoff schedule.
 */
export function enqueueFailedSync(entry: SyncEntry): void {
  enqueuePayload({ kind: 'audit', entry });
}

/**
 * Enqueue a failed quarantine sync entry for later retry.
 */
export function enqueueFailedQuarantineSync(entry: QuarantineSyncEntry): void {
  enqueuePayload({ kind: 'quarantine', entry });
}

/**
 * Enqueue a failed memory sync entry for later retry.
 */
export function enqueueFailedMemorySync(entry: SyncedMemoryRecord): void {
  enqueuePayload({
    kind: 'memory',
    entry: {
      record: entry,
      device_id: getDeviceId(),
      device_name: getDeviceName(),
      platform: `${process.platform}/${process.arch}`,
    },
  });
}

export function enqueueFailedGraphSync(entry: GraphSyncEnvelope): void {
  enqueuePayload({ kind: 'graph', entry });
}

/**
 * Hard ceiling on total sync_queue rows. The 7-day TTL (purgeOldEntries) only
 * runs when the brain worker is alive; MCP-only installs have no worker, so
 * without a size cap a long offline stretch could grow the queue without bound
 * on the user's disk. Enforced on every enqueue so it holds regardless.
 */
const MAX_SYNC_QUEUE_ROWS = 5000;

// Throttle the "queue full" warning to at most once per hour so a sustained
// outage doesn't spam stderr.
let lastCapWarnAt = 0;

/**
 * Trim the queue back to `maxRows`, evicting lowest-value rows first:
 * already-synced history → terminally-failed → oldest pending. Returns the
 * number of rows dropped. Best-effort and never throws.
 */
export function enforceQueueCap(maxRows: number = MAX_SYNC_QUEUE_ROWS): number {
  const db = getDatabase();
  const { c: total } = db
    .prepare('SELECT COUNT(*) AS c FROM sync_queue')
    .get() as { c: number };

  const overflow = total - maxRows;
  if (overflow <= 0) return 0;

  const result = db.prepare(`
    DELETE FROM sync_queue WHERE id IN (
      SELECT id FROM sync_queue
      ORDER BY
        CASE status WHEN 'synced' THEN 0 WHEN 'failed' THEN 1 ELSE 2 END,
        created_at ASC,
        id ASC
      LIMIT ?
    )
  `).run(overflow);

  const removed = Number(result.changes ?? 0);
  if (removed > 0) {
    const now = Date.now();
    if (now - lastCapWarnAt > 3_600_000) {
      lastCapWarnAt = now;
      console.warn(
        `[shieldcortex] Cloud sync queue exceeded ${maxRows} rows; dropped ${removed} oldest entries`,
      );
    }
  }
  return removed;
}

function enqueuePayload(payload: QueuePayload): void {
  const db = getDatabase();
  const payloadJson = JSON.stringify(payload);
  const nextRetryAt = new Date(Date.now() + 30_000).toISOString(); // First retry in 30s

  db.prepare(`
    INSERT INTO sync_queue (payload, attempts, next_retry_at, status)
    VALUES (?, 0, ?, 'pending')
  `).run(payloadJson, nextRetryAt);

  // Keep the queue bounded even with no brain worker running. Best-effort:
  // a failure here must never block the (already-completed) enqueue.
  try {
    enforceQueueCap();
  } catch {
    /* truly silent — fire-and-forget contract */
  }
}

function buildRetryRequest(payloadText: string): { path: string; body: string } {
  const parsed = JSON.parse(payloadText) as unknown;

  // Backwards compatibility with legacy queued audit entries (no envelope)
  if (parsed && typeof parsed === 'object' && !Array.isArray(parsed) && !('kind' in parsed)) {
    return {
      path: '/v1/audit/ingest',
      body: JSON.stringify({ entries: [parsed] }),
    };
  }

  if (
    parsed &&
    typeof parsed === 'object' &&
    !Array.isArray(parsed) &&
    'kind' in parsed &&
    (parsed as { kind: string }).kind === 'audit'
  ) {
    const payload = parsed as { kind: 'audit'; entry: SyncEntry };
    return {
      path: '/v1/audit/ingest',
      body: JSON.stringify({ entries: [payload.entry] }),
    };
  }

  if (
    parsed &&
    typeof parsed === 'object' &&
    !Array.isArray(parsed) &&
    'kind' in parsed &&
    (parsed as { kind: string }).kind === 'quarantine'
  ) {
    const payload = parsed as { kind: 'quarantine'; entry: QuarantineSyncEntry };
    return {
      path: '/v1/quarantine/ingest',
      body: JSON.stringify(payload.entry),
    };
  }

  if (
    parsed &&
    typeof parsed === 'object' &&
    !Array.isArray(parsed) &&
    'kind' in parsed &&
    (parsed as { kind: string }).kind === 'memory'
  ) {
    const payload = parsed as {
      kind: 'memory';
      entry: {
        record: SyncedMemoryRecord;
        device_id: string;
        device_name: string;
        platform: string;
      };
    };
    return {
      path: '/v1/sync/memories',
      body: JSON.stringify({
        device: {
          device_id: payload.entry.device_id,
          device_name: payload.entry.device_name,
          platform: payload.entry.platform,
        },
        memories: [payload.entry.record],
      }),
    };
  }

  if (
    parsed &&
    typeof parsed === 'object' &&
    !Array.isArray(parsed) &&
    'kind' in parsed &&
    (parsed as { kind: string }).kind === 'graph'
  ) {
    const payload = parsed as { kind: 'graph'; entry: GraphSyncEnvelope };
    return {
      path: '/v1/sync/graph',
      body: JSON.stringify(payload.entry),
    };
  }

  throw new Error('Unsupported sync queue payload');
}

/**
 * Mark a queue row as retrying (schedule next attempt) or permanently failed.
 * Exponential backoff: 2^attempts * 30s (30s, 60s, 120s).
 */
function markRetryOrFailed(
  rowId: number,
  currentAttempts: number,
  newAttempts: number,
  maxAttempts: number,
  errorMsg: string,
): boolean {
  const db = getDatabase();
  if (newAttempts >= maxAttempts) {
    db.prepare(`
      UPDATE sync_queue SET status = 'failed', attempts = ?, last_error = ?
      WHERE id = ?
    `).run(newAttempts, errorMsg, rowId);
    return true; // permanently failed
  }
  const backoffMs = Math.pow(2, currentAttempts) * 30_000;
  const nextRetry = new Date(Date.now() + backoffMs).toISOString();
  db.prepare(`
    UPDATE sync_queue SET attempts = ?, next_retry_at = ?, last_error = ?
    WHERE id = ?
  `).run(newAttempts, nextRetry, errorMsg, rowId);
  return false;
}

function formatQueueError(err: unknown): string {
  const name = err instanceof Error ? err.name : '';
  const message = err instanceof Error ? err.message : String(err ?? '');

  if (name === 'AbortError' || message === 'This operation was aborted') {
    return 'Cloud request timed out after 10 seconds';
  }

  if (!message || message === '[object Object]') {
    return 'Unknown cloud sync error';
  }

  return message;
}

/**
 * Process pending items in the retry queue.
 * SELECT pending WHERE next_retry_at <= now, retry each (up to 10 per tick).
 * Awaits each fetch so results are accurate and no double-processing occurs.
 */
export async function processRetryQueue(): Promise<SyncQueueResult> {
  const db = getDatabase();
  const config = getCloudConfig();

  const result: SyncQueueResult = {
    processed: 0,
    succeeded: 0,
    failed: 0,
    permanentlyFailed: 0,
  };

  // Bail if cloud sync is not configured
  if (!config.cloudEnabled || !config.cloudApiKey) {
    return result;
  }

  const now = new Date().toISOString();

  // Fetch up to 10 pending items ready for retry
  const rows = db.prepare(`
    SELECT id, payload, attempts, max_attempts
    FROM sync_queue
    WHERE status = 'pending' AND next_retry_at <= ?
    ORDER BY next_retry_at ASC
    LIMIT 10
  `).all(now) as Array<{
    id: number;
    payload: string;
    attempts: number;
    max_attempts: number;
  }>;

  if (rows.length === 0) {
    return result;
  }

  for (const row of rows) {
    result.processed++;
    const newAttempts = row.attempts + 1;

    try {
      const controller = new AbortController();
      const timeoutId = setTimeout(() => controller.abort(), 10_000);
      const request = buildRetryRequest(row.payload);

      const res = await fetch(`${config.cloudBaseUrl}${request.path}`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${config.cloudApiKey}`,
        },
        body: request.body,
        signal: controller.signal,
      });

      clearTimeout(timeoutId);

      if (res.ok) {
        // Success — mark as synced
        db.prepare(`
          UPDATE sync_queue SET status = 'synced', attempts = ?, synced_at = ?, last_error = NULL
          WHERE id = ?
        `).run(newAttempts, new Date().toISOString(), row.id);
        result.succeeded++;
        try { updateLastSyncAt(); } catch { /* non-critical */ }
      } else {
        const permanent = markRetryOrFailed(row.id, row.attempts, newAttempts, row.max_attempts, `HTTP ${res.status}`);
        if (permanent) result.permanentlyFailed++;
        else result.failed++;
      }
    } catch (err) {
      const errorMsg = formatQueueError(err);
      const permanent = markRetryOrFailed(row.id, row.attempts, newAttempts, row.max_attempts, errorMsg);
      if (permanent) result.permanentlyFailed++;
      else result.failed++;
    }
  }

  return result;
}

/**
 * Get queue statistics by status.
 */
export function getQueueStats(): QueueStats {
  const db = getDatabase();

  const rows = db.prepare(`
    SELECT id, payload, status, next_retry_at, last_error, created_at
    FROM sync_queue
  `).all() as Array<{
    id: number;
    payload: string;
    status: string;
    next_retry_at: string | null;
    last_error: string | null;
    created_at: string | null;
  }>;

  const stats: QueueStats = {
    pending: 0,
    failed: 0,
    synced: 0,
    byKind: {
      audit: { pending: 0, failed: 0, synced: 0 },
      quarantine: { pending: 0, failed: 0, synced: 0 },
      memory: { pending: 0, failed: 0, synced: 0 },
      graph: { pending: 0, failed: 0, synced: 0 },
      unknown: { pending: 0, failed: 0, synced: 0 },
    },
    oldestPendingAt: null,
    nextRetryAt: null,
    lastError: null,
    lastErrorKind: null,
    latestFailureAt: null,
  };

  let newestErrorRowId = -1;
  for (const row of rows) {
    const kind = getPayloadKind(row.payload);
    if (row.status === 'pending') stats.pending++;
    else if (row.status === 'failed') stats.failed++;
    else if (row.status === 'synced') stats.synced++;

    if (row.status === 'pending' || row.status === 'failed' || row.status === 'synced') {
      stats.byKind[kind][row.status]++;
    }

    if (row.status === 'pending' && row.created_at) {
      if (!stats.oldestPendingAt || row.created_at < stats.oldestPendingAt) {
        stats.oldestPendingAt = row.created_at;
      }
    }

    if (row.status === 'pending' && row.next_retry_at) {
      if (!stats.nextRetryAt || row.next_retry_at < stats.nextRetryAt) {
        stats.nextRetryAt = row.next_retry_at;
      }
    }

    if (row.last_error && row.id > newestErrorRowId) {
      newestErrorRowId = row.id;
      stats.lastError = formatQueueError(new Error(row.last_error));
      stats.lastErrorKind = kind;
    }

    if (row.status === 'failed') {
      if (!stats.latestFailureAt || (row.created_at && row.created_at > stats.latestFailureAt)) {
        stats.latestFailureAt = row.created_at ?? stats.latestFailureAt;
      }
    }
  }

  return stats;
}

export function reconcileSyncQueue(options: {
  kinds?: Array<'memory' | 'graph' | 'audit' | 'quarantine'>;
  statuses?: Array<'pending' | 'failed'>;
  maxCreatedAt?: string | null;
} = {}): ReconcileQueueResult {
  const db = getDatabase();
  const kinds = options.kinds ?? ['memory', 'graph'];
  const statuses = options.statuses ?? ['pending', 'failed'];

  if (kinds.length === 0 || statuses.length === 0) {
    return { removed: 0 };
  }

  const kindPlaceholders = kinds.map(() => '?').join(', ');
  const statusPlaceholders = statuses.map(() => '?').join(', ');
  const params: Array<string> = [...statuses, ...kinds];

  let sqlText = `
    DELETE FROM sync_queue
    WHERE status IN (${statusPlaceholders})
      AND COALESCE(json_extract(payload, '$.kind'), 'audit') IN (${kindPlaceholders})
  `;

  if (options.maxCreatedAt) {
    sqlText += ' AND created_at <= ?';
    params.push(options.maxCreatedAt);
  }

  const result = db.prepare(sqlText).run(...params);
  return { removed: Number(result.changes ?? 0) };
}

function getPayloadKind(payloadText: string): 'audit' | 'quarantine' | 'memory' | 'graph' | 'unknown' {
  try {
    const parsed = JSON.parse(payloadText) as unknown;

    if (parsed && typeof parsed === 'object' && !Array.isArray(parsed) && 'kind' in parsed) {
      const kind = (parsed as { kind?: string }).kind;
      if (kind === 'audit' || kind === 'quarantine' || kind === 'memory' || kind === 'graph') return kind;
    }

    if (parsed && typeof parsed === 'object' && !Array.isArray(parsed)) {
      return 'audit';
    }
  } catch {
    // ignore malformed payloads
  }

  return 'unknown';
}

/**
 * Purge old entries from the queue.
 * DELETE WHERE created_at < 7 days ago.
 * Returns the number of rows deleted.
 */
export function purgeOldEntries(): number {
  const db = getDatabase();
  const cutoff = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000).toISOString();

  const result = db.prepare(`
    DELETE FROM sync_queue WHERE created_at < ?
  `).run(cutoff);

  // Also enforce the absolute size cap on the worker path.
  const capped = enforceQueueCap();

  return Number(result.changes ?? 0) + capped;
}
