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
  project?: string | null;
  sensitivity_level?: string | null;
  content_redacted?: boolean;
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

/** Cap on transient backoff. A single offline laptop shouldn't wait more than
 * an hour between retry attempts, but we don't want 2^attempts*30s to grow
 * unbounded after a long outage (it hits days within ~14 attempts). */
const MAX_BACKOFF_MS = 60 * 60 * 1000; // 1h
const BASE_BACKOFF_MS = 30_000;

/**
 * Classify a sync failure to decide retry policy.
 *
 * - 'permanent': HTTP 4xx. The request is malformed, unauthorised, or points
 *   at something that doesn't exist — retrying is pointless, so fail fast.
 * - 'transient': network errors, timeouts/AbortError, HTTP 5xx, HTTP 429.
 *   The server or link is temporarily unavailable; retrying always makes
 *   sense, so we keep the row pending (capped backoff) until the 7-day TTL
 *   purge removes it.
 *
 * 429 (rate limited) is deliberately transient — backing off and retrying is
 * exactly the right response to a rate limit.
 */
function classifyHttpStatus(status: number): 'transient' | 'permanent' {
  // 4xx (except 429) is a client error → permanent. 429 + 5xx → transient.
  if (status === 429) return 'transient';
  if (status >= 400 && status < 500) return 'permanent';
  return 'transient';
}

/**
 * Heuristic for whether a stored `last_error` describes a transient failure,
 * used by the resurrection pass to revive rows that the OLD 3-attempt logic
 * wrongly marked terminal. We can't store the classification (no schema
 * change), so we infer from the message:
 *   - `HTTP 4xx` (but not `HTTP 429`) → permanent → leave failed.
 *   - everything else (timeouts, network messages, `HTTP 5xx`, `HTTP 429`)
 *     → transient → resurrect.
 * Conservative by design: an unrecognised message is treated as transient so
 * we err on the side of retrying rather than silently dropping a sync.
 */
function isTransientErrorMessage(lastError: string | null): boolean {
  if (!lastError) return true;
  const m = /^HTTP (\d{3})/.exec(lastError);
  if (m) return classifyHttpStatus(Number(m[1])) === 'transient';
  return true; // network/timeout/unknown → transient
}

/**
 * Schedule a transient-failure retry. Keeps the row `pending` with a future
 * `next_retry_at` using capped exponential backoff (min(2^attempts*30s, 1h)).
 * Crucially this does NOT honour max_attempts — transient errors retry until
 * the 7-day TTL purge, so an overnight outage recovers instead of being
 * permanently lost after 3 strikes. `attempts` still increments for observability.
 */
function scheduleRetry(rowId: number, currentAttempts: number, newAttempts: number, errorMsg: string): void {
  const db = getDatabase();
  const backoffMs = Math.min(Math.pow(2, currentAttempts) * BASE_BACKOFF_MS, MAX_BACKOFF_MS);
  const nextRetry = new Date(Date.now() + backoffMs).toISOString();
  db.prepare(`
    UPDATE sync_queue SET status = 'pending', attempts = ?, next_retry_at = ?, last_error = ?
    WHERE id = ?
  `).run(newAttempts, nextRetry, errorMsg, rowId);
}

/**
 * Mark a queue row permanently failed (HTTP 4xx). No further retries.
 */
function markPermanentlyFailed(rowId: number, newAttempts: number, errorMsg: string): void {
  const db = getDatabase();
  db.prepare(`
    UPDATE sync_queue SET status = 'failed', attempts = ?, last_error = ?
    WHERE id = ?
  `).run(newAttempts, errorMsg, rowId);
}

/**
 * Revive `failed` rows that were really transient failures (old 3-attempt
 * logic, or pre-upgrade rows). Only rows still within the 7-day TTL window
 * and whose `last_error` looks transient are reset to `pending` + due now.
 * Genuine 4xx failures stay failed. Returns the number of rows resurrected.
 */
function resurrectTransientFailures(): number {
  const db = getDatabase();
  const now = new Date().toISOString();
  const cutoff = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000).toISOString();
  // Resurrect failed rows within TTL whose last_error is NOT a 4xx (4xx except
  // 429 are permanent). `HTTP 429` and `HTTP 5xx` and network/timeout messages
  // all fall through to transient. NULL last_error → transient (be generous).
  const result = db.prepare(`
    UPDATE sync_queue
    SET status = 'pending', next_retry_at = ?
    WHERE status = 'failed'
      AND created_at > ?
      AND (
        last_error IS NULL
        OR last_error NOT GLOB 'HTTP 4[0-9][0-9]*'
        OR last_error GLOB 'HTTP 429*'
      )
  `).run(now, cutoff);
  return Number(result.changes ?? 0);
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

// Default per-tick budget for the full profile. Kept at the historical value
// so dashboard behaviour is unchanged; mcp callers pass a smaller budget.
const DEFAULT_RETRY_BUDGET = 10;

export interface ProcessRetryOptions {
  /**
   * Maximum number of pending rows to attempt in one call. Bounds the network
   * work an MCP-profile worker does per light tick (it passes a small budget,
   * e.g. 25); the full dashboard profile uses the default. Resurrection is
   * unaffected — only the pending-row SELECT is limited.
   */
  maxRows?: number;
}

/**
 * Process pending items in the retry queue.
 *
 * Runs a resurrection pass first (revive transiently-failed rows within TTL),
 * then SELECTs pending rows due for retry (up to `maxRows`) and attempts each.
 * Awaits each fetch so results are accurate and no double-processing occurs.
 *
 * Failure handling:
 *   - HTTP 4xx (≠429) → permanent: mark failed, no further retries.
 *   - network/timeout/5xx/429 → transient: keep pending with capped (≤1h)
 *     backoff, retrying until the 7-day TTL purge — survives long outages.
 */
export async function processRetryQueue(options: ProcessRetryOptions = {}): Promise<SyncQueueResult> {
  const db = getDatabase();
  const config = getCloudConfig();
  const limit = options.maxRows && options.maxRows > 0 ? options.maxRows : DEFAULT_RETRY_BUDGET;

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

  // Revive any transiently-failed rows (old 3-attempt logic / pre-upgrade)
  // before selecting the pending batch, so they get a chance this tick.
  try {
    resurrectTransientFailures();
  } catch {
    /* best-effort — resurrection failure must not block live retries */
  }

  const now = new Date().toISOString();

  // Fetch pending items ready for retry, bounded by the budget.
  const rows = db.prepare(`
    SELECT id, payload, attempts
    FROM sync_queue
    WHERE status = 'pending' AND next_retry_at <= ?
    ORDER BY next_retry_at ASC
    LIMIT ?
  `).all(now, limit) as Array<{
    id: number;
    payload: string;
    attempts: number;
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
      } else if (classifyHttpStatus(res.status) === 'permanent') {
        markPermanentlyFailed(row.id, newAttempts, `HTTP ${res.status}`);
        result.permanentlyFailed++;
      } else {
        // 5xx / 429 — transient, keep retrying with capped backoff.
        scheduleRetry(row.id, row.attempts, newAttempts, `HTTP ${res.status}`);
        result.failed++;
      }
    } catch (err) {
      // Network errors, timeouts (AbortError) — all transient.
      const errorMsg = formatQueueError(err);
      scheduleRetry(row.id, row.attempts, newAttempts, errorMsg);
      result.failed++;
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
