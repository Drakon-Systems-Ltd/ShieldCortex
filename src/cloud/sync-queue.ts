/**
 * Cloud Sync Retry Queue
 *
 * Replaces fire-and-forget cloud sync with a queue that retries failed syncs.
 * Uses SQLite sync_queue table with exponential backoff.
 */

import { getDatabase } from '../database/init.js';
import { getCloudConfig, updateLastSyncAt } from './config.js';

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

export interface QueueStats {
  pending: number;
  failed: number;
  synced: number;
}

export interface SyncQueueResult {
  processed: number;
  succeeded: number;
  failed: number;
  permanentlyFailed: number;
}

/**
 * Enqueue a failed sync entry for later retry.
 * INSERT into sync_queue with exponential backoff schedule.
 */
export function enqueueFailedSync(entry: SyncEntry): void {
  const db = getDatabase();
  const payload = JSON.stringify(entry);
  const nextRetryAt = new Date(Date.now() + 30_000).toISOString(); // First retry in 30s

  db.prepare(`
    INSERT INTO sync_queue (payload, attempts, next_retry_at, status)
    VALUES (?, 0, ?, 'pending')
  `).run(payload, nextRetryAt);
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

      const res = await fetch(`${config.cloudBaseUrl}/v1/audit/ingest`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Authorization': `Bearer ${config.cloudApiKey}`,
        },
        body: JSON.stringify({ entries: [JSON.parse(row.payload)] }),
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
      const errorMsg = (err as Error).message || 'Unknown error';
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
    SELECT status, COUNT(*) as count
    FROM sync_queue
    GROUP BY status
  `).all() as Array<{ status: string; count: number }>;

  const stats: QueueStats = { pending: 0, failed: 0, synced: 0 };
  for (const row of rows) {
    if (row.status === 'pending') stats.pending = row.count;
    else if (row.status === 'failed') stats.failed = row.count;
    else if (row.status === 'synced') stats.synced = row.count;
  }

  return stats;
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

  return result.changes;
}
