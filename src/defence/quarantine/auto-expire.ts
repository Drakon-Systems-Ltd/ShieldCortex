/**
 * Quarantine auto-expiry — rejects unreviewed items after a TTL.
 *
 * Safer default: expired items are rejected (discarded), not promoted.
 * A memory that sat in quarantine for 7 days with nobody reviewing it
 * shouldn't be promoted to the memory store.
 */

import { getDatabase } from '../../database/init.js';

/**
 * Set expires_at on quarantine items that don't have one,
 * then reject any expired items.
 *
 * @returns Number of items expired (rejected)
 */
export function expireQuarantineItems(ttlDays: number = 7): number {
  const db = getDatabase();

  // Set expires_at on new items that don't have one
  db.prepare(`
    UPDATE quarantine
    SET expires_at = datetime(created_at, '+' || ? || ' days')
    WHERE expires_at IS NULL AND status = 'pending'
  `).run(ttlDays);

  // Reject expired items
  const result = db.prepare(`
    UPDATE quarantine
    SET status = 'expired',
        reviewed_by = 'auto-expire',
        reviewed_at = CURRENT_TIMESTAMP
    WHERE status = 'pending'
      AND expires_at IS NOT NULL
      AND expires_at < datetime('now')
  `).run();

  if (result.changes > 0) {
    console.error(`[quarantine] Auto-expired ${result.changes} item(s) after ${ttlDays} days`);
  }

  // Prune old reviewed items
  pruneQuarantine();

  return result.changes;
}

/**
 * Prune old reviewed quarantine items and warn on capacity issues.
 * - Deletes approved/rejected/expired items older than 90 days
 * - Warns if pending count exceeds 10,000
 * - Warns if any single source has >500 pending items
 *
 * @returns Number of items pruned
 */
export function pruneQuarantine(retentionDays: number = 90): number {
  const db = getDatabase();

  // Delete reviewed items older than retention period
  const result = db.prepare(`
    DELETE FROM quarantine
    WHERE status IN ('approved', 'rejected', 'expired')
      AND reviewed_at IS NOT NULL
      AND reviewed_at < datetime('now', '-' || ? || ' days')
  `).run(retentionDays);

  if (result.changes > 0) {
    console.error(`[quarantine] Pruned ${result.changes} reviewed item(s) older than ${retentionDays} days`);
  }

  // Warn on total pending count
  const totalPending = db.prepare(
    "SELECT COUNT(*) as count FROM quarantine WHERE status = 'pending'"
  ).get() as { count: number };

  if (totalPending.count > 10000) {
    console.error(`[quarantine] WARNING: ${totalPending.count} pending items — review or increase auto-expiry frequency`);
  }

  // Warn on per-source pending count
  const hotSources = db.prepare(`
    SELECT source_identifier, COUNT(*) as count FROM quarantine
    WHERE status = 'pending'
    GROUP BY source_identifier
    HAVING count > 500
  `).all() as { source_identifier: string; count: number }[];

  for (const src of hotSources) {
    console.error(`[quarantine] WARNING: Source "${src.source_identifier}" has ${src.count} pending items`);
  }

  return result.changes;
}
