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

  return result.changes;
}
