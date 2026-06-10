/**
 * Audit retention + size-pressure valve (Phase 8a).
 *
 * `logAudit()` inserts a defence_audit row on EVERY pipeline run (including
 * per-tool-response scans) and nothing ever deletes them — the table grows
 * forever. The DB has a 100MB hard limit (init.ts MAX_DB_SIZE) that BLOCKS all
 * writes once exceeded, and consolidation/vacuum can't shrink audit rows that
 * are never deleted, so a busy agent bricks its own memory store with no
 * recovery path.
 *
 * Retention alone would break lifetime stats: getLifetimeStats() scans the
 * whole defence_audit table, so deleting old rows would make every lifetime
 * total silently undercount after a purge. So retention is COUPLED with an
 * aggregate rollup — before deleting, the to-be-deleted rows' stat
 * contributions are folded into the single-row `audit_aggregates` table, and
 * getLifetimeStats() returns `aggregate + scan(remaining)`. Totals never regress.
 */

import { getDatabase, checkDatabaseSize } from '../../database/init.js';

/** Default age-based retention window. */
export const DEFAULT_RETENTION_DAYS = 90;

/**
 * Hard ceiling on live defence_audit rows under size pressure. When the DB file
 * crosses the warning threshold, the valve trims the oldest rows down to (at
 * most) this many so audit growth can't carry the file to the 100MB block.
 */
export const AUDIT_PRESSURE_ROW_CAP = 100_000;

/** Per-row stat contributions, in the same shape getLifetimeStats reports. */
interface AggregateDelta {
  total_scans: number;
  threats_blocked: number;
  quarantined: number;
  memories_protected: number;
  credential_leaks: number;
}

/**
 * Compute the lifetime-stat contributions of a set of defence_audit rows
 * identified by a WHERE clause + params. Mirrors getLifetimeStats's mapping
 * EXACTLY (BLOCK→threats_blocked, QUARANTINE→quarantined, ALLOW→memories_protected,
 * and the credential predicate is the same case-insensitive LIKE) so the
 * aggregate + live split reproduces the pre-purge totals byte-for-byte.
 */
function computeDelta(where: string, params: unknown[]): AggregateDelta {
  const db = getDatabase();

  const counts = db.prepare(`
    SELECT firewall_result, COUNT(*) AS cnt
    FROM defence_audit
    WHERE ${where}
    GROUP BY firewall_result
  `).all(...params) as { firewall_result: string; cnt: number }[];

  const delta: AggregateDelta = {
    total_scans: 0,
    threats_blocked: 0,
    quarantined: 0,
    memories_protected: 0,
    credential_leaks: 0,
  };

  for (const row of counts) {
    delta.total_scans += row.cnt;
    if (row.firewall_result === 'BLOCK') delta.threats_blocked += row.cnt;
    else if (row.firewall_result === 'QUARANTINE') delta.quarantined += row.cnt;
    else if (row.firewall_result === 'ALLOW') delta.memories_protected += row.cnt;
  }

  const credRow = db.prepare(`
    SELECT COUNT(*) AS cnt
    FROM defence_audit
    WHERE (${where}) AND LOWER(threat_indicators) LIKE '%credential%'
  `).get(...params) as { cnt: number } | undefined;
  delta.credential_leaks = credRow?.cnt ?? 0;

  return delta;
}

/**
 * Fold a delta into the single-row audit_aggregates (id=1) cumulative totals.
 * UPSERT so the row is created on first purge and incremented thereafter.
 */
function rollIntoAggregate(delta: AggregateDelta): void {
  const db = getDatabase();
  db.prepare(`
    INSERT INTO audit_aggregates (
      id, total_scans, threats_blocked, quarantined, memories_protected,
      credential_leaks, updated_at
    ) VALUES (1, @total_scans, @threats_blocked, @quarantined, @memories_protected, @credential_leaks, @updated_at)
    ON CONFLICT(id) DO UPDATE SET
      total_scans = total_scans + excluded.total_scans,
      threats_blocked = threats_blocked + excluded.threats_blocked,
      quarantined = quarantined + excluded.quarantined,
      memories_protected = memories_protected + excluded.memories_protected,
      credential_leaks = credential_leaks + excluded.credential_leaks,
      updated_at = excluded.updated_at
  `).run({
    total_scans: delta.total_scans,
    threats_blocked: delta.threats_blocked,
    quarantined: delta.quarantined,
    memories_protected: delta.memories_protected,
    credential_leaks: delta.credential_leaks,
    updated_at: new Date().toISOString(),
  });
}

/**
 * Age-based retention: roll the contributions of rows older than the cutoff into
 * audit_aggregates, then DELETE them. Aggregate + delete run in one transaction
 * so a crash can't drop rows without first banking their stats (which would make
 * lifetime totals regress). Returns the number of rows deleted.
 */
export function purgeOldAuditEntries(retentionDays: number = DEFAULT_RETENTION_DAYS): number {
  const db = getDatabase();
  const cutoff = new Date(Date.now() - retentionDays * 24 * 60 * 60 * 1000).toISOString();

  return db.transaction(() => {
    const where = 'timestamp < ?';
    const params = [cutoff];

    const delta = computeDelta(where, params);
    if (delta.total_scans === 0) return 0; // nothing to do; skip the aggregate write

    rollIntoAggregate(delta);
    const res = db.prepare(`DELETE FROM defence_audit WHERE ${where}`).run(...params);
    return Number(res.changes ?? 0);
  })();
}

/**
 * Size-pressure valve. Cheap to call: it first checks the DB file size and bails
 * unless the file has crossed the warning threshold (reusing the codebase's
 * existing 50MB WARN_DB_SIZE via checkDatabaseSize(), so we don't keep a second
 * copy of the threshold). When over pressure, it trims the OLDEST audit rows
 * down to a row cap — same aggregate-then-delete path as age retention — so
 * audit growth can never carry the DB to the 100MB block.
 *
 * Thresholds are injectable for tests. Simulating a real 50MB file (and, on a
 * `:memory:` DB, ANY measurable file size) is impractical, so passing
 * `warnBytes` BYPASSES the file-size gate entirely and drives the row-cap trim
 * directly; `maxRows` sets the cap. In production neither is passed and the gate
 * uses the live file size vs WARN_DB_SIZE.
 */
export function purgeAuditUnderSizePressure(
  options: { warnBytes?: number; maxRows?: number } = {},
): number {
  const db = getDatabase();
  const maxRows = options.maxRows ?? AUDIT_PRESSURE_ROW_CAP;

  // Size gate. In production: only proceed once the live DB file crosses the
  // codebase's existing WARN_DB_SIZE (50MB), surfaced via checkDatabaseSize() —
  // we reuse that rather than keep a second copy of the threshold. When tests
  // inject `warnBytes`, the gate is bypassed (a `:memory:` DB has no measurable
  // file size) so the row-cap path can be exercised directly.
  if (options.warnBytes === undefined) {
    if (!checkDatabaseSize().warning) return 0;
  }

  return db.transaction(() => {
    const total = (db.prepare('SELECT COUNT(*) AS c FROM defence_audit').get() as { c: number }).c;
    if (total <= maxRows) return 0;

    // Trim down to the cap by deleting the OLDEST rows. Find the cutoff id: keep
    // the newest `maxRows` by timestamp, purge everything older.
    const cutoffRow = db.prepare(`
      SELECT timestamp FROM defence_audit
      ORDER BY timestamp DESC
      LIMIT 1 OFFSET ?
    `).get(maxRows) as { timestamp: string } | undefined;

    if (!cutoffRow) return 0;

    const where = 'timestamp <= ?';
    const params = [cutoffRow.timestamp];

    const delta = computeDelta(where, params);
    if (delta.total_scans === 0) return 0;

    rollIntoAggregate(delta);
    const res = db.prepare(`DELETE FROM defence_audit WHERE ${where}`).run(...params);
    return Number(res.changes ?? 0);
  })();
}
