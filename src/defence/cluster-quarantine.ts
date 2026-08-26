/**
 * #402 Phase 1 — Class-B cross-row cluster quarantine.
 *
 * A slow / fragmentation poison attack (design doc §4, Cluster B) drips N mild
 * directive fragments from one source over a short window; each fragment on its
 * own is stored INERT (content_form 'directive'|'mixed', never injectable), so
 * per-write disposition alone never holds it. When >= `threshold` such
 * fragments from the SAME source land inside `windowMinutes`, the whole cluster
 * — every matching row in the window, not just the newest — is pulled from
 * `memories` into the `quarantine` table for review.
 *
 * SQL-simple and fast: one indexed lookup by source (idx_memories_source) + a
 * single transaction to move the cluster. Runs from store.ts's write path after
 * an inert directive/mixed row is stored.
 */

import type BetterSqlite3 from 'better-sqlite3';

export interface ClusterQuarantineOptions {
  /** memories.source of the triggering row, e.g. 'agent:openclaw' or 'user:cap-5'. */
  source: string;
  /** Window in minutes (default 10). */
  windowMinutes?: number;
  /** Fragments needed to trip the cluster (default 3). */
  threshold?: number;
  /** Reason tag recorded on the held rows. */
  reasonTag?: string;
}

export interface ClusterQuarantineResult {
  quarantined: number;
  ids: number[];
}

const DEFAULT_WINDOW_MINUTES = 10;
const DEFAULT_THRESHOLD = 3;

/** The per-row form signals that make a stored row a Class-B cluster fragment.
 *  'unknown' is DELIBERATELY excluded — it sweeps in benign unparseable notes;
 *  only clear directive-adjacency (directive/mixed) counts. */
const CLUSTER_FORMS = ['directive', 'mixed'] as const;

interface FragmentRow {
  id: number;
  title: string | null;
  content: string;
  project: string | null;
  source: string | null;
}

/**
 * Sweep + quarantine a Class-B cluster for one source. Returns the count and
 * ids moved (empty when the source has fewer than `threshold` fragments in the
 * window). Never throws for a missing table/column — returns a zero result so a
 * write is never failed by an absent cluster path.
 */
export function sweepClusterQuarantine(
  db: BetterSqlite3.Database,
  options: ClusterQuarantineOptions,
): ClusterQuarantineResult {
  const source = options.source;
  if (!source) return { quarantined: 0, ids: [] };
  const windowMinutes = Number.isFinite(options.windowMinutes)
    ? Math.max(1, Math.floor(options.windowMinutes as number))
    : DEFAULT_WINDOW_MINUTES;
  const threshold = Number.isFinite(options.threshold)
    ? Math.max(2, Math.floor(options.threshold as number))
    : DEFAULT_THRESHOLD;

  try {
    const placeholders = CLUSTER_FORMS.map(() => '?').join(',');
    const rows = db
      .prepare(
        `SELECT id, title, content, project, source
           FROM memories
          WHERE source = ?
            AND content_form IN (${placeholders})
            AND COALESCE(status, 'active') = 'active'
            AND created_at >= datetime('now', ?)
          ORDER BY created_at ASC`,
      )
      .all(source, ...CLUSTER_FORMS, `-${windowMinutes} minutes`) as FragmentRow[];

    if (rows.length < threshold) return { quarantined: 0, ids: [] };

    const colonIdx = source.indexOf(':');
    const sourceType = colonIdx > 0 ? source.slice(0, colonIdx) : 'unknown';
    const sourceIdentifier = colonIdx > 0 ? source.slice(colonIdx + 1) : source;
    const reason =
      (options.reasonTag ?? 'class_b_cluster') +
      `: ${rows.length} directive-form fragments from ${source} within ${windowMinutes}m`;

    const insert = db.prepare(
      `INSERT INTO quarantine (
         original_title, original_content, project,
         source_type, source_identifier, reason,
         threat_indicators, anomaly_score, firewall_result, status
       ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'QUARANTINE', 'pending')`,
    );
    const del = db.prepare('DELETE FROM memories WHERE id = ?');

    const ids: number[] = [];
    const move = db.transaction(() => {
      for (const r of rows) {
        insert.run(
          r.title,
          r.content,
          r.project ?? null,
          sourceType,
          sourceIdentifier,
          reason,
          JSON.stringify(['class_b_cluster']),
          0.9,
        );
        del.run(r.id);
        ids.push(r.id);
      }
    });
    move();
    return { quarantined: ids.length, ids };
  } catch {
    // Missing table/column (legacy DB) or any DDL drift — fail safe to no-op:
    // a write must never be broken by the cluster path.
    return { quarantined: 0, ids: [] };
  }
}
