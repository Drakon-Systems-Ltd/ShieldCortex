/**
 * Session-events retention + size-pressure valve (issue #110).
 *
 * `recordEvent()`/`recordEvents()` insert a session_events row for EVERY
 * captured turn event (prompts, responses, tool calls/results, hook fires)
 * and nothing ever deletes them — the table grows forever. The DB has a
 * 100MB hard limit (init.ts MAX_DB_SIZE) that BLOCKS all writes once
 * exceeded, and consolidation/vacuum can't shrink rows that are never
 * deleted. Live incident (Edith box, 2026-07-21, v4.47.12): a 79.6 MB DB
 * holding only 117 memories — session_events was 62.8 MB (+ ~6 MB indexes)
 * across 29,835 rows over 65 days; doctor's suggested fixes (vacuum /
 * memories prune) were both no-ops for that failure mode.
 *
 * Mirrors the Phase 8a defence_audit valve (src/defence/audit/retention.ts)
 * with ONE deliberate difference: NO aggregate rollup. The audit valve needed
 * one because getLifetimeStats() scans the whole defence_audit table, so
 * deleting rows would make lifetime totals silently regress. Nothing computes
 * lifetime stats from session_events — the only reader is the on-demand
 * per-session replay (timeline.ts getTimeline / the sessions API routes), so
 * deletion is lossy-but-safe: replays of sessions older than the retention
 * window simply truncate. No rollup, no coupled table, plain DELETEs.
 *
 * Timestamps: rows store a caller-supplied ISO-8601 `ts` string — in practice
 * always `new Date().toISOString()` ('YYYY-MM-DDTHH:MM:SS.sssZ'; the JSONL
 * importer passes through Claude Code transcript timestamps, same format).
 * The purge compares `ts < ?` LEXICALLY against a cutoff produced by the
 * exact same `toISOString()` formatter, so both sides share the format and
 * lexical order === chronological order (proven at the millisecond boundary
 * in src/__tests__/session-events-retention.test.ts). We deliberately do NOT
 * use `datetime(current_timestamp, '-N days')` — SQLite's datetime() renders
 * 'YYYY-MM-DD HH:MM:SS' (space, no ms, no Z), which does NOT collate cleanly
 * against the stored 'T'/'Z' format at the boundary.
 *
 * Since the #110 review, the JSONL importer ENFORCES this (it previously
 * only assumed it): import-jsonl.ts normalises every transcript timestamp
 * through Date.parse → toISOString(), so epoch-millis strings can no longer
 * lexically sort as "infinitely old" and offset-bearing ISO can no longer
 * misorder at the boundary. Dedupe implication: `ts` is part of the
 * idx_session_events_dedupe UNIQUE key, so rows imported BEFORE the
 * normalisation under an offset/epoch format keep their old key — re-running
 * the same transcript now inserts normalised-ts rows alongside them rather
 * than deduping (a one-time duplication for affected legacy rows only).
 */

import { getDatabase, checkDatabaseSize } from '../database/init.js';

/** Default age-based retention window. */
export const DEFAULT_SESSION_RETENTION_DAYS = 30;

/**
 * Hard ceiling on live session_events rows under size pressure.
 *
 * Sizing (from the Edith incident data): 29,835 rows ≈ 62.8 MB payload +
 * ~6 MB indexes → ~2.3–2.4 KB per row all-in. 10,000 rows therefore bound
 * session_events at ~24 MB worst case. The audit valve's own cap
 * (AUDIT_PRESSURE_ROW_CAP = 100,000 rows of small audit entries, tens of MB
 * worst case) must fit in the same 100 MB file, so ~24 MB here leaves clear
 * joint headroom under the hard block — a 20k cap (~48 MB) would not.
 * 10k rows is still ~3 weeks of the incident box's capture rate, so recent
 * replay fidelity is preserved.
 */
export const SESSION_PRESSURE_ROW_CAP = 10_000;

/**
 * Cap on rows deleted per `purgeSessionEventsUnderSizePressure()` call
 * (#114). A single call trimming the full 40k→10k gap measured ~246ms in one
 * transaction — fine for a manual CLI run, but the light tick (every 5-15
 * min) shares its budget with cache pruning and predictive-consolidation
 * checks, so a single call should not hold a write transaction open that
 * long. Batching to 2,000 rows/call keeps each transaction cheap; the valve
 * still runs every tick, so an over-cap table converges to the row cap
 * within a handful of ticks instead of one big stall.
 */
export const SESSION_PRESSURE_BATCH_ROWS = 2_000;

/** Bounds for the env override — anything outside is treated as invalid. */
const MIN_RETENTION_DAYS = 1;
const MAX_RETENTION_DAYS = 3650;

/**
 * Resolve the retention window: the SHIELDCORTEX_SESSION_RETENTION_DAYS env
 * var when set to a valid positive integer (1–3650), otherwise the 30-day
 * default. The audit valve's 90d window is a hard-coded default with no knob;
 * session capture is far bulkier per row and per-fleet capture rates vary
 * wildly, so this one gets an override — as an env var, matching the
 * codebase's existing tunable style (SHIELDCORTEX_DISABLE_WORKER,
 * SHIELDCORTEX_SKIP_EMBEDDINGS, SHIELDCORTEX_CONFIG_DIR) rather than a new
 * config subsystem. Invalid values warn on stderr and fall back.
 */
export function resolveSessionRetentionDays(
  raw: string | undefined = process.env.SHIELDCORTEX_SESSION_RETENTION_DAYS,
): number {
  if (raw === undefined || raw === '') return DEFAULT_SESSION_RETENTION_DAYS;
  const parsed = Number(raw);
  if (
    !Number.isInteger(parsed) ||
    parsed < MIN_RETENTION_DAYS ||
    parsed > MAX_RETENTION_DAYS
  ) {
    console.error(
      `[sessions] Ignoring invalid SHIELDCORTEX_SESSION_RETENTION_DAYS=${JSON.stringify(raw)} ` +
      `(expected an integer ${MIN_RETENTION_DAYS}-${MAX_RETENTION_DAYS}); using ${DEFAULT_SESSION_RETENTION_DAYS}d`,
    );
    return DEFAULT_SESSION_RETENTION_DAYS;
  }
  return parsed;
}

/** ISO-8601 cutoff for a retention window — same formatter capture uses. */
function retentionCutoffIso(retentionDays: number): string {
  return new Date(Date.now() - retentionDays * 24 * 60 * 60 * 1000).toISOString();
}

export interface OldSessionEventsPreview {
  /** Rows strictly older than the cutoff. */
  matched: number;
  /** Total stored payload bytes of the matched rows. */
  payloadBytes: number;
  /** The ISO cutoff the counts were taken against. */
  cutoffIso: string;
}

/**
 * Dry-run support for the CLI: count the rows an age purge WOULD delete and
 * their total payload bytes, without deleting anything.
 */
export function previewOldSessionEvents(
  retentionDays: number = resolveSessionRetentionDays(),
): OldSessionEventsPreview {
  const db = getDatabase();
  const cutoffIso = retentionCutoffIso(retentionDays);
  const row = db.prepare(`
    SELECT COUNT(*) AS matched, COALESCE(SUM(LENGTH(payload)), 0) AS payloadBytes
    FROM session_events
    WHERE ts < ?
  `).get(cutoffIso) as { matched: number; payloadBytes: number };
  return { matched: row.matched, payloadBytes: row.payloadBytes, cutoffIso };
}

/**
 * Purge primitive: delete every session_events row with ts STRICTLY older
 * than the given ISO-8601 cutoff. Exposed separately so tests can pin the
 * lexical-comparison boundary with a deterministic cutoff string. Uses the
 * bare-ts index (idx_session_events_ts) — the existing (session_id, ts) /
 * (project, ts) indexes can't serve a bare ts range predicate.
 */
export function purgeSessionEventsOlderThan(cutoffIso: string): number {
  const db = getDatabase();
  const res = db.prepare('DELETE FROM session_events WHERE ts < ?').run(cutoffIso);
  return Number(res.changes ?? 0);
}

/**
 * Age-based retention: DELETE rows older than the cutoff. No rollup needed
 * (see file header — nothing aggregates session_events). Returns the number
 * of rows deleted. Note: like every SQLite DELETE, this frees pages inside
 * the file but does not shrink it on disk — `shieldcortex vacuum` does that.
 */
export function purgeOldSessionEvents(
  retentionDays: number = resolveSessionRetentionDays(),
): number {
  return purgeSessionEventsOlderThan(retentionCutoffIso(retentionDays));
}

/**
 * Size-pressure valve. Cheap to call: it first checks the DB file size and
 * bails unless the file has crossed the warning threshold (reusing the
 * codebase's existing 50MB WARN_DB_SIZE via checkDatabaseSize(), so we don't
 * keep a second copy of the threshold). When over pressure, it trims the
 * OLDEST session_events rows down to the row cap so capture growth can never
 * carry the DB to the 100MB block. Eviction is plain oldest-first (ts, then
 * id for stable ordering within a timestamp) — unlike the audit valve there
 * is no forensic-value tiering, because all session events carry equal
 * (replay-only) value.
 *
 * Thresholds are injectable for tests, mirroring purgeAuditUnderSizePressure:
 * simulating a real 50MB file (and, on a `:memory:` DB, ANY measurable file
 * size) is impractical, so passing `warnBytes` BYPASSES the file-size gate
 * entirely and drives the row-cap trim directly; `maxRows` sets the cap. In
 * production neither is passed and the gate uses the live file size vs
 * WARN_DB_SIZE.
 *
 * #114: the actual delete is capped at `batchRows` per call (see
 * SESSION_PRESSURE_BATCH_ROWS) so one call can never hold the write
 * transaction open for the full over-cap gap — a caller far over the row cap
 * converges to it over several light ticks instead of one long transaction.
 */
export function purgeSessionEventsUnderSizePressure(
  options: { warnBytes?: number; maxRows?: number; batchRows?: number } = {},
): number {
  const db = getDatabase();
  const maxRows = options.maxRows ?? SESSION_PRESSURE_ROW_CAP;
  const batchRows = options.batchRows ?? SESSION_PRESSURE_BATCH_ROWS;

  if (options.warnBytes === undefined) {
    if (!checkDatabaseSize().warning) return 0;
  }

  return db.transaction(() => {
    const total = (db.prepare('SELECT COUNT(*) AS c FROM session_events').get() as { c: number }).c;
    if (total <= maxRows) return 0;

    const over = Math.min(total - maxRows, batchRows);
    const res = db.prepare(`
      DELETE FROM session_events
      WHERE id IN (
        SELECT id FROM session_events
        ORDER BY ts ASC, id ASC
        LIMIT ?
      )
    `).run(over);
    return Number(res.changes ?? 0);
  })();
}
