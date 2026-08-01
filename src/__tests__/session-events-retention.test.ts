/**
 * Session-events retention + size-pressure tests (issue #110).
 *
 * `session_events` grows on every captured turn with no DELETE anywhere —
 * live incident (Edith box, 2026-07-21, v4.47.12): 79.6 MB DB with only 117
 * memories, of which session_events held 62.8 MB across 29,835 rows. Doctor's
 * suggested fixes (vacuum / memories prune) were both no-ops for that failure
 * mode. These tests pin down the retention purge + size-pressure valve that
 * bounds the table, mirroring the Phase 8a defence_audit valve
 * (src/__tests__/audit-retention.test.ts).
 *
 * Harness: a fresh in-memory DB per test so rows never leak across cases.
 * Rows are inserted through the real write path (recordEvent) so the ISO-8601
 * `ts` format under test is exactly what production stores.
 */

import { describe, it, expect, beforeEach, afterEach } from '@jest/globals';
import type Database from 'better-sqlite3';
import { initDatabase, closeDatabase, getDatabase } from '../database/init.js';
import { recordEvent } from '../sessions/capture.js';
import {
  DEFAULT_SESSION_RETENTION_DAYS,
  SESSION_PRESSURE_ROW_CAP,
  SESSION_PRESSURE_BATCH_ROWS,
  resolveSessionRetentionDays,
  purgeOldSessionEvents,
  purgeSessionEventsOlderThan,
  previewOldSessionEvents,
  purgeSessionEventsUnderSizePressure,
} from '../sessions/retention.js';

function daysAgo(days: number): string {
  return new Date(Date.now() - days * 24 * 60 * 60 * 1000).toISOString();
}

function insertEvent(ts: string, payload: unknown = { text: 'x' }): number {
  return recordEvent({
    session_id: 'sess-retention-test',
    ts,
    kind: 'prompt',
    payload,
  });
}

function eventCount(db: Database.Database): number {
  return (db.prepare('SELECT COUNT(*) AS c FROM session_events').get() as { c: number }).c;
}

describe('session_events retention (#110)', () => {
  beforeEach(() => {
    initDatabase(':memory:');
  });

  afterEach(() => {
    closeDatabase();
    delete process.env.SHIELDCORTEX_SESSION_RETENTION_DAYS;
  });

  describe('purgeOldSessionEvents (age-based)', () => {
    it('deletes only rows older than the cutoff and returns the count', () => {
      const db = getDatabase();

      // 3 old (older than 30d) + 2 recent.
      insertEvent(daysAgo(65));
      insertEvent(daysAgo(45));
      insertEvent(daysAgo(31));
      insertEvent(daysAgo(10));
      insertEvent(daysAgo(1));

      expect(eventCount(db)).toBe(5);

      const deleted = purgeOldSessionEvents(30);

      expect(deleted).toBe(3);
      expect(eventCount(db)).toBe(2);

      // The survivors are exactly the recent rows — every remaining ts is
      // inside the 30-day window.
      const remaining = db
        .prepare('SELECT ts FROM session_events ORDER BY ts ASC')
        .all() as { ts: string }[];
      const cutoffMs = Date.now() - 30 * 24 * 60 * 60 * 1000;
      for (const row of remaining) {
        expect(new Date(row.ts).getTime()).toBeGreaterThan(cutoffMs);
      }
    });

    it('defaults to the 30-day retention window', () => {
      expect(DEFAULT_SESSION_RETENTION_DAYS).toBe(30);
      const db = getDatabase();
      insertEvent(daysAgo(31));
      insertEvent(daysAgo(29));
      const deleted = purgeOldSessionEvents();
      expect(deleted).toBe(1);
      expect(eventCount(db)).toBe(1);
    });

    it('is a no-op on an empty table', () => {
      expect(purgeOldSessionEvents(30)).toBe(0);
    });
  });

  describe('boundary-timestamp correctness (ISO-8601 `ts` strings)', () => {
    // capture.ts stores caller-supplied ISO-8601 strings — in practice always
    // `new Date().toISOString()` → 'YYYY-MM-DDTHH:MM:SS.sssZ'. The purge
    // compares the stored `ts` against an ISO cutoff string LEXICALLY
    // (`ts < ?`), which is only correct if both sides share that exact
    // format. These cases prove the comparison at the millisecond boundary.
    it('keeps a row whose ts is exactly the cutoff (strict <)', () => {
      const db = getDatabase();
      const cutoff = '2026-01-01T00:00:00.000Z';
      insertEvent('2026-01-01T00:00:00.000Z'); // exactly at cutoff → survives
      insertEvent('2025-12-31T23:59:59.999Z'); // 1ms older → deleted

      const deleted = purgeSessionEventsOlderThan(cutoff);

      expect(deleted).toBe(1);
      const rows = db.prepare('SELECT ts FROM session_events').all() as { ts: string }[];
      expect(rows).toHaveLength(1);
      expect(rows[0].ts).toBe('2026-01-01T00:00:00.000Z');
    });

    it('orders ISO-Z strings lexically the same as chronologically across day/month/year boundaries', () => {
      const db = getDatabase();
      const cutoff = '2026-07-21T00:00:00.000Z';
      const older = [
        '2025-12-31T23:59:59.999Z',
        '2026-06-30T23:59:59.999Z',
        '2026-07-20T23:59:59.999Z',
      ];
      const newer = [
        '2026-07-21T00:00:00.000Z',
        '2026-07-21T00:00:00.001Z',
        '2026-08-01T00:00:00.000Z',
      ];
      for (const ts of [...older, ...newer]) insertEvent(ts);

      const deleted = purgeSessionEventsOlderThan(cutoff);

      expect(deleted).toBe(older.length);
      expect(eventCount(db)).toBe(newer.length);
    });
  });

  describe('purgeSessionEventsUnderSizePressure (size valve)', () => {
    it('no-ops under the size gate even when over the row cap', () => {
      const db = getDatabase();
      // 50 rows, tiny cap — but no warnBytes injected, and an in-memory DB has
      // no measurable file size, so checkDatabaseSize().warning is false and
      // the gate must hold.
      for (let i = 0; i < 50; i++) insertEvent(daysAgo(50 - i));
      const deleted = purgeSessionEventsUnderSizePressure({ maxRows: 10 });
      expect(deleted).toBe(0);
      expect(eventCount(db)).toBe(50);
    });

    it('trims the OLDEST rows down to the cap when over pressure', () => {
      const db = getDatabase();
      for (let i = 0; i < 100; i++) insertEvent(daysAgo(100 - i));
      expect(eventCount(db)).toBe(100);

      const deleted = purgeSessionEventsUnderSizePressure({ warnBytes: 0, maxRows: 40 });

      expect(deleted).toBe(60);
      expect(eventCount(db)).toBe(40);

      // Oldest-first eviction: every survivor is newer than every deleted row,
      // i.e. the oldest surviving row is at most 40 days old.
      const oldest = db
        .prepare('SELECT ts FROM session_events ORDER BY ts ASC LIMIT 1')
        .get() as { ts: string };
      expect(new Date(oldest.ts).getTime()).toBeGreaterThan(
        Date.now() - 41 * 24 * 60 * 60 * 1000,
      );
    });

    it('respects the cap exactly — no purge at or under maxRows', () => {
      const db = getDatabase();
      for (let i = 0; i < 40; i++) insertEvent(daysAgo(40 - i));
      const deleted = purgeSessionEventsUnderSizePressure({ warnBytes: 0, maxRows: 40 });
      expect(deleted).toBe(0);
      expect(eventCount(db)).toBe(40);
    });

    it('exposes a production row cap that bounds worst-case bytes well under the 100MB block', () => {
      // Edith incident: 29,835 rows ≈ 62.8MB payload + ~6MB indexes → ~2.3KB/row
      // all-in. The cap must keep session_events' worst case clearly under the
      // 100MB hard block even alongside the audit valve's own 100k-row cap.
      expect(SESSION_PRESSURE_ROW_CAP).toBeGreaterThan(0);
      expect(SESSION_PRESSURE_ROW_CAP * 2.4 * 1024).toBeLessThan(50 * 1024 * 1024);
    });

    // #114: a single valve call trimming the full over-cap gap in one
    // transaction measured ~246ms on 40k rows. These pin the batching that
    // bounds a single call's transaction time.
    describe('batched deletes (#114)', () => {
      it('a single call deletes at most batchRows, even when far over the cap', () => {
        const db = getDatabase();
        for (let i = 0; i < 100; i++) insertEvent(daysAgo(100 - i));
        expect(eventCount(db)).toBe(100);

        const deleted = purgeSessionEventsUnderSizePressure({ warnBytes: 0, maxRows: 10, batchRows: 5 });

        expect(deleted).toBe(5); // capped, NOT the full 90-row gap
        expect(eventCount(db)).toBe(95);
      });

      it('repeated calls converge to the row cap across multiple invocations (simulating successive light ticks)', () => {
        const db = getDatabase();
        for (let i = 0; i < 100; i++) insertEvent(daysAgo(100 - i));

        let totalDeleted = 0;
        for (let i = 0; i < 20; i++) {
          totalDeleted += purgeSessionEventsUnderSizePressure({ warnBytes: 0, maxRows: 10, batchRows: 5 });
          if (eventCount(db) <= 10) break;
        }

        expect(totalDeleted).toBe(90);
        expect(eventCount(db)).toBe(10);
      });

      it('does not batch when already under the batch size — single call still fully converges', () => {
        const db = getDatabase();
        for (let i = 0; i < 45; i++) insertEvent(daysAgo(45 - i));

        const deleted = purgeSessionEventsUnderSizePressure({ warnBytes: 0, maxRows: 40, batchRows: 2000 });

        expect(deleted).toBe(5);
        expect(eventCount(db)).toBe(40);
      });

      it('exposes a default batch size smaller than the row cap, so batching actually engages under sustained pressure', () => {
        expect(SESSION_PRESSURE_BATCH_ROWS).toBeGreaterThan(0);
        expect(SESSION_PRESSURE_BATCH_ROWS).toBeLessThan(SESSION_PRESSURE_ROW_CAP);
      });
    });
  });

  describe('previewOldSessionEvents (dry-run support)', () => {
    it('reports matched count + payload bytes without deleting anything', () => {
      const db = getDatabase();
      insertEvent(daysAgo(40), 'a'.repeat(1000));
      insertEvent(daysAgo(35), 'b'.repeat(500));
      insertEvent(daysAgo(5), 'c'.repeat(2000));

      const preview = previewOldSessionEvents(30);

      expect(preview.matched).toBe(2);
      expect(preview.payloadBytes).toBe(1500);
      expect(eventCount(db)).toBe(3); // nothing deleted
    });
  });

  describe('resolveSessionRetentionDays (env knob)', () => {
    it('defaults to DEFAULT_SESSION_RETENTION_DAYS when unset', () => {
      delete process.env.SHIELDCORTEX_SESSION_RETENTION_DAYS;
      expect(resolveSessionRetentionDays()).toBe(DEFAULT_SESSION_RETENTION_DAYS);
    });

    it('honours a valid SHIELDCORTEX_SESSION_RETENTION_DAYS override', () => {
      process.env.SHIELDCORTEX_SESSION_RETENTION_DAYS = '7';
      expect(resolveSessionRetentionDays()).toBe(7);
    });

    it('rejects invalid values (non-numeric, zero, negative, absurd) and falls back', () => {
      for (const bad of ['banana', '0', '-5', '1.5', '99999', '']) {
        process.env.SHIELDCORTEX_SESSION_RETENTION_DAYS = bad;
        expect(resolveSessionRetentionDays()).toBe(DEFAULT_SESSION_RETENTION_DAYS);
      }
    });

    it('feeds the env override into purgeOldSessionEvents by default', () => {
      const db = getDatabase();
      insertEvent(daysAgo(10));
      insertEvent(daysAgo(2));
      process.env.SHIELDCORTEX_SESSION_RETENTION_DAYS = '7';
      const deleted = purgeOldSessionEvents();
      expect(deleted).toBe(1);
      expect(eventCount(db)).toBe(1);
    });
  });

  describe('schema support', () => {
    it('has a bare-ts index so the age purge does not full-scan', () => {
      const db = getDatabase();
      const idx = db
        .prepare("SELECT name FROM sqlite_master WHERE type='index' AND name='idx_session_events_ts'")
        .get() as { name?: string } | undefined;
      expect(idx?.name).toBe('idx_session_events_ts');
    });
  });
});
