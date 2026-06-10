/**
 * Audit retention + size-pressure tests (Phase 8a).
 *
 * The defence_audit table grows on EVERY pipeline run with no DELETE anywhere,
 * so a busy agent eventually hits the 100MB hard block and bricks its own
 * memory store. These tests pin down the retention purge + aggregate rollup
 * that bounds the table while keeping lifetime stats correct after a purge.
 *
 * Harness: a fresh in-memory DB per test so rows/aggregates never leak across
 * cases. We insert audit rows directly (no full pipeline) to control timestamps
 * and firewall_result distributions exactly.
 */

import { describe, it, expect, beforeEach, afterEach } from '@jest/globals';
import type Database from 'better-sqlite3';
import { initDatabase, closeDatabase, getDatabase } from '../database/init.js';
import { getLifetimeStats } from '../defence/audit/queries.js';
import {
  purgeOldAuditEntries,
  purgeAuditUnderSizePressure,
} from '../defence/audit/retention.js';

interface AuditRowSeed {
  timestamp: string;
  firewall_result: 'ALLOW' | 'BLOCK' | 'QUARANTINE';
  threat_indicators?: string;
}

function insertAuditRow(db: Database.Database, seed: AuditRowSeed): void {
  db.prepare(`
    INSERT INTO defence_audit (
      memory_id, project, timestamp, source_type, source_identifier,
      trust_score, sensitivity_level, firewall_result,
      anomaly_score, threat_indicators, blocked_patterns,
      reason, fragmentation_score, pipeline_duration_ms
    ) VALUES (
      NULL, 'test', @timestamp, 'agent', 'test:agent',
      0.8, 'INTERNAL', @firewall_result,
      0, @threat_indicators, '[]',
      NULL, NULL, 1
    )
  `).run({
    timestamp: seed.timestamp,
    firewall_result: seed.firewall_result,
    threat_indicators: seed.threat_indicators ?? '[]',
  });
}

function daysAgo(days: number): string {
  return new Date(Date.now() - days * 24 * 60 * 60 * 1000).toISOString();
}

function auditCount(db: Database.Database): number {
  return (db.prepare('SELECT COUNT(*) AS c FROM defence_audit').get() as { c: number }).c;
}

describe('audit retention (Phase 8a)', () => {
  beforeEach(() => {
    initDatabase(':memory:');
  });

  afterEach(() => {
    closeDatabase();
  });

  it('has the audit_aggregates table on a fresh DB', () => {
    const db = getDatabase();
    const table = db.prepare(
      "SELECT name FROM sqlite_master WHERE type='table' AND name='audit_aggregates'"
    ).get() as { name?: string } | undefined;
    expect(table?.name).toBe('audit_aggregates');
  });

  it('purgeOldAuditEntries deletes only rows older than the cutoff and returns the count', () => {
    const db = getDatabase();

    // 3 old (older than 90d) + 2 recent.
    insertAuditRow(db, { timestamp: daysAgo(200), firewall_result: 'ALLOW' });
    insertAuditRow(db, { timestamp: daysAgo(120), firewall_result: 'BLOCK' });
    insertAuditRow(db, { timestamp: daysAgo(91), firewall_result: 'QUARANTINE' });
    insertAuditRow(db, { timestamp: daysAgo(10), firewall_result: 'ALLOW' });
    insertAuditRow(db, { timestamp: daysAgo(1), firewall_result: 'ALLOW' });

    expect(auditCount(db)).toBe(5);

    const deleted = purgeOldAuditEntries(90);

    expect(deleted).toBe(3);
    expect(auditCount(db)).toBe(2);
  });

  it('lifetime stats do NOT regress after a retention purge (aggregate rollup)', () => {
    const db = getDatabase();

    // Old rows that WILL be purged: mix of results + a credential leak.
    insertAuditRow(db, { timestamp: daysAgo(200), firewall_result: 'ALLOW' });
    insertAuditRow(db, { timestamp: daysAgo(180), firewall_result: 'BLOCK' });
    insertAuditRow(db, {
      timestamp: daysAgo(150),
      firewall_result: 'BLOCK',
      threat_indicators: JSON.stringify(['credential_leak']),
    });
    insertAuditRow(db, { timestamp: daysAgo(100), firewall_result: 'QUARANTINE' });

    // Recent rows that will SURVIVE: one of each + a recent credential leak.
    insertAuditRow(db, { timestamp: daysAgo(5), firewall_result: 'ALLOW' });
    insertAuditRow(db, {
      timestamp: daysAgo(3),
      firewall_result: 'BLOCK',
      threat_indicators: JSON.stringify(['credential_leak']),
    });

    const before = getLifetimeStats();
    expect(before.totalScans).toBe(6);
    expect(before.threatsBlocked).toBe(3);
    expect(before.quarantined).toBe(1);
    expect(before.memoriesProtected).toBe(2);
    expect(before.credentialLeaks).toBe(2);

    const deleted = purgeOldAuditEntries(90);
    expect(deleted).toBe(4);

    const after = getLifetimeStats();
    // Totals must be UNCHANGED — the aggregate captured the purged rows.
    expect(after.totalScans).toBe(before.totalScans);
    expect(after.threatsBlocked).toBe(before.threatsBlocked);
    expect(after.quarantined).toBe(before.quarantined);
    expect(after.memoriesProtected).toBe(before.memoriesProtected);
    expect(after.credentialLeaks).toBe(before.credentialLeaks);

    // Sanity: live table really shrank.
    expect(auditCount(db)).toBe(2);
  });

  it('lifetime stats accumulate correctly across repeated purges', () => {
    const db = getDatabase();

    insertAuditRow(db, { timestamp: daysAgo(300), firewall_result: 'BLOCK' });
    purgeOldAuditEntries(90);
    insertAuditRow(db, { timestamp: daysAgo(290), firewall_result: 'BLOCK' });
    purgeOldAuditEntries(90);
    insertAuditRow(db, { timestamp: daysAgo(1), firewall_result: 'ALLOW' });

    const stats = getLifetimeStats();
    expect(stats.totalScans).toBe(3);
    expect(stats.threatsBlocked).toBe(2); // both purged blocks live in the aggregate
    expect(stats.memoriesProtected).toBe(1);
    expect(auditCount(db)).toBe(1); // only the recent ALLOW survives
  });

  it('purgeAuditUnderSizePressure trims the oldest rows when over the row cap', () => {
    const db = getDatabase();

    // 100 rows spread over time; force the row-cap path with a tiny cap.
    for (let i = 0; i < 100; i++) {
      insertAuditRow(db, { timestamp: daysAgo(100 - i), firewall_result: 'ALLOW' });
    }
    expect(auditCount(db)).toBe(100);

    const before = getLifetimeStats();

    // Inject a low warn threshold (0 bytes) so the size gate always trips, and a
    // 40-row cap so the valve trims down to it.
    const deleted = purgeAuditUnderSizePressure({ warnBytes: 0, maxRows: 40 });

    expect(deleted).toBeGreaterThan(0);
    expect(auditCount(db)).toBeLessThanOrEqual(40);

    // Pressure purge must ALSO roll into the aggregate — lifetime totals hold.
    const after = getLifetimeStats();
    expect(after.totalScans).toBe(before.totalScans);
    expect(after.memoriesProtected).toBe(before.memoriesProtected);
  });

  it('purgeAuditUnderSizePressure is a no-op below the size threshold', () => {
    const db = getDatabase();
    insertAuditRow(db, { timestamp: daysAgo(1), firewall_result: 'ALLOW' });

    // A huge warn threshold the in-memory DB can never exceed → no purge.
    const deleted = purgeAuditUnderSizePressure({ warnBytes: 1024 * 1024 * 1024, maxRows: 1 });
    expect(deleted).toBe(0);
    expect(auditCount(db)).toBe(1);
  });
});
