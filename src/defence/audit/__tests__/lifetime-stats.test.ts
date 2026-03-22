/**
 * Tests for getLifetimeStats SQL logic.
 *
 * We inline the query logic here rather than importing queries.ts,
 * because queries.ts statically imports database/init.ts which uses
 * import.meta.url — incompatible with Jest's module transform.
 */
import { describe, it, expect, beforeEach, afterAll } from '@jest/globals';
import Database from 'better-sqlite3';
import type { LifetimeStats } from '../queries.js';

let db: InstanceType<typeof Database>;

function setup(): void {
  db = new Database(':memory:');
  db.exec(`
    CREATE TABLE IF NOT EXISTS defence_audit (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      timestamp TEXT NOT NULL,
      firewall_result TEXT NOT NULL,
      threat_indicators TEXT NOT NULL DEFAULT '[]',
      source_type TEXT NOT NULL DEFAULT 'test',
      source_identifier TEXT NOT NULL DEFAULT 'test',
      trust_score REAL NOT NULL DEFAULT 1.0,
      anomaly_score REAL NOT NULL DEFAULT 0.0,
      sensitivity_level TEXT NOT NULL DEFAULT 'low',
      reason TEXT,
      memory_id INTEGER,
      blocked_patterns TEXT NOT NULL DEFAULT '[]',
      project TEXT
    )
  `);
}

function insert(result: string, indicators: string[] = []): void {
  db.prepare(`
    INSERT INTO defence_audit (timestamp, firewall_result, threat_indicators)
    VALUES (datetime('now'), ?, ?)
  `).run(result, JSON.stringify(indicators));
}

/** Mirror of getLifetimeStats from queries.ts — same SQL, accepts db param */
function getLifetimeStats(): LifetimeStats {
  const counts = db.prepare(`
    SELECT firewall_result, COUNT(*) as cnt
    FROM defence_audit
    GROUP BY firewall_result
  `).all() as { firewall_result: string; cnt: number }[];

  let totalScans = 0;
  let threatsBlocked = 0;
  let quarantined = 0;
  let memoriesProtected = 0;

  for (const row of counts) {
    totalScans += row.cnt;
    if (row.firewall_result === 'BLOCK') threatsBlocked = row.cnt;
    else if (row.firewall_result === 'QUARANTINE') quarantined = row.cnt;
    else if (row.firewall_result === 'ALLOW') memoriesProtected = row.cnt;
  }

  const credRow = db.prepare(`
    SELECT COUNT(*) as cnt
    FROM defence_audit
    WHERE LOWER(threat_indicators) LIKE '%credential%'
  `).get() as { cnt: number };

  const credentialLeaks = credRow?.cnt ?? 0;

  return { totalScans, threatsBlocked, quarantined, credentialLeaks, memoriesProtected };
}

describe('getLifetimeStats', () => {
  beforeEach(() => {
    setup();
  });

  afterAll(() => {
    db?.close();
  });

  it('returns zeroes for an empty database', () => {
    const stats = getLifetimeStats();
    expect(stats.totalScans).toBe(0);
    expect(stats.threatsBlocked).toBe(0);
    expect(stats.quarantined).toBe(0);
    expect(stats.credentialLeaks).toBe(0);
    expect(stats.memoriesProtected).toBe(0);
  });

  it('counts BLOCK results as threatsBlocked', () => {
    insert('BLOCK', ['prompt_injection']);
    insert('BLOCK', ['encoded_payload']);
    insert('ALLOW');
    const stats = getLifetimeStats();
    expect(stats.threatsBlocked).toBe(2);
    expect(stats.totalScans).toBe(3);
  });

  it('counts QUARANTINE results separately', () => {
    insert('QUARANTINE', ['suspicious_pattern']);
    insert('ALLOW');
    const stats = getLifetimeStats();
    expect(stats.quarantined).toBe(1);
    expect(stats.threatsBlocked).toBe(0);
  });

  it('counts ALLOW results as memoriesProtected', () => {
    insert('ALLOW');
    insert('ALLOW');
    insert('ALLOW');
    const stats = getLifetimeStats();
    expect(stats.memoriesProtected).toBe(3);
  });

  it('detects credential leaks via threat_indicators (lowercase)', () => {
    insert('BLOCK', ['credential_leak']);
    insert('BLOCK', ['prompt_injection']);
    insert('ALLOW');
    const stats = getLifetimeStats();
    expect(stats.credentialLeaks).toBe(1);
  });

  it('detects credential leaks via threat_indicators (uppercase)', () => {
    insert('BLOCK', ['CREDENTIAL_EXPOSURE']);
    insert('ALLOW');
    const stats = getLifetimeStats();
    expect(stats.credentialLeaks).toBe(1);
  });

  it('does not double-count credential leaks in totalScans', () => {
    insert('BLOCK', ['credential_leak']);
    insert('BLOCK', ['credential_leak']);
    insert('ALLOW');
    const stats = getLifetimeStats();
    expect(stats.totalScans).toBe(3);
    expect(stats.credentialLeaks).toBe(2);
  });
});
