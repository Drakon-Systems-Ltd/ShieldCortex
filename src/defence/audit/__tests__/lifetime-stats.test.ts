import { describe, it, expect, beforeEach, afterAll } from '@jest/globals';
import Database from 'better-sqlite3';

// Use an in-memory database for isolation
let db: InstanceType<typeof Database>;

// We mock getDatabase to return our in-memory db
jest.mock('../../../database/init.js', () => ({
  getDatabase: () => db,
  isDatabaseInitialized: () => true,
}));

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

describe('getLifetimeStats', () => {
  beforeEach(() => {
    setup();
  });

  afterAll(() => {
    db?.close();
  });

  it('returns zeroes for an empty database', async () => {
    const { getLifetimeStats } = await import('../queries.js');
    const stats = getLifetimeStats();
    expect(stats.totalScans).toBe(0);
    expect(stats.threatsBlocked).toBe(0);
    expect(stats.quarantined).toBe(0);
    expect(stats.credentialLeaks).toBe(0);
    expect(stats.memoriesProtected).toBe(0);
  });

  it('counts BLOCK results as threatsBlocked', async () => {
    const { getLifetimeStats } = await import('../queries.js');
    insert('BLOCK', ['prompt_injection']);
    insert('BLOCK', ['encoded_payload']);
    insert('ALLOW');
    const stats = getLifetimeStats();
    expect(stats.threatsBlocked).toBe(2);
    expect(stats.totalScans).toBe(3);
  });

  it('counts QUARANTINE results separately', async () => {
    const { getLifetimeStats } = await import('../queries.js');
    insert('QUARANTINE', ['suspicious_pattern']);
    insert('ALLOW');
    const stats = getLifetimeStats();
    expect(stats.quarantined).toBe(1);
    expect(stats.threatsBlocked).toBe(0);
  });

  it('counts ALLOW results as memoriesProtected', async () => {
    const { getLifetimeStats } = await import('../queries.js');
    insert('ALLOW');
    insert('ALLOW');
    insert('ALLOW');
    const stats = getLifetimeStats();
    expect(stats.memoriesProtected).toBe(3);
  });

  it('detects credential leaks via threat_indicators (lowercase)', async () => {
    const { getLifetimeStats } = await import('../queries.js');
    insert('BLOCK', ['credential_leak']);
    insert('BLOCK', ['prompt_injection']);
    insert('ALLOW');
    const stats = getLifetimeStats();
    expect(stats.credentialLeaks).toBe(1);
  });

  it('detects credential leaks via threat_indicators (uppercase)', async () => {
    const { getLifetimeStats } = await import('../queries.js');
    insert('BLOCK', ['CREDENTIAL_EXPOSURE']);
    insert('ALLOW');
    const stats = getLifetimeStats();
    expect(stats.credentialLeaks).toBe(1);
  });

  it('does not double-count credential leaks in totalScans', async () => {
    const { getLifetimeStats } = await import('../queries.js');
    insert('BLOCK', ['credential_leak']);
    insert('BLOCK', ['credential_leak']);
    insert('ALLOW');
    const stats = getLifetimeStats();
    expect(stats.totalScans).toBe(3);
    expect(stats.credentialLeaks).toBe(2);
  });
});
