/**
 * Quarantine capacity and expiry tests
 */

import { describe, it, expect, beforeEach, afterEach } from '@jest/globals';
import { initDatabase, closeDatabase, getDatabase } from '../../database/init.js';

describe('Quarantine Auto-Expire', () => {
  beforeEach(() => {
    initDatabase(':memory:');
  });

  afterEach(() => {
    closeDatabase();
  });

  it('should expire pending items after TTL', async () => {
    const { expireQuarantineItems } = await import('../quarantine/auto-expire.js');
    const db = getDatabase();

    // Insert a pending item with created_at in the past
    db.prepare(`
      INSERT INTO quarantine (original_content, original_title, reason, source_type, source_identifier, firewall_result, status, created_at)
      VALUES (?, ?, ?, ?, ?, 'QUARANTINE', 'pending', datetime('now', '-10 days'))
    `).run('test content', 'test title', 'credential_leak', 'agent', 'test-agent');

    const expired = expireQuarantineItems(7);
    expect(expired).toBe(1);

    const remaining = db.prepare(
      "SELECT status FROM quarantine WHERE original_title = 'test title'"
    ).get() as { status: string };
    expect(remaining.status).toBe('expired');
  });

  it('should not expire items within TTL', async () => {
    const { expireQuarantineItems } = await import('../quarantine/auto-expire.js');
    const db = getDatabase();

    // Insert a pending item created recently
    db.prepare(`
      INSERT INTO quarantine (original_content, original_title, reason, source_type, source_identifier, firewall_result, status, created_at)
      VALUES (?, ?, ?, ?, ?, 'QUARANTINE', 'pending', datetime('now', '-2 days'))
    `).run('test content', 'recent item', 'credential_leak', 'agent', 'test-agent');

    const expired = expireQuarantineItems(7);
    expect(expired).toBe(0);

    const remaining = db.prepare(
      "SELECT status FROM quarantine WHERE original_title = 'recent item'"
    ).get() as { status: string };
    expect(remaining.status).toBe('pending');
  });
});

describe('Quarantine Pruning', () => {
  beforeEach(() => {
    initDatabase(':memory:');
  });

  afterEach(() => {
    closeDatabase();
  });

  it('should prune reviewed items older than retention period', async () => {
    const { pruneQuarantine } = await import('../quarantine/auto-expire.js');
    const db = getDatabase();

    // Insert an old approved item
    db.prepare(`
      INSERT INTO quarantine (original_content, original_title, reason, source_type, source_identifier, firewall_result, status, reviewed_at, reviewed_by, created_at)
      VALUES (?, ?, ?, ?, ?, 'QUARANTINE', 'approved', datetime('now', '-100 days'), 'admin', datetime('now', '-110 days'))
    `).run('old content', 'old approved', 'test', 'agent', 'test-agent');

    // Insert a recent approved item
    db.prepare(`
      INSERT INTO quarantine (original_content, original_title, reason, source_type, source_identifier, firewall_result, status, reviewed_at, reviewed_by, created_at)
      VALUES (?, ?, ?, ?, ?, 'QUARANTINE', 'approved', datetime('now', '-10 days'), 'admin', datetime('now', '-15 days'))
    `).run('recent content', 'recent approved', 'test', 'agent', 'test-agent');

    const pruned = pruneQuarantine(90);
    expect(pruned).toBe(1);

    // Old one should be gone
    const old = db.prepare("SELECT * FROM quarantine WHERE original_title = 'old approved'").get();
    expect(old).toBeUndefined();

    // Recent one should remain
    const recent = db.prepare("SELECT * FROM quarantine WHERE original_title = 'recent approved'").get();
    expect(recent).toBeDefined();
  });

  it('should not prune pending items regardless of age', async () => {
    const { pruneQuarantine } = await import('../quarantine/auto-expire.js');
    const db = getDatabase();

    // Insert an old pending item
    db.prepare(`
      INSERT INTO quarantine (original_content, original_title, reason, source_type, source_identifier, firewall_result, status, created_at)
      VALUES (?, ?, ?, ?, ?, 'QUARANTINE', 'pending', datetime('now', '-200 days'))
    `).run('old pending', 'old pending item', 'test', 'agent', 'test-agent');

    const pruned = pruneQuarantine(90);
    expect(pruned).toBe(0);

    const item = db.prepare("SELECT * FROM quarantine WHERE original_title = 'old pending item'").get();
    expect(item).toBeDefined();
  });

  it('should prune expired and rejected items older than retention', async () => {
    const { pruneQuarantine } = await import('../quarantine/auto-expire.js');
    const db = getDatabase();

    // Insert old expired item
    db.prepare(`
      INSERT INTO quarantine (original_content, original_title, reason, source_type, source_identifier, firewall_result, status, reviewed_at, reviewed_by, created_at)
      VALUES (?, ?, ?, ?, ?, 'QUARANTINE', 'expired', datetime('now', '-95 days'), 'auto-expire', datetime('now', '-102 days'))
    `).run('expired content', 'old expired', 'test', 'agent', 'test-agent');

    // Insert old rejected item
    db.prepare(`
      INSERT INTO quarantine (original_content, original_title, reason, source_type, source_identifier, firewall_result, status, reviewed_at, reviewed_by, created_at)
      VALUES (?, ?, ?, ?, ?, 'QUARANTINE', 'rejected', datetime('now', '-91 days'), 'admin', datetime('now', '-98 days'))
    `).run('rejected content', 'old rejected', 'test', 'agent', 'test-agent');

    const pruned = pruneQuarantine(90);
    expect(pruned).toBe(2);
  });
});
