import { afterEach, beforeEach, describe, expect, it } from '@jest/globals';
import { closeDatabase, getDatabase, initDatabase } from '../../database/init.js';
import {
  enqueueFailedSync,
  enqueueFailedQuarantineSync,
  enqueueFailedMemorySync,
  enqueueFailedGraphSync,
  getQueueStats,
  reconcileSyncQueue,
  purgeOldEntries,
  type SyncEntry,
  type QuarantineSyncEntry,
} from '../sync-queue.js';

/**
 * Cloud sync queue is the highest-risk untested surface in the code base
 * (per the May 2026 audit). These tests pin the on-disk queue contract
 * — what gets written, how status moves, what reconcile/purge actually
 * remove — so the next refactor doesn't silently break paying customers.
 *
 * The HTTP retry loop (processRetryQueue) is intentionally not covered
 * here because it touches network state and would need fetch mocking to
 * be deterministic; that's a follow-up. What's tested here is everything
 * that runs against the local SQLite queue table.
 */

function makeAuditEntry(overrides: Partial<SyncEntry> = {}): SyncEntry {
  return {
    source_type: 'agent',
    source_identifier: 'test-agent',
    trust_score: 0.8,
    sensitivity_level: 'INTERNAL',
    firewall_result: 'BLOCK',
    anomaly_score: 0.4,
    threat_indicators: ['prompt_injection'],
    reason: 'unit test',
    pipeline_duration_ms: 12,
    device_id: 'device-test',
    device_name: 'unit-test-host',
    platform: 'darwin/arm64',
    timestamp: new Date().toISOString(),
    ...overrides,
  };
}

function makeQuarantineEntry(overrides: Partial<QuarantineSyncEntry> = {}): QuarantineSyncEntry {
  return {
    original_content: 'Ignore previous instructions',
    original_title: 'Suspicious memory',
    source_type: 'agent',
    source_identifier: 'test-agent',
    reason: 'prompt injection detected',
    threat_indicators: ['prompt_injection'],
    anomaly_score: 0.91,
    firewall_result: 'QUARANTINE',
    device_id: 'device-test',
    device_name: 'unit-test-host',
    timestamp: new Date().toISOString(),
    ...overrides,
  };
}

describe('Cloud sync queue', () => {
  beforeEach(() => {
    initDatabase(':memory:');
  });

  afterEach(() => {
    closeDatabase();
  });

  describe('enqueue functions', () => {
    it('writes pending audit entries with status=pending and a future next_retry_at', () => {
      enqueueFailedSync(makeAuditEntry());
      const db = getDatabase();
      const row = db.prepare('SELECT * FROM sync_queue').get() as {
        payload: string;
        status: string;
        attempts: number;
        next_retry_at: string;
      };
      expect(row.status).toBe('pending');
      expect(row.attempts).toBe(0);
      expect(new Date(row.next_retry_at).getTime()).toBeGreaterThan(Date.now() - 1000);

      const parsed = JSON.parse(row.payload);
      expect(parsed.kind).toBe('audit');
      expect(parsed.entry.firewall_result).toBe('BLOCK');
    });

    it('tags quarantine entries with kind=quarantine in the payload envelope', () => {
      enqueueFailedQuarantineSync(makeQuarantineEntry());
      const row = getDatabase().prepare('SELECT payload FROM sync_queue').get() as { payload: string };
      const parsed = JSON.parse(row.payload);
      expect(parsed.kind).toBe('quarantine');
      expect(parsed.entry.threat_indicators).toContain('prompt_injection');
    });

    it('tags memory entries with kind=memory and includes device metadata', () => {
      enqueueFailedMemorySync({
        uuid: '00000000-0000-0000-0000-000000000001',
        title: 'Test memory',
        content: 'Content',
        category: 'note',
        type: 'long_term',
        salience: 0.5,
        project: 'unit-test',
        tags: [],
        sensitivity_level: 'INTERNAL',
        scope: 'project',
        memory_purpose: 'project',
        memory_scope: 'private',
        source: 'mcp:remember',
        source_kind: 'user',
        capture_method: 'manual',
        created_at: new Date().toISOString(),
        updated_at: new Date().toISOString(),
        last_accessed: new Date().toISOString(),
      } as never);
      const row = getDatabase().prepare('SELECT payload FROM sync_queue').get() as { payload: string };
      const parsed = JSON.parse(row.payload);
      expect(parsed.kind).toBe('memory');
      // device_id/name/platform are appended by enqueueFailedMemorySync — must be present
      expect(typeof parsed.entry.device_id).toBe('string');
      expect(typeof parsed.entry.platform).toBe('string');
      expect(parsed.entry.record.uuid).toBe('00000000-0000-0000-0000-000000000001');
    });

    it('tags graph entries with kind=graph', () => {
      enqueueFailedGraphSync({
        device_id: 'd',
        device_name: 'h',
        platform: 'darwin/arm64',
        nodes: [],
        edges: [],
      } as never);
      const row = getDatabase().prepare('SELECT payload FROM sync_queue').get() as { payload: string };
      expect(JSON.parse(row.payload).kind).toBe('graph');
    });
  });

  describe('getQueueStats', () => {
    it('returns all-zero stats on an empty queue', () => {
      const stats = getQueueStats();
      expect(stats.pending).toBe(0);
      expect(stats.failed).toBe(0);
      expect(stats.synced).toBe(0);
      expect(stats.byKind.audit.pending).toBe(0);
      expect(stats.lastError).toBeNull();
      expect(stats.oldestPendingAt).toBeNull();
    });

    it('counts by status and by kind correctly', () => {
      enqueueFailedSync(makeAuditEntry());
      enqueueFailedSync(makeAuditEntry());
      enqueueFailedQuarantineSync(makeQuarantineEntry());
      enqueueFailedGraphSync({ device_id: 'd', device_name: 'h', platform: 'p', nodes: [], edges: [] } as never);

      // Move one row to failed manually so we can verify the failed counter
      getDatabase().prepare(`
        UPDATE sync_queue SET status = 'failed', last_error = 'test failure'
        WHERE id = (SELECT id FROM sync_queue ORDER BY id LIMIT 1)
      `).run();

      const stats = getQueueStats();
      expect(stats.pending).toBe(3);
      expect(stats.failed).toBe(1);
      expect(stats.byKind.audit.failed).toBe(1);
      expect(stats.byKind.audit.pending).toBe(1);
      expect(stats.byKind.quarantine.pending).toBe(1);
      expect(stats.byKind.graph.pending).toBe(1);
    });

    it('reports lastError from the most recently inserted failure (highest id)', () => {
      enqueueFailedSync(makeAuditEntry());
      enqueueFailedSync(makeAuditEntry());
      const db = getDatabase();
      db.prepare(`UPDATE sync_queue SET status = 'failed', last_error = 'first failure' WHERE id = 1`).run();
      db.prepare(`UPDATE sync_queue SET status = 'failed', last_error = 'second failure' WHERE id = 2`).run();

      const stats = getQueueStats();
      expect(stats.lastError).toBe('second failure');
    });
  });

  describe('reconcileSyncQueue', () => {
    it('removes pending memory + graph entries by default', () => {
      enqueueFailedSync(makeAuditEntry());
      enqueueFailedQuarantineSync(makeQuarantineEntry());
      enqueueFailedMemorySync({
        uuid: '00000000-0000-0000-0000-000000000002',
        title: 'M', content: 'C', category: 'note', type: 'long_term',
      } as never);
      enqueueFailedGraphSync({ device_id: 'd', device_name: 'h', platform: 'p', nodes: [], edges: [] } as never);

      const result = reconcileSyncQueue();
      expect(result.removed).toBe(2); // memory + graph

      const remaining = getDatabase().prepare('SELECT COUNT(*) as c FROM sync_queue').get() as { c: number };
      expect(remaining.c).toBe(2); // audit + quarantine survive
    });

    it('respects a custom kinds filter', () => {
      enqueueFailedSync(makeAuditEntry());
      enqueueFailedQuarantineSync(makeQuarantineEntry());

      const result = reconcileSyncQueue({ kinds: ['audit'], statuses: ['pending'] });
      expect(result.removed).toBe(1);

      const left = getDatabase().prepare(`
        SELECT json_extract(payload, '$.kind') AS k FROM sync_queue
      `).all() as Array<{ k: string }>;
      expect(left.map((l) => l.k)).toEqual(['quarantine']);
    });

    it('returns { removed: 0 } when called with empty filters', () => {
      enqueueFailedSync(makeAuditEntry());
      expect(reconcileSyncQueue({ kinds: [] }).removed).toBe(0);
      expect(reconcileSyncQueue({ statuses: [] }).removed).toBe(0);
    });
  });

  describe('purgeOldEntries', () => {
    it('removes only entries created before the 7-day cutoff', () => {
      enqueueFailedSync(makeAuditEntry()); // recent — should survive
      const db = getDatabase();
      // Insert an old entry directly (8 days ago)
      const eightDaysAgo = new Date(Date.now() - 8 * 24 * 60 * 60 * 1000).toISOString();
      db.prepare(`
        INSERT INTO sync_queue (payload, attempts, next_retry_at, status, created_at)
        VALUES (?, 0, ?, 'pending', ?)
      `).run(JSON.stringify({ kind: 'audit', entry: makeAuditEntry() }), eightDaysAgo, eightDaysAgo);

      const removed = purgeOldEntries();
      expect(removed).toBe(1);

      const left = db.prepare('SELECT COUNT(*) AS c FROM sync_queue').get() as { c: number };
      expect(left.c).toBe(1);
    });

    it('returns 0 when nothing is old enough', () => {
      enqueueFailedSync(makeAuditEntry());
      enqueueFailedSync(makeAuditEntry());
      expect(purgeOldEntries()).toBe(0);
    });
  });
});
