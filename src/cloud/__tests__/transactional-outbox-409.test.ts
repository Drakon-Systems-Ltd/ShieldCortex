/**
 * #409 — transactional outbox: mutation + enqueue atomic; dispatch after commit.
 */
import { afterEach, beforeEach, describe, expect, it, jest } from '@jest/globals';
import { closeDatabase, getDatabase, initDatabase } from '../../database/init.js';
import { mkdtempSync, rmSync } from 'fs';
import { join } from 'path';
import { tmpdir } from 'os';

describe('#409 transactional outbox', () => {
  let configDir: string;
  let originalFetch: typeof globalThis.fetch;

  beforeEach(async () => {
    configDir = mkdtempSync(join(tmpdir(), 'shieldcortex-outbox-409-'));
    process.env.SHIELDCORTEX_CONFIG_DIR = configDir;
    process.env.SHIELDCORTEX_SKIP_EMBEDDINGS = '1';
    initDatabase(join(configDir, 'memories.db'));
    originalFetch = globalThis.fetch;

    const { setCloudConfig } = await import('../config.js');
    setCloudConfig({
      cloudEnabled: true,
      cloudApiKey: 'sc_test_key_not_real',
      cloudBaseUrl: 'https://example.invalid',
    });

    // Feature gate cloud_sync on for store path
    try {
      const gate = await import('../../license/gate.js');
      if (typeof (gate as { setFeatureOverride?: (k: string, v: boolean) => void }).setFeatureOverride === 'function') {
        (gate as { setFeatureOverride: (k: string, v: boolean) => void }).setFeatureOverride('cloud_sync', true);
      }
    } catch { /* may already be enabled in test env */ }
  });

  afterEach(() => {
    globalThis.fetch = originalFetch;
    delete process.env.SHIELDCORTEX_CONFIG_DIR;
    delete process.env.SHIELDCORTEX_SKIP_EMBEDDINGS;
    closeDatabase();
    rmSync(configDir, { recursive: true, force: true });
    jest.restoreAllMocks();
  });

  function queueRows(): Array<{ status: string; delivery_key: string | null; payload: string }> {
    return getDatabase()
      .prepare('SELECT status, delivery_key, payload FROM sync_queue ORDER BY id ASC')
      .all() as Array<{ status: string; delivery_key: string | null; payload: string }>;
  }

  it('rolled-back local mutation produces no outbox row', async () => {
    const { enqueueMemoryOutbox } = await import('../sync-queue.js');
    const { buildMemoryDeleteTombstone } = await import('../memory-sync.js');

    const db = getDatabase();
    expect(() => {
      db.transaction(() => {
        // Simulate mutation + outbox then abort
        db.prepare(
          `INSERT INTO memories (uuid, type, category, title, content, tags, salience, metadata, scope, transferable, status, pinned, defence_verdict, cloud_excluded, memory_purpose, memory_scope, updated_at)
           VALUES ('rb-uuid', 'short_term', 'note', 't', 'c', '[]', 0.5, '{}', 'project', 0, 'active', 0, 'allow', 0, 'project', 'private', CURRENT_TIMESTAMP)`,
        ).run();
        enqueueMemoryOutbox(
          {
            external_id: 'rb-uuid',
            local_id: 1,
            type: 'short_term',
            category: 'note',
            title: 't',
            content: 'c',
            project: null,
            tags: [],
            salience: 0.5,
            scope: 'project',
            transferable: false,
            trust_score: null,
            sensitivity_level: 'INTERNAL',
            source: null,
            metadata: {},
            cloud_excluded: false,
            created_at: new Date().toISOString(),
            updated_at: new Date().toISOString(),
            deleted_at: null,
          },
          { deliveryKey: 'memory:rb-uuid:upsert:1', db, dueNow: true },
        );
        throw new Error('boom-rollback');
      })();
    }).toThrow(/boom-rollback/);

    const mem = db.prepare(`SELECT COUNT(*) AS c FROM memories WHERE uuid = 'rb-uuid'`).get() as { c: number };
    expect(mem.c).toBe(0);
    expect(queueRows()).toHaveLength(0);
  });

  it('crash after mutation+outbox commit still has durable pending event (no live dispatch)', async () => {
    const { writeMemorySyncOutbox } = await import('../memory-sync.js');
    const db = getDatabase();

    db.transaction(() => {
      db.prepare(
        `INSERT INTO memories (uuid, type, category, title, content, tags, salience, metadata, scope, transferable, status, pinned, defence_verdict, cloud_excluded, memory_purpose, memory_scope, sensitivity_level, updated_at)
         VALUES ('dur-uuid', 'short_term', 'note', 'title', 'body', '[]', 0.5, '{}', 'project', 0, 'active', 0, 'allow', 0, 'project', 'private', 'INTERNAL', CURRENT_TIMESTAMP)`,
      ).run();
      const row = db.prepare('SELECT * FROM memories WHERE uuid = ?').get('dur-uuid') as Record<string, unknown>;
      writeMemorySyncOutbox(
        {
          external_id: row.uuid as string,
          local_id: row.id as number,
          type: row.type as string,
          category: row.category as string,
          title: row.title as string,
          content: row.content as string,
          project: null,
          tags: [],
          salience: 0.5,
          scope: 'project',
          transferable: false,
          trust_score: null,
          sensitivity_level: 'INTERNAL',
          source: null,
          metadata: {},
          cloud_excluded: false,
          created_at: new Date().toISOString(),
          updated_at: new Date().toISOString(),
          deleted_at: null,
        },
        { op: 'upsert', db },
      );
    })();

    // No dispatch called — simulates crash after commit before network.
    const rows = queueRows();
    expect(rows).toHaveLength(1);
    expect(rows[0].status).toBe('pending');
    expect(rows[0].delivery_key).toMatch(/^memory:dur-uuid:upsert:/);
    const mem = db.prepare(`SELECT COUNT(*) AS c FROM memories WHERE uuid = 'dur-uuid'`).get() as { c: number };
    expect(mem.c).toBe(1);
  });

  it('replayed delivery_key is idempotent (single outbox row)', async () => {
    const { writeMemorySyncOutbox } = await import('../memory-sync.js');
    const record = {
      external_id: 'idemp-uuid',
      local_id: 42,
      type: 'short_term',
      category: 'note',
      title: 't',
      content: 'c',
      project: null,
      tags: [] as string[],
      salience: 0.5,
      scope: 'project',
      transferable: false,
      trust_score: null as number | null,
      sensitivity_level: 'INTERNAL',
      source: null as string | null,
      metadata: {} as Record<string, unknown>,
      cloud_excluded: false,
      created_at: '2026-01-01T00:00:00.000Z',
      updated_at: '2026-01-02T00:00:00.000Z',
      deleted_at: null as string | null,
    };

    const a = writeMemorySyncOutbox(record, { op: 'upsert' });
    const b = writeMemorySyncOutbox(record, { op: 'upsert' });
    expect(a.inserted).toBe(true);
    expect(b.inserted).toBe(false);
    expect(a.deliveryKey).toBe(b.deliveryKey);
    expect(queueRows()).toHaveLength(1);
  });

  it('delete tombstone outbox preserves ordering key after memory row is gone', async () => {
    const { writeMemorySyncOutbox, buildMemoryDeleteTombstone } = await import('../memory-sync.js');
    const { writeGraphSyncOutbox, buildEnvelope } = await import('../graph-sync.js');
    const db = getDatabase();

    db.prepare(
      `INSERT INTO memories (uuid, type, category, title, content, tags, salience, metadata, scope, transferable, status, pinned, defence_verdict, cloud_excluded, memory_purpose, memory_scope, sensitivity_level, updated_at)
       VALUES ('del-uuid', 'short_term', 'note', 't', 'secret', '[]', 0.5, '{}', 'project', 0, 'active', 0, 'allow', 0, 'project', 'private', 'INTERNAL', CURRENT_TIMESTAMP)`,
    ).run();
    const memory = {
      id: 1,
      uuid: 'del-uuid',
      type: 'short_term',
      category: 'note',
      title: 't',
      content: 'secret',
      project: null,
      tags: [],
      salience: 0.5,
      scope: 'project',
      transferable: false,
      createdAt: new Date(),
      updatedAt: new Date(),
      cloudExcluded: false,
      sensitivityLevel: 'INTERNAL',
    } as never;

    const tomb = buildMemoryDeleteTombstone(memory);
    db.transaction(() => {
      db.prepare('DELETE FROM memories WHERE uuid = ?').run('del-uuid');
      writeMemorySyncOutbox(tomb, { op: 'delete', db });
      const env = buildEnvelope([], [], [], ['del-uuid']);
      writeGraphSyncOutbox(env, {
        deliveryKey: `graph:prune:del-uuid:${tomb.deleted_at}`,
        db,
      });
    })();

    const rows = queueRows();
    expect(rows).toHaveLength(2);
    expect(rows[0].delivery_key).toMatch(/^memory:del-uuid:delete:/);
    expect(rows[1].delivery_key).toMatch(/^graph:prune:del-uuid:/);
    // Tombstone payload has empty content
    const memPayload = JSON.parse(rows[0].payload);
    expect(memPayload.entry.record.content).toBe('');
    expect(memPayload.entry.record.deleted_at).toBeTruthy();
    // Memory gone locally
    const left = db.prepare(`SELECT COUNT(*) AS c FROM memories WHERE uuid = 'del-uuid'`).get() as { c: number };
    expect(left.c).toBe(0);
  });

  it('successful dispatch acknowledges outbox row (idempotent worker path still ok)', async () => {
    const { writeMemorySyncOutbox, dispatchMemoryOutboxBestEffort } = await import('../memory-sync.js');
    const record = {
      external_id: 'ack-uuid',
      local_id: 7,
      type: 'short_term',
      category: 'note',
      title: 't',
      content: 'c',
      project: null,
      tags: [] as string[],
      salience: 0.5,
      scope: 'project',
      transferable: false,
      trust_score: null as number | null,
      sensitivity_level: 'INTERNAL',
      source: null as string | null,
      metadata: {} as Record<string, unknown>,
      cloud_excluded: false,
      created_at: new Date().toISOString(),
      updated_at: new Date().toISOString(),
      deleted_at: null as string | null,
    };
    writeMemorySyncOutbox(record, { op: 'upsert' });
    expect(queueRows()[0].status).toBe('pending');

    globalThis.fetch = jest.fn().mockResolvedValue({ ok: true, status: 200 }) as unknown as typeof globalThis.fetch;
    dispatchMemoryOutboxBestEffort(record);
    // allow microtask
    await new Promise((r) => setTimeout(r, 30));
    expect(queueRows()[0].status).toBe('synced');
  });
});
