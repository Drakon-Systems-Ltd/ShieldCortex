/**
 * Provenance ledger (v4.39.0) — the audit trail now records read/write/delete
 * operations with a queryable `operation` discriminator and a write-time
 * `content_hash` for tamper-evidence. These tests pin:
 *  - the schema columns exist (migration + canonical schema in lockstep);
 *  - logAudit persists operation + content_hash, and queryAuditLogs filters by operation;
 *  - writes record operation='write' + content_hash (audit row AND memory row);
 *  - allowed reads record operation='read' (one row per tool call);
 *  - allowed deletes record operation='delete'.
 */

import { describe, it, expect, beforeEach, afterEach } from '@jest/globals';
import { initDatabase, closeDatabase, getDatabase } from '../database/init.js';
import { addMemory, deleteMemory, updateMemory } from '../memory/store.js';
import { executeRecall, executeGetMemory } from '../tools/recall.js';
import { queryAuditLogs } from '../defence/audit/queries.js';
import { createContentHash } from '../defence/audit/logger.js';
import { runMigrations } from '../database/migrations.js';
import type { DefenceSource } from '../defence/types.js';

const PROJECT = 'prov-ledger';
const OWNER: DefenceSource = { type: 'cli', identifier: 'owner-cli' }; // trust 0.9

function seed(title: string, content: string): number {
  return addMemory(
    { title, content, category: 'note', project: PROJECT },
    undefined,
    OWNER,
  ).id;
}

beforeEach(() => initDatabase(':memory:'));
afterEach(() => closeDatabase());

describe('schema', () => {
  it('defence_audit has operation + content_hash columns; memories has content_hash', () => {
    const auditCols = (getDatabase().prepare('PRAGMA table_info(defence_audit)').all() as { name: string }[]).map(c => c.name);
    expect(auditCols).toContain('operation');
    expect(auditCols).toContain('content_hash');
    const memCols = (getDatabase().prepare('PRAGMA table_info(memories)').all() as { name: string }[]).map(c => c.name);
    expect(memCols).toContain('content_hash');
  });
});

describe('operation filter', () => {
  it('queryAuditLogs filters by operation', () => {
    seed('a', 'first memory about typescript builds'); // emits a write audit
    const writes = queryAuditLogs({ operation: 'write', limit: 100 });
    expect(writes.length).toBeGreaterThan(0);
    expect(writes.every(r => r.operation === 'write')).toBe(true);
    // No read rows yet.
    expect(queryAuditLogs({ operation: 'read', limit: 100 })).toHaveLength(0);
  });
});

describe('writes', () => {
  it('records operation=write with a content_hash on the audit row AND the memory row', () => {
    const content = 'deploy notes: the build uses esbuild and ships to fly.io';
    const id = seed('build', content);
    const expectedHash = createContentHash(content);

    const writeRow = queryAuditLogs({ operation: 'write', limit: 100 }).find(r => r.content_hash);
    expect(writeRow).toBeDefined();
    expect(writeRow?.content_hash).toBe(expectedHash);

    const memHash = (getDatabase().prepare('SELECT content_hash FROM memories WHERE id = ?').get(id) as { content_hash: string }).content_hash;
    expect(memHash).toBe(expectedHash);
  });
});

describe('allowed reads', () => {
  it('records ONE operation=read row per recall call (not per memory)', async () => {
    seed('one', 'memory one about postgres');
    seed('two', 'memory two about drizzle');
    const before = queryAuditLogs({ operation: 'read', limit: 200 }).length;

    await executeRecall({
      mode: 'recent', limit: 50, project: PROJECT, source: OWNER,
      includeGlobal: true, includeDecayed: true,
    } as Parameters<typeof executeRecall>[0]);

    const reads = queryAuditLogs({ operation: 'read', limit: 200 });
    expect(reads.length).toBe(before + 1); // exactly one row, covering both memories
    expect(reads[0].operation).toBe('read');
    expect(reads[0].firewall_result).toBe('ALLOW');
  });

  it('records operation=read for a get_memory fetch', () => {
    const id = seed('single', 'a single fetched memory');
    executeGetMemory({ id, source: OWNER });
    const reads = queryAuditLogs({ operation: 'read', limit: 100 });
    expect(reads.some(r => r.memory_id === id)).toBe(true);
  });
});

describe('allowed deletes', () => {
  it('records operation=delete when an attributed caller deletes their own memory', () => {
    const id = seed('doomed', 'this memory will be forgotten');
    const ok = deleteMemory(id, OWNER);
    expect(ok).toBe(true);

    // memory_id is NULL by design (FK ON DELETE SET NULL); the id lives in reason/blocked_patterns.
    const deletes = queryAuditLogs({ operation: 'delete', limit: 100 });
    expect(deletes.some(r => r.firewall_result === 'ALLOW' && (r.reason ?? '').includes(`#${id}`))).toBe(true);
  });
});

describe('content_hash staleness (updates)', () => {
  it('recomputes content_hash AND emits operation=update when content is edited', () => {
    const id = seed('editable', 'original content about the build pipeline');
    const newContent = 'rewritten content about the deploy pipeline and rollbacks';
    updateMemory(id, { content: newContent });

    const memHash = (getDatabase().prepare('SELECT content_hash FROM memories WHERE id = ?').get(id) as { content_hash: string }).content_hash;
    expect(memHash).toBe(createContentHash(newContent)); // not stale

    const updates = queryAuditLogs({ operation: 'update', limit: 100 });
    expect(updates.some(r => r.memory_id === id && r.content_hash === createContentHash(newContent))).toBe(true);
  });
});

describe('operation tagging on denials', () => {
  // A deeply-nested sub-agent: trust ~0.147, not the owner → delete denied.
  const LOW_TRUST: DefenceSource = { type: 'agent', identifier: 'agent-spawned>task-1>task-2' };

  it('tags a denied delete with operation=delete (BLOCK)', () => {
    const id = seed('protected', 'a memory a low-trust agent may not delete');
    const ok = deleteMemory(id, LOW_TRUST);
    expect(ok).toBe(false);
    const blocks = queryAuditLogs({ memoryId: id, firewallResult: 'BLOCK', limit: 50 });
    expect(blocks.some(r => r.operation === 'delete')).toBe(true);
  });
});

describe('legacy NULL-operation rows', () => {
  it('are excluded by an operation filter (the core query contract)', () => {
    seed('tagged', 'a normal write that produces operation=write'); // operation='write'
    // A legacy row written before the provenance column existed (operation NULL).
    getDatabase().prepare(
      `INSERT INTO defence_audit (timestamp, source_type, source_identifier, trust_score, sensitivity_level, firewall_result, operation)
       VALUES (datetime('now'), 'user', 'direct', 1, 'INTERNAL', 'ALLOW', NULL)`,
    ).run();

    const writes = queryAuditLogs({ operation: 'write', limit: 100 });
    expect(writes.length).toBeGreaterThan(0);
    expect(writes.every(r => r.operation === 'write')).toBe(true); // legacy NULL row excluded
  });
});

describe('migration on an existing (pre-4.39) DB', () => {
  it('adds the provenance columns + indexes, preserves legacy rows, and is idempotent', () => {
    initDatabase(':memory:'); // full current schema...
    const db = getDatabase();
    // ...then simulate a pre-provenance DB by dropping the new columns + indexes.
    db.exec('DROP INDEX IF EXISTS idx_audit_operation');
    db.exec('DROP INDEX IF EXISTS idx_memories_content_hash');
    db.exec('DROP INDEX IF EXISTS idx_memories_source');
    db.exec('ALTER TABLE defence_audit DROP COLUMN operation');
    db.exec('ALTER TABLE defence_audit DROP COLUMN content_hash');
    db.exec('ALTER TABLE memories DROP COLUMN content_hash');
    db.prepare(
      `INSERT INTO defence_audit (timestamp, source_type, source_identifier, trust_score, sensitivity_level, firewall_result)
       VALUES (datetime('now'), 'user', 'direct', 1, 'INTERNAL', 'ALLOW')`,
    ).run();

    const auditBefore = (db.prepare('PRAGMA table_info(defence_audit)').all() as { name: string }[]).map(c => c.name);
    expect(auditBefore).not.toContain('operation');

    runMigrations(db); // the upgrade path that ships to every existing user

    const auditAfter = (db.prepare('PRAGMA table_info(defence_audit)').all() as { name: string }[]).map(c => c.name);
    expect(auditAfter).toContain('operation');
    expect(auditAfter).toContain('content_hash');
    const memAfter = (db.prepare('PRAGMA table_info(memories)').all() as { name: string }[]).map(c => c.name);
    expect(memAfter).toContain('content_hash');
    // legacy row survives with NULL operation
    expect((db.prepare('SELECT operation FROM defence_audit LIMIT 1').get() as { operation: string | null }).operation).toBeNull();
    // index back-filled
    const idx = db.prepare("SELECT name FROM sqlite_master WHERE type='index' AND name='idx_audit_operation'").get();
    expect(idx).toBeDefined();
    // idempotent
    expect(() => runMigrations(db)).not.toThrow();
  });
});
