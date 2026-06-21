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
import { addMemory, deleteMemory } from '../memory/store.js';
import { executeRecall, executeGetMemory } from '../tools/recall.js';
import { queryAuditLogs } from '../defence/audit/queries.js';
import { createContentHash } from '../defence/audit/logger.js';
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
