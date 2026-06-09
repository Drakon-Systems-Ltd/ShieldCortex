/**
 * Bulk forget access-control enforcement.
 *
 * Background — the bulk delete path in `forget.ts` used to run a single raw
 *   `DELETE FROM memories WHERE <whereClause>`
 * inside a transaction, bypassing `deleteMemory()` entirely. That meant the
 * delete ACL (`checkAccess(..., 'delete')`) only guarded the single-ID path: a
 * low-trust sub-agent that was denied a one-row delete could still mass-delete
 * protected memories via `forget({ category: 'note', confirm: true })`. It also
 * skipped access-denial audit logging, graph cleanup, cloud-sync deletes, and
 * the dashboard `memory_deleted` event.
 *
 * Fix: route every affected id through `deleteMemory(id, source)` inside the
 * existing transaction, count true (deleted) vs false (access-denied), and
 * surface denials in the result. These tests prove a non-owner / low-trust
 * caller can no longer mass-delete, and that an authorised owner delete fires
 * the same side effects as the single-ID path.
 */

import { describe, it, expect, beforeEach, afterEach } from '@jest/globals';
import { initDatabase, closeDatabase } from '../database/init.js';
import { addMemory, getMemoryById } from '../memory/store.js';
import { executeForget } from '../tools/forget.js';
import { queryAuditLogs } from '../defence/audit/queries.js';
import type { DefenceSource } from '../defence/types.js';

const PROJECT = 'bulk-acl-test';

// The memories are owned by this CLI source (trust 0.9). Seeding via the
// `source` string field (NOT a DefenceSource arg) stores them as real
// memories with `source = 'cli:owner-cli'` and skips the write pipeline, so
// nothing gets quarantined.
const OWNER_SOURCE_VALUE = 'cli:owner-cli';
const OWNER: DefenceSource = { type: 'cli', identifier: 'owner-cli' };

// A deeply-nested spawned sub-agent: trust = 0.3 × 0.7² = 0.147, and it does
// not own the seeded rows, so `checkAccess(..., 'delete')` denies it.
const LOW_TRUST: DefenceSource = { type: 'agent', identifier: 'agent-spawned>task-1>task-2' };

function seedNotes(n: number): number[] {
  const ids: number[] = [];
  for (let i = 0; i < n; i++) {
    const mem = addMemory({
      title: `Protected note ${i}`,
      content: `Owned by ${OWNER_SOURCE_VALUE}, must survive an unauthorised bulk forget. #${i}`,
      category: 'note',
      project: PROJECT,
      source: OWNER_SOURCE_VALUE,
    });
    ids.push(mem.id);
  }
  return ids;
}

describe('bulk forget — access control enforcement', () => {
  beforeEach(() => {
    initDatabase(':memory:');
  });

  afterEach(() => {
    closeDatabase();
  });

  it('denies a low-trust non-owner: deletes 0 rows, rows remain, denials audited', async () => {
    const ids = seedNotes(3);

    const result = await executeForget({
      category: 'note',
      project: PROJECT,
      confirm: true,
      dryRun: false,
      source: LOW_TRUST,
    });

    // Nothing the caller is not allowed to delete should be gone.
    expect(result.deleted).toBe(0);
    expect(result.denied).toBe(3);
    expect(result.memories ?? []).toHaveLength(0);

    // The protected rows must still exist (the old raw DELETE would have wiped them).
    for (const id of ids) {
      expect(getMemoryById(id)).not.toBeNull();
    }

    // Each denial is logged to the defence audit as a BLOCK with an
    // "Access denied" reason, scoped to the memory id.
    for (const id of ids) {
      const denials = queryAuditLogs({ memoryId: id, firewallResult: 'BLOCK' });
      expect(denials.length).toBeGreaterThan(0);
      expect(denials[0].reason).toMatch(/Access denied/i);
    }
  });

  it('lets the owner bulk-delete its own memories: rows removed, deleted count correct', async () => {
    const ids = seedNotes(3);

    const result = await executeForget({
      category: 'note',
      project: PROJECT,
      confirm: true,
      dryRun: false,
      source: OWNER,
    });

    expect(result.success).toBe(true);
    expect(result.deleted).toBe(3);
    expect(result.denied ?? 0).toBe(0);
    expect(result.memories).toHaveLength(3);

    for (const id of ids) {
      expect(getMemoryById(id)).toBeNull();
    }
  });

  it('routes authorised bulk deletes through deleteMemory (persists memory_deleted events)', async () => {
    const ids = seedNotes(2);
    const db = (await import('../database/init.js')).getDatabase();

    const before = (
      db.prepare("SELECT COUNT(*) AS c FROM events WHERE type = 'memory_deleted'").get() as { c: number }
    ).c;

    await executeForget({
      category: 'note',
      project: PROJECT,
      confirm: true,
      dryRun: false,
      source: OWNER,
    });

    const after = (
      db.prepare("SELECT COUNT(*) AS c FROM events WHERE type = 'memory_deleted'").get() as { c: number }
    ).c;

    // One memory_deleted event per actually-deleted row — the same side effect
    // the single-ID path produces, proving deleteMemory() was the path taken
    // (a raw bulk DELETE persists no events).
    expect(after - before).toBe(ids.length);
  });

  it('does not require a source — sourceless bulk delete still works (backwards compatible)', async () => {
    const ids = seedNotes(2);

    const result = await executeForget({ category: 'note', project: PROJECT, confirm: true, dryRun: false });

    expect(result.success).toBe(true);
    expect(result.deleted).toBe(2);
    for (const id of ids) {
      expect(getMemoryById(id)).toBeNull();
    }
  });
});
