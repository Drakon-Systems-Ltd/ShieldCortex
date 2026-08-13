/**
 * Phase E — conflict review nodes must NOT count toward the event-node cap.
 *
 * Conflict nodes reuse kind='event' but are excluded from canonicalDump. If they
 * also counted toward evictEventOverflow, an incremental tick at the cap would
 * evict REAL event nodes to make room for them while a rebuild (which mints
 * conflict nodes after eviction) would not — diverging the determinism dump.
 * They are inherently bounded and re-minted each pass, so they are excluded from
 * both the count and the eviction candidate set.
 */

import { afterEach, beforeEach, describe, expect, it } from '@jest/globals';
import { closeDatabase, getDatabase, initDatabase } from '../database/init.js';
import { evictEventOverflow } from '../threat-graph/shared.js';

beforeEach(() => initDatabase(':memory:'));
afterEach(() => closeDatabase());

function insertNode(kind: string, key: string, lastSeen: string): void {
  getDatabase()
    .prepare(
      `INSERT INTO threat_nodes (kind, key, attrs, first_seen, last_seen)
       VALUES (?, ?, '{}', ?, ?)`,
    )
    .run(kind, key, lastSeen, lastSeen);
}

function count(where: string): number {
  return (getDatabase().prepare(`SELECT COUNT(*) c FROM threat_nodes WHERE ${where}`).get() as { c: number }).c;
}

describe('Phase E — conflict nodes excluded from the event cap', () => {
  it('evicts real event nodes to the cap and never counts or evicts conflict nodes', () => {
    // 5 real event nodes (older) + 2 conflict review nodes (fresher).
    for (let i = 1; i <= 5; i++) insertNode('event', `audit:${i}`, '2026-08-01T00:00:00.000Z');
    insertNode('event', 'conflict:10:uses', '2026-08-12T00:00:00.000Z');
    insertNode('event', 'conflict:11:uses', '2026-08-12T00:00:00.000Z');

    const note = evictEventOverflow(3);

    // Real event nodes trimmed to exactly the cap; conflict nodes untouched.
    expect(count("kind = 'event' AND key NOT LIKE 'conflict:%'")).toBe(3);
    expect(count("key LIKE 'conflict:%'")).toBe(2);
    expect(note).toMatch(/evicted 2/); // 5 real - cap 3, NOT 4 (which would include the 2 conflicts)
  });

  it('does not evict anything when only conflict nodes exceed the cap', () => {
    insertNode('event', 'audit:1', '2026-08-01T00:00:00.000Z');
    for (let i = 0; i < 10; i++) insertNode('event', `conflict:${i}:uses`, '2026-08-12T00:00:00.000Z');
    // 1 real event node, cap 3 → real count (1) <= cap → no eviction despite 11 total 'event' rows.
    expect(evictEventOverflow(3)).toBeNull();
    expect(count("key LIKE 'conflict:%'")).toBe(10);
    expect(count("kind = 'event' AND key NOT LIKE 'conflict:%'")).toBe(1);
  });
});
