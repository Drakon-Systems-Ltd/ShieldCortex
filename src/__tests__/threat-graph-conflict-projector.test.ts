/**
 * Phase E — conflict detection wired into the projector lease runner + rebuild.
 *
 *  - the throttled lease pass flags conflicts and mints review nodes;
 *  - `conflictDetection: false` skips it (test seam);
 *  - a rebuild resets `disputed` (clearGraph) and re-derives it from the triples;
 *  - conflict review nodes are EXCLUDED from the canonicalDump determinism
 *    contract, so incremental and rebuilt dumps still match.
 */

import { afterEach, beforeEach, describe, expect, it } from '@jest/globals';
import { closeDatabase, getDatabase, initDatabase } from '../database/init.js';
import { canonicalDump, rebuildThreatGraph, runProjectorWithLease } from '../threat-graph/projector.js';

beforeEach(() => initDatabase(':memory:'));
afterEach(() => closeDatabase());

function entity(name: string): number {
  return Number(getDatabase().prepare("INSERT INTO entities (name, type) VALUES (?, 'tool')").run(name).lastInsertRowid);
}
function triple(subject: number, object: number, source: string, trust: number): void {
  getDatabase()
    .prepare(
      `INSERT INTO triples (subject_id, predicate, object_id, confidence, valid_from, writer_source, writer_trust)
       VALUES (?, 'uses', ?, 0.8, '2026-08-12T00:00:00.000Z', ?, ?)`,
    )
    .run(subject, object, source, trust);
}
function seedConflict(): void {
  const a = entity('deploy');
  triple(a, entity('good'), 'cli:michael', 0.95);
  triple(a, entity('evil'), 'agent:x', 0.3);
}
function disputedCount(): number {
  return (getDatabase().prepare('SELECT COUNT(*) c FROM triples WHERE disputed = 1').get() as { c: number }).c;
}
function conflictNodeCount(): number {
  return (getDatabase()
    .prepare("SELECT COUNT(*) c FROM threat_nodes WHERE kind = 'event' AND key LIKE 'conflict:%'")
    .get() as { c: number }).c;
}

const T0 = Date.parse('2026-08-12T12:00:00.000Z');

describe('Phase E — projector integration', () => {
  it('the lease pass detects conflicts and mints a review node', async () => {
    seedConflict();
    await runProjectorWithLease({ now: T0 });
    expect(disputedCount()).toBe(2);
    expect(conflictNodeCount()).toBe(1);
  });

  it('conflictDetection:false skips the pass', async () => {
    seedConflict();
    await runProjectorWithLease({ now: T0, conflictDetection: false });
    expect(disputedCount()).toBe(0);
    expect(conflictNodeCount()).toBe(0);
  });

  it('a rebuild resets disputed (clearGraph) and re-derives it', async () => {
    seedConflict();
    await runProjectorWithLease({ now: T0 });
    expect(disputedCount()).toBe(2);

    rebuildThreatGraph();
    // clearGraph zeroed disputed, then the rebuild re-derived it.
    expect(disputedCount()).toBe(2);
    expect(conflictNodeCount()).toBe(1);
  });

  it('conflict review nodes are excluded from the determinism dump', async () => {
    seedConflict();
    const before = canonicalDump();
    await runProjectorWithLease({ now: T0 });
    // Minting the conflict node does not change the canonical dump...
    expect(canonicalDump()).toBe(before);
    // ...and a rebuild still matches.
    rebuildThreatGraph();
    expect(canonicalDump()).toBe(before);
  });
});
