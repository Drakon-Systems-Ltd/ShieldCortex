/**
 * Phase E — operator resolution of relation-channel conflicts.
 *
 * Every resolution is an operation='review' audit row (the truth; a rebuild
 * replays it) applied immediately for operator UX:
 *   - keep one   → valid_to on the losers, kept stays open, disputes clear
 *   - reject both → valid_to on all contenders
 *   - keep both   → nothing suspended; the audit row's covered set suppresses
 *                   re-flagging until a NEW contender arrives outside it
 * Neither edge is ever auto-suspended by the projector — only the operator
 * suspends, and only narrowly.
 */

import { afterEach, beforeEach, describe, expect, it } from '@jest/globals';
import { closeDatabase, getDatabase, initDatabase } from '../database/init.js';
import { detectRelationConflicts, resolveConflict } from '../threat-graph/conflict.js';
import { projectToCompletion, rebuildThreatGraph } from '../threat-graph/projector.js';

beforeEach(() => initDatabase(':memory:'));
afterEach(() => closeDatabase());

function entity(name: string): number {
  return Number(getDatabase().prepare("INSERT INTO entities (name, type) VALUES (?, 'tool')").run(name).lastInsertRowid);
}

function triple(subject: number, predicate: string, object: number, source: string, trust: number): number {
  return Number(
    getDatabase()
      .prepare(
        `INSERT INTO triples (subject_id, predicate, object_id, confidence, valid_from, writer_source, writer_trust)
         VALUES (?, ?, ?, 0.8, '2026-08-12T00:00:00.000Z', ?, ?)`,
      )
      .run(subject, predicate, object, source, trust).lastInsertRowid,
  );
}

function row(id: number): { disputed: number; valid_to: string | null } {
  return getDatabase().prepare('SELECT disputed, valid_to FROM triples WHERE id = ?').get(id) as {
    disputed: number;
    valid_to: string | null;
  };
}

function conflictNodeCount(): number {
  return (getDatabase()
    .prepare("SELECT COUNT(*) c FROM threat_nodes WHERE kind = 'event' AND key LIKE 'conflict:%'")
    .get() as { c: number }).c;
}

function reviewRows(): Array<{ reason: string }> {
  return getDatabase()
    .prepare("SELECT reason FROM defence_audit WHERE operation = 'review' ORDER BY id ASC")
    .all() as Array<{ reason: string }>;
}

const NOW = Date.parse('2026-08-12T12:00:00.000Z');

describe('Phase E — conflict resolution', () => {
  it('keep_one suspends the losers, keeps the chosen edge, records a review row', () => {
    const a = entity('deploy');
    const good = entity('good');
    const evil = entity('evil');
    const tGood = triple(a, 'uses', good, 'cli:m', 0.95);
    const tEvil = triple(a, 'uses', evil, 'agent:x', 0.3);
    detectRelationConflicts({ nowMs: NOW });
    expect(conflictNodeCount()).toBe(1);

    const res = resolveConflict({ subjectId: a, predicate: 'uses', resolution: 'keep_one', keptObjectId: good }, 'michael', { nowMs: NOW + 1000 });

    expect(res.suspended).toBe(1);
    expect(row(tGood).valid_to).toBeNull();
    expect(row(tGood).disputed).toBe(0);
    expect(row(tEvil).valid_to).toBeTruthy(); // loser suspended
    expect(conflictNodeCount()).toBe(0);
    expect(reviewRows()).toHaveLength(1);

    // A fresh detection pass keeps it resolved (1 open object → no conflict).
    const again = detectRelationConflicts({ nowMs: NOW + 2000 });
    expect(again.conflicts).toBe(0);
    expect(conflictNodeCount()).toBe(0);
  });

  it('reject_both suspends every contender', () => {
    const a = entity('svc');
    const b = entity('b');
    const c = entity('c');
    const tb = triple(a, 'uses', b, 'cli:m', 0.95);
    const tc = triple(a, 'uses', c, 'agent:x', 0.2);
    detectRelationConflicts({ nowMs: NOW });

    const res = resolveConflict({ subjectId: a, predicate: 'uses', resolution: 'reject_both' }, 'michael', { nowMs: NOW + 1000 });

    expect(res.suspended).toBe(2);
    expect(row(tb).valid_to).toBeTruthy();
    expect(row(tc).valid_to).toBeTruthy();
    expect(detectRelationConflicts({ nowMs: NOW + 2000 }).conflicts).toBe(0);
  });

  it('keep_both leaves both open and suppresses re-flagging', () => {
    const a = entity('react');
    const ts = entity('ts');
    const js = entity('js');
    const t1 = triple(a, 'uses', ts, 'cli:m', 0.95);
    const t2 = triple(a, 'uses', js, 'agent:x', 0.3);
    detectRelationConflicts({ nowMs: NOW });
    expect(conflictNodeCount()).toBe(1);

    const res = resolveConflict({ subjectId: a, predicate: 'uses', resolution: 'keep_both' }, 'michael', { nowMs: NOW + 1000 });
    expect(res.suspended).toBe(0);
    expect(row(t1).valid_to).toBeNull();
    expect(row(t2).valid_to).toBeNull();
    expect(row(t1).disputed).toBe(0);

    // Re-detection respects the standing keep_both — no re-flag.
    const again = detectRelationConflicts({ nowMs: NOW + 2000 });
    expect(again.conflicts).toBe(0);
    expect(row(t1).disputed).toBe(0);
    expect(conflictNodeCount()).toBe(0);
  });

  it('keep_both re-opens when a NEW contender arrives outside the covered set', () => {
    const a = entity('react2');
    const ts = entity('ts2');
    const js = entity('js2');
    triple(a, 'uses', ts, 'cli:m', 0.95);
    triple(a, 'uses', js, 'agent:x', 0.3);
    detectRelationConflicts({ nowMs: NOW });
    resolveConflict({ subjectId: a, predicate: 'uses', resolution: 'keep_both' }, 'michael', { nowMs: NOW + 1000 });
    expect(detectRelationConflicts({ nowMs: NOW + 2000 }).conflicts).toBe(0);

    // A new, low-trust contender appears — not covered by the keep_both.
    const evil = entity('evil2');
    triple(a, 'uses', evil, 'agent:z', 0.2);
    const reopened = detectRelationConflicts({ nowMs: NOW + 3000 });
    expect(reopened.conflicts).toBe(1);
    expect(conflictNodeCount()).toBe(1);
  });

  it('a keep_both resolution survives a full rebuild (ledger is truth)', () => {
    const a = entity('react3');
    const ts = entity('ts3');
    const js = entity('js3');
    const t1 = triple(a, 'uses', ts, 'cli:m', 0.95);
    triple(a, 'uses', js, 'agent:x', 0.3);
    detectRelationConflicts({ nowMs: NOW });
    resolveConflict({ subjectId: a, predicate: 'uses', resolution: 'keep_both' }, 'michael', { nowMs: NOW + 1000 });

    // Rebuild wipes the derived graph + resets disputed, then re-derives from the
    // ledger — the keep_both audit row must still suppress the conflict.
    rebuildThreatGraph();
    expect(conflictNodeCount()).toBe(0);
    expect(row(t1).disputed).toBe(0);
  });

  it('a keep_one suspension survives a rebuild (valid_to is an operator fact)', () => {
    const a = entity('deploy4');
    const good = entity('good4');
    const evil = entity('evil4');
    const tGood = triple(a, 'uses', good, 'cli:m', 0.95);
    const tEvil = triple(a, 'uses', evil, 'agent:x', 0.3);
    detectRelationConflicts({ nowMs: NOW });
    resolveConflict({ subjectId: a, predicate: 'uses', resolution: 'keep_one', keptObjectId: good }, 'michael', { nowMs: NOW + 1000 });

    rebuildThreatGraph();
    expect(row(tEvil).valid_to).toBeTruthy(); // still suspended
    expect(row(tGood).valid_to).toBeNull();
    expect(conflictNodeCount()).toBe(0);
  });

  it('the projector skips a conflict_resolution review row without error', () => {
    const a = entity('svc9');
    triple(a, 'uses', entity('b9'), 'cli:m', 0.95);
    triple(a, 'uses', entity('c9'), 'agent:x', 0.2);
    detectRelationConflicts({ nowMs: NOW });
    resolveConflict({ subjectId: a, predicate: 'uses', resolution: 'keep_both' }, 'michael', { nowMs: NOW + 1000 });

    // The projector reads operation='review' rows; a conflict_resolution payload
    // is not a risk_reset/quarantine_decision and must be a harmless no-op.
    const result = projectToCompletion();
    expect(result.errors).toEqual([]);
  });

  it('re-suspends a keep_one loser resurrected by a memory edit (re-extraction)', () => {
    const a = entity('deploy-re');
    const good = entity('good-re');
    const evil = entity('evil-re');
    triple(a, 'uses', good, 'cli:m', 0.95);
    const tEvil = triple(a, 'uses', evil, 'agent:x', 0.3);
    detectRelationConflicts({ nowMs: NOW });
    resolveConflict({ subjectId: a, predicate: 'uses', resolution: 'keep_one', keptObjectId: good }, 'michael', { nowMs: NOW + 1000 });
    expect(row(tEvil).valid_to).toBeTruthy();

    // Simulate updateMemory/mergeMemories re-extraction: the loser's triple is
    // deleted and re-inserted fresh (valid_to NULL, disputed 0).
    getDatabase().prepare('DELETE FROM triples WHERE id = ?').run(tEvil);
    const tEvil2 = triple(a, 'uses', evil, 'agent:x', 0.3);
    expect(row(tEvil2).valid_to).toBeNull();

    // The next detection pass replays the operator's keep_one from the ledger
    // and re-suspends the resurrected loser — no conflict re-raised.
    const again = detectRelationConflicts({ nowMs: NOW + 2000 });
    expect(again.conflicts).toBe(0);
    expect(row(tEvil2).valid_to).toBeTruthy();
    expect(conflictNodeCount()).toBe(0);
  });

  it('re-suspends every reject_both contender after re-extraction', () => {
    const a = entity('svc-rb');
    const b = entity('b-rb');
    const c = entity('c-rb');
    const tb = triple(a, 'uses', b, 'cli:m', 0.95);
    triple(a, 'uses', c, 'agent:x', 0.2);
    detectRelationConflicts({ nowMs: NOW });
    resolveConflict({ subjectId: a, predicate: 'uses', resolution: 'reject_both' }, 'michael', { nowMs: NOW + 1000 });

    // Re-extract one contender.
    getDatabase().prepare('DELETE FROM triples WHERE id = ?').run(tb);
    const tb2 = triple(a, 'uses', b, 'cli:m', 0.95);

    detectRelationConflicts({ nowMs: NOW + 2000 });
    expect(row(tb2).valid_to).toBeTruthy(); // re-suspended by replay
  });

  it('#305: the resolution review row carries host-derived identity; operator is annotation only', () => {
    const a = entity('deploy-305');
    const good = entity('good-305');
    const evil = entity('evil-305');
    triple(a, 'uses', good, 'cli:m', 0.95);
    triple(a, 'uses', evil, 'agent:x', 0.3);
    detectRelationConflicts({ nowMs: NOW });
    resolveConflict({ subjectId: a, predicate: 'uses', resolution: 'keep_both' }, 'victim-name', { nowMs: NOW + 1000 });

    const audit = getDatabase().prepare(
      "SELECT source_type, source_identifier, reason FROM defence_audit WHERE operation = 'review' ORDER BY id DESC LIMIT 1",
    ).get() as { source_type: string; source_identifier: string; reason: string };
    expect(audit.source_type).not.toBe('user');
    expect(audit.source_identifier).not.toBe('victim-name');
    expect((JSON.parse(audit.reason) as { reviewed_by?: string }).reviewed_by).toBe('victim-name');
  });

  it('keep_one rejects a kept object that is not on the channel', () => {
    const a = entity('svc3');
    const b = entity('b3');
    const c = entity('c3');
    triple(a, 'uses', b, 'cli:m', 0.95);
    triple(a, 'uses', c, 'agent:x', 0.2);
    detectRelationConflicts({ nowMs: NOW });
    const bogus = entity('nowhere');
    expect(() =>
      resolveConflict({ subjectId: a, predicate: 'uses', resolution: 'keep_one', keptObjectId: bogus }, 'michael', { nowMs: NOW + 1000 }),
    ).toThrow();
  });
});
