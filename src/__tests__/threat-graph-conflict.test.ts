/**
 * Phase E — relation-channel conflict detection (the ShadowMerge defence).
 *
 * A single-valued relation channel (subject + predicate, one of
 * uses/depends_on/configures/replaces) that holds ≥2 distinct open objects
 * whose writers differ in trust by ≥0.3 is a conflict: BOTH triples are flagged
 * `disputed`, NEITHER is suspended (symmetric resolution), and one `conflict`
 * event node is minted as the operator review item. Close-trust disagreements
 * are left as benign multi-value coexistence; `related_to` is never a channel.
 * `user:approved` provenance can never be crowned the authoritative side.
 */

import { afterEach, beforeEach, describe, expect, it } from '@jest/globals';
import { closeDatabase, getDatabase, initDatabase } from '../database/init.js';
import { detectRelationConflicts } from '../threat-graph/conflict.js';

beforeEach(() => initDatabase(':memory:'));
afterEach(() => closeDatabase());

let entitySeq = 0;
function entity(name: string): number {
  const db = getDatabase();
  const r = db.prepare("INSERT INTO entities (name, type) VALUES (?, 'tool')").run(name);
  entitySeq++;
  return Number(r.lastInsertRowid);
}

interface TripleSeed {
  subject: number;
  predicate: string;
  object: number;
  writerSource?: string | null;
  writerTrust?: number | null;
  validTo?: string | null;
}

function triple(seed: TripleSeed): number {
  const db = getDatabase();
  const r = db
    .prepare(
      `INSERT INTO triples
         (subject_id, predicate, object_id, source_memory_id, confidence,
          valid_from, valid_to, writer_source, writer_trust)
       VALUES (?, ?, ?, NULL, 0.8, '2026-08-12T00:00:00.000Z', ?, ?, ?)`,
    )
    .run(
      seed.subject,
      seed.predicate,
      seed.object,
      seed.validTo ?? null,
      seed.writerSource ?? null,
      seed.writerTrust ?? null,
    );
  return Number(r.lastInsertRowid);
}

function tripleDisputed(id: number): number {
  return (getDatabase().prepare('SELECT disputed FROM triples WHERE id = ?').get(id) as { disputed: number })
    .disputed;
}

function tripleValidTo(id: number): string | null {
  return (getDatabase().prepare('SELECT valid_to FROM triples WHERE id = ?').get(id) as { valid_to: string | null })
    .valid_to;
}

function conflictNodes() {
  return getDatabase()
    .prepare("SELECT key, attrs FROM threat_nodes WHERE kind = 'event' AND key LIKE 'conflict:%'")
    .all() as Array<{ key: string; attrs: string }>;
}

const NOW = Date.parse('2026-08-12T12:00:00.000Z');

describe('Phase E — relation-channel conflict detection', () => {
  it('flags a trust-asymmetric single-valued conflict on both edges', () => {
    const a = entity('deploy');
    const good = entity('good-server');
    const evil = entity('evil-server');
    const t1 = triple({ subject: a, predicate: 'uses', object: good, writerSource: 'cli:michael', writerTrust: 0.95 });
    const t2 = triple({ subject: a, predicate: 'uses', object: evil, writerSource: 'agent:x', writerTrust: 0.3 });

    const res = detectRelationConflicts({ nowMs: NOW });

    expect(res.conflicts).toBe(1);
    expect(tripleDisputed(t1)).toBe(1);
    expect(tripleDisputed(t2)).toBe(1);
    // Symmetric — NEITHER edge is suspended.
    expect(tripleValidTo(t1)).toBeNull();
    expect(tripleValidTo(t2)).toBeNull();

    const nodes = conflictNodes();
    expect(nodes).toHaveLength(1);
    expect(nodes[0].key).toBe(`conflict:${a}:uses`);
    const attrs = JSON.parse(nodes[0].attrs);
    expect(attrs.status).toBe('open');
    expect(attrs.contenders).toHaveLength(2);
  });

  it('does NOT flag a close-trust disagreement (benign multi-value)', () => {
    const a = entity('react');
    const ts = entity('typescript');
    const js = entity('javascript');
    const t1 = triple({ subject: a, predicate: 'uses', object: ts, writerSource: 'agent:x', writerTrust: 0.5 });
    const t2 = triple({ subject: a, predicate: 'uses', object: js, writerSource: 'agent:y', writerTrust: 0.5 });

    const res = detectRelationConflicts({ nowMs: NOW });

    expect(res.conflicts).toBe(0);
    expect(tripleDisputed(t1)).toBe(0);
    expect(tripleDisputed(t2)).toBe(0);
    expect(conflictNodes()).toHaveLength(0);
  });

  it('never treats related_to as a conflict channel', () => {
    const a = entity('project');
    const b = entity('redis');
    const c = entity('docker');
    const t1 = triple({ subject: a, predicate: 'related_to', object: b, writerSource: 'cli:m', writerTrust: 0.95 });
    const t2 = triple({ subject: a, predicate: 'related_to', object: c, writerSource: 'agent:x', writerTrust: 0.2 });

    const res = detectRelationConflicts({ nowMs: NOW });

    expect(res.conflicts).toBe(0);
    expect(tripleDisputed(t1)).toBe(0);
    expect(tripleDisputed(t2)).toBe(0);
  });

  it('does not conflate different predicates on the same subject', () => {
    const a = entity('api');
    const b = entity('postgres');
    const c = entity('redis');
    triple({ subject: a, predicate: 'uses', object: b, writerSource: 'cli:m', writerTrust: 0.95 });
    triple({ subject: a, predicate: 'depends_on', object: c, writerSource: 'agent:x', writerTrust: 0.2 });

    const res = detectRelationConflicts({ nowMs: NOW });
    expect(res.conflicts).toBe(0);
  });

  it('disqualifies user:approved from being the authoritative side', () => {
    const a = entity('deploy2');
    const poison = entity('poison-host');
    const legit = entity('legit-host');
    // user:approved carries the higher raw trust, but approval must not crown facts.
    triple({ subject: a, predicate: 'uses', object: poison, writerSource: 'user:approved', writerTrust: 0.7 });
    triple({ subject: a, predicate: 'uses', object: legit, writerSource: 'agent:x', writerTrust: 0.3 });

    const res = detectRelationConflicts({ nowMs: NOW });
    expect(res.conflicts).toBe(1);
    const attrs = JSON.parse(conflictNodes()[0].attrs);
    // Authoritative side is the non-approved contender (or null), never the poison.
    expect(attrs.authoritative_object_id).not.toBe(poison);
  });

  it('is idempotent — a second pass changes nothing', () => {
    const a = entity('svc');
    const b = entity('b');
    const c = entity('c');
    triple({ subject: a, predicate: 'configures', object: b, writerSource: 'cli:m', writerTrust: 0.95 });
    triple({ subject: a, predicate: 'configures', object: c, writerSource: 'agent:x', writerTrust: 0.2 });

    const first = detectRelationConflicts({ nowMs: NOW });
    const second = detectRelationConflicts({ nowMs: NOW + 1000 });

    expect(first.conflicts).toBe(1);
    expect(second.conflicts).toBe(1);
    expect(conflictNodes()).toHaveLength(1);
  });

  it('clears a dispute + stale conflict node when a contender is suspended away', () => {
    const a = entity('svc2');
    const b = entity('b2');
    const c = entity('c2');
    const t1 = triple({ subject: a, predicate: 'uses', object: b, writerSource: 'cli:m', writerTrust: 0.95 });
    const t2 = triple({ subject: a, predicate: 'uses', object: c, writerSource: 'agent:x', writerTrust: 0.2 });

    detectRelationConflicts({ nowMs: NOW });
    expect(conflictNodes()).toHaveLength(1);

    // Operator suspends t2 (valid_to). Channel now has one open object → resolved.
    getDatabase().prepare("UPDATE triples SET valid_to = '2026-08-12T13:00:00.000Z' WHERE id = ?").run(t2);
    const res = detectRelationConflicts({ nowMs: NOW + 2000 });

    expect(res.conflicts).toBe(0);
    expect(tripleDisputed(t1)).toBe(0);
    expect(conflictNodes()).toHaveLength(0);
  });
});
