/**
 * Phase 0 graph tool + resolution fixes (2026-08-11 graph audit).
 *
 * Pins the verified bugs:
 *  - handleGraphQuery pushed to `connections` BEFORE the visited check, so
 *    every depth-1 edge was re-emitted reversed at depth 2 (the root appeared
 *    as its own depth-2 neighbour once per neighbour) and hub nodes were
 *    emitted once per incident edge. Contract after fix: each entity appears
 *    at most once, at its shallowest depth, and the root never appears.
 *  - entity lookup used LOWER(name) = LOWER(?) — the fix (COLLATE NOCASE)
 *    must keep case-insensitive lookup working.
 *  - resolveEntity's Levenshtein-≤2 fuzzy match silently merged distinct
 *    files ('server.ts' ↔ 'server.js') into one entity + alias.
 *
 * Harness: fresh in-memory DB per test via initDatabase(':memory:').
 */

import { afterEach, beforeEach, describe, expect, it } from '@jest/globals';
import { closeDatabase, getDatabase, initDatabase } from '../database/init.js';
import { handleGraphQuery } from '../tools/graph.js';
import { resolveEntity } from '../graph/resolve.js';
import { backfillGraph } from '../graph/backfill.js';

interface QueryPayload {
  entity?: { id: number; name: string };
  connections?: Array<{ predicate: string; direction: string; depth: number; entity: { id: number; name: string } }>;
  error?: string;
}

function runQuery(args: { entity: string; depth?: number }): QueryPayload {
  const result = handleGraphQuery(args);
  return JSON.parse(result.content[0].text) as QueryPayload;
}

function seedEntity(name: string, type = 'tool'): number {
  const db = getDatabase();
  const r = db.prepare('INSERT INTO entities (name, type) VALUES (?, ?)').run(name, type);
  return Number(r.lastInsertRowid);
}

function seedTriple(subjectId: number, objectId: number, predicate = 'related_to'): void {
  getDatabase()
    .prepare('INSERT INTO triples (subject_id, predicate, object_id) VALUES (?, ?, ?)')
    .run(subjectId, predicate, objectId);
}

beforeEach(() => {
  initDatabase(':memory:');
});

afterEach(() => {
  closeDatabase();
});

describe('handleGraphQuery emission dedup', () => {
  it('never emits the root entity as its own neighbour', () => {
    const a = seedEntity('Alpha');
    const b = seedEntity('Beta');
    const c = seedEntity('Gamma');
    seedTriple(a, b);
    seedTriple(a, c);

    const payload = runQuery({ entity: 'Alpha', depth: 2 });
    const names = (payload.connections ?? []).map(x => x.entity.name);
    expect(names).not.toContain('Alpha');
  });

  it('emits each reachable entity exactly once, at its shallowest depth', () => {
    // Triangle: A→B, A→C, B→C. C is reachable at depth 1 (via A) and depth 2
    // (via B) — it must appear once, at depth 1.
    const a = seedEntity('Alpha');
    const b = seedEntity('Beta');
    const c = seedEntity('Gamma');
    seedTriple(a, b);
    seedTriple(a, c);
    seedTriple(b, c);

    const payload = runQuery({ entity: 'Alpha', depth: 2 });
    const connections = payload.connections ?? [];
    const names = connections.map(x => x.entity.name);

    expect([...names].sort()).toEqual(['Beta', 'Gamma']);
    expect(connections.find(x => x.entity.name === 'Gamma')?.depth).toBe(1);
  });

  it('still finds entities case-insensitively after the lookup change', () => {
    seedEntity('SQLite');
    const payload = runQuery({ entity: 'sqlite' });
    expect(payload.error).toBeUndefined();
    expect(payload.entity?.name).toBe('SQLite');
  });
});

describe('backfill heals historic project-subject triples', () => {
  // v1.13.0–v2.9.x (pre-STOPWORDS) persisted 'project' → prefers/avoids/implements
  // triples. Later releases could neither recreate nor reach them: the per-memory
  // replace never touches triples whose source memory is gone. Backfill must
  // delete them (and the orphaned 'project' hub entity) even when it processes
  // zero memories.
  it('removes prefers/avoids/implements triples and the orphaned project entity', () => {
    const db = getDatabase();
    const project = seedEntity('project', 'concept');
    const pg = seedEntity('PostgreSQL');
    const mysql = seedEntity('MySQL');
    seedTriple(project, pg, 'prefers');
    seedTriple(project, mysql, 'avoids');
    seedTriple(pg, mysql, 'related_to');

    backfillGraph();

    const predicates = db.prepare('SELECT DISTINCT predicate FROM triples').all() as Array<{ predicate: string }>;
    expect(predicates.map(p => p.predicate)).toEqual(['related_to']);
    expect(db.prepare("SELECT id FROM entities WHERE name = 'project'").get()).toBeUndefined();
    expect(db.prepare("SELECT id FROM entities WHERE name = 'PostgreSQL'").get()).toBeDefined();
  });
});

describe('resolveEntity file fuzzy-merge', () => {
  it('keeps files with different extensions distinct (no Levenshtein merge)', () => {
    const tsId = resolveEntity('server.ts', 'file');
    const jsId = resolveEntity('server.js', 'file');
    expect(jsId).not.toBe(tsId);
  });

  it('still fuzzy-merges near-identical non-file names', () => {
    const first = resolveEntity('Kubernetes', 'tool');
    const second = resolveEntity('Kuberneters', 'tool'); // 1 edit away, same type
    expect(second).toBe(first);
  });
});
