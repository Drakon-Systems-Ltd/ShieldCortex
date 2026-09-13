/**
 * Dashboard v2 graph endpoints (docs/design/2026-09-13-dashboard-v2-ux.md
 * §6.4, §13.2–13.3): bounded overview payload, capped neighbourhood with
 * memories + all three edge families, ID-based paths with direction, project
 * scoping, strict query-param clamping, suspended-edge exclusion everywhere.
 */

import { afterEach, beforeEach, describe, expect, it } from '@jest/globals';
import { closeDatabase, getDatabase, initDatabase } from '../database/init.js';
import type { Request, Response } from 'express';
import { registerGraphRoutes } from '../api/routes/graph.js';

beforeEach(() => initDatabase(':memory:'));
afterEach(() => closeDatabase());

function entity(name: string, type = 'tool', memoryCount = 0): number {
  return Number(
    getDatabase()
      .prepare('INSERT INTO entities (name, type, memory_count) VALUES (?, ?, ?)')
      .run(name, type, memoryCount).lastInsertRowid,
  );
}

function triple(
  subject: number,
  predicate: string,
  object: number,
  opts: { validTo?: string; createdAt?: string; disputed?: number } = {},
): number {
  return Number(
    getDatabase()
      .prepare(
        `INSERT INTO triples (subject_id, predicate, object_id, confidence, created_at, valid_from, valid_to, disputed)
         VALUES (?, ?, ?, 0.8, ?, '2026-08-12T00:00:00.000Z', ?, ?)`,
      )
      .run(subject, predicate, object, opts.createdAt ?? '2026-08-12 00:00:00', opts.validTo ?? null, opts.disputed ?? 0)
      .lastInsertRowid,
  );
}

function memory(title: string, opts: { project?: string | null; salience?: number; sensitivity?: string } = {}): number {
  return Number(
    getDatabase()
      .prepare(
        `INSERT INTO memories (uuid, type, category, title, content, project, salience, sensitivity_level)
         VALUES (?, 'long_term', 'note', ?, 'fixture-content', ?, ?, ?)`,
      )
      .run(`uuid-${title}`, title, opts.project ?? null, opts.salience ?? 0.5, opts.sensitivity ?? 'INTERNAL')
      .lastInsertRowid,
  );
}

function mention(memoryId: number, entityId: number, role = 'mention'): void {
  getDatabase()
    .prepare('INSERT INTO memory_entities (memory_id, entity_id, role) VALUES (?, ?, ?)')
    .run(memoryId, entityId, role);
}

function link(source: number, target: number, relationship: string, strength = 0.7): void {
  getDatabase()
    .prepare('INSERT INTO memory_links (source_id, target_id, relationship, strength) VALUES (?, ?, ?, ?)')
    .run(source, target, relationship, strength);
}

type Handler = (req: Request, res: Response, next: (err?: unknown) => void) => unknown;

function captureRoutes() {
  const routes = new Map<string, Handler[]>();
  return {
    get(path: string, ...handlers: Handler[]) {
      routes.set(`GET ${path}`, handlers);
    },
    handler(path: string) {
      const handlers = routes.get(`GET ${path}`);
      if (!handlers) throw new Error(`no handler for ${path}`);
      return handlers;
    },
  };
}

async function invoke(handlers: Handler[], params: Record<string, string>, query: Record<string, string> = {}) {
  let statusCode = 200;
  let body: unknown;
  const req = { params, query } as unknown as Request;
  const res = {
    status(code: number) {
      statusCode = code;
      return this;
    },
    json(payload: unknown) {
      body = payload;
      return this;
    },
  } as unknown as Response;
  for (const h of handlers) {
    await h(req, res, () => undefined);
  }
  return { statusCode, body };
}

function app() {
  const a = captureRoutes();
  registerGraphRoutes(a as never, (_req, _res, next) => next());
  return a;
}

interface OverviewBody {
  entities: Array<{ id: number; name: string; type: string; memoryCount: number }>;
  triples: Array<{ subjectId: number; objectId: number; predicate: string; confidence: number; disputed: boolean }>;
  counts: {
    byType: Record<string, number>;
    byPredicate: Record<string, number>;
    totalEntities: number;
    totalEdges: number;
    omittedEntities: number;
    omittedEdges: number;
  };
}

describe('GET /api/graph/overview', () => {
  it('returns bounded entities + only edges with BOTH endpoints present, excluding suspended', async () => {
    const a = entity('alpha', 'tool', 30);
    const b = entity('beta', 'concept', 20);
    const c = entity('gamma', 'tool', 10);
    const outside = entity('outside', 'tool', 1);
    triple(a, 'uses', b);
    triple(b, 'part_of', c);
    triple(a, 'uses', outside); // endpoint below the cut when limit=3? outside has count 1
    const susp = triple(a, 'depends_on', c, { validTo: '2026-09-01T00:00:00.000Z' });
    expect(susp).toBeGreaterThan(0);

    const r = await invoke(app().handler('/api/graph/overview'), {}, { limit: '3', minMentions: '2' });
    expect(r.statusCode).toBe(200);
    const body = r.body as OverviewBody;
    expect(body.entities.map((e) => e.name)).toEqual(['alpha', 'beta', 'gamma']);
    // outside (memory_count 1) is under minMentions=2 → its edge must vanish
    // (both-endpoints rule), and the suspended a→c edge must vanish too.
    expect(body.triples).toHaveLength(2);
    expect(body.triples.map((t) => t.predicate).sort()).toEqual(['part_of', 'uses']);
    expect(body.counts.totalEntities).toBe(3);
    expect(body.counts.omittedEntities).toBe(0);
    expect(body.counts.byType).toEqual({ tool: 2, concept: 1 });
  });

  it('reports truncation counts when the entity cap bites', async () => {
    for (let i = 0; i < 6; i++) entity(`e${i}`, 'tool', 10 - i);
    const r = await invoke(app().handler('/api/graph/overview'), {}, { limit: '2', minMentions: '1' });
    const body = r.body as OverviewBody;
    expect(body.entities).toHaveLength(2);
    expect(body.counts.totalEntities).toBe(6);
    expect(body.counts.omittedEntities).toBe(4);
  });

  it('clamps hostile query params (NaN, negative, float) instead of passing them to SQLite', async () => {
    entity('solo', 'tool', 5);
    for (const bad of [{ limit: 'NaN' }, { limit: '-5' }, { limit: '2.5' }, { minMentions: '-1' }, { limit: '1e3' }]) {
      const r = await invoke(app().handler('/api/graph/overview'), {}, bad as Record<string, string>);
      expect(r.statusCode).toBe(200);
      expect((r.body as OverviewBody).entities.length).toBeGreaterThanOrEqual(0);
    }
  });

  it('scopes entities and edges by project via memory links', async () => {
    const a = entity('proj-a', 'tool', 5);
    const b = entity('proj-b', 'tool', 4);
    const other = entity('other-proj', 'tool', 9);
    const m1 = memory('m1', { project: 'atlas' });
    const m2 = memory('m2', { project: 'atlas' });
    const m3 = memory('m3', { project: 'zephyr' });
    mention(m1, a);
    mention(m2, b);
    mention(m3, other);
    triple(a, 'uses', b);
    triple(a, 'uses', other);

    const r = await invoke(app().handler('/api/graph/overview'), {}, { project: 'atlas', minMentions: '1' });
    const body = r.body as OverviewBody;
    expect(body.entities.map((e) => e.name).sort()).toEqual(['proj-a', 'proj-b']);
    // a→other crosses out of scope: both-endpoints rule drops it.
    expect(body.triples).toHaveLength(1);
  });
});

interface NeighbourhoodBody {
  focal: { id: number; name: string };
  neighbours: Array<{ id: number; name: string; depth: number; memoryCount: number }>;
  triples: Array<{ subject_id: number; object_id: number; predicate: string; disputed: boolean }>;
  memories?: Array<{ id: number; title: string; content?: unknown }>;
  memoryEntities?: Array<{ memory_id: number; entity_id: number; role: string }>;
  memoryLinks?: Array<{ source_id: number; target_id: number; relationship: string; strength: number }>;
  counts: {
    totalNeighbours: number;
    omittedNeighbours: number;
    totalMemories: number;
    omittedMemories: number;
  };
}

describe('GET /api/graph/entities/:id/neighbourhood (v2)', () => {
  it('caps ALL neighbours (meaningful ones first), not just related_to', async () => {
    const focal = entity('focal', 'tool', 50);
    // 5 meaningful neighbours with descending prominence, 2 related_to.
    const meaningful = Array.from({ length: 5 }, (_, i) => entity(`mean-${i}`, 'tool', 40 - i));
    const weak = Array.from({ length: 2 }, (_, i) => entity(`weak-${i}`, 'tool', 5 - i));
    for (const m of meaningful) triple(focal, 'uses', m);
    for (const w of weak) triple(focal, 'related_to', w);

    const r = await invoke(app().handler('/api/graph/entities/:id/neighbourhood'), { id: String(focal) }, { limit: '3' });
    expect(r.statusCode).toBe(200);
    const body = r.body as NeighbourhoodBody;
    expect(body.neighbours).toHaveLength(3);
    expect(body.neighbours.map((n) => n.name)).toEqual(['mean-0', 'mean-1', 'mean-2']);
    expect(body.counts.totalNeighbours).toBe(7);
    expect(body.counts.omittedNeighbours).toBe(4);
  });

  it('depth=2 expands within the same node budget with stable depth labels', async () => {
    const focal = entity('f2', 'tool', 50);
    const ring1 = entity('ring1', 'tool', 40);
    const ring2 = entity('ring2', 'tool', 30);
    triple(focal, 'uses', ring1);
    triple(ring1, 'uses', ring2);

    const r1 = await invoke(app().handler('/api/graph/entities/:id/neighbourhood'), { id: String(focal) }, { depth: '1' });
    expect((r1.body as NeighbourhoodBody).neighbours.map((n) => n.name)).toEqual(['ring1']);

    const r2 = await invoke(app().handler('/api/graph/entities/:id/neighbourhood'), { id: String(focal) }, { depth: '2' });
    const body2 = r2.body as NeighbourhoodBody;
    expect(body2.neighbours.map((n) => [n.name, n.depth])).toEqual([
      ['ring1', 1],
      ['ring2', 2],
    ]);
    // The ring1→ring2 triple is drawable because both endpoints are included.
    expect(body2.triples).toHaveLength(2);
  });

  it('includeMemories returns capped focal memories, memory→entity edges and memory↔memory links — metadata only', async () => {
    const focal = entity('memfocal', 'tool', 10);
    const other = entity('memother', 'tool', 8);
    triple(focal, 'uses', other);
    const m1 = memory('high', { salience: 0.9 });
    const m2 = memory('mid', { salience: 0.5 });
    const m3 = memory('low', { salience: 0.1 });
    mention(m1, focal, 'subject');
    mention(m2, focal);
    mention(m3, focal);
    mention(m1, other);
    link(m1, m2, 'conflicts', 0.9);
    link(m2, m3, 'supports', 0.4);

    const r = await invoke(
      app().handler('/api/graph/entities/:id/neighbourhood'),
      { id: String(focal) },
      { includeMemories: '1', memLimit: '2' },
    );
    const body = r.body as NeighbourhoodBody;
    expect(body.memories?.map((m) => m.title)).toEqual(['high', 'mid']);
    expect(body.counts.totalMemories).toBe(3);
    expect(body.counts.omittedMemories).toBe(1);
    // No memory content in graph payloads.
    for (const m of body.memories ?? []) expect(m).not.toHaveProperty('content');
    // m1 mentions focal AND other (both in node set) → 3 edges total.
    expect(body.memoryEntities).toHaveLength(3);
    expect(body.memoryEntities?.find((me) => me.role === 'subject')).toBeTruthy();
    // Only the link among LOADED memories (m1–m2) appears; m2–m3 is out (m3 cut).
    expect(body.memoryLinks).toHaveLength(1);
    expect(body.memoryLinks?.[0]).toMatchObject({ relationship: 'conflicts', strength: 0.9 });
  });

  it('marks disputed triples and never returns suspended ones', async () => {
    const focal = entity('dfocal', 'tool', 10);
    const okN = entity('dok', 'tool', 9);
    const suspN = entity('dsusp', 'tool', 8);
    triple(focal, 'uses', okN, { disputed: 1 });
    triple(focal, 'uses', suspN, { validTo: '2026-09-01T00:00:00.000Z' });

    const r = await invoke(app().handler('/api/graph/entities/:id/neighbourhood'), { id: String(focal) }, {});
    const body = r.body as NeighbourhoodBody;
    expect(body.neighbours.map((n) => n.name)).toEqual(['dok']);
    expect(body.triples).toHaveLength(1);
    expect(body.triples[0].disputed).toBe(true);
  });
});

interface PathBody {
  path: Array<{ entity: string; entityId: number; predicate: string; direction: string }>;
  sourceMemories: unknown[];
  message?: string;
}

describe('GET /api/graph/paths (v2)', () => {
  it('resolves numeric fromId/toId and labels hop direction honestly', async () => {
    const a = entity('pa');
    const b = entity('pb');
    const c = entity('pc');
    triple(a, 'uses', b);
    triple(c, 'monitors', b); // reverse hop b→c

    const r = await invoke(app().handler('/api/graph/paths'), {}, { fromId: String(a), toId: String(c) });
    expect(r.statusCode).toBe(200);
    const body = r.body as PathBody;
    expect(body.path.map((h) => h.entityId)).toEqual([a, b, c]);
    expect(body.path[1]).toMatchObject({ predicate: 'uses', direction: 'forward' });
    // Legacy field keeps ~; direction carries the truth.
    expect(body.path[2]).toMatchObject({ predicate: '~monitors', direction: 'reverse' });
  });

  it('still accepts legacy name params and rejects garbage ids', async () => {
    const a = entity('legacy-from');
    const b = entity('legacy-to');
    triple(a, 'uses', b);

    const ok = await invoke(app().handler('/api/graph/paths'), {}, { from: 'legacy-from', to: 'legacy-to' });
    expect((ok.body as PathBody).path).toHaveLength(2);

    const bad = await invoke(app().handler('/api/graph/paths'), {}, { fromId: 'abc', toId: String(b) });
    expect(bad.statusCode).toBe(404);
  });
});

describe('GET /api/graph/search (v2)', () => {
  it('scopes results by project', async () => {
    const inScope = entity('searchme-in', 'tool', 3);
    const outScope = entity('searchme-out', 'tool', 3);
    const m = memory('sm', { project: 'atlas' });
    mention(m, inScope);
    const mo = memory('smo', { project: 'zephyr' });
    mention(mo, outScope);

    const r = await invoke(app().handler('/api/graph/search'), {}, { q: 'searchme', project: 'atlas' });
    const body = r.body as { entities: Array<{ name: string }> };
    expect(body.entities.map((e) => e.name)).toEqual(['searchme-in']);
  });
});
