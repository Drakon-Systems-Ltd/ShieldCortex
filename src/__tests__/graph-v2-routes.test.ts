/**
 * Dashboard v2 graph endpoints (docs/design/2026-09-13-dashboard-v2-ux.md
 * §6.4, §13.2–13.3): bounded overview payload, capped neighbourhood with
 * memories + all three edge families, ID-based paths with direction, project
 * scoping, strict query-param clamping, suspended-edge exclusion everywhere.
 */

import { afterEach, beforeEach, describe, expect, it } from '@jest/globals';
import { closeDatabase, getDatabase, initDatabase } from '../database/init.js';
import type { Request, Response } from 'express';
import { PATH_VISIT_BUDGET, registerGraphRoutes } from '../api/routes/graph.js';

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
    // Each hop carries the REAL entity type/memoryCount and triple confidence/disputed
    // so the client can draw the path without inventing anything (review item 4).
    expect(body.path[1]).toMatchObject({ entityType: 'tool', memoryCount: 0, confidence: 0.8, disputed: false });
    expect(body.path[0]).toMatchObject({ entityType: 'tool', confidence: null });
    // Legacy field keeps ~; direction carries the truth.
    expect(body.path[2]).toMatchObject({ predicate: '~monitors', direction: 'reverse' });
  });

  it('still accepts legacy name params and rejects garbage ids', async () => {
    const a = entity('legacy-from');
    const b = entity('legacy-to');
    triple(a, 'uses', b);

    const ok = await invoke(app().handler('/api/graph/paths'), {}, { from: 'legacy-from', to: 'legacy-to' });
    expect((ok.body as PathBody).path).toHaveLength(2);

    // A malformed id is a client error (400), not a lookup miss (404).
    const bad = await invoke(app().handler('/api/graph/paths'), {}, { fromId: 'abc', toId: String(b) });
    expect(bad.statusCode).toBe(400);
    const junk = await invoke(app().handler('/api/graph/paths'), {}, { fromId: `${a}junk`, toId: String(b) });
    expect(junk.statusCode).toBe(400);
  });

  it('scopes endpoints, every hop and sourceMemories by project (out-of-scope bridge is invisible)', async () => {
    // atlas: a —uses→ bridge —uses→ b, where bridge is only linked to a zephyr memory.
    // Unscoped: path a→bridge→b. Scoped to atlas: no path, and bridge is 404 as an endpoint.
    const a = entity('sc-a', 'tool', 5);
    const bridge = entity('sc-bridge', 'tool', 9);
    const b = entity('sc-b', 'tool', 4);
    const ma = memory('sc-ma', { project: 'atlas' });
    const mb = memory('sc-mb', { project: 'atlas' });
    const mz = memory('sc-mz', { project: 'zephyr' });
    mention(ma, a);
    mention(mb, b);
    mention(mz, bridge);
    getDatabase().prepare('UPDATE triples SET source_memory_id = ? WHERE id = ?').run(mz, triple(a, 'uses', bridge));
    getDatabase().prepare('UPDATE triples SET source_memory_id = ? WHERE id = ?').run(mz, triple(bridge, 'uses', b));

    const global = await invoke(app().handler('/api/graph/paths'), {}, { fromId: String(a), toId: String(b) });
    const gb = global.body as PathBody & { truncated: boolean };
    expect(gb.path.map((h) => h.entityId)).toEqual([a, bridge, b]);
    expect(gb.sourceMemories).toHaveLength(1); // the zephyr source memory is visible globally
    expect(gb.truncated).toBe(false);

    const scoped = await invoke(app().handler('/api/graph/paths'), {}, { fromId: String(a), toId: String(b), project: 'atlas' });
    expect(scoped.statusCode).toBe(200);
    const sb = scoped.body as PathBody & { truncated: boolean };
    expect(sb.path).toEqual([]);
    expect(sb.sourceMemories).toEqual([]);
    expect(sb.truncated).toBe(false);

    // Out-of-scope endpoint → 404 (by id and by legacy name); self-path too.
    const endpoint = await invoke(app().handler('/api/graph/paths'), {}, { fromId: String(bridge), toId: String(b), project: 'atlas' });
    expect(endpoint.statusCode).toBe(404);
    const byName = await invoke(app().handler('/api/graph/paths'), {}, { from: 'sc-bridge', to: 'sc-b', project: 'atlas' });
    expect(byName.statusCode).toBe(404);
    const self = await invoke(app().handler('/api/graph/paths'), {}, { fromId: String(bridge), toId: String(bridge), project: 'atlas' });
    expect(self.statusCode).toBe(404);

    // An in-scope direct edge still resolves under scope, with a scoped sourceMemories lookup.
    getDatabase().prepare('UPDATE triples SET source_memory_id = ? WHERE id = ?').run(ma, triple(a, 'monitors', b));
    const direct = await invoke(app().handler('/api/graph/paths'), {}, { fromId: String(a), toId: String(b), project: 'atlas' });
    const db2 = direct.body as PathBody & { sourceMemories: Array<{ id: number }> };
    expect(db2.path.map((h) => h.entityId)).toEqual([a, b]);
    expect(db2.sourceMemories.map((m) => m.id)).toEqual([ma]);
  });

  it('stops at the visit budget and reports truncated instead of pretending no path exists', async () => {
    // hub fans out to PATH_VISIT_BUDGET + 5 leaves; the target hangs off the
    // LAST leaf, so it is only reachable past the budget.
    const from = entity('bud-from');
    const target = entity('bud-target');
    const db = getDatabase();
    const insTriple = db.prepare(
      `INSERT INTO triples (subject_id, predicate, object_id, confidence, created_at, valid_from)
       VALUES (?, 'uses', ?, 0.8, '2026-08-12 00:00:00', '2026-08-12T00:00:00.000Z')`,
    );
    const insEntity = db.prepare("INSERT INTO entities (name, type, memory_count) VALUES (?, 'tool', 0)");
    let last = 0;
    db.transaction(() => {
      for (let i = 0; i < PATH_VISIT_BUDGET + 5; i++) {
        last = Number(insEntity.run(`leaf-${i}`).lastInsertRowid);
        insTriple.run(from, last);
      }
      insTriple.run(last, target);
    })();

    const r = await invoke(app().handler('/api/graph/paths'), {}, { fromId: String(from), toId: String(target) });
    expect(r.statusCode).toBe(200);
    const body = r.body as PathBody & { truncated: boolean };
    expect(body.path).toEqual([]);
    expect(body.truncated).toBe(true);
    expect(body.message).toMatch(/budget/);
  });
});

describe('GET /api/graph/entities/:id/triples (legacy, hardened)', () => {
  it('applies a LIMIT with deterministic newest-first, id-desc order and reports total/hasMore', async () => {
    const f = entity('lt-focal');
    const others = Array.from({ length: 4 }, (_, i) => entity(`lt-${i}`));
    // Same created_at for all → tie-break must be id DESC.
    const ids = others.map((o) => triple(f, 'uses', o, { createdAt: '2026-08-12 00:00:00' }));
    const r = await invoke(app().handler('/api/graph/entities/:id/triples'), { id: String(f) }, { limit: '3' });
    expect(r.statusCode).toBe(200);
    const body = r.body as { triples: Array<{ id: number }>; total: number; limit: number; hasMore: boolean };
    expect(body.triples.map((t) => t.id)).toEqual([ids[3], ids[2], ids[1]]);
    expect(body.total).toBe(4);
    expect(body.limit).toBe(3);
    expect(body.hasMore).toBe(true);
  });

  it('optional ?project= applies the both-endpoints rule', async () => {
    const f = entity('lp-focal');
    const inN = entity('lp-in');
    const outN = entity('lp-out');
    mention(memory('lp-m1', { project: 'atlas' }), f);
    mention(memory('lp-m2', { project: 'atlas' }), inN);
    mention(memory('lp-m3', { project: 'zephyr' }), outN);
    triple(f, 'uses', inN);
    triple(outN, 'uses', f);

    const all = await invoke(app().handler('/api/graph/entities/:id/triples'), { id: String(f) });
    expect((all.body as { triples: unknown[] }).triples).toHaveLength(2);
    const scoped = await invoke(app().handler('/api/graph/entities/:id/triples'), { id: String(f) }, { project: 'atlas' });
    const body = scoped.body as { triples: Array<{ object_name: string }>; total: number };
    expect(body.triples.map((t) => t.object_name)).toEqual(['lp-in']);
    expect(body.total).toBe(1);
  });
});

describe('GET /api/graph/triples (legacy, hardened)', () => {
  it('optional ?project= applies the both-endpoints rule to the list and its total', async () => {
    const a = entity('gt-a');
    const b = entity('gt-b');
    const z = entity('gt-z');
    mention(memory('gt-m1', { project: 'atlas' }), a);
    mention(memory('gt-m2', { project: 'atlas' }), b);
    mention(memory('gt-m3', { project: 'zephyr' }), z);
    triple(a, 'uses', b);
    triple(a, 'uses', z);
    const r = await invoke(app().handler('/api/graph/triples'), {}, { project: 'atlas' });
    const body = r.body as { triples: Array<{ object_name: string }>; total: number };
    expect(body.triples.map((t) => t.object_name)).toEqual(['gt-b']);
    expect(body.total).toBe(1);
  });
});

describe('neighbourhood project scope', () => {
  it('404s an out-of-scope focal and excludes out-of-scope neighbours', async () => {
    const f = entity('ns-focal', 'tool', 5);
    const inN = entity('ns-in', 'tool', 4);
    const outN = entity('ns-out', 'tool', 9);
    mention(memory('ns-m1', { project: 'atlas' }), f);
    mention(memory('ns-m2', { project: 'atlas' }), inN);
    mention(memory('ns-m3', { project: 'zephyr' }), outN);
    triple(f, 'uses', inN);
    triple(f, 'uses', outN);

    const inScope = await invoke(app().handler('/api/graph/entities/:id/neighbourhood'), { id: String(f) }, { project: 'atlas' });
    expect(inScope.statusCode).toBe(200);
    const body = inScope.body as NeighbourhoodBody;
    expect(body.neighbours.map((n) => n.name)).toEqual(['ns-in']);
    expect(body.counts.totalNeighbours).toBe(1);

    const outScope = await invoke(app().handler('/api/graph/entities/:id/neighbourhood'), { id: String(outN) }, { project: 'atlas' });
    expect(outScope.statusCode).toBe(404);
    const unscoped = await invoke(app().handler('/api/graph/entities/:id/neighbourhood'), { id: String(outN) });
    expect(unscoped.statusCode).toBe(200);
  });

  it('caps neighbour candidates in SQL yet still reports the honest total', async () => {
    const f = entity('nc-focal', 'tool', 5);
    for (let i = 0; i < 8; i++) triple(f, 'uses', entity(`nc-${i}`, 'tool', 8 - i));
    const r = await invoke(app().handler('/api/graph/entities/:id/neighbourhood'), { id: String(f) }, { limit: '2', depth: '2' });
    const body = r.body as NeighbourhoodBody;
    expect(body.neighbours.map((n) => n.name)).toEqual(['nc-0', 'nc-1']);
    expect(body.counts.totalNeighbours).toBe(8);
    expect(body.counts.omittedNeighbours).toBe(6);
  });
});

describe('strict parsing', () => {
  it('rejects malformed :id (12junk, 0, negative, float) with 400 on every id route', async () => {
    const ok = entity('strict-ok');
    for (const route of ['/api/graph/entities/:id/triples', '/api/graph/entities/:id/memories', '/api/graph/entities/:id/neighbourhood']) {
      for (const bad of [`${ok}junk`, '0', '-1', '1.5', '1e3', '']) {
        const r = await invoke(app().handler(route), { id: bad });
        expect([route, bad, r.statusCode]).toEqual([route, bad, 400]);
      }
      const good = await invoke(app().handler(route), { id: String(ok) });
      expect(good.statusCode).toBe(200);
    }
  });

  it('returns 400 when a supplied project is not a single string (array / object), never widening scope', async () => {
    const a = entity('mp-a', 'tool', 5);
    const arr = ['atlas', 'zephyr'] as unknown as string;
    for (const [route, params] of [
      ['/api/graph/overview', {}],
      ['/api/graph/entities', {}],
      ['/api/graph/search', { q: 'mp' }],
      ['/api/graph/triples', {}],
      ['/api/graph/paths', { fromId: String(a), toId: String(a) }],
    ] as Array<[string, Record<string, string>]>) {
      const r = await invoke(app().handler(route), {}, { ...params, project: arr });
      expect([route, r.statusCode]).toEqual([route, 400]);
    }
    for (const route of ['/api/graph/entities/:id/triples', '/api/graph/entities/:id/memories', '/api/graph/entities/:id/neighbourhood']) {
      const r = await invoke(app().handler(route), { id: String(a) }, { project: { x: 'y' } as unknown as string });
      expect([route, r.statusCode]).toEqual([route, 400]);
    }
    // Empty string means "no filter" (an unset select), not an error.
    const empty = await invoke(app().handler('/api/graph/overview'), {}, { project: '' });
    expect(empty.statusCode).toBe(200);
  });

  it('boundedInt: non-integers fall back to the default, integers CLAMP (negative → min, not default)', async () => {
    entity('bi');
    const get = async (q: Record<string, string>) =>
      (await invoke(app().handler('/api/graph/entities'), {}, q)).body as { limit: number; offset: number };
    // /api/graph/entities echoes the parsed limit/offset (defaults 100 / 0, limit ∈ [1, 5000]).
    expect(await get({})).toMatchObject({ limit: 100, offset: 0 });
    expect(await get({ limit: 'abc', offset: 'NaN' })).toMatchObject({ limit: 100, offset: 0 });
    expect(await get({ limit: '2.5', offset: '1e3' })).toMatchObject({ limit: 100, offset: 0 });
    expect(await get({ limit: '-5', offset: '-3' })).toMatchObject({ limit: 1, offset: 0 }); // clamp, not default
    expect(await get({ limit: '0' })).toMatchObject({ limit: 1 });
    expect(await get({ limit: '99999' })).toMatchObject({ limit: 5000 });
    expect(await get({ limit: ' 7 ', offset: '2' })).toMatchObject({ limit: 7, offset: 2 });
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
