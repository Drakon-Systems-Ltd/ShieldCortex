/**
 * Phase E — resolution must actually change what agents see (not just the
 * conflict-review node). resolveConflict('keep_one'/'reject_both') sets
 * triples.valid_to; detectRelationConflicts treats valid_to IS NULL as the
 * "open" set. But BFS (handleGraphQuery / handleGraphExplain) and graph-rank
 * hop expansion read the triples table directly and, before this fix, never
 * filtered valid_to — a suspended (rejected) edge kept steering get_related,
 * path explanation, and graph-based recall as if it were still live.
 */

import { afterEach, beforeEach, describe, expect, it } from '@jest/globals';
import { closeDatabase, getDatabase, initDatabase } from '../database/init.js';
import type { Request, Response } from 'express';
import { handleGraphExplain, handleGraphQuery } from '../tools/graph.js';
import { detectRelationConflicts, resolveConflict } from '../threat-graph/conflict.js';
import { graphRankFromQuery } from '../memory/ranker/graph-rank.js';
import { registerGraphRoutes } from '../api/routes/graph.js';

beforeEach(() => initDatabase(':memory:'));
afterEach(() => closeDatabase());

function entity(name: string): number {
  return Number(
    getDatabase().prepare("INSERT INTO entities (name, type) VALUES (?, 'tool')").run(name).lastInsertRowid,
  );
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

interface QueryPayload {
  connections?: Array<{ predicate: string; direction: string; depth: number; entity: { id: number; name: string } }>;
}

function queryConnections(entityName: string): string[] {
  const payload = JSON.parse(handleGraphQuery({ entity: entityName, depth: 2 }).content[0].text) as QueryPayload;
  return (payload.connections ?? []).map((c) => c.entity.name);
}

function memoryMention(title: string, entityId: number): number {
  const db = getDatabase();
  const memoryId = Number(
    db.prepare(
      `INSERT INTO memories (uuid, type, category, title, content)
       VALUES (?, 'long_term', 'note', ?, 'fixture')`,
    ).run(`uuid-${title}`, title).lastInsertRowid,
  );
  db.prepare('INSERT INTO memory_entities (memory_id, entity_id, role) VALUES (?, ?, ?)')
    .run(memoryId, entityId, 'mention');
  return memoryId;
}

type Handler = (req: Request, res: Response, next: (err?: unknown) => void) => unknown;

function captureRoute() {
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

async function invokeRoute(handlers: Handler[], params: Record<string, string>, query: Record<string, string> = {}) {
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

describe('handleGraphQuery (BFS) excludes suspended (valid_to) edges', () => {
  it('drops a reject_both-suspended edge from the BFS neighbourhood', () => {
    const a = entity('deploy');
    const good = entity('good-server');
    const evil = entity('evil-server');
    triple(a, 'uses', good, 'cli:michael', 0.95);
    triple(a, 'uses', evil, 'agent:x', 0.3);

    // Before resolution both are visible.
    expect(queryConnections('deploy')).toEqual(expect.arrayContaining(['good-server', 'evil-server']));

    detectRelationConflicts();
    resolveConflict({ subjectId: a, predicate: 'uses', resolution: 'keep_one', keptObjectId: good }, 'michael');

    const names = queryConnections('deploy');
    expect(names).toContain('good-server');
    expect(names).not.toContain('evil-server');
  });
});

describe('handleGraphExplain (path-finding BFS) excludes suspended edges', () => {
  it('finds no path through a suspended edge after reject_both', () => {
    const a = entity('deploy2');
    const b = entity('b2');
    const c = entity('c2');
    triple(a, 'uses', b, 'cli:michael', 0.95);
    triple(a, 'uses', c, 'agent:x', 0.2);

    detectRelationConflicts();
    resolveConflict({ subjectId: a, predicate: 'uses', resolution: 'reject_both' }, 'michael');

    const result = JSON.parse(handleGraphExplain({ from: 'deploy2', to: 'c2' }).content[0].text) as {
      paths: unknown[];
      message?: string;
    };
    expect(result.paths).toHaveLength(0);
  });
});

describe('graphRankFromQuery excludes suspended triples from graph recall', () => {
  it('does not retrieve a memory reachable only through a suspended edge', () => {
    const auth = entity('auth-seed');
    const poison = entity('poison-rank');
    const memoryId = memoryMention('poisoned memory', poison);
    const tripleId = triple(auth, 'uses', poison, 'agent:x', 0.2);
    getDatabase().prepare('UPDATE triples SET valid_to = ? WHERE id = ?')
      .run('2026-08-12T00:00:00.000Z', tripleId);

    expect(graphRankFromQuery('auth-seed', getDatabase(), { maxHops: 1 }))
      .not.toContainEqual(expect.objectContaining({ memoryId }));
  });
});

describe('dashboard graph routes exclude suspended triples from live views', () => {
  it('omits suspended neighbours and paths from API graph route responses', async () => {
    const from = entity('dash-from');
    const kept = entity('dash-kept');
    const suspended = entity('dash-suspended');
    triple(from, 'uses', kept, 'cli:michael', 0.95);
    const suspendedTriple = triple(from, 'uses', suspended, 'agent:x', 0.2);
    getDatabase().prepare('UPDATE triples SET valid_to = ? WHERE id = ?')
      .run('2026-08-12T00:00:00.000Z', suspendedTriple);

    const app = captureRoute();
    registerGraphRoutes(app as never, (_req, _res, next) => next());

    const neighbourhood = await invokeRoute(app.handler('/api/graph/entities/:id/neighbourhood'), { id: String(from) });
    expect(neighbourhood.statusCode).toBe(200);
    const neighbourhoodBody = neighbourhood.body as { neighbours: Array<{ name: string }>; triples: Array<{ object_name: string }> };
    expect(neighbourhoodBody.neighbours.map((n) => n.name)).toContain('dash-kept');
    expect(neighbourhoodBody.neighbours.map((n) => n.name)).not.toContain('dash-suspended');
    expect(neighbourhoodBody.triples.map((t) => t.object_name)).not.toContain('dash-suspended');

    const path = await invokeRoute(app.handler('/api/graph/paths'), {}, { from: 'dash-from', to: 'dash-suspended' });
    expect(path.statusCode).toBe(200);
    const pathBody = path.body as { path: unknown[]; message?: string };
    expect(pathBody.path).toHaveLength(0);
  });
});
