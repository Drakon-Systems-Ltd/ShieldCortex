import { afterAll, beforeAll, describe, expect, it } from '@jest/globals';
import type { Request, Response } from 'express';
import { initDatabase, closeDatabase } from '../../database/init.js';
import { addMemory } from '../../memory/store.js';
import { registerMemoryRoutes } from '../routes/memories.js';

/**
 * Phase 17 A3 — pagination `total`/`hasMore` must reflect the SAME filter
 * (type/category/search) as the page query.
 *
 * Before the fix, `total` came from getMemoryStats(project).total (the
 * UNFILTERED grand count), so a filtered request reported the whole-DB total
 * and a wrong `hasMore`. This drives the real `/api/memories` handler.
 */

type Handler = (req: Request, res: Response, next: (err?: unknown) => void) => unknown;

function captureRoute() {
  const map = new Map<string, Handler[]>();
  return {
    get(path: string, ...h: Handler[]) {
      map.set(`GET ${path}`, h);
    },
    post(_path: string, ..._h: Handler[]) {
      /* ignored — only GET /api/memories is under test */
    },
    patch(_path: string, ..._h: Handler[]) {
      /* ignored */
    },
    delete(_path: string, ..._h: Handler[]) {
      /* ignored */
    },
    handler(path: string) {
      const h = map.get(`GET ${path}`);
      if (!h) throw new Error(`no handler for ${path}`);
      return h;
    },
  };
}

async function invoke(handlers: Handler[], query: Record<string, string>): Promise<any> {
  let body: unknown;
  const res = {
    status() {
      return this;
    },
    json(payload: unknown) {
      body = payload;
      return this;
    },
  } as unknown as Response;

  const passThroughMiddleware = handlers.slice(0, -1);
  const final = handlers[handlers.length - 1];
  for (const mw of passThroughMiddleware) {
    await mw({ query } as unknown as Request, res, () => undefined);
  }
  await final({ query } as unknown as Request, res, () => undefined);
  return body;
}

let routeStore: ReturnType<typeof captureRoute>;

describe('GET /api/memories filtered pagination totals', () => {
  beforeAll(() => {
    closeDatabase();
    initDatabase(':memory:');

    // Seed: 8 'error', 3 'architecture' — grand total 11.
    // No `source` arg → defence pipeline skipped, clean inserts.
    for (let i = 0; i < 8; i++) {
      addMemory({ title: `err ${i}`, content: `error detail number ${i}`, category: 'error', project: 'p1' });
    }
    for (let i = 0; i < 3; i++) {
      addMemory({ title: `arch ${i}`, content: `architecture detail ${i}`, category: 'architecture', project: 'p1' });
    }

    routeStore = captureRoute();
    registerMemoryRoutes(routeStore as any, {
      requireNotLocked: (_req, _res, next) => next(),
      requireIronDomeAction: () => (_req: Request, _res: Response, next: (err?: unknown) => void) => next(),
    });
  });

  afterAll(() => {
    closeDatabase();
  });

  it('reports the FILTERED total, not the grand total, for a category filter', async () => {
    const handlers = routeStore.handler('/api/memories');
    const body = await invoke(handlers, { project: 'p1', category: 'error', limit: '5', offset: '0' });

    // 8 errors exist; the page returns 5; total must be 8, hasMore true.
    expect(body.memories).toHaveLength(5);
    expect(body.pagination.total).toBe(8);
    expect(body.pagination.hasMore).toBe(true);
  });

  it('reports hasMore false on the last filtered page', async () => {
    const handlers = routeStore.handler('/api/memories');
    const body = await invoke(handlers, { project: 'p1', category: 'architecture', limit: '5', offset: '0' });

    expect(body.memories).toHaveLength(3);
    expect(body.pagination.total).toBe(3);
    expect(body.pagination.hasMore).toBe(false);
  });
});
