import { afterAll, beforeAll, describe, expect, it } from '@jest/globals';
import type { Request, Response } from 'express';
import { initDatabase, closeDatabase, getDatabase } from '../../database/init.js';
import { addMemory, getRecentMemories } from '../../memory/store.js';
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

interface RecentQuery {
  sql: string;
  params: unknown[];
  rowCount: number;
}

/**
 * Record every `memories` page statement run through the live handle: its SQL
 * text, the values bound to it, and how many rows SQLite handed back. Wraps
 * db.prepare from the test side only; other statements pass through untouched.
 */
function recordRecentQueries(): { calls: RecentQuery[]; restore: () => void } {
  const db = getDatabase() as unknown as {
    prepare: (sql: string) => { all: (...params: unknown[]) => unknown[] };
  };
  const original = db.prepare.bind(db);
  const calls: RecentQuery[] = [];
  db.prepare = (sql: string) => {
    const statement = original(sql);
    if (!/^\s*SELECT \* FROM memories\b[\s\S]*ORDER BY last_accessed DESC/.test(sql)) return statement;
    return {
      all: (...params: unknown[]) => {
        // Recorded before the statement runs, so a statement SQLite rejects
        // still shows which SQL and values were attempted.
        const call: RecentQuery = { sql, params, rowCount: -1 };
        calls.push(call);
        const rows = statement.all(...params);
        call.rowCount = rows.length;
        return rows;
      },
    };
  };
  return {
    calls,
    restore: () => {
      db.prepare = original;
    },
  };
}

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

  it('recent returns the last matching row past offset 1000', async () => {
    const db = getDatabase();
    const insert = db.prepare(`INSERT INTO memories
      (uuid, type, category, title, content, project, last_accessed)
      VALUES (?, 'long_term', 'error', 'Boundary row', 'Page fixture', 'boundary', ?)`);
    const oldestId = db.transaction(() => {
      let firstId = 0;
      for (let i = 0; i < 1001; i++) {
        const row = insert.run(`boundary-${i}`, new Date(i * 1000).toISOString());
        if (i === 0) firstId = Number(row.lastInsertRowid);
      }
      return firstId;
    })();

    const body = await invoke(routeStore.handler('/api/memories'), {
      mode: 'recent', project: 'boundary', category: 'error', limit: '50', offset: '1000',
    });
    expect(body.memories.map((row: { id: number }) => row.id)).toEqual([oldestId]);
    expect(body.pagination).toEqual({ offset: 1000, limit: 50, total: 1001, hasMore: false });
  });

  describe('recent page past the first is skipped in SQL', () => {
    const PAGE_PROJECT = 'page-fixture';
    const PAGE_SOURCE = { type: 'user', identifier: 'page-fixture' } as const;
    /** Matching ids in `last_accessed DESC` order (newest first). */
    let expectedOrder: number[];

    beforeAll(() => {
      const db = getDatabase();
      const insert = db.prepare(`INSERT INTO memories
        (uuid, type, category, title, content, project, last_accessed)
        VALUES (?, 'long_term', ?, 'Page row', 'Page fixture', ?, ?)`);
      const ascending: number[] = [];
      db.transaction(() => {
        // 120 matching rows with distinct timestamps, interleaved with rows of
        // another category so the filter has something to exclude mid-order.
        for (let i = 0; i < 120; i++) {
          const row = insert.run(`page-error-${i}`, 'error', PAGE_PROJECT, new Date(i * 2000).toISOString());
          ascending.push(Number(row.lastInsertRowid));
          if (i % 4 === 0) {
            insert.run(`page-arch-${i}`, 'architecture', PAGE_PROJECT, new Date(i * 2000 + 1000).toISOString());
          }
        }
      })();
      expectedOrder = ascending.reverse();
    });

    const page = (offset: string, extra: Record<string, string> = {}) =>
      invoke(routeStore.handler('/api/memories'), {
        mode: 'recent', project: PAGE_PROJECT, category: 'error', limit: '50', offset, ...extra,
      });
    const idsOf = (body: any): number[] => body.memories.map((row: { id: number }) => row.id);

    it('binds the page size and offset, and reads back only the page', async () => {
      const spy = recordRecentQueries();
      let body: any;
      try {
        body = await page('50');
      } finally {
        spy.restore();
      }

      expect(spy.calls).toHaveLength(1);
      const [call] = spy.calls;
      expect(call.sql.replace(/\s+/g, ' ')).toBe(
        'SELECT * FROM memories WHERE project = ? AND category = ? ORDER BY last_accessed DESC LIMIT ? OFFSET ?',
      );
      expect(call.params).toEqual([PAGE_PROJECT, 'error', 50, 50]);
      expect(call.rowCount).toBe(50);

      expect(idsOf(body)).toEqual(expectedOrder.slice(50, 100));
      expect(body.pagination).toEqual({ offset: 50, limit: 50, total: 120, hasMore: true });
      // Enrichment still runs on the page rows.
      expect(body.memories.every((row: any) => typeof row.decayedScore === 'number')).toBe(true);
      expect(body.memories.every((row: any) => Array.isArray(row.entity_ids))).toBe(true);
    });

    it('returns the short last page with the filtered total', async () => {
      const spy = recordRecentQueries();
      let body: any;
      try {
        body = await page('100');
      } finally {
        spy.restore();
      }

      expect(spy.calls.map((call) => call.params)).toEqual([[PAGE_PROJECT, 'error', 50, 100]]);
      expect(spy.calls[0].rowCount).toBe(20);
      expect(idsOf(body)).toEqual(expectedOrder.slice(100));
      expect(body.pagination).toEqual({ offset: 100, limit: 50, total: 120, hasMore: false });
    });

    it('pages a recent request that arrived as mode=search with no query', async () => {
      const spy = recordRecentQueries();
      let body: any;
      try {
        body = await page('50', { mode: 'search' });
      } finally {
        spy.restore();
      }

      expect(spy.calls.map((call) => call.params)).toEqual([[PAGE_PROJECT, 'error', 50, 50]]);
      expect(idsOf(body)).toEqual(expectedOrder.slice(50, 100));
    });

    it('leaves the first page on the LIMIT-only statement', async () => {
      const spy = recordRecentQueries();
      let body: any;
      try {
        body = await page('0');
      } finally {
        spy.restore();
      }

      expect(spy.calls).toHaveLength(1);
      expect(spy.calls[0].sql).not.toMatch(/OFFSET/i);
      expect(spy.calls[0].params).toEqual([PAGE_PROJECT, 'error', 51]);
      expect(idsOf(body)).toEqual(expectedOrder.slice(0, 50));
      expect(body.pagination).toEqual({ offset: 0, limit: 50, total: 120, hasMore: true });
    });

    it('keeps the read-then-slice path for a negative offset', async () => {
      const spy = recordRecentQueries();
      let body: any;
      try {
        body = await page('-10');
      } finally {
        spy.restore();
      }

      // limit + offset + 1 = 41 rows read, then slice(-10, 40) of those.
      expect(spy.calls).toHaveLength(1);
      expect(spy.calls[0].sql).not.toMatch(/OFFSET/i);
      expect(spy.calls[0].params).toEqual([PAGE_PROJECT, 'error', 41]);
      expect(idsOf(body)).toEqual(expectedOrder.slice(31, 40));
      expect(body.pagination).toEqual({ offset: -10, limit: 50, total: 120, hasMore: true });
    });

    it('keeps the read-then-slice path for a negative page size', async () => {
      const spy = recordRecentQueries();
      let body: any;
      try {
        body = await page('10', { limit: '-5' });
      } finally {
        spy.restore();
      }

      // limit + offset + 1 = 6 rows read, then slice(10, 5) of those.
      expect(spy.calls).toHaveLength(1);
      expect(spy.calls[0].sql).not.toMatch(/OFFSET/i);
      expect(spy.calls[0].params).toEqual([PAGE_PROJECT, 'error', 6]);
      expect(idsOf(body)).toEqual([]);
      expect(body.pagination).toEqual({ offset: 10, limit: -5, total: 120, hasMore: true });
    });

    it('keeps the read-then-slice path for an offset too large to be an integer', async () => {
      const spy = recordRecentQueries();
      try {
        // parseInt of a 400-digit string is Infinity.
        await page('9'.repeat(400));
      } finally {
        spy.restore();
      }

      // Same statement and the same bound value as before SQL paging existed,
      // so whatever SQLite makes of it is unchanged; only that is asserted.
      expect(spy.calls).toHaveLength(1);
      expect(spy.calls[0].sql).not.toMatch(/OFFSET/i);
      expect(spy.calls[0].params).toEqual([PAGE_PROJECT, 'error', Infinity]);
    });

    it('getRecentMemories still returns n rows when no offset is passed', () => {
      const spy = recordRecentQueries();
      let rows: ReturnType<typeof getRecentMemories>;
      try {
        rows = getRecentMemories(7, PAGE_PROJECT);
      } finally {
        spy.restore();
      }

      expect(rows).toHaveLength(7);
      expect(spy.calls[0].sql).not.toMatch(/OFFSET/i);
      expect(spy.calls[0].params).toEqual([PAGE_PROJECT, 7]);
    });

    it('getRecentMemories ignores the offset when a source is given', () => {
      const withOffset = recordRecentQueries();
      let paged: ReturnType<typeof getRecentMemories>;
      try {
        paged = getRecentMemories(5, PAGE_PROJECT, PAGE_SOURCE, { category: 'error' }, undefined, 50);
      } finally {
        withOffset.restore();
      }
      const unpaged = getRecentMemories(5, PAGE_PROJECT, PAGE_SOURCE, { category: 'error' });

      expect(withOffset.calls[0].sql).not.toMatch(/OFFSET/i);
      expect(withOffset.calls[0].params).toEqual([PAGE_PROJECT, 'error', 10]);
      expect(paged.map((row) => row.id)).toEqual(unpaged.map((row) => row.id));
      expect(paged.map((row) => row.id)).toEqual(expectedOrder.slice(0, 5));
    });
  });

  it('reports hasMore false on the last filtered page', async () => {
    const handlers = routeStore.handler('/api/memories');
    const body = await invoke(handlers, { project: 'p1', category: 'architecture', limit: '5', offset: '0' });

    expect(body.memories).toHaveLength(3);
    expect(body.pagination.total).toBe(3);
    expect(body.pagination.hasMore).toBe(false);
  });
});
