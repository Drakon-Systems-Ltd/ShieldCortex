import { afterAll, beforeAll, describe, expect, it } from '@jest/globals';
import { randomUUID } from 'crypto';
import type { Request, Response } from 'express';
import { initDatabase, closeDatabase, getDatabase } from '../../database/init.js';
import { CONTRADICTION_SCAN_WINDOW } from '../../memory/contradiction.js';
import { registerMemoryRoutes } from '../routes/memories.js';

/**
 * #692 — `/api/review/queue` summary.contradictions / summary.duplicates are
 * PAIR counts cut off at `limit` (default 20), and contradiction discovery only
 * compares the CONTRADICTION_SCAN_WINDOW highest-salience memories. The Needs
 * you inbox used to add them up as exact memory counts. `pairCoverage` now says
 * how far those numbers reach. Drives the real handler on an in-memory DB.
 */

type Handler = (req: Request, res: Response, next: (err?: unknown) => void) => unknown;

function captureRoutes() {
  const map = new Map<string, Handler[]>();
  const noop = () => undefined;
  return {
    get(path: string, ...h: Handler[]) { map.set(path, h); },
    post: noop, patch: noop, put: noop, delete: noop,
    handler(path: string) {
      const h = map.get(path);
      if (!h) throw new Error(`no handler for ${path}`);
      return h;
    },
  };
}

async function invoke(handlers: Handler[], query: Record<string, string>): Promise<any> {
  let body: unknown;
  let status = 200;
  const res = {
    status(code: number) { status = code; return this; },
    json(payload: unknown) { body = payload; return this; },
  } as unknown as Response;
  for (const h of handlers) await h({ query } as unknown as Request, res, () => undefined);
  if (status !== 200) throw new Error(`status ${status}: ${JSON.stringify(body)}`);
  return body;
}

/** Direct insert so the write-path dedupe/defence cannot merge the fixtures. */
function insert(project: string, title: string, content: string, category = 'note') {
  getDatabase().prepare(
    `INSERT INTO memories (uuid, type, category, title, content, project) VALUES (?, 'long_term', ?, ?, ?, ?)`,
  ).run(randomUUID(), category, title, content, project);
}

let routes: ReturnType<typeof captureRoutes>;

describe('GET /api/review/queue pair coverage (#692)', () => {
  beforeAll(() => {
    closeDatabase();
    initDatabase(':memory:');
    // Four near-identical memories in one category: every pair is a duplicate,
    // so 6 pairs share 4 memories — pairs are not memories.
    for (let i = 0; i < 4; i++) {
      insert('dupes', `Deploy runbook for the billing service ${i}`, 'Deploy the billing service with the blue green runbook and verify health checks');
    }
    // More memories than the contradiction scan compares.
    for (let i = 0; i < CONTRADICTION_SCAN_WINDOW + 5; i++) {
      insert('big', `Unrelated note ${i}`, `distinct content token${i} alpha${i} beta${i}`);
    }
    routes = captureRoutes();
    registerMemoryRoutes(routes as any, {
      requireNotLocked: (_req, _res, next) => next(),
      requireIronDomeAction: () => (_req: Request, _res: Response, next: (err?: unknown) => void) => next(),
    });
  });

  afterAll(() => closeDatabase());

  it('counts duplicate pairs, not memories: one memory sits in several pairs', async () => {
    const body = await invoke(routes.handler('/api/review/queue'), { project: 'dupes' });
    expect(body.pairCoverage.unit).toBe('pairs');
    expect(body.summary.duplicates).toBe(6);
    expect(body.pairCoverage.duplicates).toEqual({ found: 6, capped: false });
    const ids = new Set<number>();
    for (const p of body.sections.duplicates) { ids.add(p.memoryA.id); ids.add(p.memoryB.id); }
    expect(ids.size).toBe(4);
  });

  it('flags a backlog beyond the window as capped: the count is a floor', async () => {
    const body = await invoke(routes.handler('/api/review/queue'), { project: 'dupes', limit: '2' });
    expect(body.summary.duplicates).toBe(2);
    expect(body.pairCoverage.limit).toBe(2);
    expect(body.pairCoverage.duplicates).toEqual({ found: 2, capped: true });
  });

  it('flags contradiction discovery as partial when the store exceeds the scan window', async () => {
    const big = await invoke(routes.handler('/api/review/queue'), { project: 'big' });
    expect(big.pairCoverage.contradictions).toMatchObject({
      scanWindow: CONTRADICTION_SCAN_WINDOW,
      candidates: CONTRADICTION_SCAN_WINDOW + 5,
      scanPartial: true,
    });
    const small = await invoke(routes.handler('/api/review/queue'), { project: 'dupes' });
    expect(small.pairCoverage.contradictions).toMatchObject({ candidates: 4, scanPartial: false, capped: false });
  });
});
