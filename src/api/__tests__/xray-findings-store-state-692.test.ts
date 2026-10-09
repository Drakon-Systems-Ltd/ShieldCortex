import { afterEach, beforeEach, describe, expect, it } from '@jest/globals';
import fs from 'fs';
import os from 'os';
import path from 'path';
import type { Request, Response } from 'express';
import { createFindingsStore } from '../../xray/findings-store.js';
import { registerXRayFindingRoutes } from '../routes/xray-findings.js';

/**
 * #692 — `/api/xray/findings/stats` used to answer a successful zero when the
 * findings file existed but could not be read or parsed, and the Needs you
 * inbox counted that as a confirmed empty queue. A never-created file is still
 * a real zero; an unreadable one is 503 (unknown). Drives the real handlers
 * against an isolated temp store — never ~/.shieldcortex.
 */

type Handler = (req: Request, res: Response, next: (err?: unknown) => void) => unknown;

function captureRoutes() {
  const map = new Map<string, Handler[]>();
  const noop = () => undefined;
  return {
    get(p: string, ...h: Handler[]) { map.set(p, h); },
    post: noop, patch: noop, delete: noop,
    handler(p: string) {
      const h = map.get(p);
      if (!h) throw new Error(`no handler for ${p}`);
      return h;
    },
  };
}

async function invoke(handlers: Handler[], query: Record<string, string> = {}) {
  let body: any;
  let status = 200;
  const res = {
    status(code: number) { status = code; return this; },
    json(payload: unknown) { body = payload; return this; },
  } as unknown as Response;
  for (const h of handlers) await h({ query, params: {} } as unknown as Request, res, () => undefined);
  return { status, body };
}

describe('X-Ray findings routes: absent vs unreadable store (#692)', () => {
  let dir: string;
  let routes: ReturnType<typeof captureRoutes>;

  beforeEach(() => {
    dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sc-692-findings-'));
    routes = captureRoutes();
    registerXRayFindingRoutes(routes as any, (_req, _res, next) => next(), createFindingsStore(dir));
  });

  afterEach(() => fs.rmSync(dir, { recursive: true, force: true }));

  it('a never-created findings file is a confirmed zero, marked absent', async () => {
    const { status, body } = await invoke(routes.handler('/api/xray/findings/stats'));
    expect(status).toBe(200);
    expect(body).toMatchObject({ total: 0, new: 0, store: 'absent' });
  });

  it('a malformed findings file is 503 for stats and list, not a successful zero', async () => {
    fs.writeFileSync(path.join(dir, 'xray-findings.json'), '[{"id": "half-written"');
    const stats = await invoke(routes.handler('/api/xray/findings/stats'));
    expect(stats.status).toBe(503);
    expect(stats.body).toMatchObject({ store: 'unreadable' });
    expect(stats.body.new).toBeUndefined();
    expect(stats.body.error).toMatch(/could not be read or parsed/);

    const list = await invoke(routes.handler('/api/xray/findings'));
    expect(list.status).toBe(503);
    expect(list.body.findings).toBeUndefined();
  });

  it('a readable findings file reports its real counts', async () => {
    const store = createFindingsStore(dir);
    store.addFindings('scan-1', 'scan', '/project', [
      { severity: 'high', category: 'eval-exec', title: 'eval', description: 'x', file: 'a.js', line: 1 },
    ]);
    const { status, body } = await invoke(routes.handler('/api/xray/findings/stats'));
    expect(status).toBe(200);
    expect(body).toMatchObject({ total: 1, new: 1, store: 'ok' });
  });
});
