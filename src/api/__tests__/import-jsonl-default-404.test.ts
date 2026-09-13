/**
 * #476 default-glob 404 must not echo $HOME.
 * Isolated os.homedir() so this never scans the operator's ~/.claude.
 */
import { afterEach, beforeEach, describe, expect, it, jest } from '@jest/globals';
import { mkdtempSync, rmSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';

type Handler = (req: any, res: any, next: (err?: unknown) => void) => unknown;

describe('POST /api/sessions/import-jsonl default glob (#476)', () => {
  let isolatedHome: string;

  beforeEach(() => {
    isolatedHome = mkdtempSync(join(tmpdir(), 'sc-import-default-'));
    jest.resetModules();
    jest.unstable_mockModule('os', () => {
      const actual = jest.requireActual('os') as typeof import('os');
      return {
        ...actual,
        homedir: () => isolatedHome,
      };
    });
  });

  afterEach(() => {
    rmSync(isolatedHome, { recursive: true, force: true });
    jest.resetModules();
  });

  it('404s without the resolved home path when no default files exist', async () => {
    const initModule = await import('../../database/init.js');
    initModule.closeDatabase();
    initModule.initDatabase(':memory:');

    const { registerSessionRoutes } = await import('../routes/sessions.js');
    const routes = { post: new Map<string, Handler[]>() };
    const app = {
      get() { /* unused */ },
      post(route: string, ...handlers: Handler[]) { routes.post.set(route, handlers); },
      patch() { /* unused */ },
      delete() { /* unused */ },
    };
    registerSessionRoutes(app as never, (_req, _res, next) => next());

    const handlers = routes.post.get('/api/sessions/import-jsonl')!;
    const res: { statusCode: number; body: unknown; status(code: number): typeof res; json(payload: unknown): typeof res } = {
      statusCode: 200,
      body: undefined,
      status(code) { this.statusCode = code; return this; },
      json(payload) { this.body = payload; return this; },
    };
    let idx = 0;
    let handlerReturn: unknown;
    const req = { query: {}, params: {}, body: {} };
    const next = (err?: unknown) => {
      if (err) throw err;
      idx++;
      if (idx < handlers.length) handlerReturn = handlers[idx](req, res, next);
    };
    const first = handlers[0](req, res, next);
    if (first && typeof (first as Promise<unknown>).then === 'function') await first;
    if (handlerReturn && typeof (handlerReturn as Promise<unknown>).then === 'function') await handlerReturn;

    expect(res.statusCode).toBe(404);
    const error = String((res.body as { error?: string }).error ?? '');
    expect(error).toBe('no JSONL files matched the default import location');
    expect(error).not.toContain(isolatedHome);
    expect(JSON.stringify(res.body)).not.toContain(isolatedHome);
    expect(JSON.stringify(res.body)).not.toMatch(/\.claude/);

    initModule.closeDatabase();
  });

  it('does not echo $HOME when a default-glob match fails to import', async () => {
    const { mkdirSync, writeFileSync, chmodSync } = await import('fs');
    const projects = join(isolatedHome, '.claude', 'projects', 'x');
    mkdirSync(projects, { recursive: true });
    const bad = join(projects, 'broken.jsonl');
    writeFileSync(bad, '{"type":"user","sessionId":"s1"}\n');
    chmodSync(bad, 0o000);

    const initModule = await import('../../database/init.js');
    initModule.closeDatabase();
    initModule.initDatabase(':memory:');

    const { registerSessionRoutes } = await import('../routes/sessions.js');
    const routes = { post: new Map<string, Handler[]>() };
    const app = {
      get() { /* unused */ },
      post(route: string, ...handlers: Handler[]) { routes.post.set(route, handlers); },
      patch() { /* unused */ },
      delete() { /* unused */ },
    };
    registerSessionRoutes(app as never, (_req, _res, next) => next());

    const handlers = routes.post.get('/api/sessions/import-jsonl')!;
    const res: { statusCode: number; body: unknown; status(code: number): typeof res; json(payload: unknown): typeof res } = {
      statusCode: 200,
      body: undefined,
      status(code) { this.statusCode = code; return this; },
      json(payload) { this.body = payload; return this; },
    };
    let idx = 0;
    let handlerReturn: unknown;
    const req = { query: {}, params: {}, body: {} };
    const next = (err?: unknown) => {
      if (err) throw err;
      idx++;
      if (idx < handlers.length) handlerReturn = handlers[idx](req, res, next);
    };
    const first = handlers[0](req, res, next);
    if (first && typeof (first as Promise<unknown>).then === 'function') await first;
    if (handlerReturn && typeof (handlerReturn as Promise<unknown>).then === 'function') await handlerReturn;

    const dumped = JSON.stringify(res.body);
    expect(dumped).not.toContain(isolatedHome);
    expect(dumped).not.toMatch(/\/home\//);
    expect(dumped).toContain('broken.jsonl');
    expect(dumped).not.toContain(bad);

    chmodSync(bad, 0o644);
    initModule.closeDatabase();
  });
});
