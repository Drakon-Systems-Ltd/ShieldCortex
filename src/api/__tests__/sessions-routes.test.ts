/**
 * Session capture HTTP API tests.
 *
 * Uses the same fake-Express pattern as `route-mutations.test.ts` so we
 * can assert against handler outputs without standing up a real HTTP
 * server. Each test starts a fresh `:memory:` DB so route behaviour is
 * exercised against the real SQL queries production hits.
 */
import { afterEach, beforeEach, describe, expect, it } from '@jest/globals';
import {
  initDatabase,
  closeDatabase,
  getDatabase,
} from '../../database/init.js';
import { recordEvent, recordEvents } from '../../sessions/capture.js';
import { registerSessionRoutes } from '../routes/sessions.js';
import { mkdtempSync, writeFileSync, rmSync } from 'fs';
import { join } from 'path';
import { tmpdir } from 'os';

type Handler = (req: any, res: any, next: (err?: unknown) => void) => unknown;

function createFakeApp() {
  const routes = {
    get: new Map<string, Handler[]>(),
    post: new Map<string, Handler[]>(),
    patch: new Map<string, Handler[]>(),
    delete: new Map<string, Handler[]>(),
  };
  return {
    app: {
      get(route: string, ...handlers: Handler[]) { routes.get.set(route, handlers); },
      post(route: string, ...handlers: Handler[]) { routes.post.set(route, handlers); },
      patch(route: string, ...handlers: Handler[]) { routes.patch.set(route, handlers); },
      delete(route: string, ...handlers: Handler[]) { routes.delete.set(route, handlers); },
    },
    routes,
  };
}

interface FakeRes {
  statusCode: number;
  body: unknown;
  status(code: number): FakeRes;
  json(payload: unknown): FakeRes;
}

function newRes(): FakeRes {
  const res: FakeRes = {
    statusCode: 200,
    body: undefined,
    status(code) { this.statusCode = code; return this; },
    json(payload) { this.body = payload; return this; },
  };
  return res;
}

async function invoke(handlers: Handler[], req: Record<string, unknown> = {}): Promise<FakeRes> {
  const reqWithDefaults = { query: {}, params: {}, body: {}, ...req };
  const res = newRes();
  // Walk middleware list — requireNotLocked is the first handler.
  let idx = 0;
  const next = (err?: unknown) => {
    if (err) {
      res.status(500).json({ error: (err as Error).message ?? 'error' });
      return;
    }
    idx++;
    if (idx < handlers.length) handlers[idx](reqWithDefaults, res, next);
  };
  handlers[0](reqWithDefaults, res, next);
  // Allow microtasks to settle for async handlers.
  await new Promise((r) => setImmediate(r));
  return res;
}

const passThrough: Handler = (_req, _res, next) => next();

let app: ReturnType<typeof createFakeApp>;

beforeEach(() => {
  closeDatabase();
  initDatabase(':memory:');
  app = createFakeApp();
  registerSessionRoutes(app.app as any, passThrough);
});

afterEach(() => {
  closeDatabase();
});

describe('GET /api/sessions', () => {
  it('returns empty list + correct pagination metadata when no sessions exist', async () => {
    const res = await invoke(app.routes.get.get('/api/sessions')!);
    expect(res.statusCode).toBe(200);
    expect(res.body).toEqual({
      sessions: [],
      total: 0,
      offset: 0,
      limit: 50,
      hasMore: false,
    });
  });

  it('groups events by session_id and reports counts + first/last ts', async () => {
    recordEvents([
      { session_id: 'sA', ts: '2026-05-10T10:00:00Z', kind: 'prompt', payload: { text: 'q1' }, project: 'p1' },
      { session_id: 'sA', ts: '2026-05-10T10:00:01Z', kind: 'response', payload: { text: 'a1' }, project: 'p1' },
      { session_id: 'sB', ts: '2026-05-10T11:00:00Z', kind: 'prompt', payload: { text: 'q2' }, project: 'p2' },
    ]);
    const res = await invoke(app.routes.get.get('/api/sessions')!);
    expect(res.statusCode).toBe(200);
    const body = res.body as { sessions: Array<{ session_id: string; event_count: number; project: string }>; total: number };
    expect(body.total).toBe(2);
    // Sort order is last_ts DESC — sB (11:00) before sA (10:00:01).
    expect(body.sessions[0].session_id).toBe('sB');
    expect(body.sessions[1].session_id).toBe('sA');
    expect(body.sessions[1].event_count).toBe(2);
  });

  it('filters by project when ?project=x is supplied', async () => {
    recordEvent({ session_id: 'sA', ts: '2026-05-10T10:00:00Z', kind: 'prompt', payload: { t: 1 }, project: 'p1' });
    recordEvent({ session_id: 'sB', ts: '2026-05-10T10:00:00Z', kind: 'prompt', payload: { t: 2 }, project: 'p2' });
    const res = await invoke(app.routes.get.get('/api/sessions')!, { query: { project: 'p1' } });
    const body = res.body as { sessions: Array<{ session_id: string }>; total: number };
    expect(body.total).toBe(1);
    expect(body.sessions[0].session_id).toBe('sA');
  });

  it('honours limit + offset', async () => {
    for (let i = 0; i < 5; i++) {
      recordEvent({
        session_id: `s${i}`,
        ts: `2026-05-10T1${i}:00:00Z`,
        kind: 'prompt',
        payload: { i },
      });
    }
    const res = await invoke(app.routes.get.get('/api/sessions')!, { query: { limit: '2', offset: '1' } });
    const body = res.body as { sessions: unknown[]; total: number; offset: number; limit: number; hasMore: boolean };
    expect(body.total).toBe(5);
    expect(body.sessions).toHaveLength(2);
    expect(body.offset).toBe(1);
    expect(body.limit).toBe(2);
    expect(body.hasMore).toBe(true);
  });

  it('clamps limit to the 200 max', async () => {
    const res = await invoke(app.routes.get.get('/api/sessions')!, { query: { limit: '9999' } });
    const body = res.body as { limit: number };
    expect(body.limit).toBe(200);
  });
});

describe('GET /api/sessions/:id', () => {
  it('returns 404 for unknown session', async () => {
    const res = await invoke(app.routes.get.get('/api/sessions/:id')!, { params: { id: 'nope' } });
    expect(res.statusCode).toBe(404);
  });

  it('returns metadata + kind histogram for an existing session', async () => {
    recordEvents([
      { session_id: 's-meta', ts: '2026-05-10T10:00:00Z', kind: 'prompt', payload: { text: 'q' }, project: 'p1' },
      { session_id: 's-meta', ts: '2026-05-10T10:00:01Z', kind: 'response', payload: { text: 'a' }, project: 'p1' },
      { session_id: 's-meta', ts: '2026-05-10T10:00:02Z', kind: 'tool_call', payload: { tool: 'Read' }, project: 'p1' },
      { session_id: 's-meta', ts: '2026-05-10T10:00:03Z', kind: 'tool_call', payload: { tool: 'Bash' }, project: 'p1' },
    ]);
    const res = await invoke(app.routes.get.get('/api/sessions/:id')!, { params: { id: 's-meta' } });
    expect(res.statusCode).toBe(200);
    const body = res.body as { session_id: string; event_count: number; first_ts: string; last_ts: string; kinds: Record<string, number> };
    expect(body.session_id).toBe('s-meta');
    expect(body.event_count).toBe(4);
    expect(body.kinds).toEqual({ prompt: 1, response: 1, tool_call: 2 });
    expect(body.first_ts).toBe('2026-05-10T10:00:00Z');
    expect(body.last_ts).toBe('2026-05-10T10:00:03Z');
  });
});

describe('GET /api/sessions/:id/events', () => {
  it('returns events in ts order with parsed payload', async () => {
    recordEvents([
      { session_id: 's-ev', ts: '2026-05-10T10:00:01Z', kind: 'response', payload: { text: 'a1' } },
      { session_id: 's-ev', ts: '2026-05-10T10:00:00Z', kind: 'prompt', payload: { text: 'q1' } },
    ]);
    const res = await invoke(app.routes.get.get('/api/sessions/:id/events')!, { params: { id: 's-ev' }, query: {} });
    const body = res.body as { events: Array<{ kind: string; payload: { text: string } }>; total: number };
    expect(body.total).toBe(2);
    expect(body.events.map((e) => e.kind)).toEqual(['prompt', 'response']);
    expect(body.events[0].payload).toEqual({ text: 'q1' });
  });

  it('paginates with offset/limit + hasMore', async () => {
    for (let i = 0; i < 5; i++) {
      recordEvent({
        session_id: 's-page',
        ts: `2026-05-10T10:00:0${i}Z`,
        kind: 'prompt',
        payload: { i },
      });
    }
    const res = await invoke(app.routes.get.get('/api/sessions/:id/events')!, {
      params: { id: 's-page' },
      query: { limit: '2', offset: '2' },
    });
    const body = res.body as { events: Array<{ payload: { i: number } }>; total: number; offset: number; hasMore: boolean };
    expect(body.total).toBe(5);
    expect(body.events).toHaveLength(2);
    expect(body.offset).toBe(2);
    expect(body.hasMore).toBe(true);
    expect(body.events[0].payload.i).toBe(2);
    expect(body.events[1].payload.i).toBe(3);
  });

  it('returns empty events array for an unknown session id', async () => {
    const res = await invoke(app.routes.get.get('/api/sessions/:id/events')!, { params: { id: 'nope' }, query: {} });
    expect(res.statusCode).toBe(200);
    expect((res.body as { events: unknown[]; total: number }).events).toEqual([]);
    expect((res.body as { total: number }).total).toBe(0);
  });
});

describe('POST /api/sessions/import-jsonl', () => {
  let tempDir: string;

  beforeEach(() => {
    tempDir = mkdtempSync(join(tmpdir(), 'sc-import-route-'));
  });

  afterEach(() => {
    rmSync(tempDir, { recursive: true, force: true });
  });

  it('returns 400 when path is missing or not a string', async () => {
    const res1 = await invoke(app.routes.post.get('/api/sessions/import-jsonl')!, { body: {} });
    expect(res1.statusCode).toBe(400);
    const res2 = await invoke(app.routes.post.get('/api/sessions/import-jsonl')!, { body: { path: 123 } });
    expect(res2.statusCode).toBe(400);
  });

  it('returns 404 when the file does not exist', async () => {
    const res = await invoke(app.routes.post.get('/api/sessions/import-jsonl')!, {
      body: { path: join(tempDir, 'nope.jsonl') },
    });
    expect(res.statusCode).toBe(404);
  });

  it('imports a valid JSONL transcript and returns the result envelope', async () => {
    const path = join(tempDir, 'sample.jsonl');
    writeFileSync(
      path,
      [
        '{"type":"user","sessionId":"sX","timestamp":"2026-05-10T20:00:00Z","message":{"role":"user","content":[{"type":"text","text":"q"}]}}',
        '{"type":"assistant","sessionId":"sX","timestamp":"2026-05-10T20:00:01Z","message":{"role":"assistant","content":[{"type":"text","text":"a"}]}}',
      ].join('\n'),
    );
    const res = await invoke(app.routes.post.get('/api/sessions/import-jsonl')!, { body: { path } });
    expect(res.statusCode).toBe(200);
    const body = res.body as { sessionId: string; eventCount: number };
    expect(body.sessionId).toBe('sX');
    expect(body.eventCount).toBe(2);

    // Verify rows actually landed in the table — proves the route uses
    // the real importer, not a stub.
    const count = (
      getDatabase().prepare("SELECT COUNT(*) AS c FROM session_events WHERE session_id = 'sX'").get() as { c: number }
    ).c;
    expect(count).toBe(2);
  });
});
