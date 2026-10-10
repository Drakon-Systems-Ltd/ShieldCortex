/**
 * Dashboard bulk quarantine→Cloud sync (`POST /api/quarantine/sync-to-cloud`)
 * must apply the SAME CloudSyncControls gate and redaction as the automatic
 * quarantine sync path (`syncQuarantineToCloud`).
 *
 * Before the fix the bulk route read `quarantine` rows and POSTed
 * `original_content` verbatim: no `excludeSensitive` check, no project
 * filter, no metadata mode, no credential redaction. That broke the
 * "CONFIDENTIAL+ excluded by default" promise for anyone who pressed the
 * bulk button. These tests drive the real route against an in-memory DB with
 * the real config store (isolated HOME) and capture what `fetch` would send.
 *
 * Credential redaction itself is covered by `quarantine-sync-controls.test.ts`
 * against the shared helper; here we prove the route goes THROUGH that helper.
 */
import { afterEach, beforeEach, describe, expect, it, jest } from '@jest/globals';
import { mkdtempSync, rmSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';

type Handler = (req: any, res: any, next: (err?: unknown) => void) => unknown;

function createFakeApp() {
  const routes = {
    get: new Map<string, Handler[]>(),
    post: new Map<string, Handler[]>(),
    patch: new Map<string, Handler[]>(),
    put: new Map<string, Handler[]>(),
    delete: new Map<string, Handler[]>(),
  };
  return {
    app: {
      get(route: string, ...handlers: Handler[]) { routes.get.set(route, handlers); },
      post(route: string, ...handlers: Handler[]) { routes.post.set(route, handlers); },
      patch(route: string, ...handlers: Handler[]) { routes.patch.set(route, handlers); },
      put(route: string, ...handlers: Handler[]) { routes.put.set(route, handlers); },
      delete(route: string, ...handlers: Handler[]) { routes.delete.set(route, handlers); },
    },
    routes,
  };
}

async function invokeHandlers(handlers: Handler[], req: Record<string, unknown> = {}) {
  const res: {
    statusCode: number;
    body: unknown;
    status: (code: number) => typeof res;
    json: (payload: unknown) => typeof res;
  } = {
    statusCode: 200,
    body: undefined,
    status(code: number) {
      this.statusCode = code;
      return this;
    },
    json(payload: unknown) {
      this.body = payload;
      return this;
    },
  };

  for (const handler of handlers) {
    let nextCalled = false;
    await handler(
      { params: {}, query: {}, body: {}, get: () => undefined, ...req },
      res,
      (err?: unknown) => {
        if (err) throw err;
        nextCalled = true;
      },
    );
    if (res.body !== undefined) break;
    if (handler.length >= 3 && !nextCalled) break;
  }
  return res;
}

const passGuard = () => (_req: unknown, _res: unknown, next: (err?: unknown) => void) => next();

// Email + sort code → CONFIDENTIAL under the real classifier.
const CONFIDENTIAL_CONTENT = 'Customer record: contact jane.doe@example.com, sort code 12-34-56';
// Nothing identifying → PUBLIC under the real classifier.
const PUBLIC_CONTENT = 'Release notes: the widget now renders faster on large boards.';

function insertQuarantineRow(
  db: { prepare: (sql: string) => { run: (...args: unknown[]) => unknown } },
  row: { content: string; title?: string; project?: string | null },
): void {
  db.prepare(
    `INSERT INTO quarantine
       (original_content, original_title, project, source_type, source_identifier,
        reason, threat_indicators, anomaly_score, firewall_result, status)
     VALUES (?, ?, ?, 'agent', 'unit-test', 'injection suspected', '["pattern-a"]', 0.9, 'QUARANTINE', 'pending')`,
  ).run(row.content, row.title ?? null, row.project ?? null);
}

function captureFetch(): { bodies: string[]; calls: () => number } {
  const bodies: string[] = [];
  const fetchMock = jest.fn(async (_url: unknown, init?: { body?: string }) => {
    if (init?.body) bodies.push(init.body);
    return { ok: true, status: 200, text: async () => '' };
  });
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  (globalThis as any).fetch = fetchMock;
  return { bodies, calls: () => fetchMock.mock.calls.length };
}

async function runBulkSync() {
  const routeModule = await import('../routes/admin.js');
  const { app, routes } = createFakeApp();
  routeModule.registerAdminRoutes(app as never, {
    brainWorker: {} as never,
    requireNotLocked: passGuard(),
    requireProFeature: () => passGuard(),
    requireIronDomeAction: () => passGuard(),
  });
  const handlers = routes.post.get('/api/quarantine/sync-to-cloud');
  expect(handlers).toBeDefined();
  return invokeHandlers(handlers!);
}

describe('POST /api/quarantine/sync-to-cloud applies the quarantine sync gate', () => {
  const originalHome = process.env.HOME;
  const originalFetch = globalThis.fetch;
  let isolatedHome: string;

  beforeEach(async () => {
    jest.resetModules();
    isolatedHome = mkdtempSync(join(tmpdir(), 'sc-qbulk-'));
    process.env.HOME = isolatedHome;
    process.env.SHIELDCORTEX_CONFIG_DIR = join(isolatedHome, 'cfg');

    const initModule = await import('../../database/init.js');
    initModule.closeDatabase();
    initModule.initDatabase(':memory:');

    const config = await import('../../cloud/config.js');
    config.clearCloudConfigCache();
    config.setCloudConfig({
      cloudEnabled: true,
      cloudApiKey: 'sc_test_key',
      cloudBaseUrl: 'https://api.shieldcortex.test',
    });
    // Shipped defaults: full content, but CONFIDENTIAL+ excluded.
    config.setCloudSyncControls({
      projectMode: 'all',
      projects: [],
      contentMode: 'full',
      excludeSensitive: true,
    });
  });

  afterEach(async () => {
    globalThis.fetch = originalFetch;
    const initModule = await import('../../database/init.js');
    initModule.closeDatabase();
    if (originalHome === undefined) delete process.env.HOME;
    else process.env.HOME = originalHome;
    delete process.env.SHIELDCORTEX_CONFIG_DIR;
    rmSync(isolatedHome, { recursive: true, force: true });
    jest.restoreAllMocks();
    jest.resetModules();
  });

  it('fixtures classify as intended under the real classifier', async () => {
    const { classifySensitivity } = await import('../../defence/sensitivity/index.js');
    expect(classifySensitivity(CONFIDENTIAL_CONTENT, '').level).toBe('CONFIDENTIAL');
    expect(classifySensitivity(PUBLIC_CONTENT, '').level).toBe('PUBLIC');
  });

  it('does NOT send a CONFIDENTIAL row when excludeSensitive is true, but still sends a PUBLIC row', async () => {
    const { getDatabase } = await import('../../database/init.js');
    insertQuarantineRow(getDatabase(), { content: CONFIDENTIAL_CONTENT, title: 'customer' });
    insertQuarantineRow(getDatabase(), { content: PUBLIC_CONTENT, title: 'release' });

    const { bodies, calls } = captureFetch();
    const res = await runBulkSync();

    expect(res.statusCode).toBe(200);
    expect(res.body).toEqual(expect.objectContaining({ synced: 1, skipped: 1, total: 2 }));
    expect(calls()).toBe(1);

    const everythingSent = bodies.join('\n');
    expect(everythingSent).not.toContain(CONFIDENTIAL_CONTENT);
    expect(everythingSent).not.toContain('jane.doe@example.com');

    const sent = JSON.parse(bodies[0]) as Record<string, unknown>;
    expect(sent.original_content).toBe(PUBLIC_CONTENT);
    expect(sent.original_title).toBe('release');
    expect(sent.content_redacted).toBe(false);
    expect(sent.sensitivity_level).toBe('PUBLIC');
    expect(typeof sent.device_id).toBe('string');
  });

  it('sends a CONFIDENTIAL row only once the user has opted in (excludeSensitive=false)', async () => {
    const config = await import('../../cloud/config.js');
    config.setCloudSyncControls({ excludeSensitive: false });

    const { getDatabase } = await import('../../database/init.js');
    insertQuarantineRow(getDatabase(), { content: CONFIDENTIAL_CONTENT, title: 'customer' });

    const { bodies } = captureFetch();
    const res = await runBulkSync();

    expect(res.statusCode).toBe(200);
    expect(res.body).toEqual(expect.objectContaining({ synced: 1, skipped: 0, total: 1 }));
    expect(bodies).toHaveLength(1);
    const sent = JSON.parse(bodies[0]) as Record<string, unknown>;
    expect(sent.sensitivity_level).toBe('CONFIDENTIAL');
  });

  it('ships only a placeholder in metadata-only mode', async () => {
    const config = await import('../../cloud/config.js');
    config.setCloudSyncControls({ contentMode: 'metadata', excludeSensitive: false });

    const { getDatabase } = await import('../../database/init.js');
    insertQuarantineRow(getDatabase(), { content: PUBLIC_CONTENT, title: 'release' });

    const { bodies } = captureFetch();
    const res = await runBulkSync();

    expect(res.statusCode).toBe(200);
    expect(bodies).toHaveLength(1);
    expect(bodies[0]).not.toContain(PUBLIC_CONTENT);
    const sent = JSON.parse(bodies[0]) as Record<string, unknown>;
    expect(sent.content_redacted).toBe(true);
    expect(sent.original_title).toBe('[Metadata only]');
  });

  it('honours the project exclusion filter', async () => {
    const config = await import('../../cloud/config.js');
    config.setCloudSyncControls({ projectMode: 'exclude', projects: ['secret-project'] });

    const { getDatabase } = await import('../../database/init.js');
    insertQuarantineRow(getDatabase(), { content: PUBLIC_CONTENT, project: 'secret-project' });
    insertQuarantineRow(getDatabase(), { content: PUBLIC_CONTENT, project: 'open-project' });

    const { bodies } = captureFetch();
    const res = await runBulkSync();

    expect(res.statusCode).toBe(200);
    expect(res.body).toEqual(expect.objectContaining({ synced: 1, skipped: 1, total: 2 }));
    expect(bodies).toHaveLength(1);
    expect((JSON.parse(bodies[0]) as Record<string, unknown>).project).toBe('open-project');
  });
});
