/**
 * #475 dashboard quarantine INSERT, #477 restart confirm, #478 update confirm.
 *
 * Fake-Express + mocked version helpers so restart/update cannot process.exit
 * or spawn npm. Isolated HOME. Does not touch the live operator tree.
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
      {
        params: {},
        query: {},
        body: {},
        get: () => undefined,
        ...req,
      },
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

describe('POST /api/memories/:id/quarantine (#475)', () => {
  const originalHome = process.env.HOME;
  let isolatedHome: string;

  beforeEach(async () => {
    isolatedHome = mkdtempSync(join(tmpdir(), 'sc-qtn-'));
    process.env.HOME = isolatedHome;
    process.env.SHIELDCORTEX_CONFIG_DIR = join(isolatedHome, 'cfg');
    const initModule = await import('../../database/init.js');
    initModule.closeDatabase();
    initModule.initDatabase(':memory:');
  });

  afterEach(async () => {
    const initModule = await import('../../database/init.js');
    initModule.closeDatabase();
    if (originalHome === undefined) delete process.env.HOME;
    else process.env.HOME = originalHome;
    delete process.env.SHIELDCORTEX_CONFIG_DIR;
    rmSync(isolatedHome, { recursive: true, force: true });
  });

  it('inserts firewall_result=QUARANTINE', async () => {
    const storeModule = await import('../../memory/store.js');
    const routeModule = await import('../routes/memories.js');
    const { getDatabase } = await import('../../database/init.js');

    const memory = storeModule.addMemory({
      title: 'followup seed',
      content: 'a perfectly ordinary memory',
      project: 'patrol',
    });

    const { app, routes } = createFakeApp();
    routeModule.registerMemoryRoutes(app as never, {
      requireNotLocked: passGuard(),
      requireIronDomeAction: () => passGuard(),
    });

    const handlers = routes.post.get('/api/memories/:id/quarantine');
    expect(handlers).toBeDefined();

    const res = await invokeHandlers(handlers!, {
      params: { id: String(memory.id) },
      body: { reason: 'manual test' },
    });

    expect(res.statusCode).toBe(200);
    expect(res.body).toEqual({ success: true, quarantined: memory.id });

    const row = getDatabase()
      .prepare('SELECT firewall_result, original_title, status FROM quarantine WHERE original_title = ?')
      .get('followup seed') as { firewall_result: string; original_title: string; status: string };
    expect(row.firewall_result).toBe('QUARANTINE');
    expect(row.status).toBe('pending');
  });
});

describe('POST /api/version/restart and /update confirm (#477 #478)', () => {
  const originalHome = process.env.HOME;
  const scheduleRestartMock = jest.fn();
  const performUpdateMock = jest.fn(async () => ({
    success: true,
    previousVersion: '5.0.0',
    newVersion: '5.0.0',
    requiresRestart: false,
  }));

  beforeEach(() => {
    process.env.HOME = mkdtempSync(join(tmpdir(), 'sc-ver-'));
    scheduleRestartMock.mockClear();
    performUpdateMock.mockClear();
    jest.resetModules();
    jest.unstable_mockModule('../version.js', () => ({
      checkForUpdates: jest.fn(),
      getCurrentVersion: () => '5.0.0',
      getRunningVersion: () => '5.0.0',
      performUpdate: () => performUpdateMock(),
      scheduleRestart: (delayMs?: number) => scheduleRestartMock(delayMs),
    }));
  });

  afterEach(() => {
    if (originalHome === undefined) delete process.env.HOME;
    else process.env.HOME = originalHome;
    jest.resetModules();
  });

  async function loadSystem() {
    const routeModule = await import('../routes/system.js');
    const { app, routes } = createFakeApp();
    const broadcast = jest.fn();
    routeModule.registerSystemRoutes(app as never, {
      broadcast,
      clients: new Set(),
      requireIronDomeAction: () => passGuard(),
    });
    return { routes, broadcast };
  }

  const rejectBodies: Array<{ name: string; body: unknown }> = [
    { name: 'empty object', body: {} },
    { name: 'missing body', body: undefined },
    { name: 'boolean true', body: { confirm: true } },
    { name: 'string yes', body: { confirm: 'yes' } },
    { name: 'wrong verb', body: { confirm: 'update' } },
  ];

  for (const { name, body } of rejectBodies) {
    it(`restart rejects ${name} without scheduling`, async () => {
      const { routes, broadcast } = await loadSystem();
      const handlers = routes.post.get('/api/version/restart');
      const res = await invokeHandlers(handlers!, { body });
      expect(res.statusCode).toBe(400);
      expect(res.body).toEqual({
        error: "this action requires confirm: 'restart'",
        code: 'CONFIRMATION_REQUIRED',
      });
      expect(scheduleRestartMock).not.toHaveBeenCalled();
      expect(broadcast).not.toHaveBeenCalled();
    });
  }

  it('restart with confirm=restart schedules once', async () => {
    const { routes } = await loadSystem();
    const handlers = routes.post.get('/api/version/restart');
    const res = await invokeHandlers(handlers!, { body: { confirm: 'restart' } });
    expect(res.statusCode).toBe(200);
    expect(scheduleRestartMock).toHaveBeenCalledTimes(1);
    expect(scheduleRestartMock).toHaveBeenCalledWith(3000);
  });

  it('update rejects empty body without calling performUpdate', async () => {
    const { routes } = await loadSystem();
    const handlers = routes.post.get('/api/version/update');
    const res = await invokeHandlers(handlers!, { body: {} });
    expect(res.statusCode).toBe(400);
    expect(res.body).toEqual({
      error: "this action requires confirm: 'update'",
      code: 'CONFIRMATION_REQUIRED',
    });
    expect(performUpdateMock).not.toHaveBeenCalled();
  });

  it('update rejects confirm=restart (wrong verb)', async () => {
    const { routes } = await loadSystem();
    const handlers = routes.post.get('/api/version/update');
    const res = await invokeHandlers(handlers!, { body: { confirm: 'restart' } });
    expect(res.statusCode).toBe(400);
    expect(performUpdateMock).not.toHaveBeenCalled();
  });

  it('update with confirm=update calls performUpdate', async () => {
    const { routes } = await loadSystem();
    const handlers = routes.post.get('/api/version/update');
    const res = await invokeHandlers(handlers!, { body: { confirm: 'update' } });
    expect(res.statusCode).toBe(200);
    expect(performUpdateMock).toHaveBeenCalledTimes(1);
  });
});
