import { afterEach, beforeEach, describe, expect, it, jest } from '@jest/globals';

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
      get(route: string, ...handlers: Handler[]) {
        routes.get.set(route, handlers);
      },
      post(route: string, ...handlers: Handler[]) {
        routes.post.set(route, handlers);
      },
      patch(route: string, ...handlers: Handler[]) {
        routes.patch.set(route, handlers);
      },
      delete(route: string, ...handlers: Handler[]) {
        routes.delete.set(route, handlers);
      },
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

describe('API route mutation regressions', () => {
  const originalHome = process.env.HOME;
  const originalUserProfile = process.env.USERPROFILE;

  beforeEach(() => {
    jest.resetModules();
  });

  afterEach(async () => {
    const initModule = await import('../../database/init.js');
    initModule.closeDatabase();
    jest.restoreAllMocks();
    jest.resetModules();
    if (originalHome === undefined) {
      delete process.env.HOME;
    } else {
      process.env.HOME = originalHome;
    }
    if (originalUserProfile === undefined) {
      delete process.env.USERPROFILE;
    } else {
      process.env.USERPROFILE = originalUserProfile;
    }
  });

  describe('/api/cloud/config', () => {
    async function loadSystemRouteModule() {
      const state = {
        config: {
          cloudApiKey: null as string | null,
          cloudBaseUrl: 'https://api.shieldcortex.ai',
          cloudEnabled: false,
        },
        syncControls: {
          projectMode: 'all' as 'all' | 'include' | 'exclude',
          projects: [] as string[],
          contentMode: 'full' as 'full' | 'metadata',
          excludeSensitive: false,
        },
        openclawMemory: {
          autoMemory: false,
          dedupe: true,
          noveltyThreshold: 0.88,
          maxRecent: 300,
        },
      };

      jest.unstable_mockModule('../../cloud/config.js', () => ({
        getCloudConfig: () => state.config,
        getCloudSyncControls: () => state.syncControls,
        clearCloudConfigCache: jest.fn(),
        getDeviceId: () => 'device-123',
        getDeviceName: () => 'edith',
        getDefenceMode: () => 'balanced',
        getVerifyConfig: () => ({
          verifyEnabled: false,
          verifyMode: 'advisory',
          verifyTriggers: ['QUARANTINE'],
          verifyTimeoutMs: 5000,
        }),
        getOpenClawMemoryConfig: () => state.openclawMemory,
        getOpenClawAutoMemory: () => state.openclawMemory.autoMemory,
        getToolResponseScanConfig: () => ({
          scanToolResponses: false,
          toolResponseMode: 'advisory',
        }),
        getTrustedSkills: () => [],
        isConfigTampered: () => false,
        readRawConfig: () => ({}),
        shouldSyncProject: () => true,
        isSensitiveLevel: () => false,
        getCloudIronDomeCache: () => null,
        updateLastSyncAt: jest.fn(),
        addTrustedSkill: jest.fn(),
        removeTrustedSkill: jest.fn(),
        setCloudIronDomeCache: jest.fn(),
        setCloudConfig: (updates: Partial<typeof state.config>) => {
          state.config = { ...state.config, ...updates };
        },
        setCloudSyncControls: (updates: Partial<typeof state.syncControls>) => {
          state.syncControls = {
            ...state.syncControls,
            ...updates,
            ...(updates.projects ? { projects: [...updates.projects] } : {}),
          };
        },
        setDefenceMode: jest.fn(),
        setVerifyConfig: jest.fn(),
        setToolResponseScanConfig: jest.fn(),
        setOpenClawMemoryConfig: (updates: Partial<typeof state.openclawMemory>) => {
          state.openclawMemory = {
            ...state.openclawMemory,
            ...updates,
            ...(updates.noveltyThreshold !== undefined
              ? { noveltyThreshold: Math.max(0.6, Math.min(updates.noveltyThreshold, 0.99)) }
              : {}),
            ...(updates.maxRecent !== undefined
              ? { maxRecent: Math.floor(Math.max(50, Math.min(updates.maxRecent, 1000))) }
              : {}),
          };
        },
        setOpenClawAutoMemory: jest.fn(),
      }));

      jest.unstable_mockModule('../../cloud/sync-queue.js', () => ({
        getQueueStats: () => ({
          queue: { pending: 0, failed: 0, synced: 0 },
          breakdown: [],
          oldestPendingAgeMs: null,
          nextRetryAt: null,
          recentFailures: [],
        }),
        enqueueFailedSync: jest.fn(),
        enqueueFailedMemorySync: jest.fn(),
        enqueueFailedGraphSync: jest.fn(),
        enqueueFailedQuarantineSync: jest.fn(),
        processRetryQueue: jest.fn(),
        purgeOldEntries: jest.fn(),
      }));

      const routeModule = await import('../routes/system.js');
      return { routeModule, state };
    }

    it('rejects enabling cloud sync without an API key', async () => {
      const { routeModule } = await loadSystemRouteModule();
      const { app, routes } = createFakeApp();

      routeModule.registerSystemRoutes(app as never, {
        broadcast: jest.fn(),
        clients: new Set(),
        requireIronDomeAction: () => (_req, _res, next) => next(),
      });

      const handlers = routes.post.get('/api/cloud/config');
      expect(handlers).toBeDefined();

      const res = await invokeHandlers(handlers!, {
        body: { cloudEnabled: true, cloudBaseUrl: 'https://api.shieldcortex.ai' },
      });

      expect(res.statusCode).toBe(400);
      expect(res.body).toEqual({ error: 'Cloud API key required before enabling cloud sync' });
    });

    it('persists normalized cloud sync and OpenClaw mutation values', async () => {
      const { routeModule, state } = await loadSystemRouteModule();
      const { app, routes } = createFakeApp();

      routeModule.registerSystemRoutes(app as never, {
        broadcast: jest.fn(),
        clients: new Set(),
        requireIronDomeAction: () => (_req, _res, next) => next(),
      });

      const handlers = routes.post.get('/api/cloud/config');
      expect(handlers).toBeDefined();

      const res = await invokeHandlers(handlers!, {
        body: {
          cloudApiKey: '  test-key  ',
          cloudEnabled: true,
          cloudBaseUrl: 'https://example.com/base',
          cloudSyncProjectMode: 'include',
          cloudSyncProjects: [' zebra ', 'alpha', 'alpha', ''],
          cloudSyncContentMode: 'metadata',
          cloudSyncExcludeSensitive: true,
          openclawAutoMemory: true,
          openclawAutoMemoryDedupe: false,
          openclawAutoMemoryNoveltyThreshold: 0.7,
          openclawAutoMemoryMaxRecent: 25,
        },
      });

      expect(res.statusCode).toBe(200);
      expect(res.body).toEqual(expect.objectContaining({
        success: true,
        enabled: true,
        apiKeySet: true,
        baseUrl: 'https://example.com/base',
        syncControls: {
          projectMode: 'include',
          projects: ['alpha', 'zebra'],
          contentMode: 'metadata',
          excludeSensitive: true,
        },
        openclawMemory: {
          autoMemory: true,
          dedupe: false,
          noveltyThreshold: 0.7,
          maxRecent: 50,
        },
      }));

      expect(state.config).toEqual({
        cloudApiKey: 'test-key',
        cloudBaseUrl: 'https://example.com/base',
        cloudEnabled: true,
      });
      expect(state.syncControls).toEqual({
        projectMode: 'include',
        projects: ['alpha', 'zebra'],
        contentMode: 'metadata',
        excludeSensitive: true,
      });
      expect(state.openclawMemory).toEqual({
        autoMemory: true,
        dedupe: false,
        noveltyThreshold: 0.7,
        maxRecent: 50,
      });
    });
  });

  describe('/api/memories/:id/review', () => {
    it('rejects unsupported review actions at the route layer', async () => {
      const initModule = await import('../../database/init.js');
      const storeModule = await import('../../memory/store.js');
      const routeModule = await import('../routes/memories.js');
      initModule.initDatabase(':memory:');

      const memory = storeModule.addMemory({
        title: 'Review target',
        content: 'Route level review test',
        project: 'ShieldCortex-Project',
      });

      const { app, routes } = createFakeApp();
      routeModule.registerMemoryRoutes(app as never, {
        requireNotLocked: (_req, _res, next) => next(),
        requireIronDomeAction: () => (_req, _res, next) => next(),
      });

      const handlers = routes.patch.get('/api/memories/:id/review');
      expect(handlers).toBeDefined();

      const res = await invokeHandlers(handlers!, {
        params: { id: String(memory.id) },
        body: { action: 'doSomethingFake' },
      });

      expect(res.statusCode).toBe(400);
      expect(res.body).toEqual({ error: 'Unsupported review action' });
    });

    it('persists project rescope decisions through the review route', async () => {
      const initModule = await import('../../database/init.js');
      const storeModule = await import('../../memory/store.js');
      const routeModule = await import('../routes/memories.js');
      initModule.initDatabase(':memory:');

      const memory = storeModule.addMemory({
        title: 'Scoped review target',
        content: 'Needs to move back to project scope',
        scope: 'global',
        project: null as never,
      });

      const { app, routes } = createFakeApp();
      routeModule.registerMemoryRoutes(app as never, {
        requireNotLocked: (_req, _res, next) => next(),
        requireIronDomeAction: () => (_req, _res, next) => next(),
      });

      const handlers = routes.patch.get('/api/memories/:id/review');
      expect(handlers).toBeDefined();

      const res = await invokeHandlers(handlers!, {
        params: { id: String(memory.id) },
        body: {
          action: 'rescopeProject',
          project: 'ShieldCortex-Project',
          reviewedBy: 'operator',
        },
      });

      const updated = storeModule.getMemoryById(memory.id);
      expect(res.statusCode).toBe(200);
      expect(updated?.scope).toBe('project');
      expect(updated?.project).toBe('ShieldCortex-Project');
      expect(updated?.reviewedBy).toBe('operator');
    });

    it('canonicalizes and pins memories through the review route', async () => {
      const initModule = await import('../../database/init.js');
      const storeModule = await import('../../memory/store.js');
      const routeModule = await import('../routes/memories.js');
      initModule.initDatabase(':memory:');

      const memory = storeModule.addMemory({
        title: 'Canonical target',
        content: 'Promote this memory as the canonical one',
      });

      const { app, routes } = createFakeApp();
      routeModule.registerMemoryRoutes(app as never, {
        requireNotLocked: (_req, _res, next) => next(),
        requireIronDomeAction: () => (_req, _res, next) => next(),
      });

      const handlers = routes.patch.get('/api/memories/:id/review');
      expect(handlers).toBeDefined();

      const res = await invokeHandlers(handlers!, {
        params: { id: String(memory.id) },
        body: {
          action: 'canonicalize',
          reviewedBy: 'operator',
        },
      });

      const updated = storeModule.getMemoryById(memory.id);
      expect(res.statusCode).toBe(200);
      expect(updated?.status).toBe('canonical');
      expect(updated?.pinned).toBe(true);
      expect(updated?.reviewedBy).toBe('operator');
    });
  });
});
