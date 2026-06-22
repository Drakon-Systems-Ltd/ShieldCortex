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
        proactiveRecall: false,
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
        getLastSyncAt: () => null,
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
        isProactiveRecallEnabled: () => state.proactiveRecall,
        setProactiveRecall: (enabled: boolean) => {
          state.proactiveRecall = enabled;
        },
        getRankerConfig: () => ({
          engine: 'rrf' as const,
          rrfK: 60,
          weights: { fts: 0.4, vector: 0.6, graph: 0.3 },
        }),
        setRankerConfig: jest.fn(),
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
        reconcileSyncQueue: jest.fn(() => ({ removed: 0 })),
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

    it('exposes proactiveRecall in the GET response', async () => {
      const { routeModule, state } = await loadSystemRouteModule();
      const { app, routes } = createFakeApp();

      routeModule.registerSystemRoutes(app as never, {
        broadcast: jest.fn(),
        clients: new Set(),
        requireIronDomeAction: () => (_req, _res, next) => next(),
      });

      state.proactiveRecall = true;
      const handlers = routes.get.get('/api/cloud/config');
      expect(handlers).toBeDefined();

      const res = await invokeHandlers(handlers!, {});

      expect(res.statusCode).toBe(200);
      expect(res.body).toEqual(expect.objectContaining({ proactiveRecall: true }));
    });

    it('rejects non-boolean proactiveRecall', async () => {
      const { routeModule } = await loadSystemRouteModule();
      const { app, routes } = createFakeApp();

      routeModule.registerSystemRoutes(app as never, {
        broadcast: jest.fn(),
        clients: new Set(),
        requireIronDomeAction: () => (_req, _res, next) => next(),
      });

      const handlers = routes.post.get('/api/cloud/config');
      const res = await invokeHandlers(handlers!, {
        body: { proactiveRecall: 'yes' },
      });

      expect(res.statusCode).toBe(400);
      expect(res.body).toEqual({ error: 'proactiveRecall must be a boolean' });
    });

    it('round-trips proactiveRecall through POST and persists alongside openclawAutoMemory', async () => {
      const { routeModule, state } = await loadSystemRouteModule();
      const { app, routes } = createFakeApp();

      routeModule.registerSystemRoutes(app as never, {
        broadcast: jest.fn(),
        clients: new Set(),
        requireIronDomeAction: () => (_req, _res, next) => next(),
      });

      const handlers = routes.post.get('/api/cloud/config');
      const res = await invokeHandlers(handlers!, {
        body: { openclawAutoMemory: true, proactiveRecall: true },
      });

      expect(res.statusCode).toBe(200);
      expect(res.body).toEqual(expect.objectContaining({
        proactiveRecall: true,
        openclawMemory: expect.objectContaining({ autoMemory: true }),
      }));
      expect(state.proactiveRecall).toBe(true);
      expect(state.openclawMemory.autoMemory).toBe(true);
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

  describe('/api/memories/:id content placeholder guard', () => {
    it('never overwrites real content with the RESTRICTED redaction placeholder', async () => {
      const initModule = await import('../../database/init.js');
      const storeModule = await import('../../memory/store.js');
      const routeModule = await import('../routes/memories.js');
      const { RESTRICTED_CONTENT_PLACEHOLDER } = await import('../../defence/trust/read-guard.js');
      initModule.initDatabase(':memory:');

      const memory = storeModule.addMemory({
        title: 'Secret holder',
        content: 'the real secret value',
        project: 'ShieldCortex-Project',
      });

      const { app, routes } = createFakeApp();
      routeModule.registerMemoryRoutes(app as never, {
        requireNotLocked: (_req, _res, next) => next(),
        requireIronDomeAction: () => (_req, _res, next) => next(),
      });

      const handlers = routes.patch.get('/api/memories/:id');
      expect(handlers).toBeDefined();

      const res = await invokeHandlers(handlers!, {
        params: { id: String(memory.id) },
        body: { content: RESTRICTED_CONTENT_PLACEHOLDER, title: 'Renamed' },
      });

      expect(res.statusCode).toBe(200);
      const updated = storeModule.getMemoryById(memory.id);
      // The title edit lands, but the placeholder must NOT overwrite the real content.
      expect(updated?.title).toBe('Renamed');
      expect(updated?.content).toBe('the real secret value');
    });

    it('persists a genuine content edit', async () => {
      const initModule = await import('../../database/init.js');
      const storeModule = await import('../../memory/store.js');
      const routeModule = await import('../routes/memories.js');
      initModule.initDatabase(':memory:');

      const memory = storeModule.addMemory({ title: 'Doc', content: 'old', project: 'ShieldCortex-Project' });

      const { app, routes } = createFakeApp();
      routeModule.registerMemoryRoutes(app as never, {
        requireNotLocked: (_req, _res, next) => next(),
        requireIronDomeAction: () => (_req, _res, next) => next(),
      });

      const handlers = routes.patch.get('/api/memories/:id');
      const res = await invokeHandlers(handlers!, {
        params: { id: String(memory.id) },
        body: { content: 'new real content' },
      });

      expect(res.statusCode).toBe(200);
      expect(storeModule.getMemoryById(memory.id)?.content).toBe('new real content');
    });
  });

  describe('/api/memories/prune', () => {
    it('rejects salienceLte outside [0, 1]', async () => {
      const initModule = await import('../../database/init.js');
      const routeModule = await import('../routes/memories.js');
      initModule.initDatabase(':memory:');

      const { app, routes } = createFakeApp();
      routeModule.registerMemoryRoutes(app as never, {
        requireNotLocked: (_req, _res, next) => next(),
        requireIronDomeAction: () => (_req, _res, next) => next(),
      });

      const handlers = routes.post.get('/api/memories/prune');
      expect(handlers).toBeDefined();

      const res = await invokeHandlers(handlers!, { body: { salienceLte: 1.5 } });
      expect(res.statusCode).toBe(400);
      expect(res.body).toEqual({ error: 'salienceLte must be a number 0..1' });
    });

    it('returns matched count and sample without deleting on dryRun', async () => {
      const initModule = await import('../../database/init.js');
      const storeModule = await import('../../memory/store.js');
      const routeModule = await import('../routes/memories.js');
      initModule.initDatabase(':memory:');

      // Three low-salience old memories should match.
      const lowAndOld = storeModule.addMemory({
        title: 'Old low memory', content: 'fading away', project: 'p1', salience: 0.1,
      });
      // Force created_at to ~60 days ago (default ageDaysGte=30 should match).
      initModule.getDatabase().prepare("UPDATE memories SET created_at = datetime('now', '-60 days') WHERE id = ?").run(lowAndOld.id);
      const recent = storeModule.addMemory({
        title: 'Recent low memory', content: 'just made', project: 'p1', salience: 0.1,
      });
      const highSal = storeModule.addMemory({
        title: 'Important', content: 'keep me', project: 'p1', salience: 0.9,
      });
      initModule.getDatabase().prepare("UPDATE memories SET created_at = datetime('now', '-60 days') WHERE id = ?").run(highSal.id);

      const { app, routes } = createFakeApp();
      routeModule.registerMemoryRoutes(app as never, {
        requireNotLocked: (_req, _res, next) => next(),
        requireIronDomeAction: () => (_req, _res, next) => next(),
      });

      const handlers = routes.post.get('/api/memories/prune');
      const res = await invokeHandlers(handlers!, {
        body: { salienceLte: 0.2, ageDaysGte: 30, dryRun: true },
      });

      expect(res.statusCode).toBe(200);
      expect(res.body.matched).toBe(1);
      expect(res.body.deleted).toBeUndefined(); // dryRun
      expect(res.body.sample[0].id).toBe(lowAndOld.id);

      // Recent + high-salience untouched.
      expect(storeModule.getMemoryById(lowAndOld.id)).not.toBeNull();
      expect(storeModule.getMemoryById(recent.id)).not.toBeNull();
      expect(storeModule.getMemoryById(highSal.id)).not.toBeNull();
    });

    it('skips pinned memories when excludePinned is true (default)', async () => {
      const initModule = await import('../../database/init.js');
      const storeModule = await import('../../memory/store.js');
      const routeModule = await import('../routes/memories.js');
      initModule.initDatabase(':memory:');

      const pinned = storeModule.addMemory({
        title: 'Pinned old low', content: 'protect me', project: 'p1', salience: 0.1,
      });
      initModule.getDatabase()
        .prepare("UPDATE memories SET pinned = 1, created_at = datetime('now', '-60 days') WHERE id = ?")
        .run(pinned.id);

      const { app, routes } = createFakeApp();
      routeModule.registerMemoryRoutes(app as never, {
        requireNotLocked: (_req, _res, next) => next(),
        requireIronDomeAction: () => (_req, _res, next) => next(),
      });

      const handlers = routes.post.get('/api/memories/prune');
      const res = await invokeHandlers(handlers!, {
        body: { salienceLte: 0.2, ageDaysGte: 30, dryRun: true },
      });

      expect(res.statusCode).toBe(200);
      expect(res.body.matched).toBe(0); // pinned excluded
    });
  });

  describe('/api/memories/dedupe', () => {
    it('rejects out-of-range limit', async () => {
      const initModule = await import('../../database/init.js');
      const routeModule = await import('../routes/memories.js');
      initModule.initDatabase(':memory:');

      const { app, routes } = createFakeApp();
      routeModule.registerMemoryRoutes(app as never, {
        requireNotLocked: (_req, _res, next) => next(),
        requireIronDomeAction: () => (_req, _res, next) => next(),
      });

      const handlers = routes.post.get('/api/memories/dedupe');
      expect(handlers).toBeDefined();

      const res = await invokeHandlers(handlers!, { body: { limit: 9999 } });
      expect(res.statusCode).toBe(400);
      expect(res.body).toEqual({ error: 'limit must be a number 1..1000' });
    });

    it('returns groups + pairsFound without deleting on dryRun', async () => {
      const initModule = await import('../../database/init.js');
      const routeModule = await import('../routes/memories.js');
      initModule.initDatabase(':memory:');

      // Empty DB → zero groups, zero pairs, no error.
      const { app, routes } = createFakeApp();
      routeModule.registerMemoryRoutes(app as never, {
        requireNotLocked: (_req, _res, next) => next(),
        requireIronDomeAction: () => (_req, _res, next) => next(),
      });

      const handlers = routes.post.get('/api/memories/dedupe');
      const res = await invokeHandlers(handlers!, { body: { dryRun: true } });

      expect(res.statusCode).toBe(200);
      expect(res.body.pairsFound).toBe(0);
      expect(res.body.groups).toEqual([]);
      expect(res.body.merged).toBeUndefined();
    });
  });
});
