import { afterEach, beforeEach, describe, expect, it, jest } from '@jest/globals';

type Handler = (req: any, res: any, next: (err?: unknown) => void) => unknown;

function createFakeApp() {
  const routes = {
    post: new Map<string, Handler[]>(),
  };

  return {
    app: {
      get() { /* not needed */ },
      post(route: string, ...handlers: Handler[]) {
        routes.post.set(route, handlers);
      },
      patch() { /* not needed */ },
      put() { /* not needed */ },
      delete() { /* not needed */ },
    },
    routes,
  };
}

async function invokeHandlers(handlers: Handler[]) {
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
      { params: {}, query: {}, body: {} },
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

describe('memory files API route', () => {
  beforeEach(() => {
    jest.resetModules();
  });

  afterEach(() => {
    jest.restoreAllMocks();
    jest.resetModules();
  });

  it('uses the memory_file_scan Pro gate', async () => {
    const { registerAdminRoutes } = await import('../routes/admin.js');
    const seenFeatures: string[] = [];
    const { app, routes } = createFakeApp();

    registerAdminRoutes(app as never, {
      brainWorker: {} as never,
      requireNotLocked: (_req, _res, next) => next(),
      requireProFeature: (feature) => {
        seenFeatures.push(feature);
        return (_req, res) => res.status(403).json({
          error: 'Feature requires upgrade',
          code: 'FEATURE_GATED',
          feature,
          requiredTier: 'pro',
        });
      },
      requireIronDomeAction: () => (_req, _res, next) => next(),
    });

    const handlers = routes.post.get('/api/v1/memory-files/scan');
    expect(handlers).toBeDefined();
    expect(seenFeatures).toContain('memory_file_scan');

    const res = await invokeHandlers(handlers!);
    expect(res.statusCode).toBe(403);
    expect(res.body).toEqual(expect.objectContaining({
      code: 'FEATURE_GATED',
      feature: 'memory_file_scan',
      requiredTier: 'pro',
    }));
  });

  it('returns the scan response shape for an empty result', async () => {
    jest.unstable_mockModule('../../audit/memory-scanner.js', () => ({
      scanMemoryFilesDetailed: jest.fn(() => ({
        scannedAt: '2026-04-30T10:00:00.000Z',
        summary: {
          total: 0,
          safe: 0,
          flagged: 0,
          critical: 0,
          high: 0,
          medium: 0,
        },
        files: [],
        durationMs: 2,
      })),
      queueMemoryFileScanFindings: jest.fn(() => ({
        created: 0,
        updated: 0,
        skippedSafe: 0,
        skippedReviewed: 0,
        items: [],
      })),
    }));

    const { registerAdminRoutes } = await import('../routes/admin.js');
    const { app, routes } = createFakeApp();

    registerAdminRoutes(app as never, {
      brainWorker: {} as never,
      requireNotLocked: (_req, _res, next) => next(),
      requireProFeature: () => (_req, _res, next) => next(),
      requireIronDomeAction: () => (_req, _res, next) => next(),
    });

    const handlers = routes.post.get('/api/v1/memory-files/scan');
    expect(handlers).toBeDefined();

    const res = await invokeHandlers(handlers!);
    expect(res.statusCode).toBe(200);
    expect(res.body).toEqual({
      success: true,
      scannedAt: '2026-04-30T10:00:00.000Z',
      summary: {
        total: 0,
        safe: 0,
        flagged: 0,
        critical: 0,
        high: 0,
        medium: 0,
      },
      quarantine: {
        created: 0,
        updated: 0,
        skippedSafe: 0,
        skippedReviewed: 0,
        items: [],
      },
      files: [],
    });
  });
});
