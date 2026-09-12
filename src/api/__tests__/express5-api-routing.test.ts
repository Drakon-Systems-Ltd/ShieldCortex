/**
 * #466 — express 4 → 5 routing regression.
 *
 * The direct `express` dependency moved from `^4.21.0` to `^5.2.1` because
 * express 4.22.2 (the last 4.x) pins `qs: ~6.15.1`, and the qs fix for
 * GHSA-4mjr-xmp4-gh2g / GHSA-x5fp-wj9c-mxmx only landed in qs 6.16.0 — a
 * version that range can never reach. express 5 asks for `qs: ^6.14.0`, so the
 * patched qs resolves by ordinary semver in a consumer's tree.
 *
 * express 5 carries path-to-regexp v8, which rejects the bare `*` wildcard the
 * API catch-all used (`'/api/*'` throws at registration). These tests pin the
 * replacement pattern against a REAL express router and assert it reproduces
 * the express 4 behaviour matrix exactly — measured on express 4.22.2 before
 * the bump:
 *
 *   /api/health   -> 200 JSON (real route wins)
 *   /api/foo      -> 404 JSON (catch-all)
 *   /api/foo/bar  -> 404 JSON (catch-all)
 *   /api/         -> 404 JSON (catch-all)  <- `/api/*splat` would MISS this
 *   /api          -> falls through         <- `/api{/*splat}` would CATCH this
 *   /apix, /, /x  -> fall through
 */

import { afterEach, describe, expect, it } from '@jest/globals';
import express from 'express';
import { createServer, type Server } from 'http';
import { __test__ } from '../visualization-server.js';

const FELL_THROUGH = 'fell-through';

let server: Server | undefined;

async function listen(app: express.Express): Promise<string> {
  const srv = createServer(app);
  await new Promise<void>((resolve) => srv.listen(0, '127.0.0.1', resolve));
  server = srv;
  const addr = srv.address();
  if (!addr || typeof addr === 'string') throw new Error('no port');
  return `http://127.0.0.1:${addr.port}`;
}

/**
 * Mount the real catch-all pattern the API server uses, with a stand-in for a
 * concrete route ahead of it and a terminal marker behind it, so a request can
 * be classified as "matched a route", "hit the catch-all" or "fell through".
 */
async function mountCatchAll(): Promise<string> {
  const app = express();
  app.get('/api/health', (_req, res) => {
    res.json({ ok: true });
  });
  app.all(__test__.API_CATCH_ALL_PATH, (_req, res) => {
    res.status(404).json({ error: 'Not found' });
  });
  app.use((_req, res) => {
    res.status(404).send(FELL_THROUGH);
  });
  return listen(app);
}

async function probe(base: string, path: string): Promise<{ status: number; body: string }> {
  const res = await fetch(`${base}${path}`);
  return { status: res.status, body: await res.text() };
}

afterEach(async () => {
  if (server) {
    const srv = server;
    server = undefined;
    await new Promise<void>((resolve) => srv.close(() => resolve()));
  }
});

describe('#466 — API catch-all under express 5', () => {
  it('registers without throwing (a bare `*` wildcard would throw here)', async () => {
    await expect(mountCatchAll()).resolves.toMatch(/^http:\/\/127\.0\.0\.1:\d+$/);
  });

  it('lets a concrete /api route win over the catch-all', async () => {
    const base = await mountCatchAll();
    const res = await probe(base, '/api/health');
    expect(res.status).toBe(200);
    expect(JSON.parse(res.body)).toEqual({ ok: true });
  });

  it.each(['/api/foo', '/api/foo/bar', '/api/deep/nested/path', '/api/'])(
    'answers unmatched %s with JSON 404 rather than express HTML',
    async (path) => {
      const base = await mountCatchAll();
      const res = await probe(base, path);
      expect(res.status).toBe(404);
      expect(JSON.parse(res.body)).toEqual({ error: 'Not found' });
    },
  );

  it.each(['/api', '/apix', '/', '/dashboard'])(
    'does not swallow %s — non-API paths still fall through to the shell',
    async (path) => {
      const base = await mountCatchAll();
      const res = await probe(base, path);
      expect(res.status).toBe(404);
      expect(res.body).toBe(FELL_THROUGH);
    },
  );

  it('answers non-GET methods on unmatched /api paths with the same JSON 404', async () => {
    const base = await mountCatchAll();
    for (const method of ['POST', 'PUT', 'PATCH', 'DELETE']) {
      const res = await fetch(`${base}/api/nope`, { method });
      expect(res.status).toBe(404);
      expect(JSON.parse(await res.text())).toEqual({ error: 'Not found' });
    }
  });
});

describe('#466 — express 5 query parsing for the shapes the API actually reads', () => {
  it('parses scalar and repeated query keys the way the route handlers expect', async () => {
    const app = express();
    let seen: unknown;
    app.get('/api/echo', (req, res) => {
      seen = req.query;
      res.json({ ok: true });
    });
    const base = await listen(app);
    await probe(base, '/api/echo?risk=HIGH&deep=true&tag=a&tag=b');
    expect(seen).toEqual({ risk: 'HIGH', deep: 'true', tag: ['a', 'b'] });
  });
});
