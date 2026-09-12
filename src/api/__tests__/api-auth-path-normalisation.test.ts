/**
 * #474 — API authentication must not be bypassable by respelling the path.
 *
 * express route matching is case-INSENSITIVE by default: `/API/memories`
 * reaches the `/api/memories` handler. The auth gate asked
 * `req.path.startsWith('/api/')`, a case-SENSITIVE question, so every protected
 * route had an unprotected uppercase twin. Measured against the real server at
 * 52b0e0d9, with no `Authorization` header at all:
 *
 *   GET /api/gated-stats -> 401 AUTH_REQUIRED
 *   GET /API/gated-stats -> 200 {"total":0,"byFeature":{}}
 *   GET /api/memories    -> 401 AUTH_REQUIRED
 *   GET /API/memories    -> 200 {"memories":[...]}
 *
 * Two legs, because either alone would have missed it:
 *
 *   Structural — the gate's notion of "this is an API path" and the set the
 *   express-5 catch-all actually matches must be the SAME set. The defect was
 *   not a typo, it was two checks over one request that were allowed to
 *   disagree; a test that only pins today's spellings would let them drift
 *   apart again.
 *
 *   End-to-end — boot the real server (child process, isolated HOME, free
 *   port) and put the bypass on the wire. `req.path` is only one of the things
 *   between the socket and the handler; nothing short of a real request proves
 *   the ordering of cors/json/auth/redaction/routes.
 *
 * The gate has a second exemption list, and it had the same defect in the
 * method dimension: `HEAD` was exempt "for CORS preflight", preflight is
 * `OPTIONS`, and express routes `HEAD` to the `GET` handler. See the METHOD
 * section of leg 2 for what that answered unauthenticated.
 *
 * Percent-encoded paths are sent with `http.request`, not `fetch`: the WHATWG
 * URL parser resolves `%2E%2E` to `..` and collapses the segment CLIENT-side,
 * so a fetch-based probe never puts the traversal on the wire and proves
 * nothing about the server.
 */

import { afterAll, afterEach, beforeAll, describe, expect, it } from '@jest/globals';
import { spawn, type ChildProcess } from 'node:child_process';
import express from 'express';
import { createServer, request as httpRequest, type Server } from 'node:http';
import { createServer as createNetServer } from 'node:net';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { __test__ } from '../visualization-server.js';

const HERE = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = join(HERE, '..', '..', '..');
const BOOT_SCRIPT = join(HERE, 'support', 'boot-auth-server.ts');
/**
 * `node --import <tsx loader>` rather than the `tsx` CLI: the CLI is a wrapper
 * that spawns its own node child, so killing it leaves a grandchild holding the
 * inherited stdio pipes open and Jest never exits ("Jest did not exit one
 * second after the test run has completed"). One process is killable.
 */
const TSX_LOADER = pathToFileURL(join(REPO_ROOT, 'node_modules', 'tsx', 'dist', 'loader.mjs')).href;
const TEST_TOKEN = 'sc474-regression-token';

interface RawResponse {
  status: number;
  type: string;
  body: string;
  /** `content-length` as the server sent it, or `undefined` when absent. */
  length: string | undefined;
  /** `etag` as the server sent it, or `undefined` when absent. */
  etag: string | undefined;
}

/**
 * One request over the wire with the path byte-for-byte as given.
 * `http.request` does not normalise the path; `fetch` does.
 *
 * The response's `content-length` and `etag` are returned alongside the body
 * because a `HEAD` has no body and those two headers are exactly what leaked
 * through it (#474) — the assertion has to be able to read what the caller
 * could read.
 */
function raw(
  port: number,
  method: string,
  path: string,
  headers: Record<string, string> = {},
  body?: string,
): Promise<RawResponse> {
  return new Promise((resolve, reject) => {
    const req = httpRequest({ host: '127.0.0.1', port, path, method, headers }, (res) => {
      let received = '';
      res.setEncoding('utf8');
      res.on('data', (chunk) => (received += chunk));
      res.on('end', () =>
        resolve({
          status: res.statusCode ?? 0,
          type: String(res.headers['content-type'] ?? '').split(';')[0],
          body: received,
          length: res.headers['content-length'],
          etag: res.headers.etag,
        }),
      );
    });
    req.on('error', reject);
    if (body !== undefined) req.write(body);
    req.end();
  });
}

/** The overwhelmingly common case: a GET with no body. */
function rawGet(port: number, path: string, headers: Record<string, string> = {}): Promise<RawResponse> {
  return raw(port, 'GET', path, headers);
}

/** A port nothing is listening on, chosen by the kernel and then released. */
function freePort(): Promise<number> {
  return new Promise((resolve, reject) => {
    const probe = createNetServer();
    probe.on('error', reject);
    probe.listen(0, '127.0.0.1', () => {
      const addr = probe.address();
      if (!addr || typeof addr === 'string') {
        reject(new Error('no port'));
        return;
      }
      const { port } = addr;
      probe.close(() => resolve(port));
    });
  });
}

// ── Leg 1: the gate and the catch-all describe the same set ──────────────────

/**
 * Every path below is classified twice: by `isApiRequestPath` (what the auth
 * gate protects) and by a real express router carrying the production
 * catch-all pattern (what express will hand to an API handler). The two
 * answers must agree for every one of them.
 */
const PATH_CORPUS = [
  '/api/health',
  '/API/health',
  '/api/memories',
  '/API/memories',
  '/Api/Memories',
  '/API/MEMORIES',
  '/api/',
  '/API/',
  '/api/v1/scan',
  '/API/V1/SCAN',
  '/api/%2E%2E/memories',
  '/api/%2e%2e',
  '/api/..%2fmemories',
  '/api/../api/memories',
  '/api//memories',
  '/api/memories/',
  '/api',
  '/API',
  '/apix',
  '/APIX',
  '/',
  '/dashboard',
  '/_next/static/chunk.js',
];

describe('#474 — the auth gate and the API catch-all classify the same set', () => {
  let server: Server | undefined;

  afterEach(async () => {
    if (server) {
      const srv = server;
      server = undefined;
      await new Promise<void>((resolve) => srv.close(() => resolve()));
    }
  });

  it('matches the production catch-all exactly where isApiRequestPath says API', async () => {
    const app = express();
    app.all(__test__.API_CATCH_ALL_PATH, (_req, res) => {
      res.status(404).json({ where: 'api' });
    });
    app.use((_req, res) => {
      res.status(404).json({ where: 'shell' });
    });
    const srv = createServer(app);
    await new Promise<void>((resolve) => srv.listen(0, '127.0.0.1', resolve));
    server = srv;
    const addr = srv.address();
    if (!addr || typeof addr === 'string') throw new Error('no port');

    const disagreements: string[] = [];
    for (const path of PATH_CORPUS) {
      const res = await rawGet(addr.port, path);
      const routedToApi = res.body.includes('"api"');
      const gated = __test__.isApiRequestPath(path);
      if (routedToApi !== gated) {
        disagreements.push(`${path}: express routed to ${routedToApi ? 'api' : 'shell'}, gate says ${gated}`);
      }
    }
    expect(disagreements).toEqual([]);
  });

  it('protects every case spelling of an API path', () => {
    for (const path of ['/api/memories', '/API/memories', '/Api/Memories', '/API/MEMORIES', '/aPi/x']) {
      expect(__test__.isApiRequestPath(path)).toBe(true);
    }
  });

  it('does not claim the dashboard shell', () => {
    for (const path of ['/api', '/API', '/apix', '/APIX', '/', '/dashboard', '/apifoo/bar']) {
      expect(__test__.isApiRequestPath(path)).toBe(false);
    }
  });

  it('leaves percent-encoding encoded rather than decoding a traversal into existence', () => {
    expect(__test__.apiPathView('/api/%2E%2E/memories')).toBe('/api/%2e%2e/memories');
    expect(__test__.isApiRequestPath('/api/%2E%2E/memories')).toBe(true);
  });

  it('exempts a public path in every spelling express routes to it — and nothing else', () => {
    const publicPaths = ['/api/health', '/api/auth/session-token'];
    // express non-strict routing: one optional trailing slash reaches the same
    // handler, so the exemption has to cover exactly that and no more.
    for (const path of ['/api/health', '/API/health', '/API/HEALTH', '/api/health/', '/Api/Auth/Session-Token']) {
      expect(__test__.isPublicApiPath(path, publicPaths)).toBe(true);
    }
    for (const path of ['/api/health//', '/api//health', '/api/health/x', '/api/healthz', '/api/memories']) {
      expect(__test__.isPublicApiPath(path, publicPaths)).toBe(false);
    }
  });

  it('honours a narrowed public list — no session-token exemption on a non-loopback bind', () => {
    expect(__test__.isPublicApiPath('/API/auth/session-token', ['/api/health'])).toBe(false);
  });
});

// ── Leg 2: the real server, over the wire ────────────────────────────────────

describe('#474 — the booted server refuses every respelling without a token', () => {
  let child: ChildProcess | undefined;
  let port = 0;
  let home = '';

  beforeAll(async () => {
    port = await freePort();
    home = mkdtempSync(join(tmpdir(), 'sc474-auth-'));
    child = spawn(process.execPath, ['--import', TSX_LOADER, BOOT_SCRIPT, join(home, 'probe.db')], {
      cwd: REPO_ROOT,
      env: {
        ...process.env,
        HOME: home,
        SHIELDCORTEX_CONFIG_DIR: join(home, 'config'),
        SHIELDCORTEX_AUDIT_DIR: join(home, 'audit'),
        SHIELDCORTEX_SKIP_EMBEDDINGS: '1',
        SHIELDCORTEX_HOST: '127.0.0.1',
        SHIELDCORTEX_API_TOKEN: TEST_TOKEN,
        PORT: String(port),
        NODE_OPTIONS: '',
      },
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    let stderr = '';
    child.stderr?.setEncoding('utf8');
    child.stderr?.on('data', (chunk: string) => (stderr += chunk));

    let up = false;
    for (let attempt = 0; attempt < 100 && !up; attempt++) {
      if (child.exitCode !== null) {
        throw new Error(`server exited ${child.exitCode} before listening:\n${stderr.slice(-2000)}`);
      }
      await new Promise((resolve) => setTimeout(resolve, 200));
      try {
        up = (await rawGet(port, '/api/health')).status === 200;
      } catch {
        /* not listening yet */
      }
    }
    if (!up) throw new Error(`server never came up on ${port}:\n${stderr.slice(-2000)}`);
  }, 60_000);

  afterAll(() => {
    child?.kill('SIGKILL');
    // Drop our ends of the pipes too — a live read handle keeps Jest's event
    // loop alive even after the child is gone.
    child?.stdout?.destroy();
    child?.stderr?.destroy();
    if (home) rmSync(home, { recursive: true, force: true });
  });

  const authed = { authorization: `Bearer ${TEST_TOKEN}` };

  it.each([
    '/api/gated-stats',
    '/API/gated-stats',
    '/Api/gated-stats',
    '/api/memories',
    '/API/memories',
    '/API/MEMORIES',
  ])('answers 401 for unauthenticated %s', async (path) => {
    const res = await rawGet(port, path);
    expect({ path, status: res.status, body: JSON.parse(res.body) }).toEqual({
      path,
      status: 401,
      body: { error: 'Unauthorized', code: 'AUTH_REQUIRED' },
    });
  });

  it.each([
    '/api/%2E%2E/memories',
    '/api/%2e%2e',
    '/api/..%2fmemories',
    '/api/../api/memories',
    '/api//memories',
  ])('answers 401 for unauthenticated %s rather than letting it reach a handler', async (path) => {
    const res = await rawGet(port, path);
    expect(res.status).toBe(401);
    expect(JSON.parse(res.body).code).toBe('AUTH_REQUIRED');
  });

  it('reaches the real uppercase route once authenticated — the 401 is the gate, not a 404', async () => {
    const res = await rawGet(port, '/API/gated-stats', authed);
    expect(res.status).toBe(200);
    expect(JSON.parse(res.body)).toEqual({ total: 0, byFeature: {} });
  });

  it('keeps /api/health public in every spelling express routes to it', async () => {
    for (const path of ['/api/health', '/API/health', '/API/HEALTH', '/api/health/']) {
      const res = await rawGet(port, path);
      expect({ path, status: res.status, ok: JSON.parse(res.body).status }).toEqual({
        path,
        status: 200,
        ok: 'ok',
      });
    }
  });

  it('still answers unknown /API/ routes with the JSON 404, not the HTML shell', async () => {
    const unauthenticated = await rawGet(port, '/API/no-such-route');
    expect(unauthenticated.status).toBe(401);

    const withToken = await rawGet(port, '/API/no-such-route', authed);
    expect(withToken.status).toBe(404);
    expect(withToken.type).toBe('application/json');
    expect(JSON.parse(withToken.body)).toEqual({ error: 'Not found' });
  });

  it('leaves non-API paths on the dashboard shell', async () => {
    for (const path of ['/apix', '/dashboard']) {
      const res = await rawGet(port, path);
      expect(res.status).toBe(404);
      expect(res.type).not.toBe('application/json');
    }
  });

  it('rejects a wrong token with AUTH_INVALID rather than AUTH_REQUIRED', async () => {
    const res = await rawGet(port, '/API/memories', { authorization: 'Bearer not-the-token' });
    expect(res.status).toBe(401);
    expect(JSON.parse(res.body).code).toBe('AUTH_INVALID');
  });

  // ── The gate's METHOD exemption ────────────────────────────────────────────
  //
  // Respelling the path was half of it. The gate also exempted two METHODS,
  // `OPTIONS` and `HEAD`, with the comment "for CORS preflight" — and preflight
  // has never been a `HEAD`. express routes `HEAD` to the `GET` handler, so the
  // handler RAN for an unauthenticated caller and Node suppressed only the
  // body. Measured on this harness at ef06f9d3:
  //
  //   GET  /api/memories (no token)  -> 401  Content-Length 47
  //   HEAD /api/memories (no token)  -> 200  Content-Length 786  ETag W/"312-+pKMUUkL…"
  //   GET  /api/memories (token)     -> 200  Content-Length 786  ETag W/"312-+pKMUUkL…"
  //
  // Byte-identical length and a content-derived ETag: the size of the
  // authenticated answer, for free, on 60 of the 125 API routes. With
  // `?mode=search&query=` that is a search oracle over the memory store, and it
  // reaches a non-loopback bind too — the one mode where the token is the only
  // defence, because `/api/auth/session-token` is deliberately not registered
  // there.

  it.each(['/api/memories', '/API/memories', '/api/gated-stats', '/API/MEMORIES'])(
    'answers 401 for an unauthenticated HEAD %s — it runs the same handler as the GET',
    async (path) => {
      const head = await raw(port, 'HEAD', path);
      expect({ path, status: head.status }).toEqual({ path, status: 401 });
      // The 401 is the gate and not a 404: the same HEAD with a token reaches
      // the handler. Without this the test would pass on a server that simply
      // does not route HEAD at all.
      const authedHead = await raw(port, 'HEAD', path, authed);
      expect({ path, status: authedHead.status }).toEqual({ path, status: 200 });
    },
  );

  it('tells an unauthenticated HEAD nothing about the size of the authenticated answer', async () => {
    // Give the store something to find, so the authenticated answers differ by
    // query and the oracle would have something to leak.
    const seed = await raw(
      port,
      'POST',
      '/api/memories',
      { ...authed, 'content-type': 'application/json' },
      JSON.stringify({ title: 'oracle marker alpha', content: 'SC474-MARKER-ALPHA present in the store' }),
    );
    expect(seed.status).toBeLessThan(300);

    const hit = '/api/memories?mode=search&query=SC474-MARKER-ALPHA';
    const miss = '/api/memories?mode=search&query=SC474-NOTHING-MATCHES-THIS';

    // Authenticated, the two queries genuinely answer differently — that is the
    // signal a HEAD used to carry.
    const authedHit = await rawGet(port, hit, authed);
    const authedMiss = await rawGet(port, miss, authed);
    expect(authedHit.status).toBe(200);
    expect(authedMiss.status).toBe(200);
    expect(authedHit.length).not.toBe(authedMiss.length);

    const headHit = await raw(port, 'HEAD', hit);
    const headMiss = await raw(port, 'HEAD', miss);
    // Unauthenticated, both are the same constant refusal: same status, same
    // length, same ETag, and neither equal to the authenticated answer. A
    // constant carries no bits about the store, which is the property that
    // matters — not the mere absence of a header.
    expect({ status: headHit.status, length: headHit.length, etag: headHit.etag }).toEqual({
      status: headMiss.status,
      length: headMiss.length,
      etag: headMiss.etag,
    });
    expect(headHit.status).toBe(401);
    expect(headHit.length).not.toBe(authedHit.length);
    expect(headHit.length).not.toBe(authedMiss.length);
    expect(headHit.etag).not.toBe(authedHit.etag);
    expect(headHit.etag).not.toBe(authedMiss.etag);
    // And it is the same refusal an unauthenticated GET gets, byte for byte.
    const getRefusal = await rawGet(port, hit);
    expect({ length: headHit.length, etag: headHit.etag }).toEqual({
      length: getRefusal.length,
      etag: getRefusal.etag,
    });
  });

  it('still lets a CORS preflight through — OPTIONS is the one exempt method', async () => {
    const res = await raw(port, 'OPTIONS', '/api/memories', {
      origin: 'http://localhost:3030',
      'access-control-request-method': 'GET',
    });
    // The `cors` middleware answers preflight itself with 204. What matters is
    // that it is not the gate's 401: a browser that cannot preflight cannot
    // then send the credentialed request at all.
    expect(res.status).toBe(204);
  });

  it('keeps HEAD on a public path public, exactly like its GET', async () => {
    const head = await raw(port, 'HEAD', '/api/health');
    const get = await rawGet(port, '/api/health');
    expect({ head: head.status, get: get.status }).toEqual({ head: 200, get: 200 });
    expect(head.length).toBe(get.length);
  });
});
