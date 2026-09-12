/**
 * #466 — express 4 → 5 left `req.body` undefined, and the crash it caused was
 * answered with a stack trace.
 *
 * body-parser 1.x (express 4) initialised `req.body` to `{}` on every request.
 * body-parser 2.x (express 5) leaves it `undefined` when no parser matched, and
 * a request with no `Content-Type: application/json` matches nothing. Roughly
 * twenty mutating handlers destructure `req.body` directly, so every one of them
 * turned a validation `400` into a `TypeError` `500`. Measured on the real
 * booted server at e9a8e1a8, authenticated, `POST` with no body and no
 * content-type:
 *
 *   POST  /api/v1/scan          500 {"error":"Cannot destructure property 'content' …"}
 *   POST  /api/sql              500 {"error":"Cannot destructure property 'query' …"}
 *   POST  /api/memories         500 {"error":"Cannot destructure property 'title' …"}
 *   POST  /api/iron-dome/activate  500   (express 4: 200, config applied)
 *   POST  /api/cloud/config     500   (express 4: 200)
 *   PATCH /api/xray/findings/1  500 text/html + a stack trace naming
 *                                   /home/…/src/api/routes/xray-findings.ts and
 *                                   /home/…/node_modules/router/lib/route.js
 *
 * Two defects, two fixes, and this file pins both:
 *
 *   `defaultEmptyBody` restores the express-4 default once, for every handler.
 *   The expectations below are not invented — each is the response the SAME
 *   endpoint gives for an empty JSON object (`Content-Type: application/json`,
 *   body `{}`), which is the path express 4 put a body-less request on. The
 *   test therefore pins an equivalence ("no body behaves as an empty body")
 *   rather than a list of today's error strings.
 *
 *   `apiJsonErrorHandler` makes the API plane answer an unhandled error with
 *   JSON carrying no detail. `xray-findings.ts` has no try/catch, so its
 *   handlers reached express's default HTML error page — in a server whose
 *   catch-all exists specifically to return JSON instead of express HTML. The
 *   same leak reached a `400` for any malformed JSON body on any path.
 *
 * Three legs, because no one of them can carry the whole claim. The first boots
 * the REAL server and puts body-less requests on the wire — only that proves the
 * middleware is wired into the live stack ahead of the twenty handlers. The
 * second mounts the real exported middleware on a purpose-built app, because
 * proving the error handler needs a route that throws and no production route
 * throws on demand. The third covers the two middlewares directly, including the
 * one property no request can demonstrate: their position in the chain.
 */

import { afterAll, afterEach, beforeAll, describe, expect, it } from '@jest/globals';
import { spawn, type ChildProcess } from 'node:child_process';
import express from 'express';
import { createServer, request as httpRequest, type Server } from 'node:http';
import { createServer as createNetServer } from 'node:net';
import { mkdtempSync, readFileSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import { __test__ } from '../visualization-server.js';

const HERE = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = join(HERE, '..', '..', '..');
const BOOT_SCRIPT = join(HERE, 'support', 'boot-auth-server.ts');
/** See api-auth-path-normalisation.test.ts: the `tsx` CLI leaves a grandchild. */
const TSX_LOADER = pathToFileURL(join(REPO_ROOT, 'node_modules', 'tsx', 'dist', 'loader.mjs')).href;
const TEST_TOKEN = 'sc466-missing-body-token';

interface RawResponse {
  status: number;
  type: string;
  body: string;
}

/** One request over the wire, with full control over headers and body bytes. */
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
        }),
      );
    });
    req.on('error', reject);
    if (body !== undefined) req.write(body);
    req.end();
  });
}

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

/**
 * Nothing in a response body may disclose where the server lives on disk. Both
 * spellings appear in the leak this file fixes: express's HTML page renders the
 * stack with plain absolute paths, and the ESM frames inside it are `file://`
 * URLs.
 */
function expectNoInternals(res: RawResponse, what: string): void {
  expect({ what, homePath: res.body.includes('/home/'), esmFrame: res.body.includes('at file://') }).toEqual({
    what,
    homePath: false,
    esmFrame: false,
  });
  expect(res.body).not.toContain('node_modules');
  expect(res.body).not.toMatch(/\bat .*:\d+:\d+/);
}

// ── Leg 1: the real server, over the wire ────────────────────────────────────

/**
 * A representative sample of the twenty endpoints that regressed. Deliberately
 * spread across all four route modules that hold unguarded destructures
 * (`visualization-server.ts`, `routes/memories.ts`, `routes/system.ts`,
 * `routes/xray-findings.ts`) plus the Defence API v1 handlers, because the fix
 * is one middleware and a sample from a single module could not tell a global
 * fix from a local one.
 *
 * `expected` is the response the same endpoint gives for a literal `{}` body —
 * asserted as such below, not assumed.
 */
const SAMPLE: ReadonlyArray<{ method: string; path: string; status: number; error: string }> = [
  { method: 'POST', path: '/api/v1/scan', status: 400, error: 'content (string) is required' },
  { method: 'POST', path: '/api/v1/scan/batch', status: 400, error: 'items (array) is required' },
  { method: 'POST', path: '/api/skills/trust', status: 400, error: '"path" is required' },
  { method: 'DELETE', path: '/api/skills/file', status: 400, error: '"path" is required' },
  { method: 'POST', path: '/api/iron-dome/scan', status: 400, error: 'text (string) is required' },
  { method: 'POST', path: '/api/sql', status: 400, error: 'Query string required' },
  {
    method: 'POST',
    path: '/api/defence/config',
    status: 400,
    error: 'Invalid mode. Must be one of: strict, balanced, permissive',
  },
  { method: 'POST', path: '/api/patterns', status: 400, error: 'name and regex are required' },
  {
    method: 'POST',
    path: '/api/links',
    status: 400,
    error: 'sourceId, targetId, and relationship are required',
  },
  { method: 'POST', path: '/api/memories', status: 400, error: 'Title and content required' },
  {
    method: 'POST',
    path: '/api/memories/merge',
    status: 400,
    error: 'keptId and removedId are required integers',
  },
  {
    method: 'POST',
    path: '/api/memories/1/enrich',
    status: 400,
    error: 'Context string required in request body',
  },
  { method: 'PATCH', path: '/api/memories/1', status: 404, error: 'Memory not found' },
  {
    method: 'POST',
    path: '/api/skills/deep-scan',
    status: 400,
    error: 'files array is required (each with name and content)',
  },
  {
    method: 'PATCH',
    path: '/api/xray/findings/1',
    status: 400,
    error: 'status must be one of: reviewed, ignored, resolved',
  },
  { method: 'POST', path: '/api/license/activate', status: 400, error: 'License key is required' },
];

describe('#466 — a body-less request reaches the handler, not a TypeError', () => {
  let child: ChildProcess | undefined;
  let port = 0;
  let home = '';

  beforeAll(async () => {
    port = await freePort();
    home = mkdtempSync(join(tmpdir(), 'sc466-body-'));
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
        up = (await raw(port, 'GET', '/api/health')).status === 200;
      } catch {
        /* not listening yet */
      }
    }
    if (!up) throw new Error(`server never came up on ${port}:\n${stderr.slice(-2000)}`);
  }, 60_000);

  afterAll(() => {
    child?.kill('SIGKILL');
    child?.stdout?.destroy();
    child?.stderr?.destroy();
    if (home) rmSync(home, { recursive: true, force: true });
  });

  const authed = { authorization: `Bearer ${TEST_TOKEN}` };
  const authedJson = { ...authed, 'content-type': 'application/json', 'content-length': '2' };

  it.each(SAMPLE)('validates $method $path with no body and no content-type', async (endpoint) => {
    const res = await raw(port, endpoint.method, endpoint.path, authed);
    expect({ path: endpoint.path, status: res.status, type: res.type, body: JSON.parse(res.body) }).toEqual({
      path: endpoint.path,
      status: endpoint.status,
      type: 'application/json',
      body: expect.objectContaining({ error: endpoint.error }),
    });
    expectNoInternals(res, `${endpoint.method} ${endpoint.path}`);
  });

  it.each(SAMPLE)(
    'answers $method $path identically whether the empty body is absent or literal `{}`',
    async (endpoint) => {
      const absent = await raw(port, endpoint.method, endpoint.path, authed);
      const literal = await raw(port, endpoint.method, endpoint.path, authedJson, '{}');
      expect({ status: absent.status, type: absent.type, body: absent.body }).toEqual({
        status: literal.status,
        type: literal.type,
        body: literal.body,
      });
    },
  );

  it('does not leak the source tree when xray-findings — which has no try/catch — is hit', async () => {
    const res = await raw(port, 'PATCH', '/api/xray/findings/1', authed);
    expect(res.status).toBe(400);
    expect(res.type).toBe('application/json');
    expect(res.body).not.toContain('TypeError');
    expect(res.body).not.toContain('xray-findings');
    expectNoInternals(res, 'PATCH /api/xray/findings/1');
  });

  it('answers a malformed JSON body with JSON, keeping the 400 rather than inventing a 500', async () => {
    const truncated = '{"title": ';
    const res = await raw(
      port,
      'POST',
      '/api/memories',
      { ...authed, 'content-type': 'application/json', 'content-length': String(truncated.length) },
      truncated,
    );
    expect({ status: res.status, type: res.type, body: JSON.parse(res.body) }).toEqual({
      status: 400,
      type: 'application/json',
      body: { error: 'Bad request', code: 'BAD_REQUEST' },
    });
    expect(res.body).not.toContain('SyntaxError');
    expectNoInternals(res, 'malformed JSON body');
  });

  it('answers a refused CORS origin 403 CORS_DENIED, not a 500 server fault', async () => {
    // `/api/health` is public, so nothing here can be the auth gate: a 403 at
    // all proves `cors` runs ahead of it, and 403 rather than 500 is the fix.
    const res = await raw(port, 'GET', '/api/health', { origin: 'http://evil.example' });
    expect({ status: res.status, type: res.type, body: JSON.parse(res.body) }).toEqual({
      status: 403,
      type: 'application/json',
      body: { error: 'Origin not allowed', code: 'CORS_DENIED' },
    });
    // The refused origin is the caller's own string. It goes to the server log
    // and no further — echoing it would make the API a reflector.
    expect(res.body).not.toContain('evil.example');
    expectNoInternals(res, 'refused CORS origin');
  });

  it('leaves an allowed origin alone, so the 403 above is the policy and not the middleware', async () => {
    const res = await raw(port, 'GET', '/api/health', { origin: 'http://localhost:3030' });
    expect({ status: res.status, ok: JSON.parse(res.body).status }).toEqual({ status: 200, ok: 'ok' });
  });

  it('leaves a non-API path on express default error handling', async () => {
    const truncated = '{"title": ';
    const res = await raw(
      port,
      'POST',
      '/not-an-api-path',
      { ...authed, 'content-type': 'application/json', 'content-length': String(truncated.length) },
      truncated,
    );
    // Still express's own HTML page — the handler is scoped to the JSON plane
    // and must not quietly change the dashboard shell's behaviour.
    expect(res.status).toBe(400);
    expect(res.type).not.toBe('application/json');
  });

  it('still applies a body-less request as express 4 did, rather than only failing politely', async () => {
    // These two returned 200 on express 4 and 500 on express 5 — the regression
    // was never only about error messages. `{}` is a valid, complete request for
    // both, so "restored" means the config is applied, not that a 400 is tidy.
    const cloud = await raw(port, 'POST', '/api/cloud/config', authed);
    expect({ status: cloud.status, success: JSON.parse(cloud.body).success }).toEqual({
      status: 200,
      success: true,
    });

    const ironDome = await raw(port, 'POST', '/api/iron-dome/activate', authed);
    expect({ status: ironDome.status, success: JSON.parse(ironDome.body).success }).toEqual({
      status: 200,
      success: true,
    });
    expect(JSON.parse(ironDome.body).config.enabled).toBe(true);
  });
});

// ── Leg 2: the error handler, against a route that throws ────────────────────

describe('#466 — the API error handler answers JSON and discloses nothing', () => {
  let server: Server | undefined;
  let port = 0;

  beforeAll(async () => {
    const app = express();
    app.use(express.json());
    app.use(__test__.defaultEmptyBody);

    // The shape `xray-findings.ts` had: destructure `req.body`, no try/catch.
    app.patch('/api/destructure', (req, res) => {
      const { status } = req.body as { status?: string };
      res.json({ status });
    });
    // A synchronous throw with no status attached.
    app.post('/api/boom', () => {
      throw new Error('deliberate: /home/secret/path.ts and file:///home/secret/path.ts');
    });
    // An error tagged the way http-errors (and therefore body-parser) tags one.
    app.post('/api/boom-tagged', () => {
      throw Object.assign(new Error('deliberate: /home/secret/path.ts'), { status: 413 });
    });
    // Not an API path: must stay on express's default handler.
    app.post('/boom-shell', () => {
      throw new Error('deliberate: /home/secret/path.ts');
    });
    app.use(__test__.apiJsonErrorHandler);

    const srv = createServer(app);
    await new Promise<void>((resolve) => srv.listen(0, '127.0.0.1', resolve));
    server = srv;
    const addr = srv.address();
    if (!addr || typeof addr === 'string') throw new Error('no port');
    port = addr.port;
  });

  afterAll(async () => {
    if (server) {
      const srv = server;
      server = undefined;
      await new Promise<void>((resolve) => srv.close(() => resolve()));
    }
  });

  it('turns an unhandled throw into 500 JSON with no stack and no filesystem path', async () => {
    const res = await raw(port, 'POST', '/api/boom', {});
    expect({ status: res.status, type: res.type, body: JSON.parse(res.body) }).toEqual({
      status: 500,
      type: 'application/json',
      body: { error: 'Internal server error', code: 'INTERNAL' },
    });
    expect(res.body).not.toContain('deliberate');
    expect(res.body).not.toContain('secret');
    expectNoInternals(res, 'POST /api/boom');
  });

  it('keeps a client-error status the error carries, without echoing its message', async () => {
    const res = await raw(port, 'POST', '/api/boom-tagged', {});
    expect({ status: res.status, type: res.type, body: JSON.parse(res.body) }).toEqual({
      status: 413,
      type: 'application/json',
      body: { error: 'Bad request', code: 'BAD_REQUEST' },
    });
    expect(res.body).not.toContain('secret');
  });

  it('hands a non-API path back to express untouched', async () => {
    const res = await raw(port, 'POST', '/boom-shell', {});
    expect(res.status).toBe(500);
    expect(res.type).not.toBe('application/json');
  });

  it('lets an unguarded destructure succeed, so the 500s above are the throw and not the body', async () => {
    // Guards against this describe passing for the wrong reason: if
    // defaultEmptyBody were absent, every route here would 500 on the
    // destructure and the assertions above would still be green.
    const res = await raw(port, 'PATCH', '/api/destructure', {});
    expect({ status: res.status, body: JSON.parse(res.body) }).toEqual({ status: 200, body: {} });
  });
});

// ── Leg 3: the two middlewares in isolation ──────────────────────────────────

describe('#466 — defaultEmptyBody', () => {
  function run(body: unknown): { body: unknown; nextCalls: unknown[][] } {
    const req = { body } as unknown as Parameters<typeof __test__.defaultEmptyBody>[0];
    const nextCalls: unknown[][] = [];
    __test__.defaultEmptyBody(req, {} as never, (...args: unknown[]) => {
      nextCalls.push(args);
    });
    return { body: req.body, nextCalls };
  }

  it('substitutes an empty object for an absent body', () => {
    expect(run(undefined).body).toEqual({});
  });

  it('never replaces a body a parser produced, including the empty ones', () => {
    for (const parsed of [{ a: 1 }, {}, [], '', 0, false, null]) {
      expect(run(parsed).body).toBe(parsed);
    }
  });

  it('always continues the chain, and never with an error', () => {
    expect(run(undefined).nextCalls).toEqual([[]]);
    expect(run({ a: 1 }).nextCalls).toEqual([[]]);
  });
});

describe('#466 — a server-authored API error response', () => {
  const authored = (err: unknown): { status: number; body: unknown } => {
    const written: { status: number; body: unknown } = { status: 0, body: undefined };
    const res = {
      headersSent: false,
      status(code: number) {
        written.status = code;
        return this;
      },
      json(body: unknown) {
        written.body = body;
      },
    } as unknown as Parameters<typeof __test__.apiJsonErrorHandler>[2];
    __test__.apiJsonErrorHandler(
      err,
      { path: '/api/health', method: 'GET', originalUrl: '/api/health' } as never,
      res,
      () => {
        throw new Error('must not delegate an API-path error');
      },
    );
    return written;
  };

  it('sends exactly what the CORS refusal names', () => {
    expect(authored(__test__.corsDeniedError('http://evil.example'))).toEqual({
      status: 403,
      body: { error: 'Origin not allowed', code: 'CORS_DENIED' },
    });
  });

  it('never carries the rejected origin into the response, only into the message', () => {
    const err = __test__.corsDeniedError('http://evil.example');
    expect(err.message).toContain('http://evil.example');
    expect(JSON.stringify(authored(err).body)).not.toContain('evil.example');
  });

  /**
   * The refusal deliberately does NOT tag `status`/`statusCode`. express hands
   * non-API errors to `finalhandler`, which reads those tags — so tagging would
   * also move the status the dashboard shell answers, and this change is scoped
   * to the JSON plane exactly as the rest of the handler is.
   */
  it('keeps the status off the http-errors tags, so the shell is untouched', () => {
    const err = __test__.corsDeniedError('http://evil.example') as unknown as Record<string, unknown>;
    expect(err.status).toBeUndefined();
    expect(err.statusCode).toBeUndefined();
  });

  it.each([
    ['a bare error', new Error('nope')],
    ['a non-object', 'nope'],
    ['a null apiError', Object.assign(new Error('x'), { apiError: null })],
    ['a string apiError', Object.assign(new Error('x'), { apiError: 'CORS_DENIED' })],
    ['a missing code', Object.assign(new Error('x'), { apiError: { status: 403, error: 'no' } })],
    ['a non-numeric status', Object.assign(new Error('x'), { apiError: { status: '403', error: 'a', code: 'B' } })],
    ['a 200 status', Object.assign(new Error('x'), { apiError: { status: 200, error: 'a', code: 'B' } })],
    ['a 600 status', Object.assign(new Error('x'), { apiError: { status: 600, error: 'a', code: 'B' } })],
  ])('reads no authored response from %s', (_label, err) => {
    expect(__test__.apiAuthoredResponse(err)).toBeUndefined();
  });

  it('falls back to the fixed 500 when nothing is authored', () => {
    expect(authored(new Error('boom'))).toEqual({
      status: 500,
      body: { error: 'Internal server error', code: 'INTERNAL' },
    });
  });

  it('still prefers an http-errors client status over the 500 when nothing is authored', () => {
    expect(authored(Object.assign(new Error('too big'), { status: 413 }))).toEqual({
      status: 413,
      body: { error: 'Bad request', code: 'BAD_REQUEST' },
    });
  });
});

describe('#466 — apiJsonErrorHandler', () => {
  it('delegates rather than writing once a response has already begun', () => {
    const err = new Error('too late');
    const forwarded: unknown[] = [];
    const res = {
      headersSent: true,
      status() {
        throw new Error('must not set a status on a started response');
      },
      json() {
        throw new Error('must not write to a started response');
      },
    } as unknown as Parameters<typeof __test__.apiJsonErrorHandler>[2];
    __test__.apiJsonErrorHandler(
      err,
      { path: '/api/anything', method: 'POST', originalUrl: '/api/anything' } as never,
      res,
      (forwardedErr?: unknown) => forwarded.push(forwardedErr),
    );
    expect(forwarded).toEqual([err]);
  });

  /**
   * Both middlewares are correct only in position, and position is the one
   * property no request can demonstrate here. `defaultEmptyBody` before a parser
   * would be overwritten by it; `apiJsonErrorHandler` before the routes would
   * never see an error a route throws, because express only searches FORWARD
   * from the layer that called `next(err)`. A wire test cannot distinguish
   * "registered last" from "registered before the routes", because no production
   * route throws on demand — every one of them is either guarded or validates
   * first, which is the whole point of the fix above. So the ordering is pinned
   * where it is expressed: in the registration sequence itself.
   */
  it('is registered after every route, and the body default after every parser', () => {
    const source = readFileSync(join(HERE, '..', 'visualization-server.ts'), 'utf8');
    const at = (needle: string): number => {
      const index = source.indexOf(needle);
      expect({ needle, found: index !== -1 }).toEqual({ needle, found: true });
      return index;
    };
    const jsonParser = at('app.use(express.json());');
    const bodyDefault = at('app.use(defaultEmptyBody);');
    const authGate = at('const publicPaths =');
    const catchAll = at('app.all(API_CATCH_ALL_PATH');
    const errorHandler = at('app.use(apiJsonErrorHandler);');

    // Parsers → default → auth → … routes … → catch-all → error handler.
    expect(jsonParser).toBeLessThan(bodyDefault);
    expect(bodyDefault).toBeLessThan(authGate);
    expect(catchAll).toBeLessThan(errorHandler);
    // Nothing may be registered on the app after the error handler: a later
    // `app.use` would be unreachable for errors raised below it.
    expect(source.slice(errorHandler + 1)).not.toMatch(/\n\s*app\.(use|all|get|post|patch|delete|put)\(/);
  });

  it('claims exactly the paths the auth gate and the catch-all claim', () => {
    // One definition of "API path" in the server (#474); an error handler with a
    // second one would leave a plane that is gated but not sanitised, or vice
    // versa. Asserted against the shared predicate, not a copied prefix test.
    for (const path of ['/api/x', '/API/x', '/Api/Memories', '/api/']) {
      expect(__test__.isApiRequestPath(path)).toBe(true);
    }
    for (const path of ['/api', '/apix', '/dashboard', '/']) {
      expect(__test__.isApiRequestPath(path)).toBe(false);
    }
  });
});
