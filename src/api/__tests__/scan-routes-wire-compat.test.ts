/**
 * 5.x compat (#859, design 3.7(d)) — the HTTP scan routes keep the 5.10.5 wire
 * shape. The exported SensitivityLevel is back to the 5.6.0 four values and the
 * public functions project PERSONAL → CONFIDENTIAL, but the REST plane
 * serializes the internal precise result: `level: 'PERSONAL'` on the wire, the
 * four 5.6.0 keys in order, and no `tier` key anywhere.
 *
 * The REAL server boots in a child process (see support/boot-auth-server.ts),
 * so `/api/skills/scan` is exercised through its registered route and every
 * body below is the bytes express put on the socket.
 */
import { afterAll, beforeAll, describe, expect, it } from '@jest/globals';
import { spawn, type ChildProcess } from 'node:child_process';
import { request as httpRequest } from 'node:http';
import { createServer as createNetServer } from 'node:net';
import { mkdtempSync, realpathSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const HERE = dirname(fileURLToPath(import.meta.url));
const REPO_ROOT = join(HERE, '..', '..', '..');
const BOOT_SCRIPT = join(HERE, 'support', 'boot-auth-server.ts');
const TSX_LOADER = pathToFileURL(join(REPO_ROOT, 'node_modules', 'tsx', 'dist', 'loader.mjs')).href;
const TEST_TOKEN = 'sc859-wire-compat-token';

const FAMILY_TITLE = 'Surprise family trip';
const FAMILY_CONTENT = 'Booked a surprise trip to the coast for Sam\'s birthday with the kids in May; do not tell her before the weekend.';
const PUBLIC_NOTE = 'Use the Inter font family for the dashboard.';
const EMAIL_NOTE = 'Contact the vendor at jane.doe@example.com about the invoice.';
const RESTRICTED_NOTE = 'password: hunter2xx for the staging box';
const KEYS = ['level', 'confidence', 'detectedPatterns', 'redactionRequired'];

interface WireResponse {
  status: number;
  raw: string;
}

function post(port: number, path: string, body: unknown): Promise<WireResponse> {
  const payload = JSON.stringify(body);
  return new Promise((resolve, reject) => {
    const req = httpRequest({
      host: '127.0.0.1', port, path, method: 'POST',
      headers: {
        authorization: `Bearer ${TEST_TOKEN}`,
        'content-type': 'application/json',
        'content-length': String(Buffer.byteLength(payload)),
      },
    }, (res) => {
      let raw = '';
      res.setEncoding('utf8');
      res.on('data', (chunk) => (raw += chunk));
      res.on('end', () => resolve({ status: res.statusCode ?? 0, raw }));
    });
    req.on('error', reject);
    req.write(payload);
    req.end();
  });
}

function get(port: number, path: string): Promise<number> {
  return new Promise((resolve, reject) => {
    const req = httpRequest({ host: '127.0.0.1', port, path, method: 'GET' }, (res) => {
      res.resume();
      res.on('end', () => resolve(res.statusCode ?? 0));
    });
    req.on('error', reject);
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

/** Four-key sensitivity, in 5.6.0 order, at `level`. */
function expectWireSensitivity(s: Record<string, unknown>, level: string): void {
  expect(Object.keys(s)).toEqual(KEYS);
  expect(s.level).toBe(level);
}

describe('5.x compat: HTTP scan routes on the wire (#859, 3.7(d))', () => {
  let child: ChildProcess | undefined;
  let port = 0;
  let home = '';
  let serverLog = '';

  beforeAll(async () => {
    port = await freePort();
    home = realpathSync(mkdtempSync(join(tmpdir(), 'sc859-wire-')));
    child = spawn(process.execPath, ['--import', TSX_LOADER, BOOT_SCRIPT, join(home, 'wire.db')], {
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
    child.stderr?.setEncoding('utf8');
    child.stderr?.on('data', (chunk: string) => (serverLog += chunk));
    child.stdout?.resume();
    let up = false;
    for (let attempt = 0; attempt < 100 && !up; attempt++) {
      if (child.exitCode !== null) {
        throw new Error(`server exited ${child.exitCode} before listening:\n${serverLog.slice(-2000)}`);
      }
      await new Promise((resolve) => setTimeout(resolve, 200));
      try {
        up = (await get(port, '/api/health')) === 200;
      } catch {
        /* not listening yet */
      }
    }
    if (!up) throw new Error(`server never came up on ${port}:\n${serverLog.slice(-2000)}`);
  }, 60_000);

  afterAll(() => {
    child?.kill('SIGKILL');
    child?.stdout?.destroy();
    child?.stderr?.destroy();
    if (home) rmSync(home, { recursive: true, force: true });
  });

  it('1. POST /api/v1/scan: PERSONAL on the wire, four keys in order, 5.10.5 body keys, no tier', async () => {
    const res = await post(port, '/api/v1/scan', { content: FAMILY_CONTENT, title: FAMILY_TITLE });
    expect(res.status).toBe(200);
    const body = JSON.parse(res.raw) as Record<string, any>;
    expectWireSensitivity(body.sensitivity, 'PERSONAL');
    expect(body.sensitivity.detectedPatterns).toContain('personal-life-event');
    expect(typeof body.sensitivity.confidence).toBe('number');
    expect(body.sensitivity.redactionRequired).toBe(false);
    expect(Object.keys(body)).toEqual(['allowed', 'firewall', 'fragmentation', 'sensitivity', 'trust', 'auditId']);
    expect(res.raw).not.toContain('"tier"');
  });

  it('2. POST /api/v1/scan/batch: mixed levels per item, invalid item unchanged, no tier', async () => {
    const res = await post(port, '/api/v1/scan/batch', { items: [
      { content: FAMILY_CONTENT, title: FAMILY_TITLE },
      { content: PUBLIC_NOTE },
      { content: EMAIL_NOTE },
      { content: RESTRICTED_NOTE },
      { content: 42 },
    ] });
    expect(res.status).toBe(200);
    const body = JSON.parse(res.raw) as { results: Array<Record<string, any>> };
    const levels = ['PERSONAL', 'PUBLIC', 'CONFIDENTIAL', 'RESTRICTED'];
    levels.forEach((level, i) => expectWireSensitivity(body.results[i].sensitivity, level));
    expect(body.results[4]).toEqual({ error: 'content (string) is required', allowed: false });
    expect(res.raw).not.toContain('"tier"');
  });

  it('3. POST /api/skills/scan (registered route): PERSONAL, four keys, no tier', async () => {
    const res = await post(port, '/api/skills/scan', { content: FAMILY_CONTENT, name: 'family-skill' });
    expect(res.status).toBe(200);
    const body = JSON.parse(res.raw) as Record<string, any>;
    expectWireSensitivity(body.sensitivity, 'PERSONAL');
    expect(res.raw).not.toContain('"tier"');
  });

  it('4. POST /api/skills/deep-scan (registered route): scanResults keep PERSONAL, four keys, no tier', async () => {
    const res = await post(port, '/api/skills/deep-scan', { files: [{ name: 'family.md', content: FAMILY_CONTENT }] });
    expect(res.status).toBe(200);
    const body = JSON.parse(res.raw) as { scanResults: Array<Record<string, any>> };
    expectWireSensitivity(body.scanResults[0].sensitivity, 'PERSONAL');
    expect(res.raw).not.toContain('"tier"');
  });
});
