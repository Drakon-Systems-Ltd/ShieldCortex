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
 *
 * Two further groups (internal #89 review):
 *   - #510 PII redaction on the route: the captured body carries no raw
 *     email / phone / NI / SSN, with the `SHIELDCORTEX_PII_REDACTION=off`
 *     control proving the stage under test is the write-time redactor.
 *   - persistence-to-route classification: the stored row is NOT what the
 *     pipeline classified (it saw sanitised text; persistence may have put
 *     `[REDACTED:<kind>]` tokens in). The route must reconstruct the live
 *     level — from the linked `defence_audit` row when there is one, and
 *     conservatively from the sanitised text / redaction evidence when there
 *     is not — so a row the live path would have excluded is never shipped.
 */
import { afterEach, beforeEach, describe, expect, it, jest } from '@jest/globals';
import type Database from 'better-sqlite3';
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

// #510 probe (all synthetic): contact details + identifiers + a credential
// SHAPE assembled at runtime, so no token-looking literal sits in the repo.
const EMAIL = 'jane.doe@example.com';
const PHONE = '+44 7700 900123';
const NI = 'QQ123456C';
const SSN = '123-45-6789';
const TOKEN = ['ghp', 'a'.repeat(36)].join('_');
const PII_PROBE_CONTENT = `Customer record: email ${EMAIL} or call ${PHONE}, NI ${NI}, SSN ${SSN}, token ${TOKEN}`;
const PII_PROBE_TITLE = `contact ${EMAIL}`;
const RAW_PII = [EMAIL, PHONE, NI, SSN, TOKEN];
const REDACTED_PROBE_CONTENT =
  'Customer record: email [REDACTED:email] or call [REDACTED:phone], NI [REDACTED:ni-number], SSN [REDACTED:ssn], token [REDACTED-api_key-github]';

// Persistence-vs-live classification fixtures.
// A zero-width space inside "sort": the raw text matches no CONFIDENTIAL
// pattern, the sanitised text (what the pipeline classified) is a sort code.
const ZERO_WIDTH_CONFIDENTIAL = 'Customer record: s​ort code 12-34-56';
// Fullwidth "＠": not an email raw, an email after NFKC.
const FULLWIDTH_CONFIDENTIAL = 'Customer record: contact jane.doe＠example.com';
// A write-time redaction token where the SSN used to be: the stored text is
// PUBLIC to the classifier, but an identifier WAS present at persistence.
const PLACEHOLDER_CONTENT = 'Customer record: SSN [REDACTED:ssn] on file';

type Db = Database.Database;

function insertAuditRow(db: Db, sensitivityLevel: string): number {
  const result = db.prepare(
    `INSERT INTO defence_audit
       (source_type, source_identifier, trust_score, sensitivity_level, firewall_result, operation, reason)
     VALUES ('agent', 'unit-test', 0.4, ?, 'QUARANTINE', 'write', 'injection suspected')`,
  ).run(sensitivityLevel);
  return Number(result.lastInsertRowid);
}

function insertQuarantineRow(
  db: Db,
  row: { content: string; title?: string; project?: string | null; auditId?: number | null },
): void {
  db.prepare(
    `INSERT INTO quarantine
       (original_content, original_title, project, source_type, source_identifier,
        reason, threat_indicators, anomaly_score, firewall_result, status, audit_id)
     VALUES (?, ?, ?, 'agent', 'unit-test', 'injection suspected', '["pattern-a"]', 0.9, 'QUARANTINE', 'pending', ?)`,
  ).run(row.content, row.title ?? null, row.project ?? null, row.auditId ?? null);
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
  const originalPIIFlag = process.env.SHIELDCORTEX_PII_REDACTION;
  let isolatedHome: string;

  beforeEach(async () => {
    jest.resetModules();
    delete process.env.SHIELDCORTEX_PII_REDACTION;
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
    if (originalPIIFlag === undefined) delete process.env.SHIELDCORTEX_PII_REDACTION;
    else process.env.SHIELDCORTEX_PII_REDACTION = originalPIIFlag;
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

  // ── #510 PII redaction on the bulk route ─────────────────

  it('PII probe: an opted-in row ships with no raw email / phone / NI / SSN / credential in the captured body', async () => {
    const config = await import('../../cloud/config.js');
    config.setCloudSyncControls({ excludeSensitive: false });

    const { getDatabase } = await import('../../database/init.js');
    insertQuarantineRow(getDatabase(), { content: PII_PROBE_CONTENT, title: PII_PROBE_TITLE });

    const { bodies } = captureFetch();
    const res = await runBulkSync();

    expect(res.statusCode).toBe(200);
    expect(res.body).toEqual(expect.objectContaining({ synced: 1, skipped: 0, total: 1 }));
    expect(bodies).toHaveLength(1);
    for (const value of RAW_PII) expect(bodies[0]).not.toContain(value);

    const sent = JSON.parse(bodies[0]) as Record<string, unknown>;
    expect(sent.original_content).toBe(REDACTED_PROBE_CONTENT);
    expect(sent.original_title).toBe('contact [REDACTED:email]');
    // The SSN makes the live classification RESTRICTED; the route must agree.
    expect(sent.sensitivity_level).toBe('RESTRICTED');
  });

  it('PII-redaction-off control: SHIELDCORTEX_PII_REDACTION=off ships identifiers raw on the route, credentials still redacted', async () => {
    process.env.SHIELDCORTEX_PII_REDACTION = 'off';
    const config = await import('../../cloud/config.js');
    config.setCloudSyncControls({ excludeSensitive: false });

    const { getDatabase } = await import('../../database/init.js');
    insertQuarantineRow(getDatabase(), { content: PII_PROBE_CONTENT, title: PII_PROBE_TITLE });

    const { bodies } = captureFetch();
    await runBulkSync();

    expect(bodies).toHaveLength(1);
    const sent = JSON.parse(bodies[0]) as Record<string, string>;
    for (const value of [EMAIL, PHONE, NI, SSN]) expect(sent.original_content).toContain(value);
    expect(sent.original_content).not.toContain('[REDACTED:');
    expect(sent.original_content).not.toContain(TOKEN);
    expect(sent.original_content).toContain('[REDACTED-api_key-github]');
  });

  // ── persistence-to-route classification ──────────────────

  it('premise: the stored fixtures classify PUBLIC raw but CONFIDENTIAL as the pipeline saw them', async () => {
    const { classifySensitivity } = await import('../../defence/sensitivity/index.js');
    const { sanitiseInput } = await import('../../defence/input-sanitisation/index.js');
    for (const text of [ZERO_WIDTH_CONFIDENTIAL, FULLWIDTH_CONFIDENTIAL]) {
      expect(classifySensitivity(text, '').level).toBe('PUBLIC');
      expect(classifySensitivity(sanitiseInput(text).sanitised, '').level).toBe('CONFIDENTIAL');
    }
    expect(classifySensitivity(PLACEHOLDER_CONTENT, '').level).toBe('PUBLIC');
  });

  it('without provenance: zero-width / fullwidth-obfuscated CONFIDENTIAL rows are skipped (no egress), counts correct', async () => {
    const { getDatabase } = await import('../../database/init.js');
    insertQuarantineRow(getDatabase(), { content: ZERO_WIDTH_CONFIDENTIAL, title: 'customer' });
    insertQuarantineRow(getDatabase(), { content: FULLWIDTH_CONFIDENTIAL, title: 'customer' });

    const { bodies, calls } = captureFetch();
    const res = await runBulkSync();

    expect(res.statusCode).toBe(200);
    expect(res.body).toEqual(expect.objectContaining({ synced: 0, skipped: 2, total: 2 }));
    expect(calls()).toBe(0);
    expect(bodies).toHaveLength(0);
  });

  it('without provenance: a legacy row carrying a write-time redaction token is treated as at least CONFIDENTIAL', async () => {
    const { getDatabase } = await import('../../database/init.js');
    insertQuarantineRow(getDatabase(), { content: PLACEHOLDER_CONTENT, title: 'customer' });

    const { calls } = captureFetch();
    const res = await runBulkSync();

    expect(res.body).toEqual(expect.objectContaining({ synced: 0, skipped: 1, total: 1 }));
    expect(calls()).toBe(0);
  });

  it('with provenance: the linked audit level is trusted even when the stored text classifies PUBLIC', async () => {
    const { getDatabase } = await import('../../database/init.js');
    const db = getDatabase();
    insertQuarantineRow(db, { content: PUBLIC_CONTENT, title: 'release', auditId: insertAuditRow(db, 'CONFIDENTIAL') });

    const { calls } = captureFetch();
    const res = await runBulkSync();

    expect(res.body).toEqual(expect.objectContaining({ synced: 0, skipped: 1, total: 1 }));
    expect(calls()).toBe(0);
  });

  it('with provenance: the original level is preserved, not weakened to the token floor', async () => {
    const config = await import('../../cloud/config.js');
    config.setCloudSyncControls({ excludeSensitive: false });

    const { getDatabase } = await import('../../database/init.js');
    const db = getDatabase();
    insertQuarantineRow(db, { content: PLACEHOLDER_CONTENT, title: 'customer', auditId: insertAuditRow(db, 'RESTRICTED') });

    const { bodies } = captureFetch();
    const res = await runBulkSync();

    expect(res.body).toEqual(expect.objectContaining({ synced: 1, skipped: 0, total: 1 }));
    expect(bodies).toHaveLength(1);
    expect((JSON.parse(bodies[0]) as Record<string, unknown>).sensitivity_level).toBe('RESTRICTED');
  });

  it('genuinely PUBLIC inclusion control: PUBLIC rows with and without a PUBLIC audit link are still sent, in one mixed batch', async () => {
    const { getDatabase } = await import('../../database/init.js');
    const db = getDatabase();
    insertQuarantineRow(db, { content: PUBLIC_CONTENT, title: 'release-linked', auditId: insertAuditRow(db, 'PUBLIC') });
    insertQuarantineRow(db, { content: PUBLIC_CONTENT, title: 'release-legacy' });
    insertQuarantineRow(db, { content: ZERO_WIDTH_CONFIDENTIAL, title: 'customer' });
    insertQuarantineRow(db, { content: PLACEHOLDER_CONTENT, title: 'customer' });
    insertQuarantineRow(db, { content: PUBLIC_CONTENT, title: 'release-provenance', auditId: insertAuditRow(db, 'CONFIDENTIAL') });

    const { bodies, calls } = captureFetch();
    const res = await runBulkSync();

    expect(res.statusCode).toBe(200);
    expect(res.body).toEqual(expect.objectContaining({ synced: 2, skipped: 3, total: 5 }));
    expect(calls()).toBe(2);
    const titles = bodies.map((b) => (JSON.parse(b) as Record<string, unknown>).original_title).sort();
    expect(titles).toEqual(['release-legacy', 'release-linked']);
    for (const body of bodies) {
      const sent = JSON.parse(body) as Record<string, unknown>;
      expect(sent.original_content).toBe(PUBLIC_CONTENT);
      expect(sent.sensitivity_level).toBe('PUBLIC');
    }
    const everythingSent = bodies.join('\n');
    expect(everythingSent).not.toContain('sort code');
    expect(everythingSent).not.toContain('[REDACTED:ssn]');
  });
});
