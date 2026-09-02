/**
 * Spec for the read-only OpenClaw cron store reader (#375 shared helper).
 *
 * The load-bearing property is the honesty enum: every way of failing to read
 * the store has to land somewhere DISTINCT from "we looked and there was
 * nothing", because on the host this issue was proven against a migrated
 * store with 63 live jobs read as empty-ok for weeks.
 *
 * Fixture stores are built writable here in a tmp dir and then only ever
 * reopened through the read-only helper. Real ~/.openclaw is never touched.
 */
import Database from 'better-sqlite3';
import { chmodSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import {
  discoverDbCronScripts,
  isIncomplete,
  isJobEnabled,
  OPENCLAW_CRON_DB_SOURCE,
  probeCronSource,
  sanitiseJobName,
  walkStringLeaves,
  type CronProbeStatus,
} from '../openclaw-cron-store.js';

const isRoot = typeof process.getuid === 'function' && process.getuid() === 0;
const ESC = String.fromCharCode(27);

interface JobSeed {
  job_id: string;
  name?: string;
  enabled?: unknown;
  payload_message?: string | null;
  trigger_script?: string | null;
  job_json?: string | null;
}

interface RunSeed {
  job_id: string;
  session_key: string;
  run_at_ms: number;
  status: string;
}

interface StoreShape {
  jobs?: JobSeed[];
  runs?: RunSeed[];
  /** Omit a table entirely. */
  omit?: Array<'cron_jobs' | 'cron_run_logs'>;
  /** Drop a required column from cron_jobs / cron_run_logs. */
  dropJobColumn?: string;
  dropRunColumn?: string;
  /** Declare `enabled` TEXT to reproduce a store that writes '1'/'true'. */
  enabledType?: 'INTEGER' | 'TEXT';
}

// Mirrors the live OpenClaw schema's affinities: getting these wrong hides
// exactly the type-coercion bug the enabled-column rule exists to stop.
const JOB_COLUMNS: Record<string, string> = {
  job_id: 'TEXT',
  name: 'TEXT',
  enabled: 'INTEGER',
  payload_message: 'TEXT',
  trigger_script: 'TEXT',
  job_json: 'TEXT',
};
const RUN_COLUMNS: Record<string, string> = {
  job_id: 'TEXT',
  session_key: 'TEXT',
  run_at_ms: 'INTEGER',
  status: 'TEXT',
};

/** Writable ONLY here - the fixture build step. Everything under test reopens
 *  through openCronStore(), which is readonly + fileMustExist. */
function buildCronStore(dbPath: string, shape: StoreShape = {}): void {
  mkdirSync(join(dbPath, '..'), { recursive: true });
  const db = new Database(dbPath);
  try {
    const omit = new Set(shape.omit ?? []);
    const jobTypes = { ...JOB_COLUMNS, enabled: shape.enabledType ?? JOB_COLUMNS.enabled };
    if (!omit.has('cron_jobs')) {
      const cols = Object.keys(jobTypes).filter((c) => c !== shape.dropJobColumn);
      db.exec(`CREATE TABLE cron_jobs (${cols.map((c) => `${c} ${jobTypes[c]}`).join(', ')})`);
      for (const job of shape.jobs ?? []) {
        const values = cols.map((c) => (job as Record<string, unknown>)[c] ?? null);
        db.prepare(
          `INSERT INTO cron_jobs (${cols.join(', ')}) VALUES (${cols.map(() => '?').join(', ')})`,
        ).run(...(values as never[]));
      }
    }
    if (!omit.has('cron_run_logs')) {
      const cols = Object.keys(RUN_COLUMNS).filter((c) => c !== shape.dropRunColumn);
      db.exec(`CREATE TABLE cron_run_logs (${cols.map((c) => `${c} ${RUN_COLUMNS[c]}`).join(', ')})`);
      for (const run of shape.runs ?? []) {
        const values = cols.map((c) => (run as Record<string, unknown>)[c] ?? null);
        db.prepare(
          `INSERT INTO cron_run_logs (${cols.join(', ')}) VALUES (${cols.map(() => '?').join(', ')})`,
        ).run(...(values as never[]));
      }
    }
  } finally {
    db.close();
  }
}

// ── OC2 (gen2, #456) fixtures — the full measured live column sets ─────────

interface Gen2JobSeed {
  job_id: string;
  name?: string;
  enabled?: unknown;
  job_json?: string | null;
}
interface ReceiptSeed {
  job_id: string;
  status: string;
  started_at_ms: number;
  finished_at_ms?: number | null;
}

// Exactly the columns measured on a live OpenClaw 2026.8.1 host (82 jobs):
// no payload_message, no trigger_script, no cron_run_logs.
const GEN2_JOB_COLUMNS: Record<string, string> = {
  store_key: 'TEXT',
  job_id: 'TEXT',
  declaration_key: 'TEXT',
  owner_agent_id: 'TEXT',
  name: 'TEXT',
  description: 'TEXT',
  enabled: 'INTEGER',
  agent_id: 'TEXT',
  payload_kind: 'TEXT',
  job_json: 'TEXT',
  state_json: 'TEXT',
  runtime_updated_at_ms: 'INTEGER',
  schedule_identity: 'TEXT',
  sort_order: 'INTEGER',
  updated_at: 'INTEGER',
};
const RECEIPT_COLUMNS: Record<string, string> = {
  receipt_id: 'TEXT',
  store_key: 'TEXT',
  job_id: 'TEXT',
  config_revision: 'INTEGER',
  agent_id: 'TEXT',
  request_run_id: 'TEXT',
  status: 'TEXT',
  owner_pid: 'INTEGER',
  owner_start_time: 'INTEGER',
  started_at_ms: 'INTEGER',
  finished_at_ms: 'INTEGER',
  error_text: 'TEXT',
};

/** Writable ONLY here — the gen2 fixture build step. */
function buildGen2CronStore(
  dbPath: string,
  shape: {
    jobs?: Gen2JobSeed[];
    receipts?: ReceiptSeed[];
    omit?: Array<'cron_jobs' | 'cron_run_receipts'>;
    dropJobColumn?: string;
    /** Leave a legacy cron_run_logs table behind (a migration leftover must
     *  not satisfy the gen2 run-outcome probe). */
    legacyRunLogs?: boolean;
  } = {},
): void {
  mkdirSync(join(dbPath, '..'), { recursive: true });
  const db = new Database(dbPath);
  try {
    const omit = new Set(shape.omit ?? []);
    if (!omit.has('cron_jobs')) {
      const cols = Object.keys(GEN2_JOB_COLUMNS).filter((c) => c !== shape.dropJobColumn);
      db.prepare(
        `CREATE TABLE cron_jobs (${cols.map((c) => `${c} ${GEN2_JOB_COLUMNS[c]}`).join(', ')})`,
      ).run();
      for (const job of shape.jobs ?? []) {
        const row: Record<string, unknown> = {
          store_key: 'default',
          declaration_key: null,
          owner_agent_id: 'main',
          description: null,
          agent_id: 'main',
          payload_kind: 'agentTurn',
          state_json: '{}',
          runtime_updated_at_ms: 0,
          schedule_identity: 'cron:0 9 * * *',
          sort_order: 0,
          updated_at: 0,
          name: job.name ?? job.job_id,
          enabled: job.enabled ?? 1,
          job_id: job.job_id,
          job_json: job.job_json ?? null,
        };
        db.prepare(
          `INSERT INTO cron_jobs (${cols.join(', ')}) VALUES (${cols.map(() => '?').join(', ')})`,
        ).run(...(cols.map((c) => row[c] ?? null) as never[]));
      }
    }
    if (!omit.has('cron_run_receipts')) {
      const cols = Object.keys(RECEIPT_COLUMNS);
      db.prepare(
        `CREATE TABLE cron_run_receipts (${cols.map((c) => `${c} ${RECEIPT_COLUMNS[c]}`).join(', ')})`,
      ).run();
      let n = 0;
      for (const r of shape.receipts ?? []) {
        const row: Record<string, unknown> = {
          receipt_id: `receipt-${(n += 1)}`,
          store_key: 'default',
          job_id: r.job_id,
          config_revision: 1,
          agent_id: 'main',
          // NULL on every sampled live row — correlation must not key on it.
          request_run_id: null,
          status: r.status,
          owner_pid: 4242,
          owner_start_time: r.started_at_ms,
          started_at_ms: r.started_at_ms,
          finished_at_ms: r.finished_at_ms ?? null,
          error_text: null,
        };
        db.prepare(
          `INSERT INTO cron_run_receipts (${cols.join(', ')}) VALUES (${cols.map(() => '?').join(', ')})`,
        ).run(...(cols.map((c) => row[c] ?? null) as never[]));
      }
    }
    if (shape.legacyRunLogs) {
      db.prepare(
        'CREATE TABLE cron_run_logs (job_id TEXT, session_key TEXT, run_at_ms INTEGER, status TEXT)',
      ).run();
    }
  } finally {
    db.close();
  }
}

/** The live gen2 payload shape: the message is a string leaf in job_json. */
function gen2JobJson(message: string): string {
  return JSON.stringify({
    schedule: { kind: 'cron', expr: '0 9 * * *' },
    payload: { kind: 'agentTurn', message },
  });
}

describe('openclaw-cron-store (#375)', () => {
  let dir: string;
  let dbPath: string;

  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), 'sc-375-store-'));
    dbPath = join(dir, '.openclaw', 'state', 'openclaw.sqlite');
  });
  afterEach(() => {
    try {
      chmodSync(dbPath, 0o600);
    } catch {
      /* the file may not exist in every case */
    }
    rmSync(dir, { recursive: true, force: true });
  });

  // -- isIncomplete truth table ------------------------------

  test('isIncomplete: only unreadable and schema_mismatch are "we could not look"', () => {
    const table: Array<[CronProbeStatus, boolean]> = [
      ['ok', false],
      ['absent', false],
      ['unreadable', true],
      ['schema_mismatch', true],
    ];
    for (const [status, expected] of table) expect(isIncomplete(status)).toBe(expected);
  });

  // -- Probe matrix ------------------------------------------

  test('probe: absent file is absent on both tables', () => {
    const probe = probeCronSource(dbPath);
    expect(probe).toMatchObject({ status: 'absent', jobs: 'absent', runLogs: 'absent' });
    expect(isIncomplete(probe.status)).toBe(false);
  });

  test('probe: a healthy store is ok on both tables', () => {
    buildCronStore(dbPath, { jobs: [], runs: [] });
    expect(probeCronSource(dbPath)).toMatchObject({ status: 'ok', jobs: 'ok', runLogs: 'ok' });
  });

  test('probe: missing cron_jobs table is absent - the store is not this shape', () => {
    buildCronStore(dbPath, { omit: ['cron_jobs'] });
    const probe = probeCronSource(dbPath);
    expect(probe.jobs).toBe('absent');
    expect(probe.status).toBe('absent');
  });

  test('probe: a cron_jobs column we read is missing means schema_mismatch', () => {
    buildCronStore(dbPath, { dropJobColumn: 'payload_message' });
    const probe = probeCronSource(dbPath);
    expect(probe.jobs).toBe('schema_mismatch');
    expect(isIncomplete(probe.status)).toBe(true);
  });

  test('probe: cron_jobs ok + cron_run_logs MISSING is cannot-look, never absent-and-fine', () => {
    buildCronStore(dbPath, { omit: ['cron_run_logs'] });
    const probe = probeCronSource(dbPath);
    expect(probe.jobs).toBe('ok');
    expect(probe.runLogs).toBe('schema_mismatch');
    expect(isIncomplete(probe.runLogs)).toBe(true);
    // Discovery is unaffected - P1 can still read cron_jobs.
    expect(isIncomplete(probe.status)).toBe(false);
  });

  test('probe: cron_run_logs missing a required column means schema_mismatch', () => {
    buildCronStore(dbPath, { dropRunColumn: 'session_key' });
    const probe = probeCronSource(dbPath);
    expect(probe.jobs).toBe('ok');
    expect(probe.runLogs).toBe('schema_mismatch');
  });

  test('probe: a file that is not a database at all is unreadable', () => {
    mkdirSync(join(dir, '.openclaw', 'state'), { recursive: true });
    writeFileSync(dbPath, 'not a sqlite database at all');
    const probe = probeCronSource(dbPath);
    expect(probe.status).toBe('unreadable');
    expect(isIncomplete(probe.status)).toBe(true);
  });

  (isRoot ? test.skip : test)('probe: an unreadable file is unreadable, never absent', () => {
    buildCronStore(dbPath, { jobs: [] });
    chmodSync(dbPath, 0o000);
    const probe = probeCronSource(dbPath);
    expect(probe.status).toBe('unreadable');
    expect(probe.runLogs).toBe('unreadable');
  });

  // -- Discovery ---------------------------------------------

  test('discovery: payload_message, trigger_script and job_json leaves, labelled openclaw-cron-db', () => {
    buildCronStore(dbPath, {
      jobs: [
        {
          job_id: 'a0000000-0000-4000-8000-000000000001',
          name: 'inbox sweep',
          enabled: 1,
          payload_message: `run python3 ${join(dir, 'sweep.py')} now`,
          trigger_script: join(dir, 'trigger.sh'),
          job_json: JSON.stringify({
            payload: { message: `bash ${join(dir, 'nested.sh')}` },
            steps: [{ cmd: `node ${join(dir, 'deep.mjs')}` }],
          }),
        },
      ],
    });
    const found = discoverDbCronScripts({ dbPath, home: dir });
    expect(found.status).toBe('ok');
    const paths = found.scripts.map((s) => s.path);
    expect(paths).toContain(join(dir, 'sweep.py'));
    expect(paths).toContain(join(dir, 'trigger.sh'));
    expect(paths).toContain(join(dir, 'nested.sh'));
    expect(paths).toContain(join(dir, 'deep.mjs'));
    for (const s of found.scripts) expect(s.sources).toEqual([OPENCLAW_CRON_DB_SOURCE]);
  });

  test('discovery: ~/ paths expand against the injected home, never the real one', () => {
    buildCronStore(dbPath, {
      jobs: [
        {
          job_id: 'a0000000-0000-4000-8000-000000000002',
          name: 'tilde',
          enabled: 1,
          payload_message: 'bash ~/jobs/nightly.sh',
        },
      ],
    });
    const found = discoverDbCronScripts({ dbPath, home: dir });
    expect(found.scripts.map((s) => s.path)).toEqual([join(dir, 'jobs', 'nightly.sh')]);
  });

  test('discovery: disabled jobs contribute no scripts but stay in jobsById', () => {
    buildCronStore(dbPath, {
      jobs: [
        {
          job_id: 'a0000000-0000-4000-8000-000000000003',
          name: 'off',
          enabled: 0,
          payload_message: `python3 ${join(dir, 'off.py')}`,
        },
        {
          job_id: 'a0000000-0000-4000-8000-000000000004',
          name: 'on',
          enabled: 1,
          payload_message: `python3 ${join(dir, 'on.py')}`,
        },
      ],
    });
    const found = discoverDbCronScripts({ dbPath, home: dir });
    expect(found.scripts.map((s) => s.path)).toEqual([join(dir, 'on.py')]);
    expect(found.jobsById.get('a0000000-0000-4000-8000-000000000003')).toMatchObject({
      enabled: false,
      paths: [join(dir, 'off.py')],
    });
  });

  test('discovery: a textual enabled column cannot empty-ok a live store', () => {
    // The bug this guards: `WHERE enabled = 1` matches nothing against a store
    // that writes '1'/'true', and 63 live jobs read as zero.
    buildCronStore(dbPath, {
      enabledType: 'TEXT',
      jobs: [
        {
          job_id: 'a0000000-0000-4000-8000-000000000005',
          name: 'textual one',
          enabled: '1',
          payload_message: `python3 ${join(dir, 'one.py')}`,
        },
        {
          job_id: 'a0000000-0000-4000-8000-000000000006',
          name: 'textual true',
          enabled: 'true',
          payload_message: `python3 ${join(dir, 'true.py')}`,
        },
        {
          job_id: 'a0000000-0000-4000-8000-000000000007',
          name: 'textual zero',
          enabled: '0',
          payload_message: `python3 ${join(dir, 'zero.py')}`,
        },
      ],
    });
    const paths = discoverDbCronScripts({ dbPath, home: dir }).scripts.map((s) => s.path);
    expect(paths).toContain(join(dir, 'one.py'));
    expect(paths).toContain(join(dir, 'true.py'));
    expect(paths).not.toContain(join(dir, 'zero.py'));
  });

  test('isJobEnabled: only unambiguous off-values are off; unknowns stay visible', () => {
    for (const off of [0, '0', '0.0', ' 0 ', 'false', 'FALSE', 'no', 'off', '', false]) {
      expect(isJobEnabled(off)).toBe(false);
    }
    for (const on of [1, '1', 'true', 'yes', null, undefined, 'anything']) {
      expect(isJobEnabled(on)).toBe(true);
    }
  });

  test('discovery: a job_json that is not JSON never throws and never loses the columns', () => {
    buildCronStore(dbPath, {
      jobs: [
        {
          job_id: 'a0000000-0000-4000-8000-000000000008',
          name: 'broken json',
          enabled: 1,
          payload_message: `python3 ${join(dir, 'kept.py')}`,
          job_json: '{not json',
        },
      ],
    });
    const found = discoverDbCronScripts({ dbPath, home: dir });
    expect(found.status).toBe('ok');
    expect(found.scripts.map((s) => s.path)).toEqual([join(dir, 'kept.py')]);
  });

  test('discovery: an unreadable store yields the failing status and no scripts', () => {
    mkdirSync(join(dir, '.openclaw', 'state'), { recursive: true });
    writeFileSync(dbPath, 'corrupt');
    const found = discoverDbCronScripts({ dbPath, home: dir });
    expect(found.status).toBe('unreadable');
    expect(found.scripts).toEqual([]);
    expect(found.jobsById.size).toBe(0);
  });

  test('discovery: an absent store is absent, not an error', () => {
    const found = discoverDbCronScripts({ dbPath, home: dir });
    expect(found.status).toBe('absent');
    expect(found.scripts).toEqual([]);
  });

  // -- OC2 generation (#456) ---------------------------------

  test('probe: a gen1 store reports its generation and legacy run table', () => {
    buildCronStore(dbPath, { jobs: [], runs: [] });
    expect(probeCronSource(dbPath)).toMatchObject({
      generation: 'gen1',
      runTable: 'cron_run_logs',
    });
  });

  test('probe: an OC2 store is ok on both tables — this exact live shape read schema_mismatch before', () => {
    buildGen2CronStore(dbPath, { jobs: [], receipts: [] });
    const probe = probeCronSource(dbPath);
    expect(probe).toMatchObject({
      status: 'ok',
      jobs: 'ok',
      runLogs: 'ok',
      generation: 'gen2',
      runTable: 'cron_run_receipts',
    });
    expect(isIncomplete(probe.status)).toBe(false);
  });

  test('probe: gen2 cron_jobs with no cron_run_receipts is cannot-look on run outcomes', () => {
    // A leftover legacy cron_run_logs must not satisfy the gen2 probe either.
    buildGen2CronStore(dbPath, { omit: ['cron_run_receipts'], legacyRunLogs: true });
    const probe = probeCronSource(dbPath);
    expect(probe.jobs).toBe('ok');
    expect(probe.generation).toBe('gen2');
    expect(probe.runTable).toBe('cron_run_receipts');
    expect(probe.runLogs).toBe('schema_mismatch');
    expect(isIncomplete(probe.runLogs)).toBe(true);
  });

  test('probe: a cron_jobs matching NEITHER generation stays schema_mismatch', () => {
    // gen2 columns minus job_json: not gen1 (no payload_message), not gen2.
    buildGen2CronStore(dbPath, { dropJobColumn: 'job_json' });
    const probe = probeCronSource(dbPath);
    expect(probe.jobs).toBe('schema_mismatch');
    expect(probe.generation).toBeNull();
    expect(isIncomplete(probe.status)).toBe(true);
  });

  test('discovery: gen2 paths come from job_json payload.message', () => {
    buildGen2CronStore(dbPath, {
      jobs: [
        {
          job_id: 'b0000000-0000-4000-8000-000000000001',
          name: 'oc2 sweep',
          enabled: 1,
          job_json: gen2JobJson(`run python3 ${join(dir, 'oc2-sweep.py')} now`),
        },
      ],
      receipts: [],
    });
    const found = discoverDbCronScripts({ dbPath, home: dir });
    expect(found.status).toBe('ok');
    expect(found.scripts.map((s) => s.path)).toEqual([join(dir, 'oc2-sweep.py')]);
    for (const s of found.scripts) expect(s.sources).toEqual([OPENCLAW_CRON_DB_SOURCE]);
  });

  test('discovery: a disabled gen2 job contributes no scripts but stays in jobsById', () => {
    buildGen2CronStore(dbPath, {
      jobs: [
        {
          job_id: 'b0000000-0000-4000-8000-000000000002',
          name: 'oc2 off',
          enabled: 0,
          job_json: gen2JobJson(`python3 ${join(dir, 'oc2-off.py')}`),
        },
        {
          job_id: 'b0000000-0000-4000-8000-000000000003',
          name: 'oc2 on',
          enabled: 1,
          job_json: gen2JobJson(`python3 ${join(dir, 'oc2-on.py')}`),
        },
      ],
      receipts: [],
    });
    const found = discoverDbCronScripts({ dbPath, home: dir });
    expect(found.scripts.map((s) => s.path)).toEqual([join(dir, 'oc2-on.py')]);
    expect(found.jobsById.get('b0000000-0000-4000-8000-000000000002')).toMatchObject({
      enabled: false,
      paths: [join(dir, 'oc2-off.py')],
    });
  });

  // -- Walk + rendering hygiene ------------------------------

  test('walkStringLeaves visits string leaves structurally, not a stringified blob', () => {
    const seen: string[] = [];
    walkStringLeaves({ a: 'one', b: [{ c: 'two' }, 3, null], d: { e: { f: 'three' } } }, (s) =>
      seen.push(s),
    );
    expect(seen.sort()).toEqual(['one', 'three', 'two']);
  });

  test('walkStringLeaves terminates on a self-referencing structure', () => {
    const cyclic: Record<string, unknown> = { name: 'loop' };
    cyclic.self = cyclic;
    const seen: string[] = [];
    expect(() => walkStringLeaves(cyclic, (s) => seen.push(s))).not.toThrow();
    expect(seen).toEqual(['loop']);
  });

  test('sanitiseJobName strips escape sequences before a job name reaches a terminal', () => {
    const clean = sanitiseJobName(`${ESC}[31mFAKE${ESC}[0m name\nsecond line`);
    expect(clean).not.toContain(ESC);
    expect(clean).not.toContain('\n');
    expect(clean).toContain('FAKE');
    expect(clean).toContain('second line');
  });

  test('sanitiseJobName caps runaway names', () => {
    expect(sanitiseJobName('x'.repeat(500)).length).toBeLessThanOrEqual(81);
  });
});
