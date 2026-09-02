/**
 * Spec for the OpenClaw SQLite cron source in `allowlist scan` (#375 P1).
 *
 * #309 read `~/.openclaw/cron/jobs.json`. OpenClaw migrated that store into
 * `~/.openclaw/state/openclaw.sqlite` and deleted the JSON, leaving only
 * `.bak`/`.migrated` siblings — so scan discovered zero gateway cron scripts
 * and exited 0. Everything below exists to make that state impossible to
 * report as "all clear" again.
 *
 * Every path is injected. Real ~/.hermes, ~/.openclaw and ~/.shieldcortex are
 * never read.
 */
import Database from 'better-sqlite3';
import { mkdirSync, mkdtempSync, realpathSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { discoverScripts, runAllowlistScan } from '../allowlist-scan.js';
import { hashScriptSource } from '../../defence/iron-dome/reviewed-scripts.js';

const SOURCE = '#!/usr/bin/env python3\nprint("sentry sweep")\n';
const JOB_A = 'aaaaaaaa-1111-4111-8111-aaaaaaaaaaaa';
const keyFor = (jobId: string, run: string): string => `agent:main:cron:${jobId}:run:${run}`;

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

/** Writable ONLY here. Scan reopens through the read-only helper. */
function buildStore(
  dbPath: string,
  shape: { jobs?: JobSeed[]; runs?: RunSeed[]; dropColumn?: string } = {},
): void {
  mkdirSync(dirname(dbPath), { recursive: true });
  const db = new Database(dbPath);
  try {
    const cols: Record<string, string> = {
      job_id: 'TEXT',
      name: 'TEXT',
      enabled: 'INTEGER',
      payload_message: 'TEXT',
      trigger_script: 'TEXT',
      job_json: 'TEXT',
    };
    const names = Object.keys(cols).filter((c) => c !== shape.dropColumn);
    db.exec(`CREATE TABLE cron_jobs (${names.map((n) => `${n} ${cols[n]}`).join(', ')})`);
    for (const j of shape.jobs ?? []) {
      const values = names.map((n) => {
        const v = (j as Record<string, unknown>)[n];
        if (n === 'name') return j.name ?? j.job_id;
        if (n === 'enabled') return j.enabled ?? 1;
        return v ?? null;
      });
      db.prepare(
        `INSERT INTO cron_jobs (${names.join(', ')}) VALUES (${names.map(() => '?').join(', ')})`,
      ).run(...(values as never[]));
    }
    db.exec('CREATE TABLE cron_run_logs (job_id TEXT, session_key TEXT, run_at_ms INTEGER, status TEXT)');
    for (const r of shape.runs ?? []) {
      db.prepare(
        'INSERT INTO cron_run_logs (job_id, session_key, run_at_ms, status) VALUES (?, ?, ?, ?)',
      ).run(r.job_id, r.session_key, r.run_at_ms, r.status);
    }
  } finally {
    db.close();
  }
}




/**
 * Writable ONLY here — the OC2 (gen2, #456) fixture: the measured 2026.8.1
 * shape (no payload_message/trigger_script; cron_run_receipts, not
 * cron_run_logs). Before #456 this exact live shape scanned as
 * SCHEMA MISMATCH and exited 1 on an 82-job host.
 */
function buildGen2Store(
  dbPath: string,
  shape: { jobs?: Array<{ job_id: string; name?: string; enabled?: unknown; job_json?: string | null }> } = {},
): void {
  mkdirSync(dirname(dbPath), { recursive: true });
  const db = new Database(dbPath);
  try {
    db.prepare(
      `CREATE TABLE cron_jobs (store_key TEXT, job_id TEXT, declaration_key TEXT,
        owner_agent_id TEXT, name TEXT, description TEXT, enabled INTEGER, agent_id TEXT,
        payload_kind TEXT, job_json TEXT, state_json TEXT, runtime_updated_at_ms INTEGER,
        schedule_identity TEXT, sort_order INTEGER, updated_at INTEGER)`,
    ).run();
    for (const j of shape.jobs ?? []) {
      db.prepare(
        `INSERT INTO cron_jobs (store_key, job_id, owner_agent_id, name, enabled, agent_id,
          payload_kind, job_json, state_json, runtime_updated_at_ms, sort_order, updated_at)
         VALUES ('default', ?, 'main', ?, ?, 'main', 'agentTurn', ?, '{}', 0, 0, 0)`,
      ).run(j.job_id, j.name ?? j.job_id, (j.enabled ?? 1) as never, j.job_json ?? null);
    }
    db.prepare(
      `CREATE TABLE cron_run_receipts (receipt_id TEXT, store_key TEXT, job_id TEXT,
        config_revision INTEGER, agent_id TEXT, request_run_id TEXT, status TEXT,
        owner_pid INTEGER, owner_start_time INTEGER, started_at_ms INTEGER,
        finished_at_ms INTEGER, error_text TEXT)`,
    ).run();
  } finally {
    db.close();
  }
}

/** Paths may soft/hard-wrap for 40-col TUI; assert against whitespace-collapsed logs.
 *  macOS realpath often adds a `/private` prefix — accept both forms. */
function flatLogs(logs: string[]): string {
  return logs.join('\n').replace(/\s+/g, '');
}
function normPath(path: string): string {
  const p = path.replace(/\s+/g, '');
  return p.startsWith('/private/') ? p.slice('/private'.length) : p;
}
function expectLogPath(logs: string[], path: string): void {
  const hay = flatLogs(logs);
  const needle = path.replace(/\s+/g, '');
  const ok =
    hay.includes(needle) ||
    hay.includes(normPath(needle)) ||
    hay.includes(`/private${normPath(needle)}`);
  expect(ok).toBe(true);
}

describe('allowlist scan: OpenClaw SQLite cron source (#375)', () => {
  const NOW = 1_760_000_000_000;
  let dir: string;
  let dbPath: string;
  let denialsPath: string;
  let scriptPath: string;
  let stored: unknown[];
  let logs: string[];
  let errs: string[];

  const deps = (over: Record<string, unknown> = {}) => ({
    home: dir,
    cwd: dir,
    interactive: false,
    openclawDbPath: dbPath,
    denialsPath,
    now: NOW,
    log: (m: string) => logs.push(m),
    error: (m: string) => errs.push(m),
    readEntries: () => stored,
    writeEntries: (e: Array<Record<string, unknown>>) => {
      stored = e;
    },
    ...over,
  });

  const answers = (list: string[]) => {
    const queue = [...list];
    return async () => queue.shift() ?? '';
  };

  const writeOpenClawJson = (doc: unknown): void => {
    const cronDir = join(dir, '.openclaw', 'cron');
    mkdirSync(cronDir, { recursive: true });
    writeFileSync(join(cronDir, 'jobs.json'), JSON.stringify(doc));
  };

  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), 'sc-375-scan-'));
    dbPath = join(dir, '.openclaw', 'state', 'openclaw.sqlite');
    denialsPath = join(dir, '.shieldcortex', 'denials.jsonl');
    scriptPath = join(dir, 'sentry.py');
    writeFileSync(scriptPath, SOURCE);
    stored = [];
    logs = [];
    errs = [];
  });
  afterEach(() => rmSync(dir, { recursive: true, force: true }));

  // -- Discovery ------------------------------------------------

  test('scripts in the SQLite store are discovered and labelled openclaw-cron-db', async () => {
    buildStore(dbPath, {
      jobs: [{ job_id: JOB_A, name: 'sentry', payload_message: `python3 ${scriptPath}` }],
    });

    const found = discoverScripts({ home: dir, openclawDbPath: dbPath });
    expect(found.scripts.map((s) => s.path)).toContain(scriptPath);
    expect(found.sources.openclawDb).toMatchObject({ path: dbPath, status: 'ok' });

    const code = await runAllowlistScan([], deps());
    expect(code).toBe(3);
    expect(logs.join('\n')).toContain('openclaw-cron-db');
    expectLogPath(logs, realpathSync(scriptPath));
    expect(stored).toEqual([]);
  });

  test('the SQLite store and a surviving JSON store are unioned', async () => {
    const jsonScript = join(dir, 'legacy.sh');
    writeFileSync(jsonScript, 'echo legacy\n');
    writeOpenClawJson({ version: 1, jobs: [{ payload: { kind: 'agentTurn', message: `sh ${jsonScript}` } }] });
    buildStore(dbPath, {
      jobs: [{ job_id: JOB_A, name: 'sentry', payload_message: `python3 ${scriptPath}` }],
    });

    const found = discoverScripts({ home: dir, openclawDbPath: dbPath });
    const bySource = new Map(found.scripts.map((s) => [s.path, s.sources]));
    expect(bySource.get(jsonScript)).toEqual(['openclaw-cron']);
    expect(bySource.get(scriptPath)).toEqual(['openclaw-cron-db']);
  });

  test('a script named by BOTH stores is one item carrying both sources', () => {
    writeOpenClawJson({ version: 1, jobs: [{ payload: { message: `python3 ${scriptPath}` } }] });
    buildStore(dbPath, {
      jobs: [{ job_id: JOB_A, name: 'sentry', payload_message: `python3 ${scriptPath}` }],
    });
    const found = discoverScripts({ home: dir, openclawDbPath: dbPath });
    const entry = found.scripts.find((s) => s.path === scriptPath);
    expect(entry?.sources.sort()).toEqual(['openclaw-cron', 'openclaw-cron-db']);
  });

  test('.bak and .migrated leftovers are never read and never prove the store absent', async () => {
    const cronDir = join(dir, '.openclaw', 'cron');
    mkdirSync(cronDir, { recursive: true });
    const ghost = join(dir, 'ghost.py');
    writeFileSync(ghost, 'print("ghost")\n');
    for (const name of ['jobs.json.bak', 'jobs.json.migrated']) {
      writeFileSync(join(cronDir, name), JSON.stringify({ jobs: [{ payload: { message: `python3 ${ghost}` } }] }));
    }
    buildStore(dbPath, {
      jobs: [{ job_id: JOB_A, name: 'sentry', payload_message: `python3 ${scriptPath}` }],
    });

    const found = discoverScripts({ home: dir, openclawDbPath: dbPath });
    expect(found.scripts.map((s) => s.path)).toEqual([scriptPath]);
    expect(found.sources.openclaw.status).toBe('absent');
    expect(found.sources.openclawCronUnverifiable).toBe(false);

    // The live SQLite store is readable, so the scan is complete.
    const code = await runAllowlistScan([], deps());
    expect(code).toBe(3);
  });

  test('an OC2 (gen2, #456) store scans ok and its job_json scripts are discovered', async () => {
    // The regression this pins: before #456 this measured live shape probed
    // schema_mismatch, so a healthy 82-job OpenClaw 2 host exited 1 with an
    // empty script list.
    buildGen2Store(dbPath, {
      jobs: [
        {
          job_id: JOB_A,
          name: 'oc2 sentry',
          job_json: JSON.stringify({ payload: { kind: 'agentTurn', message: `python3 ${scriptPath}` } }),
        },
      ],
    });

    const found = discoverScripts({ home: dir, openclawDbPath: dbPath });
    expect(found.sources.openclawDb).toMatchObject({ path: dbPath, status: 'ok' });
    expect(found.scripts.map((s) => s.path)).toContain(scriptPath);

    const code = await runAllowlistScan([], deps());
    expect(code).toBe(3);
    expect(logs.join('\n')).toContain('openclaw-cron-db');
    expect(logs.join('\n')).not.toContain('SCHEMA MISMATCH');
    expectLogPath(logs, realpathSync(scriptPath));
    expect(stored).toEqual([]);
  });

  // -- Visibility rule ------------------------------------------

  test('OpenClaw installed with NO readable cron source is visible and exits 1', async () => {
    mkdirSync(join(dir, '.openclaw'), { recursive: true });

    const found = discoverScripts({ home: dir, openclawDbPath: dbPath });
    expect(found.sources.openclaw.status).toBe('absent');
    expect(found.sources.openclawDb.status).toBe('absent');
    expect(found.sources.openclawCronUnverifiable).toBe(true);

    const code = await runAllowlistScan([], deps());
    expect(code).toBe(1);
    expectLogPath([...logs, ...errs], dbPath);
    expect(`${logs.join('\n')}\n${errs.join('\n')}`).toMatch(/could not look|not readable|incomplete/i);
  });

  test('a host with no ~/.openclaw at all stays empty-ok', async () => {
    const code = await runAllowlistScan([], deps());
    expect(code).toBe(0);
    expect(discoverScripts({ home: dir, openclawDbPath: dbPath }).sources.openclawCronUnverifiable).toBe(
      false,
    );
    expect(errs).toEqual([]);
  });

  test('a readable JSON store keeps an absent SQLite store quiet', async () => {
    writeOpenClawJson({ version: 1, jobs: [] });
    const found = discoverScripts({ home: dir, openclawDbPath: dbPath });
    expect(found.sources.openclawCronUnverifiable).toBe(false);
    expect(await runAllowlistScan([], deps())).toBe(0);
  });

  // -- Broken sources -------------------------------------------

  test('a corrupt SQLite store is incomplete discovery, not empty-ok', async () => {
    mkdirSync(dirname(dbPath), { recursive: true });
    writeFileSync(dbPath, 'not a sqlite database at all');

    const code = await runAllowlistScan([], deps());
    expect(code).toBe(1);
    expect(stored).toEqual([]);
    expect(logs.join('\n')).toContain('UNREADABLE');
    expect(errs.join('\n').replace(/\s+/g, '')).toContain(String(dbPath).replace(/\s+/g, ''));
  });

  test('a cron_jobs table missing a column we read exits 1 as schema_mismatch', async () => {
    buildStore(dbPath, { jobs: [], dropColumn: 'payload_message' });

    const code = await runAllowlistScan([], deps());
    expect(code).toBe(1);
    expect(discoverScripts({ home: dir, openclawDbPath: dbPath }).sources.openclawDb.status).toBe(
      'schema_mismatch',
    );
    expect(logs.join('\n')).toContain('SCHEMA MISMATCH');
  });

  test('--json reports the SQLite source and marks discovery incomplete', async () => {
    mkdirSync(dirname(dbPath), { recursive: true });
    writeFileSync(dbPath, 'corrupt');

    const code = await runAllowlistScan(['--json'], deps());
    expect(code).toBe(1);
    const report = JSON.parse(logs.join('\n')) as {
      discoveryIncomplete: boolean;
      sources: { openclawDb: { path: string; status: string }; openclawCronUnverifiable: boolean };
    };
    expect(report.discoveryIncomplete).toBe(true);
    expect(report.sources.openclawDb).toEqual({ path: dbPath, status: 'unreadable' });
  });

  test('--openclaw-cron-db overrides the default store path', async () => {
    const elsewhere = join(dir, 'elsewhere.sqlite');
    buildStore(elsewhere, {
      jobs: [{ job_id: JOB_A, name: 'sentry', payload_message: `python3 ${scriptPath}` }],
    });
    const code = await runAllowlistScan(['--openclaw-cron-db', elsewhere], deps({ openclawDbPath: undefined }));
    expect(code).toBe(3);
    expectLogPath(logs, realpathSync(scriptPath));
  });

  // -- Denied-first ordering ------------------------------------

  test('guard-denied cron scripts sort first and say which job', async () => {
    const quiet = join(dir, 'aaa-quiet.py'); // sorts before sentry.py by path
    writeFileSync(quiet, 'print("quiet")\n');
    buildStore(dbPath, {
      jobs: [
        { job_id: JOB_A, name: 'inbox sweep', payload_message: `python3 ${scriptPath}` },
        {
          job_id: 'cccccccc-3333-4333-8333-cccccccccccc',
          name: 'quiet job',
          payload_message: `python3 ${quiet}`,
        },
      ],
      runs: [{ job_id: JOB_A, session_key: keyFor(JOB_A, 'r1'), run_at_ms: NOW - 61_000, status: 'ok' }],
    });
    mkdirSync(dirname(denialsPath), { recursive: true });
    writeFileSync(
      denialsPath,
      JSON.stringify({
        actionId: 'act-0000000000000001',
        sessionKey: keyFor(JOB_A, 'r1'),
        detectedAt: new Date(NOW - 60_000).toISOString(),
      }) + '\n',
    );

    const code = await runAllowlistScan([], deps());
    expect(code).toBe(3);
    const out = logs.join('\n');
    expect(out).toContain('guard-denied in the last 7 days (job: inbox sweep)');
    // Paths may wrap at 40 cols — compare on whitespace-collapsed text and
    // tolerate macOS /private realpath prefix.
    const flat = flatLogs(logs);
    const denied = normPath(realpathSync(scriptPath));
    const other = normPath(realpathSync(quiet));
    const di = Math.max(flat.indexOf(denied), flat.indexOf(`/private${denied}`));
    const oi = Math.max(flat.indexOf(other), flat.indexOf(`/private${other}`));
    expect(di).toBeGreaterThanOrEqual(0);
    expect(oi).toBeGreaterThanOrEqual(0);
    expect(di).toBeLessThan(oi);
    // The denial surface never reaches the review list.
    expect(out).not.toContain('act-0000000000000001');
  });

  test('no denial log means no denied-first flag and no failure', async () => {
    buildStore(dbPath, {
      jobs: [{ job_id: JOB_A, name: 'sentry', payload_message: `python3 ${scriptPath}` }],
    });
    const code = await runAllowlistScan([], deps());
    expect(code).toBe(3);
    expect(logs.join('\n')).not.toContain('guard-denied');
  });

  // -- First-backfill guard -------------------------------------

  test('--yes is refused while any SQLite-store script is still unpinned', async () => {
    buildStore(dbPath, {
      jobs: [{ job_id: JOB_A, name: 'sentry', payload_message: `python3 ${scriptPath}` }],
    });

    const code = await runAllowlistScan(['--yes'], deps({ interactive: true, prompt: answers(['approve']) }));
    expect(code).toBe(1);
    expect(stored).toEqual([]);
    expect(errs.join('\n').replace(/\s+/g, '')).toContain(String('openclaw-cron-db').replace(/\s+/g, ''));
    expect(errs.join('\n').replace(/\s+/g, '')).toContain(String('without --yes').replace(/\s+/g, ''));
  });

  test('--yes works again once the SQLite backfill has been reviewed per item', async () => {
    buildStore(dbPath, {
      jobs: [{ job_id: JOB_A, name: 'sentry', payload_message: `python3 ${scriptPath}` }],
    });
    const other = join(dir, 'zz-hermes.sh');
    writeFileSync(other, 'echo hermes\n');
    mkdirSync(join(dir, '.hermes', 'cron'), { recursive: true });
    writeFileSync(
      join(dir, '.hermes', 'cron', 'jobs.json'),
      JSON.stringify({ jobs: [{ prompt: `sh ${other}` }] }),
    );
    stored = [{ path: realpathSync(scriptPath), sha256: hashScriptSource(SOURCE) }];

    const code = await runAllowlistScan(['--yes'], deps({ interactive: true, prompt: answers(['approve']) }));
    expect(code).toBe(0);
    expect((stored as Array<Record<string, unknown>>).map((e) => e.path)).toContain(realpathSync(other));
  });

  test('the per-item review still pins a SQLite-discovered script', async () => {
    buildStore(dbPath, {
      jobs: [{ job_id: JOB_A, name: 'sentry', payload_message: `python3 ${scriptPath}` }],
    });
    const code = await runAllowlistScan([], deps({ interactive: true, prompt: answers(['y', 'reviewed']) }));
    expect(code).toBe(0);
    expect(stored).toEqual([
      {
        path: realpathSync(scriptPath),
        sha256: hashScriptSource(SOURCE),
        note: 'reviewed',
        addedAt: NOW,
      },
    ]);
  });

  // -- No writes to the OpenClaw store --------------------------

  test('a full scan leaves the OpenClaw store byte-identical', async () => {
    buildStore(dbPath, {
      jobs: [{ job_id: JOB_A, name: 'sentry', payload_message: `python3 ${scriptPath}` }],
      runs: [{ job_id: JOB_A, session_key: keyFor(JOB_A, 'r1'), run_at_ms: NOW - 61_000, status: 'ok' }],
    });
    const { readFileSync } = await import('node:fs');
    const before = readFileSync(dbPath);
    await runAllowlistScan([], deps());
    expect(readFileSync(dbPath).equals(before)).toBe(true);
  });
});
