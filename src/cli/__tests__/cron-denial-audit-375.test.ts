/**
 * Spec for cron denial correlation (#375 P2) and the doctor CRON check.
 *
 * The property under test throughout is that a WRONG answer is impossible:
 * every path that cannot prove silence reports that it could not, and none of
 * them collapses into a green "0 silent denials". The failure this replaces
 * was two crons dead for two weeks behind `last_run_status: ok`.
 *
 * Fixture stores and denial logs live in a tmp home. Real ~/.openclaw and
 * ~/.shieldcortex are never read.
 */
import Database from 'better-sqlite3';
import { readdirSync, chmodSync, mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  correlateCronDenials,
  CRON_SESSION_KEY_RE,
  DENIALS_TAIL_BYTES,
  deniedScriptPaths,
  parseDenials,
} from '../cron-denial-audit.js';
import { checkCronDenials } from '../doctor.js';

const isRoot = typeof process.getuid === 'function' && process.getuid() === 0;
const HERE = dirname(fileURLToPath(import.meta.url));

const JOB_A = 'aaaaaaaa-1111-4111-8111-aaaaaaaaaaaa';
const JOB_B = 'bbbbbbbb-2222-4222-8222-bbbbbbbbbbbb';
const keyFor = (jobId: string, run: string): string => `agent:main:cron:${jobId}:run:${run}`;

interface JobSeed {
  job_id: string;
  name?: string;
  enabled?: unknown;
  payload_message?: string | null;
  trigger_script?: string | null;
  job_json?: string | null;
  last_run_status?: string | null;
}
interface RunSeed {
  job_id: string;
  session_key: string;
  run_at_ms: number;
  status: string;
}

/** Writable ONLY here. Everything under test reopens read-only. */
function buildStore(
  dbPath: string,
  shape: { jobs?: JobSeed[]; runs?: RunSeed[]; omitRunLogs?: boolean } = {},
): void {
  mkdirSync(dirname(dbPath), { recursive: true });
  const db = new Database(dbPath);
  try {
    db.exec(
      `CREATE TABLE cron_jobs (job_id TEXT, name TEXT, enabled INTEGER, payload_message TEXT,
        trigger_script TEXT, job_json TEXT, last_run_status TEXT)`,
    );
    for (const j of shape.jobs ?? []) {
      db.prepare(
        `INSERT INTO cron_jobs (job_id, name, enabled, payload_message, trigger_script, job_json, last_run_status)
         VALUES (?, ?, ?, ?, ?, ?, ?)`,
      ).run(
        j.job_id,
        j.name ?? j.job_id,
        j.enabled ?? 1,
        j.payload_message ?? null,
        j.trigger_script ?? null,
        j.job_json ?? null,
        j.last_run_status ?? null,
      );
    }
    if (!shape.omitRunLogs) {
      db.exec(
        'CREATE TABLE cron_run_logs (job_id TEXT, session_key TEXT, run_at_ms INTEGER, status TEXT)',
      );
      for (const r of shape.runs ?? []) {
        db.prepare(
          'INSERT INTO cron_run_logs (job_id, session_key, run_at_ms, status) VALUES (?, ?, ?, ?)',
        ).run(r.job_id, r.session_key, r.run_at_ms, r.status);
      }
    }
  } finally {
    db.close();
  }
}

describe('cron denial correlation (#375 P2)', () => {
  const NOW = 1_760_000_000_000;
  let home: string;
  let dbPath: string;
  let denialsPath: string;
  let scriptA: string;

  const writeDenials = (rows: Array<Record<string, unknown>>): void => {
    mkdirSync(dirname(denialsPath), { recursive: true });
    writeFileSync(denialsPath, rows.map((r) => JSON.stringify(r)).join('\n') + '\n');
  };

  const denial = (over: Record<string, unknown> = {}): Record<string, unknown> => ({
    event: 'pre_tool_use',
    outcome: 'denied_no_prompt_surface',
    tool: 'Bash',
    surface: 'Bash: [redacted action surface; command not persisted]',
    actionId: 'act-0000000000000001',
    sessionKey: keyFor(JOB_A, 'r1'),
    detectedAt: new Date(NOW - 60_000).toISOString(),
    ...over,
  });

  const correlate = (over: Record<string, unknown> = {}) =>
    correlateCronDenials({ home, openclawDbPath: dbPath, denialsPath, now: NOW, ...over });

  beforeEach(() => {
    home = mkdtempSync(join(tmpdir(), 'sc-375-audit-'));
    dbPath = join(home, '.openclaw', 'state', 'openclaw.sqlite');
    denialsPath = join(home, '.shieldcortex', 'denials.jsonl');
    scriptA = join(home, 'sweep.py');
  });
  afterEach(() => {
    try {
      chmodSync(denialsPath, 0o600);
    } catch {
      /* may not exist */
    }
    rmSync(home, { recursive: true, force: true });
  });

  // -- Match A --------------------------------------------------

  test('Match A attributes a denial to the exact job in its session key', () => {
    buildStore(dbPath, {
      jobs: [{ job_id: JOB_A, name: 'inbox sweep', payload_message: `python3 ${scriptA}` }],
      runs: [{ job_id: JOB_A, session_key: keyFor(JOB_A, 'r1'), run_at_ms: NOW - 61_000, status: 'ok' }],
    });
    writeDenials([denial()]);

    const report = correlate();
    expect(report.cannotCorrelate).toBeNull();
    expect(report.attributedCount).toBe(1);
    expect(report.jobs).toHaveLength(1);
    expect(report.jobs[0]).toMatchObject({
      jobId: JOB_A,
      name: 'inbox sweep',
      enabled: true,
      denialCount: 1,
      silentCount: 1,
      pinnablePaths: [scriptA],
    });
    expect(report.silentCount).toBe(1);
  });

  test('malformed and foreign session keys are counted, never guessed at', () => {
    buildStore(dbPath, { jobs: [{ job_id: JOB_A }], runs: [] });
    writeDenials([
      denial({ actionId: 'act-0000000000000001', sessionKey: 'sc-abcdef0123456789' }),
      denial({ actionId: 'act-0000000000000002', sessionKey: 'agent:main:cron:not-a-uuid:run:x' }),
      denial({ actionId: 'act-0000000000000003', sessionKey: `agent:main:cron:${JOB_A}` }),
      denial({ actionId: 'act-0000000000000004' }),
    ]);

    const report = correlate();
    expect(report.attributedCount).toBe(1);
    expect(report.unattributedCount).toBe(3);
    expect(report.jobs.map((j) => j.jobId)).toEqual([JOB_A]);
  });

  test('the Match A regex requires the full cron run-key shape', () => {
    expect(CRON_SESSION_KEY_RE.test(keyFor(JOB_A, 'r1'))).toBe(true);
    expect(CRON_SESSION_KEY_RE.test(`prefix-${keyFor(JOB_A, 'r1')}`)).toBe(false);
    expect(CRON_SESSION_KEY_RE.test(`agent:main:cron:${JOB_A}`)).toBe(false);
    expect(CRON_SESSION_KEY_RE.test('agent:main:chat:x:run:y')).toBe(false);
  });

  // -- Dedupe / window ------------------------------------------

  test('the two lines one denial writes are one denial', () => {
    buildStore(dbPath, {
      jobs: [{ job_id: JOB_A, name: 'sweep', payload_message: `python3 ${scriptA}` }],
      runs: [{ job_id: JOB_A, session_key: keyFor(JOB_A, 'r1'), run_at_ms: NOW - 61_000, status: 'ok' }],
    });
    writeDenials([
      denial({ detectedAt: new Date(NOW - 60_000).toISOString() }),
      denial({ detectedAt: new Date(NOW - 59_000).toISOString(), notify: { status: 'delivered' } }),
    ]);

    const report = correlate();
    expect(report.attributedCount).toBe(1);
    expect(report.jobs[0].denialCount).toBe(1);
    expect(report.jobs[0].silentCount).toBe(1);
  });

  test('denials outside the window are not counted', () => {
    buildStore(dbPath, {
      jobs: [{ job_id: JOB_A }],
      runs: [{ job_id: JOB_A, session_key: keyFor(JOB_A, 'r1'), run_at_ms: NOW - 61_000, status: 'ok' }],
    });
    const eightDaysAgo = new Date(NOW - 8 * 86_400_000).toISOString();
    writeDenials([denial({ detectedAt: eightDaysAgo })]);

    const report = correlate();
    expect(report.attributedCount).toBe(0);
    expect(report.jobs).toEqual([]);
    expect(report.silentCount).toBe(0);
  });

  test('a run row outside the SQL window cannot confirm a denial', () => {
    buildStore(dbPath, {
      jobs: [{ job_id: JOB_A }],
      runs: [
        {
          job_id: JOB_A,
          session_key: keyFor(JOB_A, 'r1'),
          run_at_ms: NOW - 30 * 86_400_000,
          status: 'ok',
        },
      ],
    });
    writeDenials([denial()]);

    const report = correlate();
    expect(report.attributedCount).toBe(1);
    expect(report.unconfirmedCount).toBe(1);
    expect(report.silentCount).toBe(0);
  });

  test('rows with no parseable timestamp are counted, never silently dropped', () => {
    buildStore(dbPath, { jobs: [{ job_id: JOB_A }], runs: [] });
    writeDenials([denial({ detectedAt: 'not a date' })]);
    const report = correlate();
    expect(report.undatedCount).toBe(1);
    expect(report.attributedCount).toBe(0);
  });

  // -- Silence is keyed off the RUN log, not the job row ---------

  test('silence comes from the attributed run row, not the job last_run_status', () => {
    buildStore(dbPath, {
      jobs: [
        {
          job_id: JOB_A,
          name: 'sweep',
          payload_message: `python3 ${scriptA}`,
          // The job row lies in the other direction on purpose.
          last_run_status: 'error',
        },
      ],
      runs: [
        { job_id: JOB_A, session_key: keyFor(JOB_A, 'r1'), run_at_ms: NOW - 61_000, status: 'ok' },
        { job_id: JOB_A, session_key: keyFor(JOB_A, 'r2'), run_at_ms: NOW - 30_000, status: 'error' },
      ],
    });
    writeDenials([denial({ sessionKey: keyFor(JOB_A, 'r1') })]);
    expect(correlate().jobs[0].silentCount).toBe(1);

    // The same job, denied inside the run that DID report the failure.
    writeDenials([denial({ sessionKey: keyFor(JOB_A, 'r2') })]);
    const honest = correlate();
    expect(honest.jobs[0].denialCount).toBe(1);
    expect(honest.jobs[0].silentCount).toBe(0);
    expect(honest.unconfirmedCount).toBe(0);
  });

  test('no exactly-matching run row is unconfirmed, never silent and never a clean pass', () => {
    buildStore(dbPath, {
      jobs: [{ job_id: JOB_A, name: 'sweep' }],
      // A green run at the same moment, under a DIFFERENT session key. The
      // deleted nearest-run fallback would have glued the denial to it.
      runs: [
        { job_id: JOB_A, session_key: keyFor(JOB_A, 'other'), run_at_ms: NOW - 60_500, status: 'ok' },
      ],
    });
    writeDenials([denial({ sessionKey: keyFor(JOB_A, 'r1') })]);

    const report = correlate();
    expect(report.unconfirmedCount).toBe(1);
    expect(report.silentCount).toBe(0);
    expect(report.jobs[0].denialCount).toBe(1);
    expect(report.jobs[0].silentCount).toBe(0);
  });

  // -- Fail-closed source handling ------------------------------

  test('cron_jobs ok + cron_run_logs missing is cannot-correlate, NOT silentCount 0', () => {
    buildStore(dbPath, { jobs: [{ job_id: JOB_A, name: 'sweep' }], omitRunLogs: true });
    writeDenials([denial()]);

    const report = correlate();
    expect(report.cannotCorrelate).toContain('cron_run_logs');
    expect(report.silentCount).toBe(0);
    expect(report.jobs[0].denialCount).toBe(1);
    expect(report.jobs[0].silentCount).toBe(0);
  });

  test('a run-log query that dies mid-correlation drops every silence claim', () => {
    buildStore(dbPath, {
      jobs: [{ job_id: JOB_A, name: 'sweep' }],
      runs: [{ job_id: JOB_A, session_key: keyFor(JOB_A, 'r1'), run_at_ms: NOW - 61_000, status: 'ok' }],
    });
    writeDenials([denial()]);
    // Sanity: it correlates cleanly without the injected failure.
    expect(correlate().silentCount).toBe(1);

    const report = correlate({
      openStore: () => {
        throw new Error('database disk image is malformed');
      },
    });
    expect(report.cannotCorrelate).toContain('cron_run_logs');
    expect(report.storeStatus).toBe('unreadable');
    expect(report.silentCount).toBe(0);
    expect(report.jobs[0].silentCount).toBe(0);
  });

  (isRoot ? test.skip : test)('an unreadable denial log is cannot-correlate, never a pass', () => {
    buildStore(dbPath, { jobs: [{ job_id: JOB_A }], runs: [] });
    writeDenials([denial()]);
    chmodSync(denialsPath, 0o000);

    const report = correlate();
    expect(report.denialsStatus).toBe('unreadable');
    expect(report.cannotCorrelate).toBe('denial log unreadable');
    expect(report.silentCount).toBe(0);
  });

  test('an absent denial log is a clean pass', () => {
    buildStore(dbPath, { jobs: [{ job_id: JOB_A }], runs: [] });
    const report = correlate();
    expect(report.denialsStatus).toBe('absent');
    expect(report.cannotCorrelate).toBeNull();
    expect(report.jobs).toEqual([]);
    expect(report.silentCount).toBe(0);
  });

  test('a host with no OpenClaw store at all does not manufacture a warning', () => {
    writeDenials([denial({ sessionKey: 'sc-abcdef0123456789' })]);
    const report = correlate();
    expect(report.jobsStatus).toBe('absent');
    expect(report.storeStatus).toBe('absent');
    expect(report.cannotCorrelate).toBeNull();
    expect(report.unattributedCount).toBe(1);
  });

  // -- Surfaces -------------------------------------------------

  test('pinnablePaths come from the job definition, never from the denial row', () => {
    const fromDenial = join(home, 'attacker.py');
    buildStore(dbPath, {
      jobs: [{ job_id: JOB_A, name: 'sweep', payload_message: `python3 ${scriptA}` }],
      runs: [{ job_id: JOB_A, session_key: keyFor(JOB_A, 'r1'), run_at_ms: NOW - 61_000, status: 'ok' }],
    });
    writeDenials([denial({ surface: `Bash: python3 ${fromDenial}`, reason: `ran ${fromDenial}` })]);

    const report = correlate();
    expect(report.jobs[0].pinnablePaths).toEqual([scriptA]);
    expect(JSON.stringify(report)).not.toContain('attacker.py');
  });

  test('a denial attributed to a job that no longer exists is reported, not dropped', () => {
    buildStore(dbPath, {
      jobs: [],
      runs: [{ job_id: JOB_B, session_key: keyFor(JOB_B, 'r1'), run_at_ms: NOW - 61_000, status: 'ok' }],
    });
    writeDenials([denial({ sessionKey: keyFor(JOB_B, 'r1') })]);

    const report = correlate();
    expect(report.jobs[0]).toMatchObject({ jobId: JOB_B, name: JOB_B, enabled: false, pinnablePaths: [] });
    expect(report.jobs[0].silentCount).toBe(1);
  });

  test('deniedScriptPaths maps every denied job script to its job name', () => {
    buildStore(dbPath, {
      jobs: [{ job_id: JOB_A, name: 'sweep', payload_message: `python3 ${scriptA}` }],
      runs: [{ job_id: JOB_A, session_key: keyFor(JOB_A, 'r1'), run_at_ms: NOW - 61_000, status: 'ok' }],
    });
    writeDenials([denial()]);
    expect([...deniedScriptPaths(correlate())]).toEqual([[scriptA, 'sweep']]);
  });

  // -- Tail cap -------------------------------------------------

  test('only the tail of an oversized denial log is read, and never a torn line', () => {
    // Distinct, non-cron filler: same actionId would dedupe the real denial
    // away and the assertion below would pass for the wrong reason.
    const filler = { ...denial(), sessionKey: 'sc-abcdef0123456789' };
    delete filler.actionId;
    const pad = JSON.stringify({ ...filler, junk: 'x'.repeat(4096) });
    const lines: string[] = [];
    let bytes = 0;
    while (bytes < DENIALS_TAIL_BYTES + 200_000) {
      lines.push(pad);
      bytes += pad.length + 1;
    }
    lines.push(JSON.stringify(denial()));
    mkdirSync(dirname(denialsPath), { recursive: true });
    writeFileSync(denialsPath, lines.join('\n') + '\n');
    buildStore(dbPath, {
      jobs: [{ job_id: JOB_A, name: 'sweep' }],
      runs: [{ job_id: JOB_A, session_key: keyFor(JOB_A, 'r1'), run_at_ms: NOW - 61_000, status: 'ok' }],
    });

    const report = correlate();
    // The newest denial survived the cap...
    expect(report.attributedCount).toBe(1);
    expect(report.silentCount).toBe(1);
    // ...and the truncated head did not produce parse garbage.
    expect(report.unattributedCount).toBeLessThan(lines.length);
    expect(report.unattributedCount).toBeGreaterThan(0);
  });

  test('parseDenials keeps rows without an actionId distinct', () => {
    const at = new Date(NOW - 1000).toISOString();
    const text = [
      JSON.stringify({ sessionKey: 'a', detectedAt: at }),
      JSON.stringify({ sessionKey: 'b', detectedAt: at }),
    ].join('\n');
    const parsed = parseDenials(text, { windowStart: NOW - 86_400_000, now: NOW });
    expect(parsed.denials).toHaveLength(2);
  });

  // -- Import discipline ----------------------------------------

  test('cron-denial-audit imports no guard-runtime module', () => {
    const source = readFileSync(join(HERE, '..', 'cron-denial-audit.ts'), 'utf8');
    const imports = [...source.matchAll(/^\s*(?:import|export)[^;]*?from\s+'([^']+)';/gm)].map(
      (m) => m[1],
    );
    const runtimeGuardImports = imports.filter(
      (spec, i) =>
        /defence|iron-dome/.test(spec) &&
        // `import type` is erased at build time and carries no runtime edge.
        !/^\s*(?:import|export)\s+type\b/.test(
          [...source.matchAll(/^\s*(?:import|export)[^;]*?from\s+'[^']+';/gm)][i][0],
        ),
    );
    expect(runtimeGuardImports).toEqual([]);
    expect(imports).not.toContain('node:sqlite');
    expect(source).not.toMatch(/child_process|execFile|spawn/);
  });

  test('no guard-runtime module imports the audit/store modules (reverse direction)', () => {
    // The correlation lane is CLI-only. If defence/* ever grows an import of
    // these modules, the honesty surface has crept into the guard hot path.
    const defenceDir = join(HERE, '..', '..', 'defence');
    const offenders: string[] = [];
    const walk = (dir: string) => {
      for (const e of readdirSync(dir, { withFileTypes: true })) {
        const full = join(dir, e.name);
        if (e.isDirectory()) { if (e.name !== '__tests__') walk(full); continue; }
        if (!/\.(ts|mjs)$/.test(e.name)) continue;
        const src = readFileSync(full, 'utf8');
        if (/from\s+'[^']*(?:cron-denial-audit|openclaw-cron-store)[^']*'/.test(src)) offenders.push(full);
      }
    };
    walk(defenceDir);
    expect(offenders).toEqual([]);
  });
});

describe('doctor CRON check (#375)', () => {
  const NOW = 1_760_000_000_000;
  let home: string;
  let dbPath: string;
  let denialsPath: string;
  let scriptA: string;

  const writeDenials = (rows: Array<Record<string, unknown>>): void => {
    mkdirSync(dirname(denialsPath), { recursive: true });
    writeFileSync(denialsPath, rows.map((r) => JSON.stringify(r)).join('\n') + '\n');
  };
  const denial = (over: Record<string, unknown> = {}): Record<string, unknown> => ({
    event: 'pre_tool_use',
    outcome: 'denied_no_prompt_surface',
    surface: 'Bash: [redacted action surface; command not persisted]',
    actionId: 'act-0000000000000001',
    sessionKey: keyFor(JOB_A, 'r1'),
    detectedAt: new Date(NOW - 60_000).toISOString(),
    ...over,
  });
  const check = () => checkCronDenials({ home, openclawDbPath: dbPath, denialsPath, now: NOW });

  beforeEach(() => {
    home = mkdtempSync(join(tmpdir(), 'sc-375-doctor-'));
    dbPath = join(home, '.openclaw', 'state', 'openclaw.sqlite');
    denialsPath = join(home, '.shieldcortex', 'denials.jsonl');
    scriptA = join(home, 'sweep.py');
  });
  afterEach(() => rmSync(home, { recursive: true, force: true }));

  test('WARNs on silent denials, names the job and offers an allowlist add per path', async () => {
    buildStore(dbPath, {
      jobs: [{ job_id: JOB_A, name: 'inbox sweep', payload_message: `python3 ${scriptA}` }],
      runs: [{ job_id: JOB_A, session_key: keyFor(JOB_A, 'r1'), run_at_ms: NOW - 61_000, status: 'ok' }],
    });
    writeDenials([denial()]);

    const result = await check();
    expect(result.status).toBe('warn');
    expect(result.message).toContain('1 scheduled job(s) had guard denials');
    expect(result.message).toContain('runs reported ok');
    expect(result.message).toContain('inbox sweep');
    expect(result.fix).toContain(`shieldcortex allowlist add ${scriptA}`);
    // #284: never a denial surface or a command body.
    expect(`${result.message} ${result.fix}`).not.toMatch(/redacted action surface|Bash:/);
  });

  test('WARNs on cannot-look and is never info', async () => {
    buildStore(dbPath, { jobs: [{ job_id: JOB_A, name: 'sweep' }], omitRunLogs: true });
    writeDenials([denial()]);

    const result = await check();
    expect(result.status).toBe('warn');
    expect(result.message).toContain('could not correlate cron denials');
    expect(result.message).toContain('cron_run_logs');
    expect(result.message).not.toMatch(/0 scheduled job/);
  });

  test('WARNs when an attributed denial cannot be matched to a run row', async () => {
    buildStore(dbPath, {
      jobs: [{ job_id: JOB_A, name: 'sweep' }],
      runs: [{ job_id: JOB_A, session_key: keyFor(JOB_A, 'other'), run_at_ms: NOW - 61_000, status: 'ok' }],
    });
    writeDenials([denial()]);

    const result = await check();
    expect(result.status).toBe('warn');
    expect(result.message).toContain('could not be matched to a run row');
  });

  test('passes when the sources are readable and nothing landed inside a run', async () => {
    buildStore(dbPath, { jobs: [{ job_id: JOB_A, name: 'sweep' }], runs: [] });
    writeDenials([denial({ sessionKey: 'sc-abcdef0123456789' })]);

    const result = await check();
    expect(result.status).toBe('pass');
    expect(result.message).toContain('no guard denials landed inside scheduled runs');
    expect(result.fix).toBeUndefined();
  });

  test('a correlation that throws still reports cannot-look, never a pass', async () => {
    const result = await checkCronDenials({
      correlate: () => {
        throw new Error('boom');
      },
    });
    expect(result.status).toBe('warn');
    expect(result.message).toContain('could not correlate cron denials');
  });

  test('the check is never auto-fixable', async () => {
    const { runDoctor } = await import('../doctor.js');
    expect(typeof runDoctor).toBe('function');
    const doctorSource = readFileSync(join(HERE, '..', 'doctor.ts'), 'utf8');
    // The two --fix flows key off their own labels; neither may reach ours.
    const fixBlocks = doctorSource.slice(doctorSource.indexOf("args.includes('--fix-project-keys')"));
    expect(fixBlocks).not.toContain('Cron denials');
  });
});
