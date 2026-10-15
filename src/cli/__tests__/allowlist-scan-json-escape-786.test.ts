/**
 * `shieldcortex allowlist scan --json` must not emit terminal-active code
 * points literally (#786). JSON.stringify escapes C0 but prints C1 (U+009B is
 * an 8-bit CSI), bidi overrides/isolates, U+2028/U+2029 and zero-width
 * characters as-is, so a hostile-named cron source, script or job could still
 * steer a terminal that shows the output. The fix escapes them as \uXXXX;
 * JSON.parse must still return the exact original values, because machine
 * consumers need the real path, not a display-cleaned one.
 *
 * Every path is injected. Real ~/.hermes, ~/.openclaw and ~/.shieldcortex are
 * never read.
 */
import Database from 'better-sqlite3';
import { mkdirSync, mkdtempSync, realpathSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { runAllowlistScan } from '../allowlist-scan.js';
import { toTerminalSafeJson } from '../term-ui.js';

// U+009B C1 CSI, U+202E RLO, U+2066 LRI, U+2028 LINE SEPARATOR, U+200B ZWSP.
const HOSTILE_CHARS = ['\u009b', '\u202e', '\u2066', '\u2028', '\u200b'];
const H = HOSTILE_CHARS.join('');
const ESCAPES = ['\\u009b', '\\u202e', '\\u2066', '\\u2028', '\\u200b'];

const JOB_A = 'aaaaaaaa-1111-4111-8111-aaaaaaaaaaaa';
const keyFor = (jobId: string, run: string): string => `agent:main:cron:${jobId}:run:${run}`;

function buildStore(dbPath: string, jobs: Array<{ job_id: string; name: string; payload_message: string }>, runs: Array<{ job_id: string; session_key: string; run_at_ms: number; status: string }>): void {
  const db = new Database(dbPath);
  try {
    db.exec(
      'CREATE TABLE cron_jobs (job_id TEXT, name TEXT, enabled INTEGER, payload_message TEXT, trigger_script TEXT, job_json TEXT)',
    );
    for (const j of jobs) {
      db.prepare(
        'INSERT INTO cron_jobs (job_id, name, enabled, payload_message, trigger_script, job_json) VALUES (?, ?, 1, ?, NULL, NULL)',
      ).run(j.job_id, j.name, j.payload_message);
    }
    db.exec('CREATE TABLE cron_run_logs (job_id TEXT, session_key TEXT, run_at_ms INTEGER, status TEXT)');
    for (const r of runs) {
      db.prepare('INSERT INTO cron_run_logs (job_id, session_key, run_at_ms, status) VALUES (?, ?, ?, ?)').run(
        r.job_id,
        r.session_key,
        r.run_at_ms,
        r.status,
      );
    }
  } finally {
    db.close();
  }
}

describe('toTerminalSafeJson (#786)', () => {
  test('escapes each unsafe code point and round-trips to the original value', () => {
    const value = { a: `x${H}y`, b: [`\\${H}`, 'plain'], c: 'caf\u00e9 \u4e2d', d: '\u007f\u0085\u2029\u2060\ufeff' };
    const out = toTerminalSafeJson(value, 2);
    for (const c of [...HOSTILE_CHARS, '\u007f', '\u0085', '\u2029', '\u2060', '\ufeff']) {
      expect(out.includes(c)).toBe(false);
    }
    // Ordinary non-ASCII text is left alone.
    expect(out).toContain('caf\u00e9 \u4e2d');
    expect(JSON.parse(out)).toEqual(value);
  });

  test('matches JSON.stringify exactly when nothing needs escaping', () => {
    const value = { path: '/home/u/scripts/sweep.py', n: 3, ok: true, none: null };
    expect(toTerminalSafeJson(value, 2)).toBe(JSON.stringify(value, null, 2));
  });
});

describe('allowlist scan --json escapes host-derived control code points (#786)', () => {
  const NOW = 1_760_000_000_000;
  let dir: string;
  let oddDir: string;
  let dbPath: string;
  let denialsPath: string;
  let plainScript: string;
  let oddScript: string;
  let logs: string[];
  let errs: string[];

  beforeEach(() => {
    dir = realpathSync(mkdtempSync(join(tmpdir(), 'sc-786-scan-')));
    oddDir = join(dir, `odd${H}dir`);
    mkdirSync(oddDir, { recursive: true });
    dbPath = join(oddDir, 'openclaw.sqlite'); // source path
    denialsPath = join(dir, '.shieldcortex', 'denials.jsonl');
    plainScript = join(dir, 'sentry.py');
    writeFileSync(plainScript, 'print("sentry sweep")\n');
    oddScript = join(oddDir, `run${H}.sh`); // item path
    writeFileSync(oddScript, 'echo run\n');
    logs = [];
    errs = [];

    buildStore(
      dbPath,
      [{ job_id: JOB_A, name: `sweep${H}job`, payload_message: `python3 ${plainScript}` }], // denial note
      [{ job_id: JOB_A, session_key: keyFor(JOB_A, 'r1'), run_at_ms: NOW - 61_000, status: 'ok' }],
    );
    mkdirSync(join(dir, '.shieldcortex'), { recursive: true });
    writeFileSync(
      denialsPath,
      JSON.stringify({
        actionId: 'act-0000000000000786',
        sessionKey: keyFor(JOB_A, 'r1'),
        detectedAt: new Date(NOW - 60_000).toISOString(),
      }) + '\n',
    );
  });
  afterEach(() => {
    rmSync(dir, { recursive: true, force: true });
  });

  test('source path, item path and denial note: no literal code points, exact values after parse', async () => {
    const stored: unknown[] = [];
    const code = await runAllowlistScan(['--json', '--glob', join(oddDir, '*.sh')], {
      home: dir,
      env: {},
      cwd: dir,
      interactive: false,
      openclawDbPath: dbPath,
      denialsPath,
      now: NOW,
      log: (m: string) => logs.push(m),
      error: (m: string) => errs.push(m),
      readEntries: () => stored,
      writeEntries: () => {
        throw new Error('scan --json must not write');
      },
    });
    expect(code).toBe(3);
    const out = logs.join('\n');

    for (const c of HOSTILE_CHARS) expect(out.includes(c)).toBe(false);
    for (const e of ESCAPES) expect(out).toContain(e);

    const report = JSON.parse(out) as {
      sources: { openclawDb: { path: string; status: string } };
      items: Array<{ path: string; cronDenied: string | null }>;
    };
    // Machine consumers see the real values, not display-cleaned ones.
    expect(report.sources.openclawDb.path).toBe(dbPath);
    expect(report.sources.openclawDb.status).toBe('ok');
    const paths = report.items.map((i) => i.path);
    expect(paths).toContain(oddScript);
    const denied = report.items.find((i) => i.path === plainScript);
    // The cron store already folds whitespace in job names (sanitiseJobName:
    // U+2028 matches \s and becomes a space), so the note carries the other
    // four code points; JSON.parse must still return them unchanged.
    expect(denied?.cronDenied).toBe('guard-denied in the last 7 days (job: sweep\u009b\u202e\u2066 \u200bjob)');
  });
});
