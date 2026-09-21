/**
 * #538 (follow-up to #510/#534) — the hook-side session_events writer's
 * FAIL-SAFE when the shared write-time PII redactor cannot be used.
 *
 * `scripts/lib/session-capture.mjs` resolves `redactJsonForPersistence` from
 * `dist` ONCE at module load, relative to its own file. So each scenario is a
 * disposable layout on disk — the real `.mjs` copied under `<layout>/scripts/lib/`
 * next to a `<layout>/dist/defence/sensitivity/pii.js` that is absent, stale
 * (no such export) or throwing — driven by a child `node` process. That makes
 * "exactly one stderr notice per process" a literal count of the child's stderr,
 * not a spy on a module-level flag.
 *
 * Contract under test (the review-declared residual, not fail-closed redaction):
 *   - the event is still written (capture must not stop a hook);
 *   - it is stored at CONFIDENTIAL or above, never as ordinary INTERNAL/PUBLIC;
 *   - an already RESTRICTED / SECRET event keeps its level (never downgraded);
 *   - the redactor gap is reported on stderr exactly once per process.
 *
 * Fixtures are synthetic (HMRC's invalid "QQ" NI prefix, example domains).
 */
import { describe, expect, it, beforeAll, afterAll } from '@jest/globals';
import { spawnSync } from 'child_process';
import { copyFileSync, existsSync, mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'fs';
import { tmpdir } from 'os';
import path from 'path';
import { pathToFileURL } from 'url';

const REPO_ROOT = process.cwd();
const REAL_MJS = path.join(REPO_ROOT, 'scripts', 'lib', 'session-capture.mjs');
const REAL_DIST_REDACTOR = path.join(REPO_ROOT, 'dist', 'defence', 'sensitivity', 'pii.js');
const SCHEMA_SQL = path.join(REPO_ROOT, 'src', 'database', 'schema.sql');
const NOTICE = 'PII redactor unavailable';

const NI = 'QQ123456C';
const EMAIL = 'alice@corp.example';
const TEXT = `Pat Example, National Insurance ${NI}, reach ${EMAIL}`;

type Row = { kind: string; payload: string; sensitivity_level: string };
type ChildResult = {
  status: number | null;
  stderr: string;
  rows: Row[];
  results: unknown[];
};

let scratch: string;

beforeAll(() => {
  scratch = mkdtempSync(path.join(tmpdir(), 'sc-538-'));
});

afterAll(() => {
  rmSync(scratch, { recursive: true, force: true });
});

/**
 * Lay out `<dir>/scripts/lib/session-capture.mjs` (a byte copy of the real
 * module) and, unless `distRedactorSource` is null, `<dir>/dist/defence/
 * sensitivity/pii.js` with the given source. Returns the copied module path.
 */
function layout(name: string, distRedactorSource: string | null): string {
  const dir = path.join(scratch, name);
  mkdirSync(path.join(dir, 'scripts', 'lib'), { recursive: true });
  const mjs = path.join(dir, 'scripts', 'lib', 'session-capture.mjs');
  copyFileSync(REAL_MJS, mjs);
  if (distRedactorSource !== null) {
    const distDir = path.join(dir, 'dist', 'defence', 'sensitivity');
    mkdirSync(distDir, { recursive: true });
    writeFileSync(path.join(distDir, 'pii.js'), distRedactorSource);
  }
  return mjs;
}

/**
 * Run the writer in a child process against an in-memory DB seeded with the
 * real schema. Writes, in order: a single object event with no sensitivity,
 * a single string event at RESTRICTED, then a batch of [SECRET, PUBLIC].
 */
function runWriter(mjsPath: string, runnerName: string): ChildResult {
  const runner = path.join(scratch, `${runnerName}.mjs`);
  writeFileSync(
    runner,
    `
import { createRequire } from 'module';
import { readFileSync } from 'fs';
const require = createRequire(${JSON.stringify(path.join(REPO_ROOT, 'package.json'))});
const Database = require('better-sqlite3');
const { recordSessionEvent, recordSessionEvents } = await import(${JSON.stringify(pathToFileURL(mjsPath).href)});

const db = new Database(':memory:');
db.exec(readFileSync(${JSON.stringify(SCHEMA_SQL)}, 'utf8'));

const text = ${JSON.stringify(TEXT)};
const base = { session_id: 'failsafe-538', kind: 'prompt' };
const results = [];
results.push(recordSessionEvent(db, { ...base, ts: '2026-09-20T10:00:00.000Z', payload: { text } }));
results.push(recordSessionEvent(db, { ...base, ts: '2026-09-20T10:00:01.000Z', kind: 'response', payload: text, sensitivity_level: 'RESTRICTED' }));
results.push(recordSessionEvents(db, [
  { ...base, ts: '2026-09-20T10:00:02.000Z', kind: 'tool_result', payload: { text }, sensitivity_level: 'SECRET' },
  { ...base, ts: '2026-09-20T10:00:03.000Z', kind: 'hook_fire', payload: { text }, sensitivity_level: 'PUBLIC' },
]));

const rows = db.prepare("SELECT kind, payload, sensitivity_level FROM session_events WHERE session_id = 'failsafe-538' ORDER BY id").all();
process.stdout.write(JSON.stringify({ rows, results }));
`,
  );
  const child = spawnSync(process.execPath, [runner], { encoding: 'utf8', timeout: 20_000 });
  let parsed: { rows: Row[]; results: unknown[] } = { rows: [], results: [] };
  try {
    parsed = JSON.parse(child.stdout);
  } catch {
    // leave empty — the assertions below will print stderr for diagnosis
  }
  return { status: child.status, stderr: child.stderr ?? '', rows: parsed.rows, results: parsed.results };
}

function notices(stderr: string): number {
  return stderr.split('\n').filter((line) => line.includes(NOTICE)).length;
}

function byKind(rows: Row[], kind: string): Row {
  const row = rows.find((r) => r.kind === kind);
  if (!row) throw new Error(`no ${kind} row written; rows=${JSON.stringify(rows)}`);
  return row;
}

/** The shared assertions for every "redactor cannot be used" layout. */
function expectFailSafe(result: ChildResult): void {
  expect(result.status).toBe(0);
  // Every event was still written — capture never blocks the hook.
  expect(result.rows).toHaveLength(4);
  expect(result.results[0]).toEqual(expect.any(Number));
  expect(result.results[1]).toEqual(expect.any(Number));
  expect(result.results[2]).toEqual([expect.any(Number), expect.any(Number)]);

  // The raw payload is retained (this is the declared residual, not a loss).
  for (const row of result.rows) {
    expect(row.payload).toContain(NI);
    expect(row.payload).toContain(EMAIL);
    expect(row.payload).not.toContain('[REDACTED:');
  }

  // Never stored as ordinary text: unset and PUBLIC are raised to CONFIDENTIAL…
  expect(byKind(result.rows, 'prompt').sensitivity_level).toBe('CONFIDENTIAL');
  expect(byKind(result.rows, 'hook_fire').sensitivity_level).toBe('CONFIDENTIAL');
  // …and an already higher level is preserved, never downgraded.
  expect(byKind(result.rows, 'response').sensitivity_level).toBe('RESTRICTED');
  expect(byKind(result.rows, 'tool_result').sensitivity_level).toBe('SECRET');

  // Exactly one notice for the whole process, across single, string and batch writes.
  expect(notices(result.stderr)).toBe(1);
}

describe('#538 session-capture.mjs redactor fail-safe', () => {
  it('positive control: with the real dist redactor the payload is redacted, INTERNAL stays INTERNAL, no notice', () => {
    // The runner (`scripts/run-jest.mjs`) builds dist before any worker starts;
    // a bare `jest` without a build fails here honestly rather than mysteriously.
    expect(existsSync(REAL_DIST_REDACTOR)).toBe(true);

    const result = runWriter(REAL_MJS, 'healthy');
    expect(result.status).toBe(0);
    expect(result.rows).toHaveLength(4);
    for (const row of result.rows) {
      expect(row.payload).not.toContain(NI);
      expect(row.payload).not.toContain(EMAIL);
      expect(row.payload).toContain('[REDACTED:ni-number]');
    }
    expect(byKind(result.rows, 'prompt').sensitivity_level).toBe('INTERNAL');
    expect(byKind(result.rows, 'hook_fire').sensitivity_level).toBe('PUBLIC');
    expect(byKind(result.rows, 'response').sensitivity_level).toBe('RESTRICTED');
    expect(byKind(result.rows, 'tool_result').sensitivity_level).toBe('SECRET');
    expect(notices(result.stderr)).toBe(0);
  });

  it('redactor MISSING (no dist): event kept unredacted at >= CONFIDENTIAL, RESTRICTED/SECRET preserved, one notice', () => {
    const mjs = layout('missing-dist', null);
    expectFailSafe(runWriter(mjs, 'missing'));
  });

  it('redactor STALE (dist predates the export): same fail-safe, one notice', () => {
    const mjs = layout(
      'stale-dist',
      "// synthetic stale build: the module exists but has no write-time redactor\nexport const redactPII = (s) => s;\n",
    );
    expectFailSafe(runWriter(mjs, 'stale'));
  });

  it('redactor THROWS: same fail-safe, one notice, and the throw never escapes to the hook', () => {
    const mjs = layout(
      'throwing-dist',
      "export function redactJsonForPersistence() { throw new Error('synthetic redactor failure'); }\n",
    );
    const result = runWriter(mjs, 'throwing');
    expectFailSafe(result);
    expect(result.stderr).not.toContain('synthetic redactor failure');
  });
});
