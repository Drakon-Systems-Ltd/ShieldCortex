/**
 * #1140 — the hook writer's own BLOCK rows must be chained once the database
 * has a chained ledger.
 *
 * `scripts/lib/save-memory.mjs` writes a `defence_audit` row itself in the
 * cases the pipeline produced none: a refused auto-capture candidate, a
 * pipeline that threw, and a missing dist build. Before #1140 that row was a
 * plain INSERT without chain columns, so on a database whose chain had started
 * every such row was an `unchained-row-after-start` problem and
 * `shieldcortex ledger verify` reported the whole ledger INCONSISTENT.
 *
 * What this file pins:
 *   - chain started, refused candidate: the row is chained and verify is clean;
 *   - chain started, pipeline threw: the same;
 *   - chain started, chained writer not loadable: NO row is written (an
 *     unchained row on a chained database is worse than no row) and verify is
 *     unchanged;
 *   - no chain yet: a row is still written, unchained, exactly as before;
 *   - two overlapping first calls in ONE process: the second call waits for
 *     the chained writer the first call is still loading, so both rows are
 *     written and linked (and, with no writer to load, both still write none).
 *
 * How: the REAL writer, unmodified, runs in a child process from a throwaway
 * package whose `dist/` re-exports the real build module by module. Two
 * modules are test-owned where a case needs it:
 *   - `defence/firewall/provenance-policy.js` flags one inert marker word, so a
 *     refusal is produced without any instruction-shaped text in this file;
 *   - `defence/pipeline.js` throws, for the pipeline-error case;
 *   - `defence/ledger/chain.js` settles late (a timer, then the real module),
 *     for the overlapping-calls case, so the overlap does not depend on timing.
 * The chain writer, the database module and the verifier are the real ones.
 *
 * Hermetic: every database is a new file under a temp directory; the child
 * gets its own HOME / config / audit directories there and a fetch that fails.
 */
import fs from 'fs';
import os from 'os';
import path from 'path';
import { spawnSync } from 'child_process';
import { createRequire } from 'module';
import { fileURLToPath, pathToFileURL } from 'url';
import { afterEach, beforeEach, describe, expect, it } from '@jest/globals';
import Database from 'better-sqlite3';
import { ensureLedger } from '../defence/ledger/chain.js';
import { verifyLedger } from '../defence/ledger/verify.js';

const thisFile = fileURLToPath(import.meta.url);
const repoRoot = path.resolve(path.dirname(thisFile), '..', '..');
const realDist = path.join(repoRoot, 'dist');
const schemaPath = path.join(repoRoot, 'src', 'database', 'schema.sql');
const sqliteEntry = createRequire(import.meta.url).resolve('better-sqlite3');

/** Inert marker the test-owned screen flags. Not an instruction of any kind. */
const MARKER = 'sc1140-refusal-marker';
const CHILD_MS = 30_000;
const CASE_MS = 2 * CHILD_MS;

type Variant = 'full' | 'pipeline-throws' | 'no-chain-writer' | 'no-dist' | 'slow-chain-writer';

/** How long the `slow-chain-writer` chain module takes to finish loading. */
const SLOW_CHAIN_LOAD_MS = 400;

const reexport = (rel: string): string =>
  `export * from ${JSON.stringify(pathToFileURL(path.join(realDist, rel)).href)};\n`;

/** Build a package holding a copy of the actual writer and a variant dist. */
function buildPackage(root: string, variant: Variant): string {
  const pkg = path.join(root, `pkg-${variant}`);
  fs.mkdirSync(path.join(pkg, 'scripts'), { recursive: true });
  fs.writeFileSync(path.join(pkg, 'package.json'), '{ "type": "module" }\n');
  fs.cpSync(path.join(repoRoot, 'scripts', 'lib'), path.join(pkg, 'scripts', 'lib'), { recursive: true });
  if (variant === 'no-dist') return pkg;

  const write = (rel: string, body: string): void => {
    const file = path.join(pkg, 'dist', rel);
    fs.mkdirSync(path.dirname(file), { recursive: true });
    fs.writeFileSync(file, body);
  };
  write('database/init.js', reexport('database/init.js'));
  write('defence/disposition.js', reexport('defence/disposition.js'));
  write('defence/form-classifier.js', reexport('defence/form-classifier.js'));
  write('defence/sensitivity/pii.js', reexport('defence/sensitivity/pii.js'));
  write(
    'defence/firewall/memory-directive-policy.js',
    'export function detectMemoryDirective() { return { detected: false, patterns: [] }; }\n',
  );
  write(
    'defence/firewall/provenance-policy.js',
    'export function detectNonAuthoritativeInstruction(text) {\n'
    + `  return String(text).includes(${JSON.stringify(MARKER)})\n`
    + "    ? { detected: true, patterns: ['sc1140_fixture'] }\n"
    + '    : { detected: false, patterns: [] };\n'
    + '}\n',
  );
  write(
    'defence/pipeline.js',
    variant === 'pipeline-throws'
      ? "export function runDefencePipeline() { throw new Error('sc1140 fixture pipeline fault'); }\n"
      : reexport('defence/pipeline.js'),
  );
  if (variant === 'slow-chain-writer') {
    // The real chain module, but this copy of it finishes loading only after a
    // timer. A second call that does not wait for the first call's load sees
    // "no writer" for the whole of that window.
    write(
      'defence/ledger/chain.js',
      `await new Promise((done) => setTimeout(done, ${SLOW_CHAIN_LOAD_MS}));\n`
      + reexport('defence/ledger/chain.js'),
    );
  } else if (variant !== 'no-chain-writer') {
    write('defence/ledger/chain.js', reexport('defence/ledger/chain.js'));
  }
  return pkg;
}

interface AuditRow {
  id: number;
  source_type: string;
  source_identifier: string;
  firewall_result: string;
  reason: string;
  threat_indicators: string;
  blocked_patterns: string;
  operation: string | null;
  content_hash: string | null;
  source_attested: number | null;
  ledger_id: string | null;
  epoch: number | null;
  seq: number | null;
  prev_hash: string | null;
  content_digest: string | null;
  row_hash: string | null;
}

describe('#1140: hook-written BLOCK rows are chained once the chain has started', () => {
  let tempDir: string;

  beforeEach(() => {
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'sc-1140-'));
  });

  afterEach(() => {
    fs.rmSync(tempDir, { recursive: true, force: true });
  });

  /** A new temp database from the real schema; optionally with its chain started. */
  function makeDb(name: string, { chain }: { chain: boolean }): string {
    const dbPath = path.join(tempDir, name);
    const db = new Database(dbPath);
    try {
      db.exec(fs.readFileSync(schemaPath, 'utf-8'));
      if (chain) expect(ensureLedger(db)).not.toBeNull();
    } finally {
      db.close();
    }
    return dbPath;
  }

  /**
   * Run the real writer in its own process against `dbPath`: once for a single
   * `content`, or — given several — as calls that all start before any of them
   * has finished (one `Promise.all`, one process, one database handle).
   */
  function runWriter(variant: Variant, dbPath: string, content: string | string[]): { stderr: string } {
    const contents = Array.isArray(content) ? content : [content];
    const pkg = buildPackage(tempDir, variant);
    const home = path.join(tempDir, `home-${variant}`);
    const configDir = path.join(home, '.shieldcortex');
    const auditDir = path.join(configDir, 'audit');
    fs.mkdirSync(auditDir, { recursive: true, mode: 0o700 });

    const guard = path.join(pkg, 'netguard.mjs');
    fs.writeFileSync(
      guard,
      "globalThis.fetch = async () => { throw new Error('netguard: no outbound fetch in this test'); };\n",
    );
    const probe = path.join(pkg, 'probe.mjs');
    fs.writeFileSync(
      probe,
      "import './netguard.mjs';\n"
      + "import { createRequire } from 'module';\n"
      + "import { saveAutoExtractedMemory } from './scripts/lib/save-memory.mjs';\n"
      + 'const [sqliteEntry, dbPath, ...contents] = process.argv.slice(2);\n'
      + 'const Database = createRequire(import.meta.url)(sqliteEntry);\n'
      + 'const db = new Database(dbPath);\n'
      + 'await Promise.all(contents.map((content) => saveAutoExtractedMemory(db, {\n'
      + "  title: 'Queue design note', content, category: 'note', salience: 0.6, tags: ['auto-extracted'],\n"
      + "}, 'sc1140', { source: 'session-end-hook' })));\n"
      + 'db.close();\n'
      + 'process.exit(0);\n',
    );

    const env: Record<string, string | undefined> = { ...process.env };
    for (const key of Object.keys(env)) {
      if (/^(https?|all|no)_proxy$/i.test(key)) delete env[key];
    }
    env.HOME = home;
    env.USERPROFILE = home;
    env.SHIELDCORTEX_CONFIG_DIR = configDir;
    env.SHIELDCORTEX_AUDIT_DIR = auditDir;

    const res = spawnSync(process.execPath, [probe, sqliteEntry, dbPath, ...contents], {
      cwd: pkg,
      env,
      encoding: 'utf-8',
      timeout: CHILD_MS,
    });
    if (res.status !== 0) {
      throw new Error(
        `writer child failed (status ${res.status}, signal ${res.signal})\nstdout: ${res.stdout}\nstderr: ${res.stderr}`,
      );
    }
    return { stderr: res.stderr };
  }

  function inspect(dbPath: string) {
    const db = new Database(dbPath);
    try {
      const rows = db.prepare('SELECT * FROM defence_audit ORDER BY id').all() as AuditRow[];
      const memories = (db.prepare('SELECT COUNT(*) AS c FROM memories').get() as { c: number }).c;
      const report = verifyLedger(db);
      return { rows, memories, report };
    } finally {
      db.close();
    }
  }

  const problemKinds = (dbPath: string): string[] => inspect(dbPath).report.problems.map((p) => p.kind);

  function expectChained(row: AuditRow): void {
    expect(row.seq).not.toBeNull();
    expect(row.ledger_id).not.toBeNull();
    expect(row.epoch).not.toBeNull();
    expect(row.prev_hash).toMatch(/^[0-9a-f]{64}$/);
    expect(row.content_digest).toMatch(/^[0-9a-f]{64}$/);
    expect(row.row_hash).toMatch(/^[0-9a-f]{64}$/);
  }

  /** The row shape #1140 must not change. */
  function expectUnchangedShape(row: AuditRow): void {
    expect(row.firewall_result).toBe('BLOCK');
    expect(row.source_identifier).toBe('session-end-hook');
    expect(row.operation).toBeNull();
    expect(row.content_hash).toBeNull();
    expect(row.source_attested).toBeNull();
  }

  it('chain started, refused candidate: the refusal row is chained and verify stays consistent', () => {
    const dbPath = makeDb('refusal.db', { chain: true });
    expect(inspect(dbPath).report.status).toBe('consistent');

    const { stderr } = runWriter('full', dbPath, `Batched writer chosen for ingest. ${MARKER}`);
    expect(stderr).toContain('refused (non_authoritative_instruction');

    const { rows, memories, report } = inspect(dbPath);
    expect(memories).toBe(0);
    expect(rows).toHaveLength(1);
    expect(rows[0].source_type).toBe('memory_candidate');
    expect(rows[0].reason).toBe('Refused auto-capture: non_authoritative_instruction (sc1140_fixture)');
    expect(JSON.parse(rows[0].blocked_patterns)).toEqual(['sc1140_fixture']);
    expectUnchangedShape(rows[0]);
    expectChained(rows[0]);
    expect(report.problems).toEqual([]);
    expect(report.status).toBe('consistent');
  }, CASE_MS);

  it('chain started, pipeline threw: the fallback row is chained and verify stays consistent', () => {
    const dbPath = makeDb('pipeline-error.db', { chain: true });

    const { stderr } = runWriter('pipeline-throws', dbPath, 'Compaction now runs before the index rebuild.');
    expect(stderr).toContain('dropped (pipeline error)');

    const { rows, memories, report } = inspect(dbPath);
    expect(memories).toBe(0);
    expect(rows).toHaveLength(1);
    expect(rows[0].source_type).toBe('hook');
    expect(rows[0].reason).toBe('pipeline_error: sc1140 fixture pipeline fault');
    expectUnchangedShape(rows[0]);
    expectChained(rows[0]);
    expect(report.problems).toEqual([]);
    expect(report.status).toBe('consistent');
  }, CASE_MS);

  it('chain started, two hook rows in a row: each links to the one before', () => {
    const dbPath = makeDb('two-rows.db', { chain: true });
    runWriter('full', dbPath, `First note. ${MARKER}`);
    runWriter('pipeline-throws', dbPath, 'Second note about retry budgets.');

    const { rows, report } = inspect(dbPath);
    expect(rows).toHaveLength(2);
    expectChained(rows[0]);
    expectChained(rows[1]);
    expect(rows[1].seq).toBe(Number(rows[0].seq) + 1);
    expect(rows[1].prev_hash).toBe(rows[0].row_hash);
    expect(report.status).toBe('consistent');
  }, CASE_MS);

  it.each(['no-dist', 'no-chain-writer'] as const)(
    'chain started, chained writer not loadable (%s): no row is written and verify is unchanged',
    (variant) => {
      const dbPath = makeDb(`${variant}.db`, { chain: true });
      const before = inspect(dbPath);
      expect(before.rows).toHaveLength(0);
      expect(before.report.status).toBe('consistent');

      // no-dist drops every capture; no-chain-writer needs a refusal to reach the writer.
      const { stderr } = runWriter(variant, dbPath, `Session ids are minted by the writer. ${MARKER}`);
      expect(stderr).toContain(variant === 'no-dist' ? 'dropped (defence pipeline unavailable)' : 'refused (');

      const after = inspect(dbPath);
      expect(after.memories).toBe(0);
      expect(after.rows).toHaveLength(0);
      expect(after.report.problems).toEqual([]);
      expect(after.report.status).toBe('consistent');
      expect(after.report.chainedRows).toBe(before.report.chainedRows);
    },
    CASE_MS,
  );

  it('chain started, two overlapping first calls in one process: both rows are chained and linked', () => {
    const dbPath = makeDb('overlap.db', { chain: true });
    const before = inspect(dbPath);
    expect(before.rows).toHaveLength(0);

    // Both calls start before either has loaded the chained writer, and the
    // writer takes SLOW_CHAIN_LOAD_MS to load. The second call must wait for
    // that load rather than conclude there is no writer.
    const { stderr } = runWriter('slow-chain-writer', dbPath, [
      `First overlapping note. ${MARKER}`,
      `Second overlapping note. ${MARKER}`,
    ]);
    expect(stderr.match(/refused \(non_authoritative_instruction/g)).toHaveLength(2);

    const { rows, memories, report } = inspect(dbPath);
    expect(memories).toBe(0);
    expect(rows).toHaveLength(2);
    for (const row of rows) {
      expect(row.source_type).toBe('memory_candidate');
      expect(row.reason).toBe('Refused auto-capture: non_authoritative_instruction (sc1140_fixture)');
      expectUnchangedShape(row);
      expectChained(row);
    }
    expect(rows[1].seq).toBe(Number(rows[0].seq) + 1);
    expect(rows[1].prev_hash).toBe(rows[0].row_hash);
    expect(report.problems).toEqual([]);
    expect(report.status).toBe('consistent');
    expect(report.chainedRows).toBe(before.report.chainedRows + 2);
  }, CASE_MS);

  it('chain started, two overlapping first calls, chained writer not loadable: still no row', () => {
    const dbPath = makeDb('overlap-no-writer.db', { chain: true });
    const before = inspect(dbPath);

    const { stderr } = runWriter('no-chain-writer', dbPath, [
      `First overlapping note. ${MARKER}`,
      `Second overlapping note. ${MARKER}`,
    ]);
    expect(stderr.match(/refused \(/g)).toHaveLength(2);

    const after = inspect(dbPath);
    expect(after.memories).toBe(0);
    expect(after.rows).toHaveLength(0);
    expect(after.report.problems).toEqual([]);
    expect(after.report.status).toBe('consistent');
    expect(after.report.chainedRows).toBe(before.report.chainedRows);
  }, CASE_MS);

  it('no chain yet: the row is still written, unchained, as before', () => {
    const dbPath = makeDb('no-chain.db', { chain: false });

    const { stderr } = runWriter('no-dist', dbPath, 'Cache eviction switched to a segmented LRU.');
    expect(stderr).toContain('dropped (defence pipeline unavailable)');

    const { rows, memories } = inspect(dbPath);
    expect(memories).toBe(0);
    expect(rows).toHaveLength(1);
    expect(rows[0].source_type).toBe('hook');
    expect(rows[0].reason).toBe('defence_pipeline_unavailable: dist build missing');
    expectUnchangedShape(rows[0]);
    expect(rows[0].seq).toBeNull();
    expect(rows[0].prev_hash).toBeNull();
    expect(rows[0].row_hash).toBeNull();
    // Written before any chain existed, so it is unchained history, not a problem.
    expect(problemKinds(dbPath)).not.toContain('unchained-row-after-start');
  }, CASE_MS);

  it('no ledger tables at all (older schema): the row is still written', () => {
    const dbPath = makeDb('no-ledger-tables.db', { chain: false });
    const db = new Database(dbPath);
    try {
      db.exec('DROP TABLE ledger_meta');
    } finally {
      db.close();
    }

    runWriter('no-dist', dbPath, 'Retry budgets moved into the scheduler.');

    const db2 = new Database(dbPath);
    try {
      const rows = db2.prepare('SELECT * FROM defence_audit').all() as AuditRow[];
      expect(rows).toHaveLength(1);
      expect(rows[0].reason).toBe('defence_pipeline_unavailable: dist build missing');
      expect(rows[0].seq).toBeNull();
    } finally {
      db2.close();
    }
  }, CASE_MS);
});
