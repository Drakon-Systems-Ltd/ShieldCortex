/**
 * #617 — `shieldcortex ledger verify [--json]` and the doctor's chained-ledger
 * row. Both use the same verifier (`verifyLedger`); the CLI opens the database
 * read-only and never writes.
 *
 * Exit codes: 0 consistent (or no chain yet), 1 inconsistent, 2 usage / no DB.
 */

import { describe, it, expect, afterEach } from '@jest/globals';
import Database from 'better-sqlite3';
import { mkdtempSync, rmSync, readFileSync, statSync } from 'fs';
import { tmpdir } from 'os';
import path from 'path';
import { fileURLToPath } from 'url';
import { initDatabase, closeDatabase } from '../../database/init.js';
import { logAudit } from '../../defence/audit/logger.js';
import { LEDGER_LIMITS_STATEMENT, __resetLedgerStateForTests } from '../../defence/ledger/index.js';
import { runLedgerCommand, LEDGER_HELP } from '../ledger.js';
import { checkChainedLedger } from '../doctor.js';

const here = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(here, '..', '..', '..');
const V521_SCHEMA = path.join(repoRoot, 'src', '__fixtures__', 'schema-v5.2.1.sql');

const dirs: string[] = [];
afterEach(() => {
  closeDatabase();
  __resetLedgerStateForTests();
  for (const d of dirs.splice(0)) rmSync(d, { recursive: true, force: true });
});

function chainedDb(rows = 4): string {
  const dir = mkdtempSync(path.join(tmpdir(), 'sc-ledger-cli-'));
  dirs.push(dir);
  const p = path.join(dir, 'memories.db');
  initDatabase(p);
  for (let i = 0; i < rows; i++) {
    logAudit({
      memory_id: null, project: 'cli', timestamp: new Date().toISOString(),
      source_type: 'cli', source_identifier: 'ledger-cli', trust_score: 0.9,
      sensitivity_level: 'INTERNAL', firewall_result: 'ALLOW', operation: 'write',
      anomaly_score: 0, threat_indicators: '[]', blocked_patterns: '[]',
      reason: `cli ${i}`, fragmentation_score: null, pipeline_duration_ms: null,
    });
  }
  closeDatabase();
  return p;
}

function run(args: string[]): { code: number; out: string; err: string } {
  const out: string[] = [];
  const err: string[] = [];
  const code = runLedgerCommand(args, { stdout: (s) => out.push(s), stderr: (s) => err.push(s) });
  return { code, out: out.join(''), err: err.join('') };
}

describe('shieldcortex ledger verify', () => {
  it('exit 0 and a plain consistent report, including the limits statement', () => {
    const p = chainedDb();
    const r = run(['verify', '--db', p]);
    expect(r.code).toBe(0);
    expect(r.out).toMatch(/chained ledger: consistent/i);
    expect(r.out).toContain(LEDGER_LIMITS_STATEMENT);
  });

  it('--json emits the report with status and the limits statement', () => {
    const p = chainedDb();
    const r = run(['verify', '--json', '--db', p]);
    expect(r.code).toBe(0);
    const j = JSON.parse(r.out);
    expect(j.status).toBe('consistent');
    expect(j.head.seq).toBe(4);
    expect(j.limits).toBe(LEDGER_LIMITS_STATEMENT);
  });

  it('exit 1 and the first bad seq when a middle row was edited', () => {
    const p = chainedDb();
    const db = new Database(p);
    db.prepare("UPDATE defence_audit SET reason = 'tampered' WHERE seq = 2").run();
    db.close();
    const r = run(['verify', '--db', p]);
    expect(r.code).toBe(1);
    expect(r.out).toMatch(/inconsistent/i);
    expect(r.out).toMatch(/seq 2/);
    const j = JSON.parse(run(['verify', '--json', '--db', p]).out);
    expect(j.status).toBe('inconsistent');
    expect(j.firstBad.seq).toBe(2);
  });

  it('never writes to the database it verifies', () => {
    const p = chainedDb();
    const before = readFileSync(p);
    const mtime = statSync(p).mtimeMs;
    run(['verify', '--db', p]);
    run(['verify', '--json', '--db', p]);
    expect(readFileSync(p).equals(before)).toBe(true);
    expect(statSync(p).mtimeMs).toBe(mtime);
  });

  it('a pre-ledger database reports unchained history, exit 0, and is not migrated by verify', () => {
    const dir = mkdtempSync(path.join(tmpdir(), 'sc-ledger-cli-'));
    dirs.push(dir);
    const p = path.join(dir, 'old.db');
    const raw = new Database(p);
    raw.exec(readFileSync(V521_SCHEMA, 'utf-8'));
    raw.prepare("INSERT INTO defence_audit (source_type, source_identifier, trust_score, firewall_result) VALUES ('cli','x',1,'ALLOW')").run();
    raw.close();
    const r = run(['verify', '--db', p]);
    expect(r.code).toBe(0);
    expect(r.out).toMatch(/unchained/i);
    const check = new Database(p, { readonly: true });
    const hasMeta = check.prepare("SELECT name FROM sqlite_master WHERE name = 'ledger_meta'").get();
    check.close();
    expect(hasMeta).toBeUndefined();
  });

  it('usage errors exit 2: no verb, unknown verb, unknown flag, --db without a value, missing DB', () => {
    expect(run([]).code).toBe(2);
    expect(run(['frobnicate']).code).toBe(2);
    expect(run(['verify', '--bogus']).code).toBe(2);
    expect(run(['verify', '--db']).code).toBe(2);
    expect(run(['verify', '--db', '/nonexistent/sc-617/none.db']).code).toBe(2);
  });

  it('--help / -h / help print usage and exit 0 without opening a database', () => {
    for (const args of [['--help'], ['-h'], ['help'], ['verify', '--help']]) {
      const r = run(args);
      expect(r.code).toBe(0);
      expect(r.out).toContain(LEDGER_HELP.split('\n')[0]);
    }
  });

  it('is dispatched from src/index.ts', () => {
    const src = readFileSync(path.join(repoRoot, 'src', 'index.ts'), 'utf-8');
    expect(src).toMatch(/process\.argv\[2\] === 'ledger'/);
    expect(src).toMatch(/runLedgerCommand\(process\.argv\.slice\(3\)\)/);
    expect(src).toMatch(/ledger\$\{reset\} verify \[--json\]/);
  });
});

describe('doctor: chained ledger row (same verifier)', () => {
  it('pass when consistent', async () => {
    const p = chainedDb();
    const r = await checkChainedLedger({ dbPath: p });
    expect(r.label).toBe('Chained ledger');
    expect(r.status).toBe('pass');
    expect(r.message).toMatch(/^consistent/);
  });

  it('fail when inconsistent, naming the first bad seq', async () => {
    const p = chainedDb();
    const db = new Database(p);
    db.prepare('DELETE FROM defence_audit WHERE seq = 3').run();
    db.close();
    const r = await checkChainedLedger({ dbPath: p });
    expect(r.status).toBe('fail');
    expect(r.message).toMatch(/^inconsistent/);
    expect(r.message).toMatch(/seq 3/);
  });

  it('warn when the database has no chain yet', async () => {
    const dir = mkdtempSync(path.join(tmpdir(), 'sc-ledger-cli-'));
    dirs.push(dir);
    const p = path.join(dir, 'old.db');
    const raw = new Database(p);
    raw.exec(readFileSync(V521_SCHEMA, 'utf-8'));
    raw.close();
    const r = await checkChainedLedger({ dbPath: p });
    expect(r.status).toBe('warn');
    expect(r.message).toMatch(/^unchained/);
  });

  it('is registered in the doctor check list', () => {
    const src = readFileSync(path.join(repoRoot, 'src', 'cli', 'doctor.ts'), 'utf-8');
    expect(src).toMatch(/\n\s+checkChainedLedger,\n/);
  });
});
