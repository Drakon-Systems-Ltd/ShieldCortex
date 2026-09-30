/**
 * #617 §5.7 gating tests that need real processes:
 *  - crash mid-write: a writer is SIGKILLed between the row INSERT and the
 *    chain finalise, inside the DB transaction. The survivor must see no
 *    half-chained row and a head that still matches the chain.
 *  - concurrent writers: several processes append to one database at once;
 *    they serialise through the DB transaction, so seq is unique and the
 *    chain verifies end to end.
 *
 * Children run the TypeScript sources through tsx with an isolated HOME.
 */

import { describe, it, expect, beforeAll, afterAll } from '@jest/globals';
import Database from 'better-sqlite3';
import { spawn, spawnSync } from 'child_process';
import { mkdtempSync, rmSync, writeFileSync, existsSync } from 'fs';
import { tmpdir } from 'os';
import path from 'path';
import { fileURLToPath } from 'url';
import { verifyLedger, readLedgerMeta } from '../defence/ledger/index.js';

const here = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(here, '..', '..');
const tsx = path.join(repoRoot, 'node_modules', '.bin', 'tsx');
const initTs = path.join(repoRoot, 'src', 'database', 'init.ts');
const loggerTs = path.join(repoRoot, 'src', 'defence', 'audit', 'logger.ts');
const ledgerTs = path.join(repoRoot, 'src', 'defence', 'ledger', 'index.ts');

let work: string;
let home: string;
let childScript: string;

beforeAll(() => {
  work = mkdtempSync(path.join(tmpdir(), 'sc-ledger-mp-'));
  home = path.join(work, 'home');
  childScript = path.join(work, 'writer.ts');
  writeFileSync(childScript, `
import { initDatabase, closeDatabase } from ${JSON.stringify(initTs)};
import { logAudit } from ${JSON.stringify(loggerTs)};
import { __setLedgerFaultForTests } from ${JSON.stringify(ledgerTs)};
const [dbPath, countArg, tag, mode] = process.argv.slice(2);
initDatabase(dbPath);
const count = Number(countArg);
let ok = 0;
for (let i = 0; i < count; i++) {
  if (mode === 'crash' && i === count - 1) {
    __setLedgerFaultForTests(() => { process.kill(process.pid, 'SIGKILL'); });
  }
  const id = logAudit({
    memory_id: null, project: 'mp', timestamp: new Date().toISOString(),
    source_type: 'cli', source_identifier: tag, trust_score: 0.9,
    sensitivity_level: 'INTERNAL', firewall_result: 'ALLOW', operation: 'write',
    anomaly_score: 0, threat_indicators: '[]', blocked_patterns: '[]',
    reason: tag + ' ' + i, fragmentation_score: null,
  });
  if (id > 0) ok++;
}
closeDatabase();
process.stdout.write(String(ok));
`);
});

afterAll(() => {
  rmSync(work, { recursive: true, force: true });
});

function childEnv(): NodeJS.ProcessEnv {
  const env: NodeJS.ProcessEnv = { ...process.env, HOME: home, SHIELDCORTEX_SKIP_EMBEDDINGS: '1' };
  for (const k of Object.keys(env)) {
    if (k.startsWith('MULTI_CLAWD_') || k.startsWith('CLAUDE_') || k.startsWith('JEST_')) delete env[k];
  }
  delete env.NODE_OPTIONS;
  return env;
}

function runWriter(dbPath: string, count: number, tag: string, mode = ''): Promise<{ code: number | null; signal: NodeJS.Signals | null; out: string; err: string }> {
  return new Promise((resolve) => {
    const child = spawn(tsx, [childScript, dbPath, String(count), tag, mode], { env: childEnv(), cwd: repoRoot });
    let out = '';
    let err = '';
    child.stdout.on('data', (d) => { out += d; });
    child.stderr.on('data', (d) => { err += d; });
    child.on('close', (code, signal) => resolve({ code, signal, out, err }));
  });
}

describe('multi-process ledger gates', () => {
  it('tsx is available to run child writers', () => {
    expect(existsSync(tsx)).toBe(true);
  });

  it('crash mid-write (SIGKILL inside the transaction) leaves no half-chained row', async () => {
    const dbPath = path.join(work, 'crash.db');
    const res = await runWriter(dbPath, 5, 'crasher', 'crash');
    expect(res.signal).toBe('SIGKILL');

    const db = new Database(dbPath);
    try {
      const rows = db.prepare("SELECT seq, row_hash, content_digest FROM defence_audit WHERE source_identifier = 'crasher' ORDER BY seq").all() as Array<{ seq: number | null; row_hash: string | null; content_digest: string | null }>;
      expect(rows).toHaveLength(4); // the fifth write died mid-transaction
      expect(rows.every((r) => r.seq !== null && r.row_hash !== null && r.content_digest !== null)).toBe(true);
      const meta = readLedgerMeta(db)!;
      expect(meta.head_seq).toBe(4);
      expect(verifyLedger(db).status).toBe('consistent');
    } finally { db.close(); }

    // And a later writer continues the same chain.
    const again = await runWriter(dbPath, 2, 'after-crash');
    expect(again.code).toBe(0);
    const db2 = new Database(dbPath, { readonly: true });
    try {
      const r = verifyLedger(db2);
      expect(r.status).toBe('consistent');
      expect(r.head?.seq).toBe(6);
    } finally { db2.close(); }
  }, 60_000);

  it('concurrent writer processes serialise through the DB transaction', async () => {
    const dbPath = path.join(work, 'concurrent.db');
    // Create the ledger once so the writers race on appends, not on genesis.
    const init = spawnSync(tsx, [childScript, dbPath, '0', 'init'], { env: childEnv(), cwd: repoRoot });
    expect(init.status).toBe(0);

    const WRITERS = 4;
    const EACH = 40;
    const results = await Promise.all(
      Array.from({ length: WRITERS }, (_, i) => runWriter(dbPath, EACH, `w${i}`)),
    );
    for (const r of results) {
      expect({ code: r.code, err: r.code === 0 ? '' : r.err }).toEqual({ code: 0, err: '' });
      expect(r.out).toBe(String(EACH));
    }

    const db = new Database(dbPath, { readonly: true });
    try {
      const seqs = (db.prepare('SELECT seq FROM defence_audit WHERE seq IS NOT NULL ORDER BY seq').all() as { seq: number }[]).map((r) => r.seq);
      expect(seqs).toHaveLength(WRITERS * EACH);
      expect(new Set(seqs).size).toBe(seqs.length);
      const r = verifyLedger(db);
      expect(r.status).toBe('consistent');
      expect(r.gaps).toEqual([]);
      expect(r.head?.seq).toBe(WRITERS * EACH);
    } finally { db.close(); }
  }, 120_000);
});
