/**
 * #617 §5.7 gating tests that need real processes:
 *  - crash mid-write: a writer is SIGKILLed between the row INSERT and the
 *    chain finalise, inside the DB transaction. The survivor must see no
 *    half-chained row and a head that still matches the chain.
 *  - concurrent writers: several processes append to one database at once;
 *    they serialise through the DB transaction, so seq is unique and the
 *    chain verifies end to end. The writers are released together through a
 *    file barrier once every child has loaded and opened the DB, and each
 *    reports when it began and finished appending — the test asserts those
 *    windows overlap, so a serial run (child start-up skew on a cold macOS
 *    runner once made 4 writers run back to back) cannot pass as concurrent.
 *
 * Children run the TypeScript sources through tsx with an isolated HOME.
 */

import { describe, it, expect, beforeAll, afterAll } from '@jest/globals';
import Database from 'better-sqlite3';
import { spawn, spawnSync, type ChildProcess } from 'child_process';
import { mkdtempSync, mkdirSync, rmSync, writeFileSync, existsSync } from 'fs';
import { tmpdir } from 'os';
import path from 'path';
import { fileURLToPath, pathToFileURL } from 'url';
import { verifyLedger, readLedgerMeta } from '../defence/ledger/index.js';

const here = path.dirname(fileURLToPath(import.meta.url));
const repoRoot = path.resolve(here, '..', '..');
// tsx as an --import loader (not the tsx CLI, which runs the script in a
// grandchild): the process we SIGKILL must be the one we spawned.
const tsxLoader = pathToFileURL(path.join(repoRoot, 'node_modules', 'tsx', 'dist', 'loader.mjs')).href;
const nodeArgs = (script: string, args: string[]): string[] => ['--import', tsxLoader, script, ...args];
const initTs = path.join(repoRoot, 'src', 'database', 'init.ts');
const loggerTs = path.join(repoRoot, 'src', 'defence', 'audit', 'logger.ts');
const ledgerTs = path.join(repoRoot, 'src', 'defence', 'ledger', 'index.ts');

let work: string;
let home: string;
let childScript: string;
const liveChildren = new Set<ChildProcess>();

beforeAll(() => {
  work = mkdtempSync(path.join(tmpdir(), 'sc-ledger-mp-'));
  home = path.join(work, 'home');
  childScript = path.join(work, 'writer.ts');
  writeFileSync(childScript, `
import { initDatabase, closeDatabase } from ${JSON.stringify(initTs)};
import { logAudit } from ${JSON.stringify(loggerTs)};
import { __setLedgerFaultForTests } from ${JSON.stringify(ledgerTs)};
import { existsSync as goExists, writeFileSync as writeReady } from 'fs';
import { join as joinPath } from 'path';
const [dbPath, countArg, tag, mode, barrierDir] = process.argv.slice(2);
initDatabase(dbPath);
const count = Number(countArg);
// Start barrier: announce readiness only once the loader has done its work and
// the DB is open, then spin until the parent drops the go file. Without it,
// start-up skew between children lets one writer finish every append before
// the next has loaded, and the race is serial in disguise.
if (barrierDir) {
  writeReady(joinPath(barrierDir, 'ready-' + tag), '');
  const go = joinPath(barrierDir, 'go');
  const nap = new Int32Array(new SharedArrayBuffer(4));
  // Longer than the parent's 60s wait, so a barrier failure is reported by the
  // parent (which knows who is missing), not by children giving up first.
  const deadline = Date.now() + 90_000;
  while (!goExists(go)) {
    if (Date.now() > deadline) { process.stderr.write('barrier timeout'); process.exit(3); }
    Atomics.wait(nap, 0, 0, 1);
  }
}
const start = Date.now();
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
const end = Date.now();
closeDatabase();
process.stdout.write(JSON.stringify({ ok, start, end }));
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

function runWriter(dbPath: string, count: number, tag: string, mode = '', barrierDir = ''): Promise<{ code: number | null; signal: NodeJS.Signals | null; out: string; err: string }> {
  return new Promise((resolve) => {
    const child = spawn(process.execPath, nodeArgs(childScript, [dbPath, String(count), tag, mode, barrierDir]), { env: childEnv(), cwd: repoRoot });
    liveChildren.add(child);
    let out = '';
    let err = '';
    child.stdout.on('data', (d) => { out += d; });
    child.stderr.on('data', (d) => { err += d; });
    child.on('close', (code, signal) => { liveChildren.delete(child); resolve({ code, signal, out, err }); });
  });
}

async function waitFor(ready: () => boolean, what: () => string, timeoutMs: number): Promise<void> {
  const deadline = Date.now() + timeoutMs;
  while (!ready()) {
    if (Date.now() > deadline) throw new Error(`timed out waiting for ${what()}`);
    await new Promise((r) => setTimeout(r, 5));
  }
}

describe('multi-process ledger gates', () => {
  it('the tsx loader is available to run child writers', () => {
    expect(existsSync(fileURLToPath(tsxLoader))).toBe(true);
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
    const init = spawnSync(process.execPath, nodeArgs(childScript, [dbPath, '0', 'init']), { env: childEnv(), cwd: repoRoot });
    expect(init.status).toBe(0);

    const WRITERS = 4;
    const EACH = 150;
    const tags = Array.from({ length: WRITERS }, (_, i) => `w${i}`);
    const barrierDir = path.join(work, 'barrier');
    mkdirSync(barrierDir);
    const pending = Promise.all(tags.map((t) => runWriter(dbPath, EACH, t, '', barrierDir)));
    // Release the writers only once every one of them is loaded and has the
    // DB open, so they contend for appends rather than for start-up.
    const readyFile = (t: string) => path.join(barrierDir, `ready-${t}`);
    try {
      await waitFor(
        () => tags.every((t) => existsSync(readyFile(t))),
        () => `writers to reach the barrier (missing: ${tags.filter((t) => !existsSync(readyFile(t))).join(', ')})`,
        60_000,
      );
    } catch (e) {
      // Do not leave stragglers spinning at the barrier: stop them and join
      // them before reporting, so the failure is the only thing left behind.
      for (const c of liveChildren) c.kill('SIGKILL');
      await pending;
      throw e;
    }
    writeFileSync(path.join(barrierDir, 'go'), '');
    const results = await pending;

    for (const r of results) {
      expect({ code: r.code, err: r.code === 0 ? '' : r.err }).toEqual({ code: 0, err: '' });
    }
    const timings = results.map((r) => JSON.parse(r.out) as { ok: number; start: number; end: number });
    expect(timings.map((t) => t.ok)).toEqual(tags.map(() => EACH));

    const db = new Database(dbPath, { readonly: true });
    try {
      // Product contract first, so a fixture that failed to overlap can never
      // hide a broken chain: seq unique and dense, chain verifies end to end.
      const seqs = (db.prepare('SELECT seq FROM defence_audit WHERE seq IS NOT NULL ORDER BY seq').all() as { seq: number }[]).map((r) => r.seq);
      expect(seqs).toHaveLength(WRITERS * EACH);
      expect(new Set(seqs).size).toBe(seqs.length);
      const r = verifyLedger(db);
      expect(r.status).toBe('consistent');
      expect(r.gaps).toEqual([]);
      expect(r.head?.seq).toBe(WRITERS * EACH);
    } finally { db.close(); }

    // Fixture contract: the writers' append loops overlapped in time — every
    // writer began before any writer finished, so the processes were appending
    // concurrently. This proves overlapping loop lifetimes, not that commits
    // interleaved; interleaving is lock hand-off order, which is what a count
    // of writer switches in seq order measures and why it was unsound here:
    // with busy_timeout a writer that has just committed re-takes the WAL
    // write lock before a sleeping rival wakes.
    const latestStart = Math.max(...timings.map((t) => t.start));
    const earliestEnd = Math.min(...timings.map((t) => t.end));
    expect({ overlapped: latestStart < earliestEnd, latestStart, earliestEnd, timings })
      .toEqual(expect.objectContaining({ overlapped: true }));
  }, 120_000);
});
