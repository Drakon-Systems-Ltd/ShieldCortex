import fs from 'fs';
import os from 'os';
import path from 'path';
import Database from 'better-sqlite3';
import { afterEach, beforeEach, describe, expect, it } from '@jest/globals';

import { checkDiskUsage } from '../doctor.js';

/**
 * v4.45.1: the Disk check's remedy used to always say "memories prune / dedupe"
 * even when the space was stale migration backups or session-capture rows —
 * neither of which prune/dedupe can reach. EDITH hit exactly this: a stack of
 * pre-backfill backups pushed her over 100 MB and the suggested fix did nothing.
 * The check now breaks the data down (live DB / backups / logs) and points at the
 * remedy that matches the actual consumer. A `limitBytes` arg keeps it testable
 * without writing ~100 MB of fixture data.
 */
describe('doctor checkDiskUsage names the real disk consumer (4.45.1)', () => {
  let tmpDir: string;
  const KB = 1024;

  beforeEach(() => {
    tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'sc-disk-breakdown-'));
  });

  afterEach(() => {
    try { fs.rmSync(tmpDir, { recursive: true, force: true }); } catch { /* ignore */ }
  });

  function writeBytes(rel: string, bytes: number): void {
    const fullPath = path.join(tmpDir, rel);
    fs.mkdirSync(path.dirname(fullPath), { recursive: true });
    fs.writeFileSync(fullPath, Buffer.alloc(bytes, 0));
  }

  it('points at the backup copies when they dominate the budget', async () => {
    writeBytes('memories.db', 4 * KB);
    writeBytes('memories.db.pre-backfill-1700000000000', 40 * KB);
    writeBytes('memories.db.empty-live.1700000000001', 20 * KB);
    const result = await checkDiskUsage(tmpDir, 32 * KB);
    expect(result.status).toBe('fail');
    // Names the backup copies and the files to act on.
    expect(result.fix).toMatch(/backup copies/i);
    expect(result.fix).toMatch(/memories\.db/);
    // Still NOT the old blanket "Run memories prune/dedupe" advice.
    expect(result.fix).not.toMatch(/^Run `shieldcortex memories prune/);
    // #148: it must no longer call these "stale migration snapshots" — on a
    // large-DB host the dominant file is usually a safety copy written minutes
    // earlier by a repair doctor itself recommended — nor promise an
    // auto-prune that was never implemented.
    expect(result.fix).not.toMatch(/stale DB backups/i);
    expect(result.fix).not.toMatch(/auto-prune/i);
  });

  it('includes a DB / backups / logs breakdown in the message', async () => {
    writeBytes('memories.db', 40 * KB);
    writeBytes('memories.db.pre-backfill-1700000000000', 4 * KB);
    const result = await checkDiskUsage(tmpDir, 32 * KB);
    expect(result.status).toBe('fail');
    expect(result.message).toMatch(/DB .* · backups .* · logs/);
  });

  it('points at `shieldcortex vacuum` when the live DB itself is the bulk', async () => {
    writeBytes('memories.db', 60 * KB);
    const result = await checkDiskUsage(tmpDir, 32 * KB);
    expect(result.status).toBe('fail');
    // Must be the native command, NOT an invocation of the `sqlite3` binary — that
    // CLI is not bundled and is absent on minimal boxes (a fleet agent had none).
    // Mentioning "no sqlite3 CLI needed" in prose is fine; recommending you RUN
    // `sqlite3 ~/… 'VACUUM'` is the bug. Forbid only the command form.
    expect(result.fix).toMatch(/shieldcortex vacuum/);
    expect(result.fix).not.toMatch(/sqlite3 ['"~]/);
  });

  it('flags audit/log files when those dominate', async () => {
    writeBytes('memories.db', 2 * KB);
    writeBytes('audit/realtime.jsonl', 40 * KB);
    const result = await checkDiskUsage(tmpDir, 32 * KB);
    expect(result.status).toBe('fail');
    expect(result.fix).toMatch(/audit\/log files/);
  });

  // ── #110 signature: big DB, tiny memories table ─────────────────────────
  // Live incident (Edith, 2026-07-21, v4.47.12): 79.6 MB DB with only 117
  // memories — dbstat put session_events at 62.8 MB. The old remedy pointed at
  // vacuum (0.0 MB of free pages — no-op) and memories prune (117 rows — no-op).
  // When session_events payload dominates the memories table, the remedy must
  // name `shieldcortex sessions prune` (and vacuum AFTER, to reclaim the pages
  // the prune frees).
  function buildRealDb(opts: {
    memories: number;
    memoryBytes: number;
    events: number;
    eventBytes: number;
    auditRows?: number;
    auditBytes?: number;
  }): void {
    const db = new Database(path.join(tmpDir, 'memories.db'));
    db.exec(`
      CREATE TABLE memories (id INTEGER PRIMARY KEY AUTOINCREMENT, content TEXT NOT NULL);
      CREATE TABLE session_events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        session_id TEXT NOT NULL,
        ts TIMESTAMP NOT NULL,
        kind TEXT NOT NULL,
        payload TEXT NOT NULL
      );
      CREATE TABLE defence_audit (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        reason TEXT,
        threat_indicators TEXT DEFAULT '[]',
        blocked_patterns TEXT DEFAULT '[]',
        source_type TEXT NOT NULL DEFAULT 'test',
        source_identifier TEXT NOT NULL DEFAULT 'test'
      );
    `);
    const insMem = db.prepare('INSERT INTO memories (content) VALUES (?)');
    for (let i = 0; i < opts.memories; i++) insMem.run('m'.repeat(opts.memoryBytes));
    const insEvt = db.prepare(
      "INSERT INTO session_events (session_id, ts, kind, payload) VALUES ('s', ?, 'prompt', ?)",
    );
    for (let i = 0; i < opts.events; i++) {
      insEvt.run(new Date(Date.now() - i * 60_000).toISOString(), 'p'.repeat(opts.eventBytes));
    }
    const insAudit = db.prepare('INSERT INTO defence_audit (reason) VALUES (?)');
    for (let i = 0; i < (opts.auditRows ?? 0); i++) {
      insAudit.run('a'.repeat(opts.auditBytes ?? 0));
    }
    db.close();
  }

  it('points at `shieldcortex sessions prune` when session_events dominate a big DB (#110)', async () => {
    // ~200 KB of session payload vs ~1 KB of memories → DB well over 50% of a
    // 128 KB limit, with the #110 signature (big DB, tiny memories table).
    buildRealDb({ memories: 5, memoryBytes: 200, events: 100, eventBytes: 2048 });

    const result = await checkDiskUsage(tmpDir, 128 * KB);

    expect(result.status).toBe('fail');
    expect(result.fix).toMatch(/shieldcortex sessions prune/);
    // Vacuum must still be named — prune alone leaves free pages in the file.
    expect(result.fix).toMatch(/shieldcortex vacuum/);
    // And it must NOT lead with the no-op remedies the incident hit.
    expect(result.fix).not.toMatch(/^Run `shieldcortex memories prune/);
  });

  it('does NOT recommend sessions prune on an audit-dominated DB (#111 review repro)', async () => {
    // Reviewer repro: 1 memory + ~600 B of session events + ~200 KB of
    // defence_audit. The pre-review condition (sessionEventBytes >
    // memoriesBytes) blamed session capture and recommended `sessions prune`
    // — a no-op. Session capture may only be named when it genuinely
    // dominates (> 40% of the live DB AND > audit bytes).
    buildRealDb({
      memories: 1,
      memoryBytes: 100,
      events: 3,
      eventBytes: 200,
      auditRows: 100,
      auditBytes: 2048,
    });

    const result = await checkDiskUsage(tmpDir, 128 * KB);

    expect(result.status).toBe('fail');
    expect(result.fix).not.toMatch(/sessions prune/);
    expect(result.fix).not.toMatch(/bulk is session-capture/);
    // Vacuum guidance is retained for the audit-dominated case.
    expect(result.fix).toMatch(/shieldcortex vacuum/);
  });

  it('does not claim session capture is the bulk when the memories table dominates', async () => {
    buildRealDb({ memories: 100, memoryBytes: 2048, events: 3, eventBytes: 100 });

    const result = await checkDiskUsage(tmpDir, 128 * KB);

    expect(result.status).toBe('fail');
    // Generic big-DB remedy — must not assert that session_events is the bulk.
    expect(result.fix).not.toMatch(/session_events .*is the bulk|bulk is session-capture/);
    expect(result.fix).toMatch(/shieldcortex vacuum/);
  });

  it('honours a custom limit (the plumbing behind the breakdown remedy)', async () => {
    writeBytes('memories.db', 10 * KB);
    const small = await checkDiskUsage(tmpDir, 8 * KB);
    expect(small.status).toBe('fail');
    const large = await checkDiskUsage(tmpDir, 100 * 1024 * 1024);
    expect(large.status).toBe('pass');
  });
});
