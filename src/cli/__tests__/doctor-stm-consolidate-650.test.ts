/**
 * Issue #650 — doctor's `consolidation needed` row must clear after running
 * doctor's own suggested command.
 *
 * Field report (v5.4.0): doctor said `100/100 STM — consolidation needed` and
 * pointed at `shieldcortex consolidate`. That command reported a successful
 * pass (merged 23, archived 59 — all LTM rows) and doctor immediately said
 * `101/100 STM — consolidation needed`. Two defects:
 *
 *   1. The `consolidate` CLI ran only Dream Mode (`consolidateMemories`: LTM
 *      near-duplicate merge, archival flags, contradictions). The phase that
 *      promotes, expires and cap-evicts SHORT-TERM rows — `consolidate()` —
 *      was only ever run by the brain worker, so the suggested command could
 *      not touch the number the row was complaining about.
 *   2. The row warned at 90% of the cap, but consolidation drains STM to the
 *      cap and no further (`enforceMemoryLimits`), so 90..100 was a permanent
 *      warning that no command could clear.
 *
 * The test drives the BUILT CLI (`dist/index.js consolidate`) exactly as the
 * doctor row names it, against an isolated HOME. It never touches the real
 * ~/.shieldcortex.
 *
 * Driving a checkout's `dist/index.js` against a default-path database is
 * precisely what `enforceSafeRuntimePath` refuses: an entry path containing
 * `/ShieldCortex/` is classed `project-checkout` and `initDatabase()` throws
 * before the command runs (exit 1). GitHub Actions checks out to
 * `.../work/ShieldCortex/ShieldCortex/`, so CI tripped it on every spawn while
 * a worktree named anything else sailed through. The fixture HOME is the whole
 * point of this suite — there is no live database to protect — so the child
 * gets the guard's own documented opt-out, `SHIELDCORTEX_ALLOW_UNSAFE_RUNTIME=1`,
 * and NOT an inherited `CLAUDE_MEMORY_DB`, which would silently redirect the
 * command away from the fixture (several sibling suites set it without
 * restoring it, and Jest workers are long-lived). For the same reason the
 * child's `SHIELDCORTEX_CONFIG_DIR` is pinned to the fixture's own
 * `.shieldcortex`, never inherited: the caps the spawned command resolves must
 * be the fixture's, not whatever a sibling suite last pointed the loader at.
 */
import fs from 'fs';
import os from 'os';
import path from 'path';
import { createHmac, randomUUID } from 'node:crypto';
import { spawnSync } from 'child_process';
import Database from 'better-sqlite3';
import { afterEach, beforeEach, describe, expect, it } from '@jest/globals';
import { initDatabase, getDatabase, closeDatabase } from '../../database/init.js';
import { runMemoryStatsCheck } from '../doctor.js';

const CAP = 100; // DEFAULT_CONFIG.maxShortTermMemories, what the spawned CLI resolves under the fixture HOME
// Pinned explicitly so the in-process doctor check never reads this host's memory settings.
const CAPS = { maxShortTermMemories: CAP, maxLongTermMemories: 1000 };
const DAY = 86_400_000;

/** SQLite CURRENT_TIMESTAMP format ('YYYY-MM-DD HH:MM:SS'), offset into the past. */
function sqliteTs(agoMs: number): string {
  return new Date(Date.now() - agoMs).toISOString().slice(0, 19).replace('T', ' ');
}

describe('#650 doctor STM row clears after its own suggested command', () => {
  let root: string;
  let scDir: string;
  let dbPath: string;
  const cli = path.join(process.cwd(), 'dist', 'index.js');

  beforeEach(() => {
    root = fs.mkdtempSync(path.join(os.tmpdir(), 'sc-650-home-'));
    scDir = path.join(root, '.shieldcortex');
    fs.mkdirSync(scDir, { recursive: true, mode: 0o700 });
    dbPath = path.join(scDir, 'memories.db');
    expect(fs.existsSync(cli)).toBe(true); // run-jest.mjs builds dist first
  });

  /**
   * Write a SIGNED config.json into the fixture's config dir so the spawned
   * CLI resolves these caps (the loader ignores an unsigned file). Same
   * HMAC scheme as `configurable-caps-wiring.test.ts`.
   */
  function writeFixtureConfig(obj: unknown): void {
    const key = 'a'.repeat(64);
    fs.writeFileSync(path.join(scDir, '.integrity-key'), key, { mode: 0o600 });
    const body = JSON.stringify(obj, null, 2) + '\n';
    fs.writeFileSync(path.join(scDir, 'config.json'), body);
    const sig = createHmac('sha256', key).update(body, 'utf-8').digest('hex');
    fs.writeFileSync(path.join(scDir, '.config-sig'), sig, { mode: 0o600 });
  }

  afterEach(() => {
    try { closeDatabase(); } catch { /* already closed */ }
    try { fs.rmSync(root, { recursive: true, force: true }); } catch { /* ignore */ }
  });

  /**
   * Seed `n` ordinary short-term rows: mid salience (no promotion), recently
   * accessed (no decay expiry), created days ago (outside the one-hour
   * eviction grace window), unpinned. The only thing that can drain them is
   * cap enforcement — which is what the doctor row claims `consolidate` does.
   */
  function seedStm(n: number): void {
    initDatabase(dbPath);
    const db = getDatabase();
    const ins = db.prepare(`
      INSERT INTO memories (uuid, type, category, title, content, salience, access_count, last_accessed, created_at)
      VALUES (?, 'short_term', 'note', ?, ?, 0.5, 1, ?, ?)
    `);
    for (let i = 0; i < n; i++) {
      ins.run(randomUUID(), `stm ${i}`, `short-term fixture row ${i}`, sqliteTs(2 * DAY + i * 1000), sqliteTs(3 * DAY + i * 1000));
    }
    closeDatabase();
  }

  function stmCount(): number {
    const db = new Database(dbPath, { readonly: true });
    try {
      return (db.prepare("SELECT COUNT(*) AS c FROM memories WHERE type = 'short_term'").get() as { c: number }).c;
    } finally {
      db.close();
    }
  }

  function ltmCount(): number {
    const db = new Database(dbPath, { readonly: true });
    try {
      return (db.prepare("SELECT COUNT(*) AS c FROM memories WHERE type = 'long_term'").get() as { c: number }).c;
    } finally {
      db.close();
    }
  }

  /**
   * Seed `n` LONG-TERM rows, no STM at all, with the same "only cap
   * enforcement can touch these" shape as seedStm. Titles and bodies carry a
   * UUID so neither the pre-pass dedup nor Dream Mode's near-duplicate merge
   * can pair them: the only thing that may change the LTM count is eviction.
   */
  function seedLtm(n: number): void {
    initDatabase(dbPath);
    const db = getDatabase();
    const ins = db.prepare(`
      INSERT INTO memories (uuid, type, category, title, content, salience, access_count, last_accessed, created_at)
      VALUES (?, 'long_term', 'note', ?, ?, 0.5, 1, ?, ?)
    `);
    for (let i = 0; i < n; i++) {
      const tag = randomUUID();
      ins.run(tag, `${tag} ltm ${i}`, `long-term fixture ${tag} row ${i}`, sqliteTs(2 * DAY + i * 1000), sqliteTs(3 * DAY + i * 1000));
    }
    closeDatabase();
  }

  function runSuggestedCommand(): { status: number | null; stdout: string; stderr: string } {
    // Never let a sibling suite's leaked CLAUDE_MEMORY_DB pick the database:
    // this suite is about the DEFAULT path under HOME, like the doctor row.
    // Likewise the config dir is the fixture's own, never an inherited one.
    const { CLAUDE_MEMORY_DB: _leakedDb, SHIELDCORTEX_CONFIG_DIR: _leakedCfg, ...inherited } = process.env;
    const res = spawnSync(process.execPath, [cli, 'consolidate'], {
      env: {
        ...inherited,
        HOME: root,
        USERPROFILE: root,
        SHIELDCORTEX_CONFIG_DIR: scDir,
        // See the header: a checkout's dist against a default-path DB is what
        // the runtime-path guard exists to stop. HOME is a throwaway fixture.
        SHIELDCORTEX_ALLOW_UNSAFE_RUNTIME: '1',
      },
      encoding: 'utf-8',
      timeout: 120_000,
    });
    return { status: res.status, stdout: res.stdout ?? '', stderr: res.stderr ?? '' };
  }

  /** Exit-status assertion that shows the child's own output when it fails, not just `Received: 1`. */
  function expectExitZero(run: { status: number | null; stdout: string; stderr: string }): void {
    if (run.status !== 0) {
      throw new Error(
        `\`shieldcortex consolidate\` exited ${run.status}\n--- stderr ---\n${run.stderr}\n--- stdout ---\n${run.stdout}`,
      );
    }
  }

  it('the reported repro: STM over the cap, doctor warns, `shieldcortex consolidate` drains it, doctor passes', () => {
    seedStm(CAP + 1); // the report's second reading: 101/100

    const before = runMemoryStatsCheck(dbPath, CAPS);
    expect(before.status).toBe('warn');
    expect(before.message).toContain(`${CAP + 1}/${CAP} STM — consolidation needed`);
    // The row names the command the test is about to run.
    expect(before.fix).toContain('shieldcortex consolidate');

    const run = runSuggestedCommand();
    expect(run.stderr).not.toContain('Unknown command');
    expectExitZero(run);

    // The command actually drained STM to the cap…
    expect(stmCount()).toBeLessThanOrEqual(CAP);
    // …and said so, rather than reporting a pass that touched nothing.
    expect(run.stdout).toMatch(/evicted over cap \(STM\):\s+1\b/i);
    expect(run.stdout).toMatch(/evicted over cap \(LTM\):\s+0\b/i);

    // …and the row that sent the user here is gone.
    const after = runMemoryStatsCheck(dbPath, CAPS);
    expect(after.status).toBe('pass');
    expect(after.message).not.toContain('consolidation needed');
  });

  it('at exactly the cap (the report\'s first reading): the row does not fire, so there is nothing to clear', () => {
    seedStm(CAP);
    // A busy install sits at its cap by design: the worker consolidates down to
    // the cap and no further, so a warning here could never be cleared by the
    // command it names (that was the second defect behind #650).
    const row = runMemoryStatsCheck(dbPath, CAPS);
    expect(row.status).toBe('pass');
    expect(row.message).toContain(`(${CAP} STM, 0 LTM)`);
    expect(row.message).not.toContain('consolidation needed');
  });

  it('STM that consolidation cannot drain yet (newborn rows) keeps the row and says why', () => {
    // Rows inside the one-hour eviction grace window are never evicted (#236).
    initDatabase(dbPath);
    const db = getDatabase();
    const ins = db.prepare(`
      INSERT INTO memories (uuid, type, category, title, content, salience, access_count, last_accessed, created_at)
      VALUES (?, 'short_term', 'note', ?, ?, 0.5, 1, ?, ?)
    `);
    for (let i = 0; i < CAP + 1; i++) {
      ins.run(randomUUID(), `newborn ${i}`, `newborn fixture row ${i}`, sqliteTs(60_000), sqliteTs(60_000));
    }
    closeDatabase();

    const run = runSuggestedCommand();
    expectExitZero(run);
    expect(stmCount()).toBe(CAP + 1);

    const after = runMemoryStatsCheck(dbPath, CAPS);
    expect(after.status).toBe('warn');
    expect(after.message).toContain(`${CAP + 1}/${CAP} STM — consolidation needed`);
    expect(after.fix).toMatch(/hour/);
  });

  // ── #667 review (CASE B1 / TARS 2): the maintenance phase is not STM-only ──

  it('LTM-only over cap: the command evicts long-term rows and says so under the LTM line, not an STM heading', () => {
    // Case's runtime repro used 1,005 aged LTM rows against the default cap of
    // 1,000. The shape is the same at a configured cap of 20 with 25 rows, and
    // the pass stays well under a second: Dream Mode's duplicate scans are
    // O(n²) over LTM, so a thousand unique rows cost tens of seconds on a
    // slow runner for no extra coverage.
    const LTM_CAP = 20;
    const caps = { maxShortTermMemories: CAP, maxLongTermMemories: LTM_CAP };
    writeFixtureConfig({ memory: caps });
    seedLtm(LTM_CAP + 5); // 0 STM

    expect(stmCount()).toBe(0);
    const run = runSuggestedCommand();
    expectExitZero(run);

    // Five long-term rows really were hard-deleted (cap policy unchanged)…
    expect(ltmCount()).toBe(LTM_CAP);
    // …and the output attributes them to the LONG-TERM cap, with STM at zero,
    // instead of printing `Evicted: 5` under "Consolidating short-term memory".
    expect(run.stdout).toMatch(/evicted over cap \(LTM\):\s+5\b/i);
    expect(run.stdout).toMatch(/evicted over cap \(STM\):\s+0\b/i);
    expect(run.stdout).not.toMatch(/consolidating short-term memory/i);
    expect(run.stdout).not.toMatch(/^\s*evicted:\s+\d/im); // the old unqualified line is gone
    // Nothing else moved: these rows are unique, so dedup resolved none.
    expect(run.stdout).toMatch(/LTM duplicates resolved \(deleted or downvoted\):\s+0\b/);

    // The STM row has nothing to say about an LTM-only store.
    const after = runMemoryStatsCheck(dbPath, caps);
    expect(after.message).not.toContain('consolidation needed');
  });

  // ── #667 review (CASE B2 / TARS 1): the pre-pass LTM dedup is reported ──

  it('identical LTM pair: the pre-pass dedup resolves it and the command reports it on its own line', () => {
    initDatabase(dbPath);
    const db = getDatabase();
    const ins = db.prepare(`
      INSERT INTO memories (uuid, type, category, title, content, salience, access_count, last_accessed, created_at)
      VALUES (?, 'long_term', 'note', ?, ?, 0.5, 1, ?, ?)
    `);
    for (let i = 0; i < 2; i++) {
      ins.run(randomUUID(), 'identical title', 'identical long-term content for the dedup regression', sqliteTs(2 * DAY + i * 1000), sqliteTs(3 * DAY + i * 1000));
    }
    closeDatabase();

    const run = runSuggestedCommand();
    expectExitZero(run);

    // A row disappeared (identical pair → the loser is deleted)…
    expect(ltmCount()).toBe(1);
    // …and the output accounts for it, instead of every counter printing 0.
    // It is reported as a dedup resolution, NOT as an eviction or an expiry:
    // `deduplicated` also counts downvoted losers, so it must not be folded
    // into a hard-delete total.
    expect(run.stdout).toMatch(/LTM duplicates resolved \(deleted or downvoted\):\s+1\b/);
    expect(run.stdout).toMatch(/evicted over cap \(STM\):\s+0\b/i);
    expect(run.stdout).toMatch(/evicted over cap \(LTM\):\s+0\b/i);
    expect(run.stdout).toMatch(/expired \(decayed\):\s+0\b/i);
  });
});
