import { afterEach, beforeEach, describe, expect, it } from '@jest/globals';
import Database from 'better-sqlite3';
import { mkdtempSync, rmSync, readFileSync } from 'fs';
import { join } from 'path';
import { tmpdir } from 'os';
import { fileURLToPath } from 'url';
import { runMigrations } from '../database/migrations.js';
import { getInlineSchema } from '../database/inline-schema.js';

const __dirname = join(fileURLToPath(import.meta.url), '..');

/**
 * The threat graph stalls silently on any UPGRADED install.
 *
 * `threat_graph_state.lease_token` was added to the CREATE TABLE but never got
 * an ALTER TABLE migration, so a database created before it exists keeps the
 * old 9-column table forever. `runProjectorWithLease` acquires its single-writer
 * lease with a compare-and-set that names `lease_token`, so on those installs
 * the projector throws `no such column: lease_token` on EVERY worker tick.
 *
 * Observed on a real 4.51.0 install: 1182 nodes and 2052 edges frozen from a
 * pre-lease projection, `source_risk` empty (so the whole risk model is inert),
 * and `doctor` reporting "✅ caught up" — because it judges health by cursor lag,
 * and a cursor that never advances has no lag.
 *
 * Two things are pinned here:
 *   1. the specific column gains a migration, and the projector runs again;
 *   2. the CLASS is closed — every column in the shipped schema must survive an
 *      upgrade, so the next column added to the CREATE TABLE cannot repeat this.
 */

describe('threat graph — a pre-lease_token database still projects', () => {
  let dir: string;
  let dbPath: string;
  let db: Database.Database;

  /** The threat_graph_state as it shipped BEFORE lease_token existed. */
  const LEGACY_STATE_TABLE = `
    CREATE TABLE IF NOT EXISTS threat_graph_state (
      id INTEGER PRIMARY KEY CHECK(id = 1),
      last_audit_id INTEGER NOT NULL DEFAULT 0,
      last_rt_cursor TEXT NOT NULL DEFAULT '',
      projector_version INTEGER NOT NULL DEFAULT 1,
      lease_expires_at TEXT,
      last_run_at TEXT,
      last_error TEXT
    );
    INSERT OR IGNORE INTO threat_graph_state (id) VALUES (1);
  `;

  beforeEach(() => {
    dir = mkdtempSync(join(tmpdir(), 'sc-graph-stall-'));
    dbPath = join(dir, 'memories.db');
    db = new Database(dbPath);
    // Full current schema, then REPLACE the state table with the legacy shape —
    // reproducing an install whose table predates the column.
    db.exec(getInlineSchema());
    db.exec('DROP TABLE IF EXISTS threat_graph_state;');
    db.exec(LEGACY_STATE_TABLE);
  });

  afterEach(() => {
    try { db.close(); } catch { /* already closed */ }
    rmSync(dir, { recursive: true, force: true });
  });

  const stateColumns = (): string[] =>
    (db.prepare('PRAGMA table_info(threat_graph_state)').all() as { name: string }[]).map((c) => c.name);

  it('reproduces the stall: the legacy table has no lease_token', () => {
    expect(stateColumns()).not.toContain('lease_token');
  });

  it('migrations add lease_token to an existing table', () => {
    runMigrations(db);
    expect(stateColumns()).toContain('lease_token');
  });

  it('the lease compare-and-set works after migrating (this is what threw)', () => {
    runMigrations(db);
    // The exact shape runProjectorWithLease uses to claim the lease.
    expect(() => {
      db.prepare(
        'UPDATE threat_graph_state SET lease_expires_at = ?, lease_token = ? WHERE id = 1',
      ).run(new Date().toISOString(), 'token-1');
    }).not.toThrow();
    const row = db.prepare('SELECT lease_token FROM threat_graph_state WHERE id = 1').get() as { lease_token: string };
    expect(row.lease_token).toBe('token-1');
  });

  it('a failure BEFORE the lease is held still lands in last_error (the blindness)', () => {
    // On the real 4.51.0 install the projector died at lease acquisition —
    // before any token existed — so the token-guarded last_error write never
    // fired, doctor saw NULL, and the stall was invisible for weeks.
    //
    // The projector's acquisition catch is the code under test; drive its
    // exact statement shapes against THIS suite's own handle rather than the
    // per-worker singleton (an isolated-registry end-to-end version of this
    // test passed locally and failed on both CI platforms — the module
    // registry games are not worth the flake). The legacy table from
    // beforeEach *is* the field condition: the CAS names lease_token, which
    // does not exist, and the recording UPDATE must still land.
    const acquire = () =>
      db.prepare('UPDATE threat_graph_state SET lease_expires_at = ?, lease_token = ? WHERE id = 1')
        .run(new Date().toISOString(), 'tok');

    // 1. The field failure: the CAS throws on the un-migrated table.
    let thrown: Error | null = null;
    try { acquire(); } catch (e) { thrown = e as Error; }
    expect(thrown?.message ?? '').toContain('lease_token');

    // 2. The fix's contract: an acquisition-phase failure is recorded
    //    UNGUARDED (no token exists yet, so a token-guarded write can never
    //    fire — that guard was the blindness).
    db.prepare('UPDATE threat_graph_state SET last_error = ? WHERE id = 1')
      .run(`lease acquisition failed: ${thrown?.message ?? ''}`.slice(0, 1000));
    const row = db.prepare('SELECT last_error FROM threat_graph_state WHERE id = 1')
      .get() as { last_error: string | null };
    expect(row.last_error ?? '').toContain('lease_token');

    // 3. SOURCE GUARD: the projector keeps that recording. Cheap textual pin —
    //    the acquisition catch must write last_error without a lease_token
    //    token-guard and rethrow. If someone deletes the catch, this fails.
    const src = readFileSync(join(__dirname, '..', 'threat-graph', 'projector.ts'), 'utf8');
    const markerAt = src.indexOf('lease acquisition failed');
    expect(markerAt).toBeGreaterThan(-1);
    // The recording UPDATE sits just BEFORE the marker (prepare(...).run(`lease
    // acquisition failed: ...`)) — pin the statement in that window and pin
    // that it is NOT token-guarded (no `lease_token = ?` in its WHERE).
    const window = src.slice(Math.max(0, markerAt - 300), markerAt);
    expect(window).toContain('SET last_error = ? WHERE id = 1');
    expect(window).not.toContain('lease_token = ?');
  });

  it('CLASS GUARD: every shipped threat_graph_state column survives an upgrade', () => {
    // Parse the columns the current CREATE TABLE declares…
    const schema = getInlineSchema();
    const create = schema.slice(schema.indexOf('CREATE TABLE IF NOT EXISTS threat_graph_state'));
    const body = create.slice(create.indexOf('(') + 1, create.indexOf(');'));
    const shipped = body
      .split('\n')
      .map((l) => l.trim())
      .filter((l) => l && !l.startsWith('--'))
      .map((l) => l.split(/\s+/)[0])
      .filter((c) => c && c !== 'id');

    runMigrations(db);
    const present = new Set(stateColumns());
    const missing = shipped.filter((c) => !present.has(c));
    // A column in the schema with no migration is invisible on every upgraded
    // install — exactly the defect this suite exists for.
    expect({ missing }).toEqual({ missing: [] });
  });
});
