import { describe, it, expect, beforeEach, afterEach } from '@jest/globals';
import Database from 'better-sqlite3';
import path from 'path';
import os from 'os';
import fs from 'fs';
import { getSalienceDistribution } from '../memory/metrics.js';

/**
 * Phase 0 (measure-first) instrument: make the "salience wall" queryable BEFORE
 * changing the model. The edith field finding was 43/43 long-term memories at
 * raw salience ≥0.99 and 81% of that cohort mid-sentence fragments. This
 * instrument quantifies exactly that (and lets us re-run it after a change to
 * prove the wall spread / fragments fell). Pure read — no mutation, no deletion.
 */
describe('getSalienceDistribution — the salience-wall instrument', () => {
  let db: InstanceType<typeof Database>;
  let dbPath: string;

  beforeEach(() => {
    dbPath = path.join(os.tmpdir(), `sc-saldist-${Date.now()}-${Math.random().toString(36).slice(2)}.db`);
    db = new Database(dbPath);
    db.exec(`CREATE TABLE memories (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      type TEXT NOT NULL DEFAULT 'short_term',
      title TEXT NOT NULL DEFAULT '',
      content TEXT NOT NULL DEFAULT '',
      salience REAL DEFAULT 0.5
    );`);
  });
  afterEach(() => {
    db.close();
    try { fs.unlinkSync(dbPath); } catch { /* ignore */ }
  });

  function insert(type: string, salience: number, content: string): void {
    db.prepare('INSERT INTO memories (type, salience, content) VALUES (?, ?, ?)').run(type, salience, content);
  }

  it('reports the salience wall: % of long-term memories at >=0.95', () => {
    for (let i = 0; i < 10; i++) insert('long_term', 1.0, 'PostgreSQL chosen for JSONB support.');
    for (let i = 0; i < 5; i++) insert('short_term', 0.4, 'A complete short-term note.');
    const d = getSalienceDistribution(db);
    expect(d.total).toBe(15);
    expect(d.wall.ltmTotal).toBe(10);
    expect(d.wall.ltmAtOrAbove095).toBe(10);
    expect(d.wall.ltmPct).toBe(100);
  });

  it('counts mid-sentence fragments within the high-salience cohort', () => {
    // 8 fragments (start mid-clause) + 2 complete, all long-term at 1.0
    for (let i = 0; i < 8; i++) insert('long_term', 1.0, 'the resources this year.');
    for (let i = 0; i < 2; i++) insert('long_term', 1.0, 'PostgreSQL chosen for JSONB.');
    const d = getSalienceDistribution(db);
    expect(d.fragments.atOrAbove095).toBe(8);
    expect(d.fragments.pctOfWall).toBe(80);
  });

  it('WARNs when >40% of long-term sit at >=0.95 OR >30% of the wall are fragments', () => {
    for (let i = 0; i < 9; i++) insert('long_term', 1.0, 'so you can run the test first?'); // fragment
    insert('long_term', 1.0, 'A complete decision was recorded here.');
    const d = getSalienceDistribution(db);
    expect(d.warnings.some((w) => /salience wall|≥?>=?\s*0?\.?95|wall/i.test(w))).toBe(true);
    expect(d.warnings.some((w) => /fragment/i.test(w))).toBe(true);
  });

  it('a healthy spread (no wall, no fragments) produces no warnings', () => {
    insert('long_term', 0.55, 'Decision: use Drizzle for the schema layer.');
    insert('long_term', 0.62, 'The auth bug was an expired JWT; rotate on refresh.');
    insert('short_term', 0.30, 'Transient note about a flaky test.');
    insert('short_term', 0.45, 'Checked the deploy logs, all green.');
    const d = getSalienceDistribution(db);
    expect(d.wall.ltmAtOrAbove095).toBe(0);
    expect(d.fragments.atOrAbove095).toBe(0);
    expect(d.warnings).toEqual([]);
  });

  it('buckets every memory into a salience band by type (sums to total)', () => {
    insert('long_term', 1.0, 'x complete sentence here.');
    insert('short_term', 0.1, 'A low one.');
    insert('long_term', 0.7, 'A mid one.');
    const d = getSalienceDistribution(db);
    const summed = d.bands.reduce((n, b) => n + b.count, 0);
    expect(summed).toBe(d.total);
    expect(d.total).toBe(3);
  });

  it('tolerates an empty store (no rows) without dividing by zero', () => {
    const d = getSalienceDistribution(db);
    expect(d.total).toBe(0);
    expect(d.wall.ltmPct).toBe(0);
    expect(d.fragments.pctOfWall).toBe(0);
    expect(d.warnings).toEqual([]);
  });
});
