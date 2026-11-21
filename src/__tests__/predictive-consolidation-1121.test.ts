/**
 * #1121: a store sitting exactly at its caps made the brain worker log
 * "Predictive consolidation triggered: STM at 100% (critical threshold)" every
 * five minutes, while every consolidate() changed nothing — it evicts only
 * rows strictly OVER the cap, and nothing in STM met the promotion rule.
 *
 * The trigger and enforceMemoryLimitsByTier now agree on "over the cap"
 * (strictly greater), fullness thresholds fire only when a run would change
 * something, and a run that changed nothing is logged at most once an hour.
 *
 * In-memory database; the sandbox config dir from jest-config-sandbox.mjs
 * holds no caps, so the defaults (STM 100 / LTM 1000) apply.
 */
import { randomUUID } from 'crypto';
import { describe, it, expect, beforeEach, afterEach, jest } from '@jest/globals';
import { initDatabase, closeDatabase, getDatabase } from '../database/init.js';
import { getMemoryStats } from '../memory/store.js';
import { consolidate } from '../memory/consolidate.js';
import { shouldTriggerPredictiveConsolidation } from '../worker/predictive-consolidation.js';
import { DEFAULT_WORKER_CONFIG } from '../worker/types.js';
import { BrainWorker } from '../worker/brain-worker.js';

const DAY = 86_400_000;
const sqliteTs = (agoMs: number): string => new Date(Date.now() - agoMs).toISOString().slice(0, 19).replace('T', ' ');

/**
 * STM rows consolidate() will neither promote (salience 0.5 < 0.6) nor
 * decay-delete (just accessed), created two days ago so they are past the
 * one-hour eviction grace.
 */
function seedStm(n: number, opts: { pinned?: boolean } = {}): void {
  const stmt = getDatabase().prepare(`
    INSERT INTO memories (uuid, type, category, title, content, salience, access_count, last_accessed, created_at, pinned)
    VALUES (?, 'short_term', 'note', ?, 'seeded', 0.5, 0, ?, ?, ?)
  `);
  for (let i = 0; i < n; i++) stmt.run(randomUUID(), `stm ${i}`, sqliteTs(0), sqliteTs(2 * DAY + i * 1000), opts.pinned ? 1 : 0);
}

function stmCount(): number {
  return (getDatabase().prepare("SELECT COUNT(*) AS n FROM memories WHERE type = 'short_term'").get() as { n: number }).n;
}

beforeEach(() => {
  initDatabase(':memory:');
});

afterEach(() => {
  jest.restoreAllMocks();
  closeDatabase();
});

describe('#1121 predictive trigger agrees with consolidate() on "over the cap"', () => {
  it('STM exactly at its cap with nothing promotable: no trigger at all', () => {
    seedStm(100);
    const decision = shouldTriggerPredictiveConsolidation(getMemoryStats(), DEFAULT_WORKER_CONFIG);
    expect(decision).toMatchObject({ shouldRun: false });
    // And consolidate() really would change nothing here.
    const result = consolidate();
    expect({ promoted: result.consolidated, deleted: result.deleted, stm: stmCount() }).toEqual({ promoted: 0, deleted: 0, stm: 100 });
  });

  it('STM over its cap still triggers critical, and consolidate evicts down to the cap', () => {
    seedStm(105);
    const decision = shouldTriggerPredictiveConsolidation(getMemoryStats(), DEFAULT_WORKER_CONFIG);
    expect(decision).toMatchObject({ shouldRun: true, urgency: 'critical' });
    expect(decision.reason).toMatch(/STM over its cap \(105\/100\)/);
    const result = consolidate();
    expect(result.evictedShortTerm).toBe(5);
    expect(stmCount()).toBe(100);
  });

  it('near the cap with a promotable row, the critical trigger still fires', () => {
    seedStm(90);
    getDatabase().prepare(`
      INSERT INTO memories (uuid, type, category, title, content, salience, access_count, last_accessed, created_at)
      VALUES (?, 'short_term', 'note', 'worth keeping', 'seeded', 0.9, 5, ?, ?)
    `).run(randomUUID(), sqliteTs(0), sqliteTs(DAY));
    const decision = shouldTriggerPredictiveConsolidation(getMemoryStats(), DEFAULT_WORKER_CONFIG);
    expect(decision).toMatchObject({ shouldRun: true, urgency: 'critical' });
  });
});

describe('#1121 a run that changes nothing is logged at most once an hour', () => {
  it('pinned over-cap STM: one "changed nothing" line across ticks within the hour', async () => {
    // Over the cap, but every row is pinned, so the run cannot evict.
    seedStm(105, { pinned: true });
    const errors: string[] = [];
    jest.spyOn(console, 'error').mockImplementation((...a: unknown[]) => { errors.push(a.map(String).join(' ')); });
    jest.spyOn(console, 'log').mockImplementation(() => {});

    const worker = new BrainWorker({ profile: 'mcp' });
    await worker.lightTick();
    await worker.lightTick();
    await worker.lightTick();

    const noop = errors.filter((l) => /Predictive consolidation .* changed nothing/.test(l));
    expect(noop).toHaveLength(1);
    // The light-tick summary is throttled the same way (round 2): one line,
    // not one per tick.
    const summary = errors.filter((l) => /\[BrainWorker\] Light tick: pruned 0 activations, consolidated 0/.test(l));
    expect(summary).toHaveLength(1);
    expect(errors.some((l) => /Predictive consolidation triggered/.test(l))).toBe(false);
    expect(stmCount()).toBe(105);
  });
});
