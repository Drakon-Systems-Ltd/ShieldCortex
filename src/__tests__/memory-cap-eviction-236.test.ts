import { randomUUID } from 'node:crypto';
import { describe, it, expect, beforeEach, afterEach } from '@jest/globals';
import { initDatabase, closeDatabase, getDatabase } from '../database/init.js';
import { addMemory, getMemoryById } from '../memory/store.js';
import { enforceMemoryLimits } from '../memory/consolidate.js';
import { DEFAULT_CONFIG } from '../memory/types.js';

/**
 * Issue #236 — once `long_term` reaches its cap, `enforceMemoryLimits()`
 * deleted the memory that was JUST INSERTED, milliseconds after `remember`
 * returned success with its ID.
 *
 * Mechanism: eviction ordered by raw `salience ASC`, but long-term salience is
 * a forward-only ratchet — the decay pass is fed short-term rows only — so a
 * mature store sits at a solid wall of 1.0 (field data: 1000 of 1000 rows).
 * A new write lands below the wall (importance:"high" → 0.8), making it the
 * unique global minimum: always the victim. Field numbers over 16 days:
 * 169 of 171 sub-1.0 new writes deleted within 2s of insert; every write at
 * exactly 1.0 survived. The memories most worth keeping were exactly the ones
 * being dropped, with a success response for every one.
 *
 * The fix has two independent legs, both pinned here:
 *   1. GRACE WINDOW (state-independent): a row created within the last hour is
 *      never an eviction victim, whatever the salience distribution says. A
 *      cap breach during the window is temporary overshoot, not data loss.
 *   2. EFFECTIVE-SALIENCE RANKING: past the window, victims are chosen by the
 *      shared computeEffectiveSalience (recency × access × pin × downvotes) —
 *      the same signal recall ranks by — instead of a saturated raw salience.
 *      Eviction and recall now agree about what is valuable.
 * Plus pin parity with prune.ts: pinned rows are never cap-evicted.
 */

// Small cap so the wall is cheap to build; enforceMemoryLimits takes a config.
const CAP = 10;
const cfg = { ...DEFAULT_CONFIG, maxLongTermMemories: CAP, maxShortTermMemories: CAP };

/** SQLite CURRENT_TIMESTAMP format ('YYYY-MM-DD HH:MM:SS'), offset into the past. */
function sqliteTs(agoMs: number): string {
  return new Date(Date.now() - agoMs).toISOString().slice(0, 19).replace('T', ' ');
}
const DAYS = 86_400_000;

interface SeedRow {
  salience?: number;
  createdAgoMs?: number;
  accessedAgoMs?: number;
  accessCount?: number;
  pinned?: boolean;
  type?: 'short_term' | 'long_term';
  title?: string;
}

/** Direct seed (defaults satisfy the WS3 provenance trigger). Returns row id. */
function seed(row: SeedRow): number {
  const db = getDatabase();
  const r = db.prepare(`
    INSERT INTO memories (uuid, type, category, title, content, salience, access_count, last_accessed, created_at)
    VALUES (?, ?, 'note', ?, ?, ?, ?, ?, ?)
  `).run(
    randomUUID(),
    row.type ?? 'long_term',
    row.title ?? 'wall row',
    'seeded content for cap-eviction tests',
    row.salience ?? 1.0,
    row.accessCount ?? 0,
    sqliteTs(row.accessedAgoMs ?? 30 * DAYS),
    sqliteTs(row.createdAgoMs ?? 60 * DAYS),
  );
  return Number(r.lastInsertRowid);
}

/** The field state: a full store whose every row sits at salience 1.0. */
function buildWall(n: number = CAP): number[] {
  return Array.from({ length: n }, (_, i) =>
    seed({ salience: 1.0, createdAgoMs: (60 + i) * DAYS, accessedAgoMs: (20 + i) * DAYS, accessCount: 3 })
  );
}

describe('#236 — a brand-new memory must survive cap enforcement', () => {
  beforeEach(() => {
    initDatabase(':memory:');
  });

  afterEach(() => {
    closeDatabase();
  });

  it('the reported repro: at cap, a fresh high-importance write is NOT the victim', () => {
    buildWall();
    // The real path: remember → addMemory. importance:"high" ⇒ salience 0.8 —
    // below the wall, i.e. the exact shape that was 100% fatal in the field.
    const fresh = addMemory({
      title: 'probe',
      content: 'the memory most worth keeping, per the field data',
      category: 'note',
      type: 'long_term',
      salience: 0.8,
    } as never, cfg);

    const deleted = enforceMemoryLimits(cfg);

    expect(deleted).toBe(1); // cap is still enforced…
    expect(getMemoryById(fresh.id)).not.toBeNull(); // …but never against the newborn
  });

  it('remember success stays true: the returned ID resolves after enforcement', () => {
    buildWall();
    const fresh = addMemory({
      title: 'durable', content: 'an ID handed back must keep meaning something',
      category: 'note', type: 'long_term', salience: 0.6,
    } as never, cfg);
    enforceMemoryLimits(cfg);
    // The field failure: ✓ Remembered → get_memory: "not found" ~5ms later.
    expect(getMemoryById(fresh.id)?.title).toBe('durable');
  });

  it('grace window is state-independent: even a global-minimum newborn survives', () => {
    // Adversarial wall: every row accessed JUST NOW with real access counts, so
    // effective-salience ranking alone would still sort the newborn (0.3) last.
    // Only the grace window saves it — this is the leg that must not regress.
    for (let i = 0; i < CAP; i++) {
      seed({ salience: 1.0, createdAgoMs: 60 * DAYS, accessedAgoMs: 0, accessCount: 10 });
    }
    const fresh = seed({ salience: 0.3, createdAgoMs: 0, accessedAgoMs: 0, title: 'newborn minimum' });

    const deleted = enforceMemoryLimits(cfg);

    expect(deleted).toBe(1);
    expect(getMemoryById(fresh)).not.toBeNull();
  });

  it('past the window, the stalest row loses — not the most recently useful', () => {
    // Same raw salience everywhere; only recency/access differ. Eviction must
    // agree with recall about value: the 90-days-stale row dies first.
    const stale = seed({ salience: 1.0, createdAgoMs: 100 * DAYS, accessedAgoMs: 90 * DAYS, accessCount: 0, title: 'stale' });
    for (let i = 0; i < CAP; i++) {
      seed({ salience: 1.0, createdAgoMs: 100 * DAYS, accessedAgoMs: 1 * DAYS, accessCount: 5 });
    }
    const deleted = enforceMemoryLimits(cfg);

    expect(deleted).toBe(1);
    expect(getMemoryById(stale)).toBeNull();
  });

  it('never evicts a pinned row (parity with prune.ts)', () => {
    // The pinned row is deliberately the WORST candidate by every other signal.
    const pinned = seed({ salience: 1.0, createdAgoMs: 200 * DAYS, accessedAgoMs: 180 * DAYS, accessCount: 0, pinned: true, title: 'pinned keepsake' });
    getDatabase().prepare('UPDATE memories SET pinned = 1 WHERE id = ?').run(pinned);
    const expendable = seed({ salience: 1.0, createdAgoMs: 150 * DAYS, accessedAgoMs: 100 * DAYS, accessCount: 0, title: 'expendable' });
    for (let i = 0; i < CAP; i++) {
      seed({ salience: 1.0, createdAgoMs: 100 * DAYS, accessedAgoMs: 1 * DAYS, accessCount: 5 });
    }

    enforceMemoryLimits(cfg);

    expect(getMemoryById(pinned)).not.toBeNull();
    expect(getMemoryById(expendable)).toBeNull();
  });

  it('short_term eviction gets the same newborn protection', () => {
    for (let i = 0; i < CAP; i++) {
      seed({ type: 'short_term', salience: 0.9, createdAgoMs: 10 * DAYS, accessedAgoMs: 5 * DAYS });
    }
    const fresh = seed({ type: 'short_term', salience: 0.25, createdAgoMs: 0, accessedAgoMs: 0, title: 'st newborn' });

    const deleted = enforceMemoryLimits(cfg);

    expect(deleted).toBe(1);
    expect(getMemoryById(fresh)).not.toBeNull();
  });

  it('an all-newborn overflow overshoots the cap instead of eating itself', () => {
    // Pathological burst: cap+3 rows all inside the grace window. Nothing is
    // evictable yet — the store must overshoot temporarily rather than destroy
    // writes it just accepted. (The wall ages out of the window within the
    // hour and the next enforcement pass reclaims the overshoot.)
    for (let i = 0; i < CAP + 3; i++) {
      seed({ salience: 0.5, createdAgoMs: 0, accessedAgoMs: 0 });
    }
    const deleted = enforceMemoryLimits(cfg);
    expect(deleted).toBe(0);
    const count = (getDatabase().prepare("SELECT COUNT(*) AS n FROM memories WHERE type='long_term'").get() as { n: number }).n;
    expect(count).toBe(CAP + 3);
  });
});
