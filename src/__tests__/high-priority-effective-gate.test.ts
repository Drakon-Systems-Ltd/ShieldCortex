import { describe, it, expect, beforeEach, afterEach } from '@jest/globals';
import path from 'path';
import os from 'os';
import fs from 'fs';
import { initDatabase, closeDatabase, getDatabase } from '../database/init.js';
import { addMemory, getHighPriorityMemories } from '../memory/store.js';

/**
 * Phase 1b: getHighPriorityMemories was the real raw-salience gap — it gated on
 * `salience >= 0.6` AND ordered by raw salience with NO effective re-rank, so a
 * ratchet-saturated stale row (raw 1.0, but old / decayed) ranked top of the
 * MCP recall no-query path. Repoint to COALESCE(decayed_score, salience): a
 * stale-saturated row falls out of the gate, a fresh one stays, and ordering
 * follows the decaying score. (decayed_score is maintained in MCP/API contexts
 * where this runs; NULL falls back to raw salience, so never-scored rows are
 * unaffected.)
 */
describe('getHighPriorityMemories — gate + order on effective (decayed) salience', () => {
  let dbPath: string;

  beforeEach(() => {
    dbPath = path.join(os.tmpdir(), `sc-hpm-${Date.now()}-${Math.random().toString(36).slice(2)}.db`);
    initDatabase(dbPath);
  });
  afterEach(() => { closeDatabase(); try { fs.unlinkSync(dbPath); } catch { /* ignore */ } });

  /** Seed a memory and force exact salience + decayed_score. */
  function seed(title: string, salience: number, decayed: number | null): number {
    const m = addMemory({ title, content: `${title} — a benign self-contained note about the deploy pipeline.`, type: 'long_term', project: 'p' });
    getDatabase().prepare('UPDATE memories SET salience = ?, decayed_score = ? WHERE id = ?').run(salience, decayed, m.id);
    return m.id;
  }

  it('excludes a stale-saturated row (raw 1.0, decayed 0.30) and keeps a fresh 0.65', () => {
    const stale = seed('stale-saturated', 1.0, 0.30);
    const fresh = seed('fresh-relevant', 0.70, 0.65);
    const ids = getHighPriorityMemories(50, 'p').map((m) => m.id);
    expect(ids).toContain(fresh);
    expect(ids).not.toContain(stale);
  });

  it('falls back to raw salience when decayed_score is NULL (never scored)', () => {
    const unscored = seed('never-scored', 1.0, null);
    expect(getHighPriorityMemories(50, 'p').map((m) => m.id)).toContain(unscored);
  });

  it('orders by decayed score, not raw salience (lower-raw but higher-effective wins)', () => {
    const highRaw = seed('high-raw-low-eff', 1.0, 0.62);
    const lowRaw = seed('low-raw-high-eff', 0.70, 0.95);
    const ordered = getHighPriorityMemories(50, 'p').map((m) => m.id);
    expect(ordered.indexOf(lowRaw)).toBeLessThan(ordered.indexOf(highRaw));
  });
});
