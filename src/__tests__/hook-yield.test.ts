import { describe, it, expect, beforeEach, afterEach } from '@jest/globals';
import Database from 'better-sqlite3';
import path from 'path';
import os from 'os';
import fs from 'fs';
import { getHookYield } from '../memory/metrics.js';

/**
 * Phase 0 slices 3+4: turn the existing hook_invocations telemetry into a YIELD
 * instrument — fires vs memories-extracted per hook. Quantifies the imbalance
 * EDITH flagged ("pre-compact fired once vs 270 stop-fires") and, once the
 * recall hook also records an invocation, the cumulative recall-injected count
 * ("is the store actually being read into prompts?"). Pure read aggregation —
 * no schema change, no hot-path write here.
 */
describe('getHookYield — fires vs extracted per hook', () => {
  let db: InstanceType<typeof Database>;
  let dbPath: string;

  beforeEach(() => {
    dbPath = path.join(os.tmpdir(), `sc-hookyield-${Date.now()}-${Math.random().toString(36).slice(2)}.db`);
    db = new Database(dbPath);
    db.exec(`CREATE TABLE hook_invocations (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      hook_name TEXT NOT NULL,
      invoked_at TEXT NOT NULL,
      memories_extracted INTEGER DEFAULT 0
    );`);
  });
  afterEach(() => { db.close(); try { fs.unlinkSync(dbPath); } catch { /* ignore */ } });

  function fire(hook: string, extracted: number, n = 1): void {
    const stmt = db.prepare('INSERT INTO hook_invocations (hook_name, invoked_at, memories_extracted) VALUES (?, ?, ?)');
    for (let i = 0; i < n; i++) stmt.run(hook, '2026-06-14T00:00:00.000Z', extracted);
  }

  it('aggregates fires and extracted per hook', () => {
    fire('stop', 1, 270);       // fires a lot, low yield each
    fire('pre-compact', 2, 1);  // fires rarely, the valuable one
    fire('session-end', 3, 5);
    const y = getHookYield(db);
    const stop = y.hooks.find((h) => h.hook === 'stop')!;
    const pre = y.hooks.find((h) => h.hook === 'pre-compact')!;
    expect(stop.fires).toBe(270);
    expect(stop.extracted).toBe(270);
    expect(pre.fires).toBe(1);
    expect(pre.extracted).toBe(2);
    expect(y.totalFires).toBe(276);        // 270 + 1 + 5
    expect(y.totalExtracted).toBe(287);    // 270*1 + 1*2 + 5*3
  });

  it('reports the recall hook as the "is the store read" signal (prompt-recall injections)', () => {
    fire('prompt-recall', 3, 4); // 4 recall events, 3 injected each = 12 injected
    const y = getHookYield(db);
    const recall = y.hooks.find((h) => h.hook === 'prompt-recall')!;
    expect(recall.fires).toBe(4);
    expect(recall.extracted).toBe(12);
  });

  it('orders hooks by fire count descending and computes avg per fire', () => {
    fire('stop', 1, 10);
    fire('pre-compact', 4, 2);
    const y = getHookYield(db);
    expect(y.hooks[0].hook).toBe('stop'); // 10 fires > 2 fires
    expect(y.hooks.find((h) => h.hook === 'pre-compact')!.avgPerFire).toBe(4);
  });

  it('tolerates an empty telemetry table', () => {
    const y = getHookYield(db);
    expect(y.hooks).toEqual([]);
    expect(y.totalFires).toBe(0);
    expect(y.totalExtracted).toBe(0);
  });
});
