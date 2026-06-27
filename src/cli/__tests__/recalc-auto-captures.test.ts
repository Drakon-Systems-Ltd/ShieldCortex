import fs from 'fs';
import os from 'os';
import path from 'path';
import { randomUUID } from 'crypto';
import { afterEach, beforeEach, describe, expect, it } from '@jest/globals';
import { initDatabase, getDatabase, closeDatabase } from '../../database/init.js';
import { recalcAutoCaptures } from '../migrate-legacy.js';

/**
 * Issue #49 (task 4): a one-off back-catalogue maintenance command that
 *   (a) re-flags auto-captured FRAGMENTS (mid-sentence start / trailing `?`)
 *       into the review queue (status='suppressed') so they can be purged, and
 *   (b) re-scores stale salience>0.6 auto rows older than 7 days under the
 *       current (0.6-capped) rules.
 *
 * It MUST default to dry-run and only mutate with an explicit apply flag, and
 * it must reuse the store/review primitives (no hand-deletes / raw mutation).
 */

interface SeedRow {
  title: string;
  content: string;
  tags: string[];
  salience: number;
  createdAt: string;
  /** Drives the historical flat-clamp migration; defaults to 'auto'. */
  captureMethod?: string;
  status?: string;
}

function seed(dbPath: string, rows: SeedRow[]): number[] {
  initDatabase(dbPath);
  const db = getDatabase();
  const insert = db.prepare(
    `INSERT INTO memories (uuid, type, category, title, content, project, tags, salience, created_at, updated_at, status, source_kind, capture_method)
     VALUES (?, 'long_term', 'note', ?, ?, 'demo', ?, ?, ?, ?, ?, 'hook', ?)`,
  );
  const ids: number[] = [];
  for (const r of rows) {
    const info = insert.run(
      randomUUID(),
      r.title,
      r.content,
      JSON.stringify(r.tags),
      r.salience,
      r.createdAt,
      r.createdAt,
      r.status ?? 'active',
      r.captureMethod ?? 'auto',
    );
    ids.push(Number(info.lastInsertRowid));
  }
  closeDatabase();
  return ids;
}

function readRow(dbPath: string, id: number): { salience: number; status: string } {
  initDatabase(dbPath);
  const row = getDatabase().prepare('SELECT salience, status FROM memories WHERE id = ?').get(id) as {
    salience: number;
    status: string;
  };
  closeDatabase();
  return row;
}

const OLD = '2020-01-01T00:00:00.000Z'; // > 7 days old
const NOW = new Date().toISOString();

describe('recalcAutoCaptures (issue #49 back-catalogue cleanup)', () => {
  let tempDir: string;
  let dbPath: string;
  let fragmentId: number;
  let interrogativeId: number;
  let cleanAutoId: number;
  let staleInflatedId: number;
  let manualInflatedId: number;

  beforeEach(() => {
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'shieldcortex-recalc-'));
    dbPath = path.join(tempDir, 'memories.db');
    [fragmentId, interrogativeId, cleanAutoId, staleInflatedId, manualInflatedId] = seed(dbPath, [
      // auto-captured conjunction-led fragment → should be flagged for purge
      { title: 'Note: and so they sit at null', content: 'and so they sit at project null until reconciliation runs', tags: ['auto-extracted'], salience: 0.6, createdAt: NOW },
      // auto-captured interrogative → flagged
      { title: 'Pref: should we', content: 'should we just buy a brand new development computer?', tags: ['auto-extracted'], salience: 0.6, createdAt: NOW },
      // clean auto fact → never flagged, salience already within cap
      { title: 'Note: deploy key', content: 'the deploy key rotates every ninety days across all environments', tags: ['auto-extracted'], salience: 0.6, createdAt: NOW },
      // stale inflated auto-extracted row (salience 1.0, > 7d) that ESCAPED the
      // historical flat-clamp migration (capture_method outside auto/legacy/plugin)
      // → re-scored DOWN to its true value under the current 0.6-capped rules.
      { title: 'Note: build speed', content: 'the build now runs in under two minutes on the CI runners', tags: ['auto-extracted'], salience: 1.0, createdAt: OLD, captureMethod: 'hook' },
      // manual inflated row (NOT auto-extracted) → untouched
      { title: 'Manual', content: 'the manual note that a human wrote and pinned deliberately here', tags: [], salience: 1.0, createdAt: OLD, captureMethod: 'manual' },
    ]);
  });

  afterEach(() => {
    closeDatabase();
    fs.rmSync(tempDir, { recursive: true, force: true });
  });

  it('dry-run reports planned changes but mutates nothing', async () => {
    const report = await recalcAutoCaptures({ dbPath, apply: false });

    expect(report.apply).toBe(false);
    expect(report.flagged.map((f) => f.id).sort((a, b) => a - b)).toEqual([fragmentId, interrogativeId].sort((a, b) => a - b));
    expect(report.rescored.map((r) => r.id)).toEqual([staleInflatedId]);

    // Nothing changed on disk.
    expect(readRow(dbPath, fragmentId).status).toBe('active');
    expect(readRow(dbPath, interrogativeId).status).toBe('active');
    expect(readRow(dbPath, staleInflatedId).salience).toBe(1.0);
    expect(readRow(dbPath, manualInflatedId).salience).toBe(1.0);
  });

  it('apply flags fragments for purge and re-scores stale inflated auto rows', async () => {
    const report = await recalcAutoCaptures({ dbPath, apply: true });

    expect(report.apply).toBe(true);

    // Fragments are moved into the review queue (suppressed → excluded from
    // recall + eligible for the standard prune purge), not hand-deleted.
    expect(readRow(dbPath, fragmentId).status).toBe('suppressed');
    expect(readRow(dbPath, interrogativeId).status).toBe('suppressed');

    // The clean auto fact is left active and untouched.
    expect(readRow(dbPath, cleanAutoId).status).toBe('active');

    // The stale inflated auto row is re-scored DOWN to the auto cap (<= 0.6).
    const rescored = readRow(dbPath, staleInflatedId);
    expect(rescored.salience).toBeLessThanOrEqual(0.6);
    expect(rescored.salience).toBeLessThan(1.0);
    expect(rescored.status).toBe('active'); // a valid fact, not a fragment

    // The manual (non-auto) inflated row is NEVER touched by this command.
    expect(readRow(dbPath, manualInflatedId).salience).toBe(1.0);
    expect(readRow(dbPath, manualInflatedId).status).toBe('active');
  });

  it('defaults to dry-run when apply is omitted', async () => {
    const report = await recalcAutoCaptures({ dbPath });
    expect(report.apply).toBe(false);
    expect(readRow(dbPath, fragmentId).status).toBe('active');
  });
});
