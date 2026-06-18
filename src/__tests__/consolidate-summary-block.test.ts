/**
 * Feature #2 regression fix — a consolidation auto-summary whose content trips
 * the defence pipeline (now that every write is scanned) must NOT roll back the
 * whole 4-hourly consolidation. clusterAndSummarise must skip-and-continue like
 * importMemories, not let one flagged summary abort the transaction.
 */

import { describe, it, expect, beforeEach, afterEach } from '@jest/globals';
import { initDatabase, closeDatabase, getDatabase } from '../database/init.js';
import { clusterAndSummarise } from '../memory/consolidate.js';

describe('clusterAndSummarise — blocking summary does not abort consolidation', () => {
  beforeEach(() => { initDatabase(':memory:'); });
  afterEach(() => { closeDatabase(); });

  it('skips a summary whose content hard-blocks, without throwing', () => {
    const db = getDatabase();
    // Raw-insert a cluster (same category+tags) where one TITLE carries an AWS
    // key — simulating a legacy/raw row. The summary bullet-lists titles, so the
    // summary content would hard-block at addMemory; that must be caught.
    const insert = db.prepare(
      `INSERT INTO memories (uuid, type, category, title, content, tags, salience, trust_score, sensitivity_level, status)
       VALUES (?, 'long_term', 'error', ?, ?, '["bug"]', 0.8, 1.0, 'INTERNAL', 'active')`,
    );
    insert.run('u1', 'AWS key AKIAIOSFODNN7EXAMPLE wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY in logs', 'one');
    insert.run('u2', 'Another error note', 'two');

    expect(() => clusterAndSummarise({ minClusterSize: 2 })).not.toThrow();
    // The blocked cluster's summary was skipped, not stored.
    const summaries = db.prepare("SELECT COUNT(*) AS n FROM memories WHERE title LIKE 'Summary:%'").get() as { n: number };
    expect(summaries.n).toBe(0);
  });

  it('still creates a summary for a benign cluster', () => {
    const db = getDatabase();
    const insert = db.prepare(
      `INSERT INTO memories (uuid, type, category, title, content, tags, salience, trust_score, sensitivity_level, status)
       VALUES (?, 'long_term', 'note', ?, ?, '["deploy"]', 0.8, 1.0, 'INTERNAL', 'active')`,
    );
    insert.run('b1', 'Deploy step one of the runbook', 'one');
    insert.run('b2', 'Deploy step two of the runbook', 'two');

    const result = clusterAndSummarise({ minClusterSize: 2 });
    expect(result.summariesCreated).toBeGreaterThanOrEqual(1);
  });
});
