/**
 * Phase E — production provenance stamping through addMemory (not raw SQL).
 *
 * graph-phase-e-provenance.test.ts already covers processExtractionResult's
 * capping rule directly, but nothing pinned that addMemory itself (the real
 * call site in src/memory/store.ts) actually builds and passes that
 * provenance. Deleting the stamping call there left those tests green.
 *
 * These tests also pin the ShadowMerge margin fix: two UNATTESTED writes at
 * different nominal trust (a `hook` write capped 1.0→0.7, and a low-trust
 * `agent` write at 0.441) collapse to a spread of 0.259 — below the old
 * CONFLICT_TRUST_MARGIN (0.3), so the conflict was silently missed, but at
 * or above the corrected margin (0.2).
 */

import { afterEach, beforeEach, describe, expect, it } from '@jest/globals';
import { closeDatabase, getDatabase, initDatabase } from '../database/init.js';
import { addMemory, updateMemory } from '../memory/store.js';
import { detectRelationConflicts } from '../threat-graph/conflict.js';
import { backfillGraph } from '../graph/backfill.js';

beforeEach(() => initDatabase(':memory:'));
afterEach(() => closeDatabase());

function tripleFor(subjectName: string, objectName: string) {
  return getDatabase()
    .prepare(
      `SELECT t.writer_source, t.writer_trust, t.valid_to
       FROM triples t
       JOIN entities s ON s.id = t.subject_id
       JOIN entities o ON o.id = t.object_id
       WHERE s.name = ? AND o.name = ?`,
    )
    .get(subjectName, objectName) as
    | { writer_source: string | null; writer_trust: number | null; valid_to: string | null }
    | undefined;
}

describe('addMemory — production provenance stamping (Phase E)', () => {
  it('stamps writer_source/writer_trust on the real INSERT path, capped for an unattested claim', () => {
    const mem = addMemory(
      { title: 'Stack note', content: 'React uses TypeScript for the frontend.' },
      undefined,
      { type: 'cli', identifier: 'michael' },
    );
    expect(mem.id).toBeGreaterThan(0);

    const row = tripleFor('React', 'TypeScript');
    expect(row).toBeDefined();
    expect(row!.writer_source).toBe('cli:michael');
    // cli raw trust is 0.9, but addMemory never passes sourceAttested for this
    // call site — an unattested claim cannot mint trust above the 0.7 cap.
    expect(row!.writer_trust).toBe(0.7);
  });

  it('a genuinely attested write keeps its raw (uncapped) trust', () => {
    addMemory(
      { title: 'Stack note', content: 'React uses TypeScript for the frontend.' },
      undefined,
      { type: 'cli', identifier: 'michael' },
      { sourceAttested: true },
    );

    const row = tripleFor('React', 'TypeScript');
    expect(row!.writer_trust).toBe(0.9);
  });

  it('ShadowMerge: a hook write (capped 0.7) and a low-trust agent write (0.441) on the same channel are flagged — margin 0.2, not the old 0.3', () => {
    // Legit CI write: hook raw trust 0.8, unattested → capped to 0.7.
    addMemory(
      { title: 'Stack note A', content: 'React uses TypeScript for the frontend.' },
      undefined,
      { type: 'hook', identifier: 'ci-pipeline' },
    );
    // Poisoned contender: a deeply-nested sub-agent write, raw trust
    // 0.9 * 0.7^2 = 0.441 (below the 0.5 sub-agent quarantine band, so it
    // stores directly) — same channel (React uses *), different object.
    addMemory(
      { title: 'Stack note B', content: 'React uses JavaScript for the frontend.' },
      undefined,
      { type: 'agent', identifier: 'user-spawned>task-1>subtask-2' },
    );

    const legit = tripleFor('React', 'TypeScript');
    const poisoned = tripleFor('React', 'JavaScript');
    expect(legit!.writer_trust).toBe(0.7);
    expect(poisoned!.writer_trust).toBe(0.441);

    const result = detectRelationConflicts();
    expect(result.conflicts).toBe(1);
    expect(result.channels[0]).toMatch(/:uses$/);
  });
});

describe('updateMemory — re-extraction re-stamps provenance from the memory\'s own trust (Phase E)', () => {
  it('stamps the update-time triple with the memory\'s stored source/trust, capped (unattested)', () => {
    const mem = addMemory(
      { title: 'Stack note', content: 'Uses no tools yet.' },
      undefined,
      { type: 'cli', identifier: 'michael' },
    );

    updateMemory(mem.id, { content: 'React uses TypeScript for the frontend.' });

    const row = tripleFor('React', 'TypeScript');
    expect(row).toBeDefined();
    expect(row!.writer_source).toBe('cli:michael');
    // updateProvenance always treats a re-extraction as unattested.
    expect(row!.writer_trust).toBe(0.7);
  });
});

describe('backfillGraph — re-extraction preserves provenance instead of stripping it (Phase E)', () => {
  it('a forced backfill re-stamps writer_source/writer_trust rather than nulling them out', () => {
    const mem = addMemory(
      { title: 'Stack note', content: 'React uses TypeScript for the frontend.' },
      undefined,
      { type: 'cli', identifier: 'michael' },
    );

    const before = tripleFor('React', 'TypeScript');
    expect(before!.writer_source).toBe('cli:michael');
    expect(before!.writer_trust).toBe(0.7);

    backfillGraph({ force: true });

    const after = tripleFor('React', 'TypeScript');
    expect(after!.writer_source).toBe('cli:michael');
    expect(after!.writer_trust).toBe(0.7);
    void mem;
  });

  it('incremental backfill re-processes version-4 rows so stale related_to confidence is corrected to 0.3', () => {
    const mem = addMemory(
      { title: 'Co-occurrence note', content: 'Touched both Docker and Vercel today.' },
      undefined,
      { type: 'cli', identifier: 'michael' },
    );

    const db = getDatabase();
    db.prepare("UPDATE triples SET confidence = 0.8 WHERE source_memory_id = ? AND predicate = 'related_to'").run(mem.id);
    db.prepare('UPDATE memories SET graph_extraction_version = 4 WHERE id = ?').run(mem.id);

    const result = backfillGraph();
    expect(result.memoriesProcessed).toBe(1);

    const row = db
      .prepare("SELECT confidence FROM triples WHERE source_memory_id = ? AND predicate = 'related_to'")
      .get(mem.id) as { confidence: number } | undefined;
    expect(row?.confidence).toBe(0.3);
    const version = db.prepare('SELECT graph_extraction_version FROM memories WHERE id = ?').get(mem.id) as { graph_extraction_version: number };
    expect(version.graph_extraction_version).toBe(5);
  });
});
