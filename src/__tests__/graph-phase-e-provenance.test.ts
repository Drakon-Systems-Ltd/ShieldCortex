/**
 * Phase E — triple write-time provenance (threat-graph design doc,
 * "Policing the memory graph").
 *
 * Every persisted triple records who wrote it and how much they were trusted,
 * so the conflict detector can reason about relation-channel disputes:
 *  - `confidence`    — from the extraction rule (verb 0.8 / co-occurrence 0.3)
 *  - `writer_source` — the canonical source tuple of the memory write
 *  - `writer_trust`  — trust at write time, **stored already-capped**: raw when
 *                      the source was attested, else min(raw, 0.7)
 *  - `valid_from`    — when the assertion became live
 *  - `valid_to`      — NULL (open); set only by an operator resolution
 *  - `disputed`      — 0 until the projector flags a conflict
 *
 * Backfilled triples (no write-time provenance) leave writer_* NULL but still
 * carry a rule-derived confidence.
 */

import { afterEach, beforeEach, describe, expect, it } from '@jest/globals';
import { closeDatabase, getDatabase, initDatabase } from '../database/init.js';
import { processExtractionResult } from '../graph/resolve.js';
import type { ExtractionResult } from '../graph/extract.js';

beforeEach(() => initDatabase(':memory:'));
afterEach(() => closeDatabase());

function seedMemory(): number {
  const db = getDatabase();
  const r = db.prepare(
    `INSERT INTO memories (uuid, type, category, title, content, project)
     VALUES (?, 'long_term', 'note', 'Stack', 'React uses TypeScript', 'test')`,
  ).run('mem-e-prov-1');
  return Number(r.lastInsertRowid);
}

const RESULT: ExtractionResult = {
  entities: [
    { name: 'React', type: 'tool' },
    { name: 'TypeScript', type: 'language' },
  ],
  triples: [{ subject: 'React', predicate: 'uses', object: 'TypeScript', confidence: 0.8 }],
};

function tripleRow() {
  return getDatabase()
    .prepare(
      `SELECT t.predicate, t.confidence, t.writer_source, t.writer_trust,
              t.valid_from, t.valid_to, t.disputed
       FROM triples t JOIN entities s ON s.id = t.subject_id
       WHERE s.name = 'React'`,
    )
    .get() as
    | {
        predicate: string;
        confidence: number;
        writer_source: string | null;
        writer_trust: number | null;
        valid_from: string | null;
        valid_to: string | null;
        disputed: number;
      }
    | undefined;
}

describe('Phase E — triples provenance schema', () => {
  it('the provenance columns exist on triples', () => {
    const cols = (getDatabase().prepare('PRAGMA table_info(triples)').all() as Array<{ name: string }>)
      .map((c) => c.name);
    expect(cols).toEqual(
      expect.arrayContaining(['valid_from', 'valid_to', 'writer_source', 'writer_trust', 'disputed']),
    );
  });
});

describe('Phase E — provenance stamping on write', () => {
  it('stamps confidence, writer_source, capped writer_trust and valid_from', () => {
    const memId = seedMemory();
    processExtractionResult(RESULT, memId, {
      writerSource: 'agent:jarvis',
      writerTrust: 0.9,
      attested: false,
    });

    const row = tripleRow();
    expect(row).toBeDefined();
    expect(row!.confidence).toBe(0.8);
    expect(row!.writer_source).toBe('agent:jarvis');
    // Not attested → capped at 0.7 (a claimed identity cannot mint high trust).
    expect(row!.writer_trust).toBe(0.7);
    expect(row!.valid_from).toBeTruthy();
    expect(row!.valid_to).toBeNull();
    expect(row!.disputed).toBe(0);
  });

  it('an attested writer keeps its raw trust (no cap)', () => {
    const memId = seedMemory();
    processExtractionResult(RESULT, memId, {
      writerSource: 'cli:michael',
      writerTrust: 0.95,
      attested: true,
    });

    const row = tripleRow();
    expect(row!.writer_trust).toBe(0.95);
    expect(row!.writer_source).toBe('cli:michael');
  });

  it('without provenance (backfill), writer_* are NULL but confidence still set', () => {
    const memId = seedMemory();
    processExtractionResult(RESULT, memId);

    const row = tripleRow();
    expect(row!.confidence).toBe(0.8);
    expect(row!.writer_source).toBeNull();
    expect(row!.writer_trust).toBeNull();
    // valid_from still stamped so temporal queries always have a lower bound.
    expect(row!.valid_from).toBeTruthy();
  });
});
