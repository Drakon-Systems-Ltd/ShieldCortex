/**
 * Feature #2 — close the `if (source)` write bypass.
 *
 * Before: addMemory ran the defence pipeline only when a DefenceSource was
 * passed; the source-less branch stamped trust 1.0 / INTERNAL with NO scan, so
 * the dashboard POST, importMemories, consolidate and quarantine-approve all
 * wrote fully-trusted, unscanned rows. These tests pin that EVERY write is
 * scanned and an unattributed write lands low-trust (web:unattributed = 0.3,
 * strictly below the 0.5–0.7 auto-quarantine band so it does not throw).
 */

import { describe, it, expect, beforeEach, afterEach } from '@jest/globals';
import { initDatabase, closeDatabase, getDatabase } from '../database/init.js';
import { addMemory, MemoryBlockedError } from '../memory/store.js';

describe('addMemory — source-less writes are scanned + low-trust (Feature #2)', () => {
  beforeEach(() => { initDatabase(':memory:'); });
  afterEach(() => { closeDatabase(); });

  it('scans a source-less write and stamps web:unattributed at trust 0.3 (not user:direct/1.0)', () => {
    const mem = addMemory({ title: 'Build note', content: 'a normal benign note about the dashboard build' });

    const db = getDatabase();
    const row = db.prepare(
      'SELECT trust_score, source, sensitivity_level FROM memories WHERE id = ?',
    ).get(mem.id) as { trust_score: number; source: string; sensitivity_level: string };

    expect(row.trust_score).toBe(0.3);          // NOT the old 1.0
    expect(row.source).toBe('web:unattributed'); // NOT the old 'user:direct'
    // Classified by the pipeline (benign → PUBLIC/INTERNAL), not a blanket stamp.
    expect(['PUBLIC', 'INTERNAL']).toContain(row.sensitivity_level);

    // The pipeline logs an audit row unconditionally on its success path, so a
    // row here proves the scan actually ran for an unattributed write.
    const audit = db.prepare(
      "SELECT COUNT(*) AS n FROM defence_audit WHERE source_type = 'web' AND source_identifier = 'unattributed'",
    ).get() as { n: number };
    expect(audit.n).toBeGreaterThanOrEqual(1);
  });

  it('still BLOCKS a source-less write that leaks a credential (no bypass)', () => {
    // An AWS-key-shaped secret must be caught even with no source attribution.
    const content = 'aws key AKIAIOSFODNN7EXAMPLE secret wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY';
    expect(() => addMemory({ title: 'leak', content })).toThrow(MemoryBlockedError);
  });

  it('leaves attributed writes byte-for-byte unchanged (user:direct stays trust 1.0)', () => {
    const mem = addMemory(
      { title: 'Attributed', content: 'a benign attributed note' },
      undefined,
      { type: 'user', identifier: 'direct' },
    );
    const db = getDatabase();
    const row = db.prepare('SELECT trust_score, source FROM memories WHERE id = ?')
      .get(mem.id) as { trust_score: number; source: string };
    expect(row.trust_score).toBe(1.0);
    expect(row.source).toBe('user:direct');
  });

  it('does NOT push an unattributed write into the 0.5–0.7 auto-quarantine band', () => {
    const mem = addMemory({ title: 'ok', content: 'another benign note' });
    const db = getDatabase();
    const row = db.prepare('SELECT status FROM memories WHERE id = ?')
      .get(mem.id) as { status: string };
    expect(row.status).toBe('active'); // stored, not quarantined / thrown
  });
});
