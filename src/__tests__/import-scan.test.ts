/**
 * Feature #2 — importMemories must route through the defence pipeline.
 *
 * Before: importMemories did a raw INSERT omitting source/trust_score, so the
 * schema defaults (trust 1.0 / 'user:direct') applied with NO scan and NO audit
 * — a single MCP call could plant fully-trusted, unscanned poisoned memories.
 * Now each row goes through addMemory at file:import (trust 0.4 — below the
 * auto-quarantine band so a benign restore succeeds) and the pipeline blocks
 * poisoned rows.
 */

import { describe, it, expect, beforeEach, afterEach } from '@jest/globals';
import { initDatabase, closeDatabase, getDatabase } from '../database/init.js';
import { addMemory } from '../memory/store.js';
import { exportMemories, importMemories } from '../memory/consolidate.js';

describe('importMemories — imported rows are scanned + attributed (Feature #2)', () => {
  beforeEach(() => { initDatabase(':memory:'); });
  afterEach(() => { closeDatabase(); });

  it('routes imports through the scan: file:import / trust 0.4, not user:direct/1.0', () => {
    addMemory({ title: 'A', content: 'benign note one about builds', tags: ['x'] }, undefined, { type: 'user', identifier: 'direct' });
    addMemory({ title: 'B', content: 'benign note two about tests' }, undefined, { type: 'user', identifier: 'direct' });
    const json = exportMemories();

    closeDatabase();
    initDatabase(':memory:');

    const n = importMemories(json);
    expect(n).toBe(2);

    const db = getDatabase();
    const rows = db.prepare('SELECT trust_score, source, tags FROM memories ORDER BY id')
      .all() as Array<{ trust_score: number; source: string; tags: string }>;
    expect(rows).toHaveLength(2);
    for (const r of rows) {
      expect(r.trust_score).toBe(0.4);       // NOT the exported 1.0
      expect(r.source).toBe('file:import');  // NOT 'user:direct'
    }
    // tags survived the JSON-string → array → re-store round trip (order of the
    // two rows isn't guaranteed — created_at ties — so check across both)
    expect(rows.some((r) => (JSON.parse(r.tags) as string[]).includes('x'))).toBe(true);

    const audit = db.prepare(
      "SELECT COUNT(*) AS n FROM defence_audit WHERE source_type = 'file' AND source_identifier = 'import'",
    ).get() as { n: number };
    expect(audit.n).toBeGreaterThanOrEqual(2);
  });

  it('skips a poisoned imported row but imports the clean ones', () => {
    addMemory({ title: 'clean', content: 'totally benign content here' }, undefined, { type: 'user', identifier: 'direct' });
    const rows = JSON.parse(exportMemories()) as Record<string, unknown>[];
    rows.push({
      type: 'long_term',
      category: 'note',
      title: 'leak',
      content: `sandbox key AKIA${'IOSFODNN7EXAMPLE'} secret wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY`,
      project: null,
      tags: '[]',
      salience: 0.5,
      metadata: '{}',
    });

    closeDatabase();
    initDatabase(':memory:');

    const n = importMemories(JSON.stringify(rows));
    expect(n).toBe(1); // only the clean row survived the scan

    const db = getDatabase();
    const count = (db.prepare('SELECT COUNT(*) AS c FROM memories').get() as { c: number }).c;
    expect(count).toBe(1);
  });
});
