/**
 * #406 — consolidation must not compound temporal decay into base salience.
 *
 * Athena repro (v4.54.11): processDecay output was written back to
 * memories.salience, then updateDecayScores recomputed from the already-
 * reduced base → 0.9 → ~0.71 → ~0.56 with no real elapsed-time event.
 */
import { afterEach, beforeEach, describe, expect, it } from '@jest/globals';

describe('#406 consolidation decay invariant', () => {
  beforeEach(async () => {
    const { closeDatabase, initDatabase } = await import('../../database/init.js');
    closeDatabase();
    initDatabase(':memory:');
  });

  afterEach(async () => {
    const { closeDatabase } = await import('../../database/init.js');
    closeDatabase();
  });

  it('calculateDecayedScore never mutates base salience and is pure for fixed inputs', async () => {
    const { calculateDecayedScore } = await import('../decay.js');
    const base = 0.9;
    const lastAccessed = new Date(Date.now() - 48 * 60 * 60 * 1000); // 48h ago
    const memory = {
      id: 1,
      uuid: 'aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa',
      type: 'short_term' as const,
      category: 'general' as const,
      title: 't',
      content: 'c',
      tags: [] as string[],
      salience: base,
      accessCount: 0,
      lastAccessed,
      createdAt: lastAccessed,
      updatedAt: lastAccessed,
      decayedScore: base,
      metadata: {},
      scope: 'project' as const,
      transferable: false,
      status: 'active' as const,
      pinned: false,
      reviewedAt: null,
      reviewedBy: null,
      sourceKind: 'user' as const,
      captureMethod: 'manual' as const,
      trustScore: 0.8,
      sensitivityLevel: 'INTERNAL',
      source: null,
      cloudExcluded: false,
      memoryPurpose: 'durable_fact' as const,
      memoryScope: 'project' as const,
      hostId: null,
      agentId: null,
      captureLayer: null,
    };

    const a = calculateDecayedScore(memory as any);
    const b = calculateDecayedScore(memory as any);
    expect(memory.salience).toBe(base);
    expect(a).toBeCloseTo(b, 10);
    expect(a).toBeLessThan(base); // real time decay applied as a view
  });

  it('updateDecayScores writes decayed_score only — base salience stable across repeats', async () => {
    const { getDatabase } = await import('../../database/init.js');
    const { addMemory, getMemoryById } = await import('../store.js');
    const { updateDecayScores } = await import('../lifecycle.js');

    const m = addMemory({
      title: 'decay base preserve',
      content: 'base salience must not be eaten by temporal view',
      type: 'short_term',
      salience: 0.9,
      project: '406',
    });
    const db = getDatabase();
    // Age the row so decay is material, without changing base salience.
    db.prepare(
      `UPDATE memories SET last_accessed = datetime('now', '-48 hours'), created_at = datetime('now', '-48 hours'), salience = 0.9 WHERE id = ?`,
    ).run(m.id);

    const before = getMemoryById(m.id)!;
    expect(before.salience).toBeCloseTo(0.9, 5);

    const n1 = updateDecayScores();
    const mid = getMemoryById(m.id)!;
    expect(mid.salience).toBeCloseTo(0.9, 5);
    expect(mid.decayedScore).toBeLessThan(0.9);

    const n2 = updateDecayScores();
    const after = getMemoryById(m.id)!;
    expect(after.salience).toBeCloseTo(0.9, 5);
    // Second pass may no-op writes (threshold) but must not drop base or
    // compound the view beyond wall-clock noise.
    expect(Math.abs(after.decayedScore - mid.decayedScore)).toBeLessThan(0.02);
    expect(n1).toBeGreaterThanOrEqual(0);
    expect(n2).toBeGreaterThanOrEqual(0);
  });

  it('repeated consolidate() does not compound base salience (Athena class)', async () => {
    const { getDatabase } = await import('../../database/init.js');
    const { addMemory, getMemoryById } = await import('../store.js');
    const { consolidate } = await import('../consolidate.js');

    const m = addMemory({
      title: 'consolidation compound guard',
      content: 'short-term row used only for decay path; keep below promote thresholds',
      type: 'short_term',
      salience: 0.9,
      project: '406',
    });
    const db = getDatabase();
    db.prepare(
      `UPDATE memories SET
         last_accessed = datetime('now', '-24 hours'),
         created_at = datetime('now', '-24 hours'),
         access_count = 0,
         salience = 0.9
       WHERE id = ?`,
    ).run(m.id);

    const s0 = getMemoryById(m.id)!.salience;
    expect(s0).toBeCloseTo(0.9, 5);

    consolidate();
    const after1 = getMemoryById(m.id);
    if (!after1) {
      // Deleted by aggressive decay/expiry — nothing left to compound.
      return;
    }
    expect(after1.salience).toBeCloseTo(0.9, 5);
    const d1 = after1.decayedScore;

    consolidate();
    const after2 = getMemoryById(m.id);
    if (!after2) return;
    expect(after2.salience).toBeCloseTo(0.9, 5);
    // Decayed view may tick with wall clock, but must NOT half again from a
    // reduced base the way the pre-#406 bug did (~0.9→0.71→0.56).
    expect(after2.decayedScore).toBeGreaterThan(d1 * 0.85);
    expect(Math.abs(after2.decayedScore - d1)).toBeLessThan(0.15);
  });

  it('processDecay updated map is a decayed_score view, not a new base', async () => {
    const { processDecay, calculateDecayedScore } = await import('../decay.js');
    const lastAccessed = new Date(Date.now() - 12 * 60 * 60 * 1000);
    const memory = {
      id: 7,
      uuid: 'bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb',
      type: 'short_term' as const,
      category: 'general' as const,
      title: 't',
      content: 'c',
      tags: [] as string[],
      salience: 0.9,
      accessCount: 0,
      lastAccessed,
      createdAt: lastAccessed,
      updatedAt: lastAccessed,
      decayedScore: 0.9,
      metadata: {},
      scope: 'project' as const,
      transferable: false,
      status: 'active' as const,
      pinned: false,
      reviewedAt: null,
      reviewedBy: null,
      sourceKind: 'user' as const,
      captureMethod: 'manual' as const,
      trustScore: 0.8,
      sensitivityLevel: 'INTERNAL',
      source: null,
      cloudExcluded: false,
      memoryPurpose: 'durable_fact' as const,
      memoryScope: 'project' as const,
      hostId: null,
      agentId: null,
      captureLayer: null,
    } as any;

    const { updated } = processDecay([memory]);
    const view = updated.get(7)!;
    expect(view).toBeCloseTo(calculateDecayedScore(memory), 10);
    expect(memory.salience).toBe(0.9);
    expect(view).toBeLessThan(0.9);
  });
});
