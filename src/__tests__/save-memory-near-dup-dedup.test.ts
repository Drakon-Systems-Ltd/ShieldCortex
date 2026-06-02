import fs from 'fs';
import os from 'os';
import path from 'path';
import { fileURLToPath } from 'url';
import { afterEach, beforeEach, describe, expect, it } from '@jest/globals';
import Database from 'better-sqlite3';
// @ts-expect-error -- importing a .mjs hook util
import { saveAutoExtractedMemory } from '../../scripts/lib/save-memory.mjs';
// @ts-expect-error -- importing the pure .mjs dedup helpers
import { jaccardSimilarity, isNearDuplicate } from '../../scripts/lib/dedup.mjs';

/**
 * T8 (P5) — write-path near-dup + cross-path dedup.
 *
 * The hook write path (`insertMemoryRow`) used to dedup ONLY on an exact
 * title match scoped to `source_kind='hook'`. Two gaps EDITH flagged:
 *   (a) near-duplicate titles slip through ("Fix: X" vs "Fix: X (updated)")
 *   (b) a hook re-extraction of something the user ALREADY saved manually
 *       was never caught (the SELECT only looked at prior hook rows).
 *
 * These tests pin the hardened behaviour: cross-path exact-title dedup +
 * a title-gated content-Jaccard near-dup scan that SKIPS the insert.
 */
describe('save-memory near-dup + cross-path dedup (T8)', () => {
  const thisFile = fileURLToPath(import.meta.url);
  const repoRoot = path.resolve(path.dirname(thisFile), '..', '..');
  const schemaPath = path.join(repoRoot, 'src', 'database', 'schema.sql');

  let tempDir: string;
  let dbPath: string;
  let db: Database.Database;

  beforeEach(() => {
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'shieldcortex-near-dup-'));
    dbPath = path.join(tempDir, 'memories.db');
    db = new Database(dbPath);
    const schema = fs.readFileSync(schemaPath, 'utf-8');
    db.exec(schema);
  });

  afterEach(() => {
    db.close();
    fs.rmSync(tempDir, { recursive: true, force: true });
  });

  function count(): number {
    return (db.prepare('SELECT COUNT(*) AS c FROM memories').get() as { c: number }).c;
  }

  function mem(overrides: Record<string, unknown> = {}) {
    return {
      title: 'Decision: chose Drizzle for the SaaS schema',
      content: 'After comparing Prisma and Kysely we decided Drizzle for the SaaS layer.',
      category: 'architecture',
      salience: 0.45,
      tags: ['auto-extracted'],
      ...overrides,
    } as { title: string; content: string; category: string; salience: number; tags: string[] };
  }

  it('1. skips a near-duplicate whose title differs (exact-title misses, near-dup catches)', async () => {
    // Same finding captured twice: the title gains a qualifier word and the
    // content is lightly reworded. Exact-title misses (titles differ), so the
    // near-dup gate is what catches B. (Titles still share >= 0.6 tokens — a
    // fully-reworded title is intentionally out of scope for the write-path
    // pre-gate; consolidate.ts sweeps those every 4h.)
    await saveAutoExtractedMemory(
      db,
      mem({
        title: 'Fix: SQLite concurrent access crash',
        content:
          'Multiple processes accessing the same database caused crashes; fixed with busy_timeout 10000ms and WAL checkpointing.',
        category: 'error',
      }),
      'shieldcortex',
    );
    await saveAutoExtractedMemory(
      db,
      mem({
        title: 'Fix: SQLite concurrent access crash (updated)',
        content:
          'Multiple processes accessing the same database caused crashes; the fix was busy_timeout 10000ms plus WAL checkpointing.',
        category: 'error',
      }),
      'shieldcortex',
    );

    expect(count()).toBe(1);
  });

  it('2. inserts two genuinely distinct memories', async () => {
    await saveAutoExtractedMemory(
      db,
      mem({ title: 'Auth: magic-link tokens are single-use', content: 'Verify endpoint burns the token on first use.', category: 'architecture' }),
      'shieldcortex',
    );
    await saveAutoExtractedMemory(
      db,
      mem({ title: 'Dashboard theme branches at the page level', content: 'Terminal mode is selected per route, not globally.', category: 'preference' }),
      'shieldcortex',
    );

    expect(count()).toBe(2);
  });

  it('3. cross-path: a hook write is deduped against a prior MANUAL (user) row', async () => {
    // A manual row the user saved themselves (raw INSERT, source_kind='user').
    db.prepare(`
      INSERT INTO memories (
        uuid, title, content, type, category, salience, tags, project,
        memory_purpose, source, source_kind, capture_method,
        created_at, last_accessed
      )
      VALUES (?, ?, ?, 'short_term', ?, ?, ?, ?, 'project', 'user', 'user', 'manual', ?, ?)
    `).run(
      '00000000-0000-4000-8000-000000000001',
      'SQLite concurrent access fix',
      'Multiple processes accessing the same database caused crashes. Fixed by adding busy_timeout 10000ms and WAL checkpointing.',
      'error',
      0.6,
      JSON.stringify(['manual']),
      'shieldcortex',
      new Date().toISOString(),
      new Date().toISOString(),
    );

    // A hook re-extraction of the same learning, slightly reworded.
    await saveAutoExtractedMemory(
      db,
      mem({
        title: 'SQLite concurrent access fix confirmed',
        content:
          'Multiple processes accessing the same database caused crashes. Fixed by adding busy_timeout 10000ms plus WAL checkpointing.',
        category: 'error',
      }),
      'shieldcortex',
    );

    // Manual row stays, hook write dropped.
    expect(count()).toBe(1);
  });

  it('4. exact hook re-extraction is still skipped (regression — preserve prior behaviour)', async () => {
    const m = mem({ title: 'Repeated regex match', content: 'The hook surfaces the same match across overlapping windows.' });
    await saveAutoExtractedMemory(db, m, 'shieldcortex');
    await saveAutoExtractedMemory(db, m, 'shieldcortex');

    expect(count()).toBe(1);
  });
});

describe('dedup pure helpers (T8)', () => {
  const A = {
    title: 'Fix: SQLite concurrent access crash',
    content:
      'Multiple processes accessing the same database caused crashes; fixed with busy_timeout 10000ms and WAL checkpointing.',
  };
  const B = {
    title: 'Fix: SQLite concurrent access crash (updated)',
    content:
      'Multiple processes accessing the same database caused crashes; the fix was busy_timeout 10000ms plus WAL checkpointing.',
  };
  const opts = { titleJaccard: 0.6, combinedThreshold: 0.5 };

  it('jaccardSimilarity returns 1.0 for identical content', () => {
    expect(jaccardSimilarity(A.content, A.content)).toBe(1.0);
  });

  it('jaccardSimilarity returns 0 for fully disjoint content', () => {
    expect(jaccardSimilarity('alpha bravo charlie', 'delta echo foxtrot')).toBe(0);
  });

  it('isNearDuplicate flags reworded near-duplicates as duplicate', () => {
    const res = isNearDuplicate(B, A, opts);
    expect(res.duplicate).toBe(true);
    expect(res.combined).toBeGreaterThanOrEqual(0.5);
  });

  it('isNearDuplicate does NOT flag unrelated memories', () => {
    const unrelated = {
      title: 'Dashboard theme branches at the page level',
      content: 'Terminal mode is selected per route, not globally across the app.',
    };
    const res = isNearDuplicate(unrelated, A, opts);
    expect(res.duplicate).toBe(false);
  });

  it('isNearDuplicate treats an identical pair as duplicate with combined 1.0', () => {
    const res = isNearDuplicate(A, A, opts);
    expect(res.duplicate).toBe(true);
    expect(res.combined).toBe(1.0);
  });

  it('title pre-gate: a fully-reworded title is NOT flagged even with similar content (deliberate scope boundary)', () => {
    const reworded = {
      title: 'Database lock contention resolved',
      content: A.content, // identical content, but the title shares no tokens
    };
    const res = isNearDuplicate(reworded, A, opts);
    expect(res.duplicate).toBe(false);
  });

  it('empty-title guard: two un-tokenizable short titles do NOT auto-pass the pre-gate', () => {
    // jaccardSimilarity("A","B") is 1.0 (both tokenize to empty sets); the
    // dedup pre-gate must reject that rather than treat it as a title match.
    const res = isNearDuplicate(
      { title: 'A', content: A.content },
      { title: 'B', content: A.content },
      opts,
    );
    expect(res.duplicate).toBe(false);
    expect(res.titleSim).toBe(0);
  });
});
