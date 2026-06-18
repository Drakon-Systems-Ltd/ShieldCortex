import fs from 'fs';
import os from 'os';
import path from 'path';
import { fileURLToPath } from 'url';
import { afterEach, beforeEach, describe, expect, it } from '@jest/globals';
import Database from 'better-sqlite3';
// @ts-expect-error -- importing a .mjs hook util
import { saveAutoExtractedMemory } from '../../scripts/lib/save-memory.mjs';

/**
 * v4.12.4's auto-extract path silently failed every insert with
 * "NOT NULL constraint failed: memories.uuid" because the inline
 * INSERT in pre-compact-hook.mjs was missing the uuid column.
 * Reproduced on TARS 2026-04-25 immediately after the v4.12.4
 * path-encoding fix unblocked the read side.
 *
 * v4.12.5 extracts the writer into `scripts/lib/save-memory.mjs` and
 * generates a UUID before INSERT. This regression test wires up a fresh
 * temp DB against the real schema and asserts the row lands.
 */
describe('saveAutoExtractedMemory — auto-extract write path', () => {
  const thisFile = fileURLToPath(import.meta.url);
  const repoRoot = path.resolve(path.dirname(thisFile), '..', '..');
  const schemaPath = path.join(repoRoot, 'src', 'database', 'schema.sql');

  let tempDir: string;
  let dbPath: string;
  let db: Database.Database;

  beforeEach(() => {
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'shieldcortex-save-memory-'));
    dbPath = path.join(tempDir, 'memories.db');
    db = new Database(dbPath);
    const schema = fs.readFileSync(schemaPath, 'utf-8');
    db.exec(schema);
  });

  afterEach(() => {
    db.close();
    fs.rmSync(tempDir, { recursive: true, force: true });
  });

  function makeMemory(overrides: Partial<Record<string, unknown>> = {}) {
    return {
      title: 'Decision: chose Drizzle for the SaaS schema',
      content: 'After comparing Prisma and Kysely we decided Drizzle for the SaaS layer because…',
      category: 'architecture',
      salience: 0.45,
      tags: ['auto-extracted', 'decision'],
      ...overrides,
    } as { title: string; content: string; category: string; salience: number; tags: string[] };
  }

  it('inserts a memory row (the v4.12.4 NOT NULL uuid bug repro)', async () => {
    await expect(saveAutoExtractedMemory(db, makeMemory(), 'shieldcortex')).resolves.not.toThrow();

    const row = db.prepare('SELECT uuid, title, project, type FROM memories WHERE title = ?')
      .get('Decision: chose Drizzle for the SaaS schema') as { uuid: string; title: string; project: string; type: string };

    expect(row).toBeDefined();
    expect(row.uuid).toMatch(/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/);
    expect(row.project).toBe('shieldcortex');
    expect(row.type).toBe('short_term');
  });

  it('persists the COMPUTED hook trust + sensitivity, not the schema default 1.0', async () => {
    // The busiest write path scanned content but its INSERT omitted
    // trust_score/sensitivity_level, so every hook-captured memory landed at the
    // schema DEFAULT trust 1.0 — silently over-trusting the bulk of the store and
    // undercutting the recall shim's trust filter.
    await saveAutoExtractedMemory(
      db,
      makeMemory({ title: 'Trust persist check', content: 'A benign architecture note about the build pipeline and nothing sensitive.' }),
      'p',
      { source: 'session-end-hook' },
    );
    const row = db.prepare("SELECT trust_score, sensitivity_level FROM memories WHERE title = 'Trust persist check'")
      .get() as { trust_score: number; sensitivity_level: string } | undefined;
    expect(row).toBeDefined();
    expect(row!.trust_score).toBe(0.8); // hook source — NOT the schema DEFAULT 1.0
    expect(['PUBLIC', 'INTERNAL']).toContain(row!.sensitivity_level);
  });

  it('generates a unique UUID per insert (no collision on bulk auto-extract)', async () => {
    // Five genuinely distinct findings (distinct titles AND content) so the
    // T8 near-dup gate doesn't fold them — this test asserts UUID uniqueness
    // across a bulk extract, not dedup behaviour.
    const findings = [
      { title: 'Auth tokens are single-use', content: 'The verify endpoint burns the magic-link token on first use.' },
      { title: 'WAL checkpoint cadence', content: 'SQLite auto-checkpoints the write-ahead log every hundred pages.' },
      { title: 'Dashboard polls every thirty seconds', content: 'WebSocket falls back to polling when the socket drops.' },
      { title: 'Drizzle chosen for the schema', content: 'Comparing Prisma and Kysely, Drizzle won on type ergonomics.' },
      { title: 'British spelling throughout', content: 'Defence, colour, analyse — the product copy stays British.' },
    ];
    for (const f of findings) {
      await saveAutoExtractedMemory(db, makeMemory(f), 'p');
    }
    const uuids = db.prepare('SELECT uuid FROM memories').all() as Array<{ uuid: string }>;
    expect(uuids).toHaveLength(5);
    expect(new Set(uuids.map((r) => r.uuid)).size).toBe(5);
  });

  it('respects the uuid UNIQUE constraint by always producing fresh values', async () => {
    await saveAutoExtractedMemory(db, makeMemory({ title: 'A' }), 'p');
    await saveAutoExtractedMemory(db, makeMemory({ title: 'B' }), 'p');
    const count = (db.prepare('SELECT COUNT(*) AS c FROM memories').get() as { c: number }).c;
    expect(count).toBe(2);
  });

  it('accepts null project (Claude Code session without a scoped project)', async () => {
    await expect(saveAutoExtractedMemory(db, makeMemory(), null)).resolves.not.toThrow();
    const row = db.prepare('SELECT project FROM memories WHERE title = ?')
      .get('Decision: chose Drizzle for the SaaS schema') as { project: string | null };
    expect(row.project).toBeNull();
  });

  it('persists tags as JSON-encoded text (matches existing reader contract)', async () => {
    await saveAutoExtractedMemory(db, makeMemory({ tags: ['decision', 'architecture'] }), 'p');
    const row = db.prepare('SELECT tags FROM memories WHERE title = ?')
      .get('Decision: chose Drizzle for the SaaS schema') as { tags: string };
    expect(JSON.parse(row.tags)).toEqual(['decision', 'architecture']);
  });

  // ===== v4.25.0: taxonomy + source identification =====

  it('v4.25: writes memoryPurpose from the segment (not the schema default)', async () => {
    await saveAutoExtractedMemory(
      db,
      makeMemory({ title: 'P', memoryPurpose: 'feedback' }),
      'p',
      { source: 'pre-compact-hook' },
    );
    const row = db.prepare('SELECT memory_purpose FROM memories WHERE title = ?')
      .get('P') as { memory_purpose: string };
    expect(row.memory_purpose).toBe('feedback');
  });

  it('v4.25: defaults memoryPurpose to "project" when the segment does not set one', async () => {
    await saveAutoExtractedMemory(db, makeMemory({ title: 'D' }), 'p', { source: 'pre-compact-hook' });
    const row = db.prepare('SELECT memory_purpose FROM memories WHERE title = ?')
      .get('D') as { memory_purpose: string };
    expect(row.memory_purpose).toBe('project');
  });

  it('v4.25: stamps source/source_kind/capture_method so hook writes are distinguishable from user writes', async () => {
    await saveAutoExtractedMemory(db, makeMemory({ title: 'S' }), 'p', { source: 'pre-compact-hook' });
    const row = db.prepare('SELECT source, source_kind, capture_method FROM memories WHERE title = ?')
      .get('S') as { source: string; source_kind: string; capture_method: string };
    expect(row.source).toBe('hook:pre-compact-hook');
    expect(row.source_kind).toBe('hook');
    expect(row.capture_method).toBe('auto');
  });

  it('v4.25: session-end-hook and pre-compact-hook are distinguishable via source column', async () => {
    await saveAutoExtractedMemory(db, makeMemory({ title: 'PC' }), 'p', { source: 'pre-compact-hook' });
    await saveAutoExtractedMemory(db, makeMemory({ title: 'SE' }), 'p', { source: 'session-end-hook' });
    const rows = db.prepare('SELECT title, source FROM memories ORDER BY title').all() as Array<{ title: string; source: string }>;
    const sources = Object.fromEntries(rows.map((r) => [r.title, r.source]));
    expect(sources.PC).toBe('hook:pre-compact-hook');
    expect(sources.SE).toBe('hook:session-end-hook');
  });

  it('v4.25: downvote_count + last_downvoted_at columns exist with safe defaults', async () => {
    await saveAutoExtractedMemory(db, makeMemory({ title: 'DV' }), 'p', { source: 'pre-compact-hook' });
    const row = db.prepare('SELECT downvote_count, last_downvoted_at FROM memories WHERE title = ?')
      .get('DV') as { downvote_count: number; last_downvoted_at: string | null };
    expect(row.downvote_count).toBe(0);
    expect(row.last_downvoted_at).toBeNull();
  });
});
