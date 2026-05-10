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

  it('generates a unique UUID per insert (no collision on bulk auto-extract)', async () => {
    for (let i = 0; i < 5; i++) {
      await saveAutoExtractedMemory(db, makeMemory({ title: `Memory ${i}` }), 'p');
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
});
