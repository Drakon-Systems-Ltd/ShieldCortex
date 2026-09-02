import fs from 'fs';
import os from 'os';
import path from 'path';
import { fileURLToPath } from 'url';
import { afterEach, beforeEach, describe, expect, it } from '@jest/globals';
import Database from 'better-sqlite3';
import { execFileSync } from 'node:child_process';
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

  it('#402: stamps content_form=fact for a hook-captured work fact (injectable via two-key)', async () => {
    await saveAutoExtractedMemory(
      db,
      makeMemory({ title: 'Deploy state note', content: 'The staging deploy shipped v4.28.1 on 2026-08-12.' }),
      'p',
      { source: 'session-end-hook' },
    );
    const row = db.prepare("SELECT content_form FROM memories WHERE title = 'Deploy state note'")
      .get() as { content_form: string | null } | undefined;
    expect(row).toBeDefined();
    // Requires the compiled classifier (dist/defence/form-classifier.js from
    // `npm run build:ts`). Fail-closed to NULL only if dist is missing.
    expect(row!.content_form).toBe('fact');
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

  /**
   * #458: the hook write path never populated `embedding`.
   *
   * `addMemory()` (src/memory/store.ts) schedules an embedding for every row it
   * writes. `scripts/lib/save-memory.mjs` was a second, independent writer whose
   * INSERT simply never mentioned the column — so every `capture_method='auto'`
   * row went in vector-less, and `src/memory/search.ts` (`WHERE embedding IS NOT
   * NULL`) silently excluded it from semantic recall for ever after. Measured on
   * clawdbot1 2026-09-02: 267 auto rows, 0 embedded, all-time.
   *
   * This runs in a REAL SUBPROCESS, deliberately, for two reasons.
   *
   * 1. `scripts/run-jest.mjs` sets `SHIELDCORTEX_SKIP_EMBEDDINGS=1` for the whole
   *    suite. That is why no existing test could have caught this bug, and it is
   *    why an in-process assertion here would be testing the stub, not the fix.
   * 2. A hook is a short-lived process that ends at `process.exit(0)`. The defect
   *    class this guards against is an embedding that is *scheduled* rather than
   *    *awaited* — which passes any in-process test that happens to yield, and
   *    still writes NULL in production. Only a real process that runs the write
   *    and then exits can tell those two apart.
   */
  it('#458: a real hook process persists the embedding before it exits', () => {
    const probe = path.join(tempDir, 'probe.mjs');
    const probeDbPath = path.join(tempDir, 'probe.db');
    fs.writeFileSync(probe, `
      import Database from ${JSON.stringify(path.join(repoRoot, 'node_modules', 'better-sqlite3', 'lib', 'index.js'))};
      import { readFileSync } from 'fs';
      import { saveAutoExtractedMemory } from ${JSON.stringify(path.join(repoRoot, 'scripts', 'lib', 'save-memory.mjs'))};

      const db = new Database(${JSON.stringify(probeDbPath)});
      db.exec(readFileSync(${JSON.stringify(schemaPath)}, 'utf-8'));
      await saveAutoExtractedMemory(
        db,
        {
          title: 'EMB probe',
          content: 'After comparing Prisma and Kysely we decided Drizzle for the SaaS layer.',
          category: 'architecture',
          salience: 0.45,
          tags: ['auto-extracted'],
        },
        'p',
        { source: 'stop-hook' },
      );
      const row = db.prepare('SELECT length(embedding) AS len FROM memories WHERE title = ?').get('EMB probe');
      process.stdout.write(JSON.stringify(row ?? null));
      // Exactly what stop-hook.mjs does — nothing gets a chance to drain here.
      process.exit(0);
    `);

    const env = { ...process.env };
    delete env.SHIELDCORTEX_SKIP_EMBEDDINGS;

    const out = execFileSync(process.execPath, [probe], {
      env,
      timeout: 120_000,
      stdio: ['pipe', 'pipe', 'pipe'],
    }).toString();

    const row = JSON.parse(out) as { len: number | null } | null;
    expect(row).not.toBeNull();
    // 384 float32 dimensions — the all-MiniLM-L6-v2 output width store.ts writes.
    expect(row!.len).toBe(384 * 4);
  }, 180_000);

  /**
   * The suite-wide `SHIELDCORTEX_SKIP_EMBEDDINGS=1` (and any host that has
   * deliberately disabled embeddings) must still get its memory stored. Losing
   * the row because the ONNX worker is unavailable would be strictly worse than
   * losing the vector, so the embed step is best-effort by construction and the
   * backfill is what guarantees eventual coverage.
   */
  it('#458: a disabled embedder still stores the row (best-effort, never fail-closed)', async () => {
    expect(process.env.SHIELDCORTEX_SKIP_EMBEDDINGS).toBe('1');

    await saveAutoExtractedMemory(db, makeMemory({ title: 'NOEMB' }), 'p', { source: 'stop-hook' });

    const row = db.prepare('SELECT title, embedding FROM memories WHERE title = ?')
      .get('NOEMB') as { title: string; embedding: Buffer | null } | undefined;

    expect(row).toBeDefined();
    expect(row!.embedding).toBeNull();
  });
});
