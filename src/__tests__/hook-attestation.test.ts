import fs from 'fs';
import os from 'os';
import path from 'path';
import { fileURLToPath } from 'url';
import { afterEach, beforeEach, describe, expect, it, jest } from '@jest/globals';
import Database from 'better-sqlite3';
// @ts-expect-error -- importing a .mjs hook util
import { saveAutoExtractedMemory } from '../../scripts/lib/save-memory.mjs';
// @ts-expect-error -- importing a .mjs hook util
import { emitRecallAudit } from '../../scripts/lib/recall-defence.mjs';

/**
 * Phase 2 of the attestation gap: the .mjs hook plane.
 *
 * On a real install the TOP audit source is hook:session-end-hook (5,973 rows)
 * — every one source_attested NULL, so the biggest single writer never accrues.
 * The hook identity is a string literal in package-shipped hook code, which is
 * attested by construction — but ONLY behind an allowlist clamp, because
 * saveAutoExtractedMemory is an importable shipped module whose opts.source is
 * otherwise a free string that would mint attested rows under any name.
 *
 * Polarity rule (the Phase 1 mute-lever lesson): out-of-allowlist sources get
 * undefined → NULL, NEVER false → 0. An explicit 0 under a real key is the
 * mute lever risk.ts's latest-non-null resolution hands to whoever writes it.
 */
describe('hook plane attestation', () => {
  const thisFile = fileURLToPath(import.meta.url);
  const repoRoot = path.resolve(path.dirname(thisFile), '..', '..');
  const schemaPath = path.join(repoRoot, 'src', 'database', 'schema.sql');

  let tempDir: string;

  beforeEach(() => {
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'shieldcortex-hook-attest-'));
  });

  afterEach(() => {
    fs.rmSync(tempDir, { recursive: true, force: true });
  });

  function freshDb(name: string): Database.Database {
    const db = new Database(path.join(tempDir, name));
    db.exec(fs.readFileSync(schemaPath, 'utf-8'));
    return db;
  }

  it('a known hook source writes an ATTESTED audit row', async () => {
    const db = freshDb('known.db');
    try {
      await saveAutoExtractedMemory(db, {
        title: 'Decision: chose Drizzle for the SaaS schema',
        content: 'After comparing Prisma and Kysely we decided Drizzle for the SaaS layer.',
        category: 'architecture',
        salience: 0.45,
        tags: ['auto-extracted'],
      }, 'shieldcortex', { source: 'session-end-hook' });

      const row = db.prepare(
        "SELECT source_attested FROM defence_audit WHERE source_identifier = 'session-end-hook' ORDER BY id DESC LIMIT 1",
      ).get() as { source_attested: number | null } | undefined;
      expect(row?.source_attested).toBe(1);
    } finally {
      db.close();
    }
  });

  it('every shipped hook identifier is allowlisted (session-end, pre-compact, stop, default)', async () => {
    for (const source of ['session-end-hook', 'pre-compact-hook', 'stop-hook', undefined]) {
      const db = freshDb(`each-${source ?? 'default'}.db`);
      try {
        await saveAutoExtractedMemory(db, {
          title: `Decision: fact for ${source ?? 'default'}`,
          content: 'A perfectly benign auto-extracted engineering fact for the allowlist sweep.',
          category: 'learning',
          salience: 0.4,
          tags: ['auto-extracted'],
        }, 'shieldcortex', source === undefined ? {} : { source });

        const row = db.prepare(
          'SELECT source_identifier, source_attested FROM defence_audit ORDER BY id DESC LIMIT 1',
        ).get() as { source_identifier: string; source_attested: number | null } | undefined;
        expect(row?.source_identifier).toBe(source ?? 'hook');
        expect(row?.source_attested).toBe(1);
      } finally {
        db.close();
      }
    }
  });

  it('an out-of-allowlist opts.source lands NULL — never 0, never 1', async () => {
    // saveAutoExtractedMemory ships in the package and is importable by any
    // same-user process; a free opts.source must not mint attested rows under
    // an arbitrary name (→ not 1), and must not write an explicit 0 that could
    // mute a real key via latest-non-null (→ not 0). NULL only.
    const db = freshDb('rogue.db');
    try {
      await saveAutoExtractedMemory(db, {
        title: 'Decision: rogue importer fact',
        content: 'Content written through the shipped module by an arbitrary importer.',
        category: 'learning',
        salience: 0.4,
        tags: ['auto-extracted'],
      }, 'shieldcortex', { source: 'victim-hook-name' });

      const row = db.prepare(
        "SELECT source_attested, firewall_result FROM defence_audit WHERE source_identifier = 'victim-hook-name' ORDER BY id DESC LIMIT 1",
      ).get() as { source_attested: number | null; firewall_result: string } | undefined;
      // firewall_result ALLOW + a stored memories row prove the REAL pipeline
      // ran — the writeFallbackAudit path (dist missing / pipeline throw) also
      // writes a NULL row, but as a BLOCK with nothing stored, so without
      // these two assertions this test passes vacuously off the fallback.
      expect(row).toMatchObject({ firewall_result: 'ALLOW', source_attested: null });
      const stored = db.prepare(
        "SELECT COUNT(*) AS c FROM memories WHERE source = 'hook:victim-hook-name'",
      ).get() as { c: number };
      expect(stored.c).toBe(1);
    } finally {
      db.close();
    }
  });

  it('the fallback audit rows stay NULL deliberately (source pin)', () => {
    // writeFallbackAudit fires when the pipeline could not run (dist missing /
    // pipeline throw) — self-inflicted states that must not accrue full-weight
    // risk against the hook's own identity. Its INSERT must NOT include
    // source_attested (schema default NULL). Textual pin on the shipped .mjs.
    const src = fs.readFileSync(path.join(repoRoot, 'scripts', 'lib', 'save-memory.mjs'), 'utf-8');
    const fnStart = src.indexOf('function writeFallbackAudit');
    expect(fnStart).toBeGreaterThan(-1);
    const fnBody = src.slice(fnStart, src.indexOf('\n}', fnStart));
    // The INSERT itself must not carry the column (comments may discuss it).
    const insertStart = fnBody.indexOf('INSERT INTO defence_audit');
    expect(insertStart).toBeGreaterThan(-1);
    const insertStmt = fnBody.slice(insertStart, fnBody.indexOf(').run(', insertStart));
    expect(insertStmt).not.toContain('source_attested');
    // And the deliberate-NULL decision is documented where the next editor
    // will see it, so it isn't "fixed" into an accruing row later.
    expect(fnBody).toMatch(/DELIBERATELY absent/);
  });

  it('emitRecallAudit stamps attested=1 (hook:recall-defence is a code literal)', () => {
    const captured: Array<Record<string, unknown>> = [];
    const fakeLogAudit = jest.fn((entry: Record<string, unknown>) => {
      captured.push(entry);
      return 1;
    });
    emitRecallAudit(fakeLogAudit, {
      memoryId: 7,
      action: 'withheld',
      layer: 'trust',
      reason: 'below floor',
      project: 'shieldcortex',
    });
    expect(captured).toHaveLength(1);
    expect(captured[0]).toMatchObject({
      source_type: 'hook',
      source_identifier: 'recall-defence',
      source_attested: 1,
    });
  });
});
