/**
 * #458 — the repair and the detector.
 *
 * Fixing `scripts/lib/save-memory.mjs` stops new rows landing without a vector;
 * it does nothing for the ones already written, and before this change nothing
 * in the codebase so much as looked for `embedding IS NULL`. These two pieces
 * are what turn "fixed going forward" into "fixed", and what makes the same
 * failure loud rather than silent if it ever returns.
 */
import fs from 'fs';
import os from 'os';
import path from 'path';
import { fileURLToPath } from 'url';
import { afterEach, beforeEach, describe, expect, it } from '@jest/globals';
import Database from 'better-sqlite3';
import { backfillEmbeddings } from '../cli/embed-backfill.js';
import { runSemanticCoverageCheck } from '../cli/doctor.js';

const thisFile = fileURLToPath(import.meta.url);
const repoRoot = path.resolve(path.dirname(thisFile), '..', '..');
const schemaPath = path.join(repoRoot, 'src', 'database', 'schema.sql');

/** A deterministic stand-in for the ONNX embedder: same width, no worker. */
function fakeEmbedder(): (text: string) => Promise<Float32Array> {
  return async (text: string) => {
    const v = new Float32Array(384);
    for (let i = 0; i < v.length; i++) v[i] = ((text.charCodeAt(i % text.length) || 1) % 17) / 17;
    return v;
  };
}

describe('#458 embed-backfill + semantic coverage', () => {
  let tempDir: string;
  let dbPath: string;
  let db: Database.Database;

  beforeEach(() => {
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'shieldcortex-458-'));
    dbPath = path.join(tempDir, 'memories.db');
    db = new Database(dbPath);
    db.exec(fs.readFileSync(schemaPath, 'utf-8'));
  });

  afterEach(() => {
    db.close();
    fs.rmSync(tempDir, { recursive: true, force: true });
  });

  function seed(count: number, opts: { embedded?: boolean; project?: string } = {}): void {
    const insert = db.prepare(
      `INSERT INTO memories (uuid, title, content, type, category, salience, tags, project, embedding)
       VALUES (?, ?, ?, 'short_term', 'note', 0.5, '[]', ?, ?)`,
    );
    for (let i = 0; i < count; i++) {
      insert.run(
        `uuid-${opts.project ?? 'p'}-${opts.embedded ? 'e' : 'n'}-${i}`,
        `Title ${i}`,
        `Content body number ${i}`,
        opts.project ?? 'p',
        opts.embedded ? Buffer.from(new Float32Array(384).buffer) : null,
      );
    }
  }

  describe('backfillEmbeddings', () => {
    it('reports without writing by default (dry run)', async () => {
      seed(5);

      const result = await backfillEmbeddings({ db, embed: fakeEmbedder() });

      expect(result.dryRun).toBe(true);
      expect(result.missing).toBe(5);
      expect(result.total).toBe(5);
      expect(result.embedded).toBe(0);

      const stillNull = (db.prepare('SELECT COUNT(*) AS n FROM memories WHERE embedding IS NULL').get() as { n: number }).n;
      expect(stillNull).toBe(5);
    });

    it('fills every missing vector under --execute and leaves existing ones alone', async () => {
      seed(3, { embedded: true });
      seed(4);

      const result = await backfillEmbeddings({ db, execute: true, embed: fakeEmbedder() });

      expect(result.embedded).toBe(4);
      expect(result.failed).toBe(0);

      const rows = db.prepare('SELECT length(embedding) AS len FROM memories').all() as Array<{ len: number | null }>;
      expect(rows).toHaveLength(7);
      expect(rows.every((r) => r.len === 384 * 4)).toBe(true);
    });

    it('a single un-embeddable row does not abandon the rest', async () => {
      seed(4);
      let calls = 0;
      const flaky = async (text: string): Promise<Float32Array> => {
        calls += 1;
        if (calls === 2) throw new Error('worker exploded');
        return fakeEmbedder()(text);
      };

      const result = await backfillEmbeddings({ db, execute: true, embed: flaky });

      expect(result.embedded).toBe(3);
      expect(result.failed).toBe(1);
    });

    it('honours --limit and --project', async () => {
      seed(3, { project: 'alpha' });
      seed(3, { project: 'beta' });

      const result = await backfillEmbeddings({ db, execute: true, project: 'alpha', limit: 2, embed: fakeEmbedder() });

      expect(result.embedded).toBe(2);
      const betaNull = (db.prepare("SELECT COUNT(*) AS n FROM memories WHERE project = 'beta' AND embedding IS NULL").get() as { n: number }).n;
      expect(betaNull).toBe(3);
    });
  });

  describe('runSemanticCoverageCheck', () => {
    it('warns, with the ratio, when a tenth or more of the store has no vector', () => {
      // The shape this host was actually in: 88% invisible while every other
      // check passed.
      seed(40, { embedded: true });
      seed(302);

      const result = runSemanticCoverageCheck(dbPath);

      expect(result.status).toBe('warn');
      expect(result.message).toContain('40/342');
      expect(result.message).toContain('88%');
      expect(result.fix).toContain('embed-backfill');
    });

    it('passes once the store is fully embedded', () => {
      seed(10, { embedded: true });

      const result = runSemanticCoverageCheck(dbPath);

      expect(result.status).toBe('pass');
      expect(result.message).toContain('10/10');
    });

    it('tolerates the odd row the best-effort hook embed skipped', () => {
      seed(99, { embedded: true });
      seed(1);

      expect(runSemanticCoverageCheck(dbPath).status).toBe('pass');
    });

    it('passes on an empty store rather than reporting 0% of nothing', () => {
      expect(runSemanticCoverageCheck(dbPath).status).toBe('pass');
    });
  });
});
