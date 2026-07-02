import fs from 'fs';
import os from 'os';
import path from 'path';
import crypto from 'crypto';
import { afterEach, beforeEach, describe, expect, it, jest } from '@jest/globals';
import Database from 'better-sqlite3';

import { fixProjectKeyCollisions, scanProjectKeyCollisions } from '../cli/doctor.js';

/**
 * `shieldcortex doctor --fix-project-keys` — the auto-heal path for the
 * legacy/canonical project-key collision warning (#42 residue). The fix
 * applies only unambiguous mappings (exactly one canonical candidate per
 * legacy key), includes STM rows when the collision has them, and leaves
 * ambiguous collisions untouched for a human --map decision.
 */
describe('doctor --fix-project-keys', () => {
  let tempDir: string;
  let dbPath: string;

  function seed(rows: Array<{ type: string; project: string }>) {
    const db = new Database(dbPath);
    db.exec(`
      CREATE TABLE memories (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        uuid TEXT,
        type TEXT,
        category TEXT,
        title TEXT,
        content TEXT,
        project TEXT,
        salience REAL
      );
    `);
    const insert = db.prepare(
      `INSERT INTO memories (uuid, type, category, title, content, project, salience)
       VALUES (?, ?, 'note', 't', 'c', ?, 0.5)`
    );
    for (const row of rows) {
      insert.run(crypto.randomUUID(), row.type, row.project);
    }
    db.close();
  }

  function projectCounts(): Record<string, number> {
    const db = new Database(dbPath, { readonly: true });
    const rows = db
      .prepare('SELECT project, COUNT(*) AS n FROM memories GROUP BY project')
      .all() as Array<{ project: string; n: number }>;
    db.close();
    return Object.fromEntries(rows.map((r) => [r.project, r.n]));
  }

  beforeEach(() => {
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'shieldcortex-doctor-fix-'));
    dbPath = path.join(tempDir, 'memories.db');
    jest.spyOn(console, 'log').mockImplementation(() => {});
  });

  afterEach(() => {
    fs.rmSync(tempDir, { recursive: true, force: true });
    jest.restoreAllMocks();
  });

  it('scan reports single-candidate collisions and STM need', () => {
    seed([
      { type: 'long_term', project: 'workspace' },
      { type: 'short_term', project: 'workspace' },
      { type: 'long_term', project: 'edith-vitaetpax-edith-workspace' },
    ]);
    const scan = scanProjectKeyCollisions(dbPath);
    expect(scan.collisions).toHaveLength(1);
    expect(scan.collisions[0]).toMatchObject({
      legacy: 'workspace',
      canonical: 'edith-vitaetpax-edith-workspace',
      candidates: ['edith-vitaetpax-edith-workspace'],
    });
    expect(scan.needsStm).toBe(true);
  });

  it('fix remaps unambiguous collisions including STM rows and reports zero remaining', async () => {
    seed([
      { type: 'long_term', project: 'workspace' },
      { type: 'long_term', project: 'workspace' },
      { type: 'short_term', project: 'workspace' },
      { type: 'long_term', project: 'edith-vitaetpax-edith-workspace' },
    ]);
    const result = await fixProjectKeyCollisions({ dbPath });
    expect(result.applied).toBe(3);
    expect(result.skippedAmbiguous).toBe(0);
    expect(result.remaining).toBe(0);
    expect(result.backupPath && fs.existsSync(result.backupPath)).toBe(true);

    const counts = projectCounts();
    expect(counts.workspace).toBeUndefined();
    expect(counts['edith-vitaetpax-edith-workspace']).toBe(4);
  });

  it('fix skips ambiguous collisions (two canonical candidates) untouched', async () => {
    seed([
      { type: 'long_term', project: 'workspace' },
      { type: 'long_term', project: 'alpha-workspace' },
      { type: 'long_term', project: 'beta-workspace' },
    ]);
    const result = await fixProjectKeyCollisions({ dbPath });
    expect(result.applied).toBe(0);
    expect(result.skippedAmbiguous).toBe(1);
    expect(result.remaining).toBe(1);
    expect(projectCounts().workspace).toBe(1);
  });

  it('fix is a no-op when there are no collisions', async () => {
    seed([{ type: 'long_term', project: 'acme-myrepo' }]);
    const result = await fixProjectKeyCollisions({ dbPath });
    expect(result.applied).toBe(0);
    expect(result.skippedAmbiguous).toBe(0);
    expect(result.remaining).toBe(0);
  });
});
