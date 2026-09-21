import fs from 'fs';
import os from 'os';
import path from 'path';
import { fileURLToPath } from 'url';
import { afterEach, beforeEach, describe, expect, it } from '@jest/globals';
import Database from 'better-sqlite3';
import { migrateLegacy } from '../migrate-legacy.js';

/**
 * #510: legacy rows are redacted on the way in. The legacy vector is computed
 * over title + content, so it is dropped only when THAT text changed — never
 * because tags or metadata alone were redacted. Synthetic values only.
 */
describe('#510 legacy migration — embeddings survive tag-only redaction', () => {
  const thisFile = fileURLToPath(import.meta.url);
  const repoRoot = path.resolve(path.dirname(thisFile), '..', '..', '..');
  const schemaPath = path.join(repoRoot, 'src', 'database', 'schema.sql');

  let tempDir: string;
  let sourcePath: string;
  let targetPath: string;

  beforeEach(() => {
    tempDir = fs.mkdtempSync(path.join(os.tmpdir(), 'shieldcortex-migrate-pii-'));
    sourcePath = path.join(tempDir, 'legacy.db');
    targetPath = path.join(tempDir, 'memories.db');

    const target = new Database(targetPath);
    target.exec(fs.readFileSync(schemaPath, 'utf-8'));
    target.close();

    const source = new Database(sourcePath);
    source.exec(`
      CREATE TABLE memories (
        id INTEGER PRIMARY KEY, type TEXT, category TEXT, title TEXT, content TEXT, project TEXT,
        tags TEXT, salience REAL, decayed_score REAL, access_count INTEGER, last_accessed TEXT,
        created_at TEXT, metadata TEXT, embedding BLOB, scope TEXT, transferable INTEGER
      );
      CREATE TABLE memory_links (source_id INTEGER, target_id INTEGER, relationship TEXT, strength REAL, created_at TEXT);
    `);
    const insert = source.prepare(`
      INSERT INTO memories (type, category, title, content, tags, salience, created_at, last_accessed, metadata, embedding, scope, transferable)
      VALUES ('long_term', 'note', ?, ?, ?, 0.5, '2026-01-01T00:00:00Z', '2026-01-01T00:00:00Z', '{}', ?, 'project', 0)
    `);
    insert.run('Payroll contact', 'Ask the payroll team about the starter.', JSON.stringify(['hr', 'NINO QQ123456C']), Buffer.from([1, 2, 3, 4]));
    insert.run('Payroll record', 'Starter has National Insurance QQ123456C.', JSON.stringify(['hr']), Buffer.from([5, 6, 7, 8]));
    insert.run('Deploy note', 'The deploy script lives in scripts/deploy.sh.', JSON.stringify(['ops']), Buffer.from([9, 9, 9, 9]));
    source.close();
  });

  afterEach(() => {
    fs.rmSync(tempDir, { recursive: true, force: true });
  });

  it('drops the vector only when title or content changed', () => {
    const report = migrateLegacy({ sources: [sourcePath], target: targetPath });
    expect(report.sources[0].error).toBeUndefined();
    expect(report.totalMemories).toBe(3);

    const target = new Database(targetPath, { readonly: true });
    const rows = target.prepare('SELECT title, content, tags, embedding, sensitivity_level FROM memories ORDER BY id')
      .all() as Array<{ title: string; content: string; tags: string; embedding: Buffer | null; sensitivity_level: string }>;
    target.close();

    expect(JSON.stringify(rows.map(r => [r.title, r.content, r.tags]))).not.toContain('QQ123456C');
    const [tagOnly, contentRedacted, clean] = rows;

    expect(JSON.parse(tagOnly.tags)).toEqual(['hr', 'NINO [REDACTED:ni-number]']);
    expect(tagOnly.embedding && [...tagOnly.embedding]).toEqual([1, 2, 3, 4]);
    expect(tagOnly.sensitivity_level).toBe('CONFIDENTIAL');

    expect(contentRedacted.content).toContain('[REDACTED:ni-number]');
    expect(contentRedacted.embedding).toBeNull();

    expect(clean.embedding && [...clean.embedding]).toEqual([9, 9, 9, 9]);
    expect(clean.sensitivity_level).toBe('INTERNAL');
  });
});
