import fs from 'fs';
import path from 'path';
import { fileURLToPath } from 'url';
import Database from 'better-sqlite3';
import { describe, expect, it } from '@jest/globals';
import { getInlineSchema } from '../inline-schema.js';

/**
 * inline-schema.ts promises in its header to stay in sync with schema.sql,
 * but nothing enforced it: by v4.47.13 the inline copy was missing the
 * defence_verdict column AND the trg_memories_provenance trigger, so bundled
 * deployments created fresh DBs without provenance enforcement (found while
 * chasing the 21 Jul 2026 doctor false-green incident).
 *
 * This test applies both sources to throwaway in-memory DBs and diffs the
 * resulting objects. Comments, whitespace, and formatting may differ freely —
 * the materialised schema may not.
 */

const schemaSqlPath = path.join(
  path.dirname(fileURLToPath(import.meta.url)),
  '..',
  'schema.sql',
);

interface Materialised {
  tables: Record<string, string[]>;
  triggers: string[];
  indexes: string[];
}

function materialise(sql: string): Materialised {
  const db = new Database(':memory:');
  try {
    db.exec(sql);
    const tables: Record<string, string[]> = {};
    const tableRows = db
      .prepare("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")
      .all() as Array<{ name: string }>;
    for (const { name } of tableRows) {
      tables[name] = (db.pragma(`table_info(${name})`) as Array<{ name: string }>).map(
        (c) => c.name,
      );
    }
    const names = (type: string) =>
      (db.prepare(`SELECT name FROM sqlite_master WHERE type=? AND name NOT LIKE 'sqlite_%'`)
        .all(type) as Array<{ name: string }>)
        .map((r) => r.name)
        .sort();
    return { tables, triggers: names('trigger'), indexes: names('index') };
  } finally {
    db.close();
  }
}

describe('inline schema stays in sync with schema.sql', () => {
  const fromFile = materialise(fs.readFileSync(schemaSqlPath, 'utf-8'));
  const fromInline = materialise(getInlineSchema());

  it('creates the same set of tables', () => {
    expect(Object.keys(fromInline.tables).sort()).toEqual(Object.keys(fromFile.tables).sort());
  });

  it('creates identical column sets for every table', () => {
    for (const [table, columns] of Object.entries(fromFile.tables)) {
      expect({ table, columns: (fromInline.tables[table] ?? []).sort() }).toEqual({
        table,
        columns: [...columns].sort(),
      });
    }
  });

  it('creates the same triggers', () => {
    expect(fromInline.triggers).toEqual(fromFile.triggers);
  });

  it('creates the same indexes', () => {
    expect(fromInline.indexes).toEqual(fromFile.indexes);
  });
});
