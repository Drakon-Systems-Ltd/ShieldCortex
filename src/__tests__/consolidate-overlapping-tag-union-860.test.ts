import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it } from '@jest/globals';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

let database: typeof import('../database/init.js');
let store: typeof import('../memory/store.js');
let consolidation: typeof import('../memory/consolidate.js');
let home: string;
const originalHome = process.env.HOME;

beforeAll(async () => {
  home = mkdtempSync(join(tmpdir(), 'consolidate-tags-860-'));
  process.env.HOME = home;
  database = await import('../database/init.js');
  store = await import('../memory/store.js');
  consolidation = await import('../memory/consolidate.js');
});

beforeEach(() => {
  database.closeDatabase();
  database.initDatabase(':memory:');
});

afterEach(() => database.closeDatabase());
afterAll(() => {
  if (originalHome === undefined) delete process.env.HOME;
  else process.env.HOME = originalHome;
  rmSync(home, { recursive: true, force: true });
});

const title = 'Garden irrigation timer schedule';
const content = 'The garden irrigation timer waters the vegetable beds every morning before sunrise for twenty minutes.';
const tags = ['alpha', 'bravo', 'charlie'];

function seed(saliences: number[]): number[] {
  const now = Date.now();
  return saliences.map((salience, index) => {
    const memory = store.addMemory({
      title, content, category: 'note', project: 'tag-union-860',
      type: 'long_term', salience, tags: [tags[index], 'shared'],
    });
    // Make pair order and recency deterministic without changing the ranking.
    database.getDatabase().prepare(
      'UPDATE memories SET created_at = ?, last_accessed = ? WHERE id = ?',
    ).run(new Date(now - (3 - index) * 1000).toISOString(), new Date(now).toISOString(), memory.id);
    return memory.id;
  });
}

function expectSurvivor(ids: number[], winner: number): void {
  const rows = database.getDatabase().prepare('SELECT id, tags, content FROM memories').all() as {
    id: number; tags: string; content: string;
  }[];
  expect(rows.map(row => row.id)).toEqual([ids[winner]]);
  expect(rows[0].content).toBe(content);
  expect(JSON.parse(rows[0].tags).sort()).toEqual([...tags.slice(0, ids.length), 'shared'].sort());
}

describe.each(['dream', 'deduplicate'] as const)('%s overlapping tag union (#860)', mode => {
  function run(): number {
    return mode === 'dream'
      ? consolidation.consolidateMemories().nearDuplicatesMerged
      : consolidation.deduplicateMemories().merged;
  }

  it.each([
    { label: 'keeps A across both overlapping pairs', saliences: [0.9, 0.3, 0.2], winner: 0 },
    { label: 'keeps B across both overlapping pairs', saliences: [0.3, 0.9, 0.2], winner: 1 },
    { label: 'passes accumulated loser tags to C', saliences: [0.5, 0.3, 0.9], winner: 2 },
    { label: 'keeps the older A on equal salience', saliences: [0.5, 0.5, 0.5], winner: 0 },
  ])('$label without losing any deleted copy tag', ({ saliences, winner }) => {
    const ids = seed(saliences);
    expect(consolidation.findDuplicateMemoryPairs().map(pair => [pair.memoryA.id, pair.memoryB.id]))
      .toEqual([[ids[0], ids[1]], [ids[0], ids[2]], [ids[1], ids[2]]]);
    expect(run()).toBe(2);
    expectSurvivor(ids, winner);
  });

  it('still unions tags for one simple pair', () => {
    const ids = seed([0.9, 0.3]);
    expect(run()).toBe(1);
    expectSurvivor(ids, 0);
  });
});

it('deduplicate dry-run leaves stored tags and duplicate rows untouched', () => {
  seed([0.9, 0.3, 0.2]);
  const db = database.getDatabase();
  const before = db.prepare('SELECT * FROM memories ORDER BY id').all();
  expect(consolidation.deduplicateMemories({ dryRun: true }).merged).toBe(2);
  expect(db.prepare('SELECT * FROM memories ORDER BY id').all()).toEqual(before);
});
