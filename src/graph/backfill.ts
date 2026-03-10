import { getDatabase } from '../database/init.js';
import { extractFromMemory } from './extract.js';
import { replaceMemoryGraph } from './resolve.js';

/** Bump this when extract.ts logic changes to force re-extraction */
const EXTRACTION_VERSION = 3;

export interface BackfillResult {
  entities: number;
  triples: number;
  memoriesProcessed: number;
  memoriesSkipped: number;
}

export function backfillGraph(options?: { force?: boolean }): BackfillResult {
  const db = getDatabase();
  const force = options?.force ?? false;

  // Check whether the graph_extraction_version column exists
  let hasVersionColumn = true;
  try {
    const cols = db.prepare('PRAGMA table_info(memories)').all() as { name: string }[];
    hasVersionColumn = cols.some(c => c.name === 'graph_extraction_version');
  } catch {
    hasVersionColumn = false;
  }

  // If no version column or force mode, fall back to processing all memories
  const useIncremental = hasVersionColumn && !force;

  const memories = useIncremental
    ? db.prepare(
        'SELECT id, title, content, category FROM memories WHERE graph_extraction_version < ? ORDER BY id'
      ).all(EXTRACTION_VERSION) as Array<{ id: number; title: string; content: string; category: string }>
    : db.prepare(
        'SELECT id, title, content, category FROM memories ORDER BY id'
      ).all() as Array<{ id: number; title: string; content: string; category: string }>;

  // Count total memories to report how many were skipped
  const totalMemories = (db.prepare('SELECT COUNT(*) as c FROM memories').get() as { c: number }).c;
  const memoriesSkipped = totalMemories - memories.length;

  const entitiesBefore = (db.prepare('SELECT COUNT(*) as c FROM entities').get() as { c: number }).c;
  const triplesBefore = (db.prepare('SELECT COUNT(*) as c FROM triples').get() as { c: number }).c;

  const updateVersion = hasVersionColumn
    ? db.prepare('UPDATE memories SET graph_extraction_version = ? WHERE id = ?')
    : null;

  let processed = 0;
  for (const mem of memories) {
    try {
      const extraction = extractFromMemory(mem.title, mem.content, mem.category);
      replaceMemoryGraph(mem.id, extraction);
      // Mark this memory as extracted at the current version
      if (updateVersion) {
        updateVersion.run(EXTRACTION_VERSION, mem.id);
      }
    } catch (e) {
      console.error(`[backfill] Failed on memory #${mem.id}: ${e}`);
    }
    processed++;
    if (processed % 50 === 0) {
      console.log(`[backfill] Processed ${processed}/${memories.length} memories...`);
    }
  }

  const entitiesAfter = (db.prepare('SELECT COUNT(*) as c FROM entities').get() as { c: number }).c;
  const triplesAfter = (db.prepare('SELECT COUNT(*) as c FROM triples').get() as { c: number }).c;

  console.log(
    `[backfill] Incremental extraction: processed ${processed} new memories, ${memoriesSkipped} already up-to-date`
  );

  return {
    entities: entitiesAfter - entitiesBefore,
    triples: triplesAfter - triplesBefore,
    memoriesProcessed: processed,
    memoriesSkipped,
  };
}
