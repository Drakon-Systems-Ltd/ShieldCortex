import { getDatabase } from '../database/init.js';
import { extractFromMemory } from './extract.js';
import { processExtractionResult } from './resolve.js';

export function backfillGraph(): { entities: number; triples: number; memoriesProcessed: number } {
  const db = getDatabase();

  const memories = db.prepare('SELECT id, title, content, category FROM memories ORDER BY id').all() as Array<{
    id: number;
    title: string;
    content: string;
    category: string;
  }>;

  let entitiesBefore = (db.prepare('SELECT COUNT(*) as c FROM entities').get() as { c: number }).c;
  let triplesBefore = (db.prepare('SELECT COUNT(*) as c FROM triples').get() as { c: number }).c;

  let processed = 0;
  for (const mem of memories) {
    try {
      const extraction = extractFromMemory(mem.title, mem.content, mem.category);
      if (extraction.entities.length > 0) {
        processExtractionResult(extraction, mem.id);
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

  return {
    entities: entitiesAfter - entitiesBefore,
    triples: triplesAfter - triplesBefore,
    memoriesProcessed: processed,
  };
}
