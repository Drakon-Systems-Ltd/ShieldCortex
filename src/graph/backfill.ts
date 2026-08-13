import { getDatabase } from '../database/init.js';
import { extractFromMemory } from './extract.js';
import { replaceMemoryGraph, type TripleProvenance } from './resolve.js';

/**
 * Bump this when extract.ts logic changes to force re-extraction. 5: the
 * related_to co-occurrence confidence dropped 0.8 -> 0.3 (Phase E) and this
 * version was never bumped when that landed, so already-backfilled databases
 * kept the stale 0.8 confidence on every related_to triple indefinitely.
 */
const EXTRACTION_VERSION = 5;

/**
 * A re-extracted triple always carries the memory's OWN stored source/trust,
 * treated as unattested — a backfill re-scan runs unattributed, mirroring
 * updateProvenance() in memory/store.ts. Returns undefined (NULL provenance)
 * when the memory has no recorded source.
 */
function backfillProvenance(mem: { source: string | null; trust_score: number | null }): TripleProvenance | undefined {
  if (!mem.source) return undefined;
  return { writerSource: mem.source, writerTrust: mem.trust_score ?? 1, attested: false };
}

export interface BackfillResult {
  entities: number;
  triples: number;
  memoriesProcessed: number;
  memoriesSkipped: number;
}

export function backfillGraph(options?: { force?: boolean }): BackfillResult {
  const db = getDatabase();
  const force = options?.force ?? false;

  // Heal for v1.13.0–v2.9.x databases: the pre-STOPWORDS extractor persisted
  // 'project' → prefers/avoids/implements triples. Later extractors could
  // neither recreate nor reach them (the per-memory replace never touches
  // triples whose source memory is gone), so they linger indefinitely without
  // this. These predicates were only ever emitted with the 'project' subject.
  // Idempotent: no-ops on healthy databases.
  db.prepare("DELETE FROM triples WHERE predicate IN ('prefers', 'avoids', 'implements')").run();
  db.prepare(`
    DELETE FROM entities WHERE name = 'project'
      AND NOT EXISTS (SELECT 1 FROM memory_entities me WHERE me.entity_id = entities.id)
      AND NOT EXISTS (SELECT 1 FROM triples t WHERE t.subject_id = entities.id OR t.object_id = entities.id)
  `).run();

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

  type BackfillMemoryRow = { id: number; title: string; content: string; category: string; source: string | null; trust_score: number | null };
  const memories = useIncremental
    ? db.prepare(
        'SELECT id, title, content, category, source, trust_score FROM memories WHERE graph_extraction_version < ? ORDER BY id'
      ).all(EXTRACTION_VERSION) as BackfillMemoryRow[]
    : db.prepare(
        'SELECT id, title, content, category, source, trust_score FROM memories ORDER BY id'
      ).all() as BackfillMemoryRow[];

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
      replaceMemoryGraph(mem.id, extraction, backfillProvenance(mem));
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
