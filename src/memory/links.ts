/**
 * Memory relationships (links).
 *
 * Lifted out of the 2,166-line store.ts so the linking surface can be
 * read, tested, and modified without scrolling past every CRUD/search
 * helper in the memory module. No behaviour change vs the original
 * implementation in store.ts — exports re-emerge from store.ts via
 * a barrel re-export so existing import paths keep working.
 *
 * Imports from store.ts (getMemoryById, rowToMemory) form a module
 * cycle, but both are only invoked inside function bodies — ESM live
 * bindings handle this correctly at runtime.
 */

import { getDatabase } from '../database/init.js';
import { cosineSimilarity } from '../embeddings/index.js';
import type { Memory } from './types.js';
import { jaccardSimilarity } from './similarity.js';
import { escapeFts5Query } from './fts.js';
import { getMemoryById, rowToMemory } from './store.js';

export type RelationshipType = 'references' | 'extends' | 'contradicts' | 'related';

export interface MemoryLink {
  id: number;
  sourceId: number;
  targetId: number;
  relationship: RelationshipType;
  strength: number;
  createdAt: Date;
}

/**
 * Create a link between two memories.
 *
 * Returns null if either memory id doesn't exist, the source equals
 * the target, or the link already exists (UNIQUE constraint).
 */
export function createMemoryLink(
  sourceId: number,
  targetId: number,
  relationship: RelationshipType,
  strength: number = 0.5,
): MemoryLink | null {
  const db = getDatabase();

  const source = getMemoryById(sourceId);
  const target = getMemoryById(targetId);
  if (!source || !target) return null;

  if (sourceId === targetId) return null;

  try {
    const result = db.prepare(`
      INSERT INTO memory_links (source_id, target_id, relationship, strength)
      VALUES (?, ?, ?, ?)
    `).run(sourceId, targetId, relationship, strength);

    return {
      id: result.lastInsertRowid as number,
      sourceId,
      targetId,
      relationship,
      strength,
      createdAt: new Date(),
    };
  } catch {
    return null;
  }
}

/**
 * Get all memories related to a given memory (incoming + outgoing links).
 */
export function getRelatedMemories(memoryId: number): {
  memory: Memory;
  relationship: RelationshipType;
  strength: number;
  direction: 'outgoing' | 'incoming';
}[] {
  const db = getDatabase();

  const outgoing = db.prepare(`
    SELECT m.*, ml.relationship, ml.strength
    FROM memory_links ml
    JOIN memories m ON m.id = ml.target_id
    WHERE ml.source_id = ?
  `).all(memoryId) as (Record<string, unknown> & { relationship: string; strength: number })[];

  const incoming = db.prepare(`
    SELECT m.*, ml.relationship, ml.strength
    FROM memory_links ml
    JOIN memories m ON m.id = ml.source_id
    WHERE ml.target_id = ?
  `).all(memoryId) as (Record<string, unknown> & { relationship: string; strength: number })[];

  const results: {
    memory: Memory;
    relationship: RelationshipType;
    strength: number;
    direction: 'outgoing' | 'incoming';
  }[] = [];

  for (const row of outgoing) {
    results.push({
      memory: rowToMemory(row),
      relationship: row.relationship as RelationshipType,
      strength: row.strength,
      direction: 'outgoing',
    });
  }

  for (const row of incoming) {
    results.push({
      memory: rowToMemory(row),
      relationship: row.relationship as RelationshipType,
      strength: row.strength,
      direction: 'incoming',
    });
  }

  return results;
}

/**
 * Delete a memory link by source/target id pair. Returns true if a row was removed.
 */
export function deleteMemoryLink(sourceId: number, targetId: number): boolean {
  const db = getDatabase();
  const result = db.prepare(`
    DELETE FROM memory_links WHERE source_id = ? AND target_id = ?
  `).run(sourceId, targetId);
  return result.changes > 0;
}

/**
 * Get every memory link in the database, newest first.
 */
export function getAllMemoryLinks(): MemoryLink[] {
  const db = getDatabase();
  const rows = db.prepare('SELECT * FROM memory_links ORDER BY created_at DESC').all() as Record<string, unknown>[];

  return rows.map((row) => ({
    id: row.id as number,
    sourceId: row.source_id as number,
    targetId: row.target_id as number,
    relationship: row.relationship as RelationshipType,
    strength: row.strength as number,
    createdAt: new Date(row.created_at as string),
  }));
}

/**
 * Detect tag-based links for a memory.
 * Finds memories sharing tags and scores by overlap count.
 */
function detectTagLinks(
  db: ReturnType<typeof getDatabase>,
  memory: Memory,
  maxResults: number,
): { targetId: number; relationship: RelationshipType; strength: number }[] {
  const results: { targetId: number; relationship: RelationshipType; strength: number }[] = [];

  if (memory.tags.length > 0) {
    const tagPlaceholders = memory.tags.map(() => '?').join(',');
    const tagMatches = db.prepare(`
      SELECT DISTINCT m.id, m.tags
      FROM memories m, json_each(m.tags)
      WHERE json_each.value IN (${tagPlaceholders})
        AND m.id != ?
      LIMIT ?
    `).all(...memory.tags, memory.id, maxResults) as { id: number; tags: string }[];

    for (const match of tagMatches) {
      const matchTags = JSON.parse(match.tags) as string[];
      const sharedCount = memory.tags.filter((t) => matchTags.includes(t)).length;
      const strength = Math.min(0.9, 0.3 + (sharedCount * 0.2));
      results.push({ targetId: match.id, relationship: 'related', strength });
    }
  }

  return results;
}

/**
 * Detect embedding-based semantic links for a memory.
 * Computes cosine similarity against top memories that have embeddings.
 */
function detectEmbeddingLinks(
  db: ReturnType<typeof getDatabase>,
  memory: Memory,
  maxResults: number,
): { targetId: number; relationship: RelationshipType; strength: number }[] {
  if (!memory.embedding) return [];

  const candidates = db.prepare(`
    SELECT id, embedding FROM memories
    WHERE embedding IS NOT NULL AND id != ?
    ORDER BY decayed_score DESC
    LIMIT 100
  `).all(memory.id) as { id: number; embedding: Buffer }[];

  const results: { targetId: number; relationship: RelationshipType; strength: number }[] = [];
  const sourceEmbedding = new Float32Array(
    memory.embedding.buffer,
    memory.embedding.byteOffset,
    memory.embedding.byteLength / 4,
  );

  for (const candidate of candidates) {
    const candidateEmbedding = new Float32Array(
      candidate.embedding.buffer,
      candidate.embedding.byteOffset,
      candidate.embedding.byteLength / 4,
    );
    const similarity = cosineSimilarity(sourceEmbedding, candidateEmbedding);
    if (similarity >= 0.6) {
      results.push({
        targetId: candidate.id,
        relationship: 'related',
        strength: Math.min(0.9, similarity),
      });
    }
  }

  return results;
}

/**
 * Detect content-based links using FTS5 and Jaccard similarity.
 * Fallback when embeddings are not available.
 */
function detectFtsLinks(
  db: ReturnType<typeof getDatabase>,
  memory: Memory,
  maxResults: number,
): { targetId: number; relationship: RelationshipType; strength: number }[] {
  const queryText = `${memory.title} ${memory.content.slice(0, 200)}`;
  const escapedQuery = escapeFts5Query(queryText);
  if (!escapedQuery.trim()) return [];

  let ftsMatches: { id: number; title: string; content: string }[];
  try {
    ftsMatches = db.prepare(`
      SELECT m.id, m.title, m.content
      FROM memories_fts fts
      JOIN memories m ON m.id = fts.rowid
      WHERE memories_fts MATCH ?
        AND m.id != ?
      LIMIT ?
    `).all(escapedQuery, memory.id, maxResults * 2) as { id: number; title: string; content: string }[];
  } catch {
    return [];
  }

  const results: { targetId: number; relationship: RelationshipType; strength: number }[] = [];
  for (const match of ftsMatches) {
    const matchText = `${match.title} ${match.content.slice(0, 200)}`;
    const sim = jaccardSimilarity(queryText, matchText);
    if (sim >= 0.3) {
      results.push({
        targetId: match.id,
        relationship: 'related',
        strength: Math.min(0.7, sim + 0.2),
      });
    }
  }

  return results;
}

/**
 * Detect potential relationships for a new memory.
 *
 * Three strategies in priority order:
 *   1. Tag-based linking (shared tags)
 *   2. Embedding-based semantic linking (cosine similarity >= 0.6)
 *   3. FTS content similarity fallback (Jaccard similarity >= 0.3)
 *
 * Returns deduped results sorted by strength descending, capped at
 * maxResults.
 */
export function detectRelationships(
  memory: Memory,
  maxResults: number = 5,
): { targetId: number; relationship: RelationshipType; strength: number }[] {
  const db = getDatabase();
  const seen = new Set<number>();
  const results: { targetId: number; relationship: RelationshipType; strength: number }[] = [];

  function addResults(links: { targetId: number; relationship: RelationshipType; strength: number }[]) {
    for (const link of links) {
      if (!seen.has(link.targetId)) {
        seen.add(link.targetId);
        results.push(link);
      }
    }
  }

  addResults(detectTagLinks(db, memory, maxResults));
  addResults(detectEmbeddingLinks(db, memory, maxResults));

  if (!memory.embedding) {
    addResults(detectFtsLinks(db, memory, maxResults));
  }

  return results
    .sort((a, b) => b.strength - a.strength)
    .slice(0, maxResults);
}
