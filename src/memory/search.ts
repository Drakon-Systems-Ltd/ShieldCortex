import type Database from 'better-sqlite3';
import { cosineSimilarity } from '../embeddings/index.js';
import { Memory, MemoryCategory, MemoryConfig, SearchResult } from './types.js';

export interface SearchExecutionOptions {
  enableSideEffects: boolean;
  includeExplanation: boolean;
}

export interface SearchScoringContext {
  db: Database.Database;
  config: MemoryConfig;
  detectedCategory: MemoryCategory | null;
  queryTags: string[];
  vectorResults: Map<number, number>;
  query: string;
}

export interface SearchScoreValues {
  ftsScore: number;
  vectorSimilarity: number;
  vectorBoost: number;
  decayedScore: number;
  priorityBoost: number;
  recencyBoost: number;
  categoryBoost: number;
  linkBoost: number;
  tagBoost: number;
  activationBoost: number;
  finalScore: number;
}

export type MemoryRowConverter = (row: Record<string, unknown>) => Memory;

export function detectQueryCategory(query: string): MemoryCategory | null {
  const lower = query.toLowerCase();

  if (/architect|design|structure|pattern|system|schema|model/.test(lower)) {
    return 'architecture';
  }
  if (/error|bug|fix|issue|crash|exception|fail|problem/.test(lower)) {
    return 'error';
  }
  if (/prefer|always|never|style|convention|like|want/.test(lower)) {
    return 'preference';
  }
  if (/learn|discover|realiz|found\s+out|turns?\s+out/.test(lower)) {
    return 'learning';
  }
  if (/todo|task|pending|need\s+to|should\s+do/.test(lower)) {
    return 'todo';
  }
  if (/relation|depend|connect|link|reference/.test(lower)) {
    return 'relationship';
  }

  return null;
}

export function calculateLinkBoost(memoryId: number, db: Database.Database): number {
  try {
    const linked = db.prepare(`
      SELECT m.salience, ml.strength
      FROM memory_links ml
      JOIN memories m ON (m.id = ml.target_id OR m.id = ml.source_id)
      WHERE (ml.source_id = ? OR ml.target_id = ?)
        AND m.id != ?
    `).all(memoryId, memoryId, memoryId) as { salience: number; strength: number }[];

    if (linked.length === 0) return 0;

    const totalWeight = linked.reduce((sum, link) => sum + link.strength, 0);
    if (totalWeight === 0) return 0;

    const weightedSalience = linked.reduce(
      (sum, link) => sum + link.salience * link.strength,
      0,
    ) / totalWeight;

    return Math.min(0.15, weightedSalience * 0.2);
  } catch {
    return 0;
  }
}

export function calculateTagScore(queryTags: string[], memoryTags: string[]): number {
  if (queryTags.length === 0 || memoryTags.length === 0) return 0;

  let matches = 0;
  for (const queryTag of queryTags) {
    const lowerQueryTag = queryTag.toLowerCase();
    if (memoryTags.some((memoryTag) => {
      const lowerMemoryTag = memoryTag.toLowerCase();
      return lowerMemoryTag.includes(lowerQueryTag) || lowerQueryTag.includes(lowerMemoryTag);
    })) {
      matches++;
    }
  }

  return (matches / queryTags.length) * 0.1;
}

export function extractQueryTags(query: string): string[] {
  const words = query.toLowerCase().split(/\s+/);
  return words.filter((word) =>
    word.length > 2 &&
    /^[a-z][a-z0-9-]*$/.test(word) &&
    !['the', 'and', 'for', 'with', 'how', 'what', 'when', 'where', 'why'].includes(word),
  );
}

export function vectorSearch(
  db: Database.Database,
  rowToMemory: MemoryRowConverter,
  queryEmbedding: Float32Array,
  limit: number,
  project?: string,
  includeGlobal: boolean = true,
): Array<{ memory: Memory; similarity: number }> {
  let query = `
    SELECT * FROM memories
    WHERE embedding IS NOT NULL
  `;
  const params: unknown[] = [];

  if (project && includeGlobal) {
    query += ` AND (project = ? OR scope = 'global')`;
    params.push(project);
  } else if (project) {
    query += ` AND project = ?`;
    params.push(project);
  }

  const rows = db.prepare(query).all(...params) as Record<string, unknown>[];

  return rows
    .map((row) => {
      const embeddingBuffer = row.embedding as Buffer;
      const embedding = new Float32Array(
        embeddingBuffer.buffer,
        embeddingBuffer.byteOffset,
        embeddingBuffer.length / 4,
      );
      return {
        memory: rowToMemory(row),
        similarity: cosineSimilarity(queryEmbedding, embedding),
      };
    })
    .filter((result) => result.similarity > 0.3)
    .sort((a, b) => b.similarity - a.similarity)
    .slice(0, limit);
}

export function buildSearchExplanation(
  memory: Memory,
  context: SearchScoringContext,
  values: SearchScoreValues,
): SearchResult['explanation'] {
  const matchedTags = context.queryTags.filter((queryTag) =>
    memory.tags.some((memoryTag) => {
      const lowerMemoryTag = memoryTag.toLowerCase();
      return lowerMemoryTag.includes(queryTag) || queryTag.includes(lowerMemoryTag);
    }),
  );

  const reasons: string[] = [];
  if (values.vectorSimilarity > 0) {
    reasons.push(`Semantic similarity ${(values.vectorSimilarity * 100).toFixed(0)}%`);
  }
  if (values.ftsScore > 0.3) {
    reasons.push('Strong keyword match');
  }
  if (values.categoryBoost > 0 && context.detectedCategory) {
    reasons.push(`Matches ${context.detectedCategory} category intent`);
  }
  if (matchedTags.length > 0) {
    reasons.push(`Shared tags: ${matchedTags.slice(0, 3).join(', ')}`);
  }
  if (values.recencyBoost > 0) {
    reasons.push('Recently accessed');
  }
  if (values.linkBoost > 0) {
    reasons.push('Connected to related memories');
  }
  if (values.activationBoost > 0) {
    reasons.push('Activated by recent recall activity');
  }
  if (reasons.length === 0) {
    reasons.push('Ranked by salience and base recall heuristics');
  }

  return {
    query: context.query,
    reasons,
    breakdown: {
      ftsScore: values.ftsScore,
      vectorSimilarity: values.vectorSimilarity,
      vectorBoost: values.vectorBoost,
      decayedScore: values.decayedScore,
      priorityBoost: values.priorityBoost,
      recencyBoost: values.recencyBoost,
      categoryBoost: values.categoryBoost,
      linkBoost: values.linkBoost,
      tagBoost: values.tagBoost,
      activationBoost: values.activationBoost,
      finalScore: values.finalScore,
      matchedTags,
      matchedCategory: values.categoryBoost > 0 ? context.detectedCategory : null,
    },
  };
}
