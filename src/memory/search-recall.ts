/**
 * Memory search and recall.
 *
 * Phase 3 of the audit-recommended store.ts split. The "search/recall"
 * group is the hybrid FTS5 + vector pipeline (`searchMemoriesInternal`)
 * and its three public entry points (`searchMemories`,
 * `searchMemoriesExplained`, `recallWithEmbeddings`). Lifted out of
 * store.ts (1,564 lines after phase 2) so the search pipeline can be
 * read on its own without scrolling past every CRUD helper. No
 * behaviour change vs the original implementation — exports re-emerge
 * from store.ts via a barrel re-export so existing import paths keep
 * working.
 *
 * Imports from store.ts (`rowToMemory`, `logAccessDenial`) form a
 * module cycle, but both are only invoked inside function bodies —
 * never at module load. ESM live bindings handle this correctly at
 * runtime. `logAccessDenial` is exported from store.ts purely as a
 * cycle artifact; it is not intended as public API (same precedent
 * as `MAX_CONTENT_SIZE` in phase 2).
 *
 * Imports from lifecycle.ts (`reinforceFromSearch`, `enrichMemory`)
 * are not cyclic — phase 2 added them to store.ts specifically for
 * the search pipeline; in phase 3 they move with the consumer.
 */

import { getDatabase } from '../database/init.js';
import {
  Memory,
  MemoryConfig,
  DEFAULT_CONFIG,
  RankerConfig,
  SearchOptions,
  SearchResult,
} from './types.js';
import {
  calculateDecayedScore,
  calculatePriority,
} from './decay.js';
import {
  getActivationBoost,
  pruneActivationCache,
} from './activation.js';
import { getCachedQueryEmbedding, findSimilarMemories } from './embedding.js';
import {
  buildSearchExplanation,
  calculateLinkBoost,
  calculateTagScore,
  detectQueryCategory,
  extractQueryTags,
  SearchExecutionOptions,
  SearchScoringContext,
  vectorSearch,
} from './search.js';
import { escapeFts5Query } from './fts.js';
import { checkAccess } from '../defence/trust/access-control.js';
import type { DefenceSource } from '../defence/types.js';
import { reinforceFromSearch, enrichMemory } from './lifecycle.js';
// Cyclic import — see header. rowToMemory and logAccessDenial live in store.ts;
// both are only invoked inside function bodies below, never at module load.
import { rowToMemory, logAccessDenial } from './store.js';
import { runHybridRanker } from './ranker/index.js';
import { graphRankFromQuery } from './ranker/graph-rank.js';
import { getRankerConfig } from '../cloud/config.js';

let searchCount = 0;

async function searchMemoriesInternal(
  options: SearchOptions,
  config: MemoryConfig,
  source: DefenceSource | undefined,
  execution: SearchExecutionOptions,
): Promise<SearchResult[]> {
  if (++searchCount % 100 === 0) {
    pruneActivationCache();
  }
  const db = getDatabase();
  const limit = options.limit || 20;
  const includeGlobal = options.includeGlobal ?? true;

  const detectedCategory = options.query ? detectQueryCategory(options.query) : null;
  const queryTags = options.query ? extractQueryTags(options.query) : [];

  let queryEmbedding: Float32Array | null = null;
  const vectorResults: Map<number, number> = new Map();
  if (options.query && options.query.trim()) {
    try {
      queryEmbedding = await getCachedQueryEmbedding(options.query);
      if (!queryEmbedding) {
        throw new Error('query embedding unavailable');
      }
      const vectorHits = vectorSearch(db, queryEmbedding, limit * 2, options.project, includeGlobal);
      for (const hit of vectorHits) {
        vectorResults.set(hit.id, hit.similarity);
      }
    } catch {
      if (process.env.SHIELDCORTEX_SKIP_EMBEDDINGS !== '1') {
        console.log('[shieldcortex] Vector search unavailable, using FTS only');
      }
    }
  }

  let sql: string;
  const params: unknown[] = [];

  if (options.query && options.query.trim()) {
    const escapedQuery = escapeFts5Query(options.query.trim());
    sql = `
      SELECT m.*, fts.rank
      FROM memories m
      JOIN memories_fts fts ON m.id = fts.rowid
      WHERE memories_fts MATCH ?
    `;
    params.push(escapedQuery);
  } else {
    sql = `SELECT *, 0 as rank FROM memories m WHERE 1=1`;
  }

  if (options.project) {
    if (includeGlobal) {
      sql += ` AND (m.project = ? OR m.scope = 'global')`;
    } else {
      sql += ' AND m.project = ?';
    }
    params.push(options.project);
  }
  if (options.category) {
    sql += ' AND m.category = ?';
    params.push(options.category);
  }
  if (options.type) {
    sql += ' AND m.type = ?';
    params.push(options.type);
  }
  if (!options.includeArchived) {
    sql += ` AND m.status != 'archived'`;
  }
  if (!options.includeSuppressed) {
    sql += ` AND m.status != 'suppressed'`;
  }
  if (options.minSalience) {
    sql += ' AND m.salience >= ?';
    params.push(options.minSalience);
  }
  if (options.tags && options.tags.length > 0) {
    const tagPlaceholders = options.tags.map(() => '?').join(',');
    sql += ` AND EXISTS (
      SELECT 1 FROM json_each(m.tags)
      WHERE json_each.value IN (${tagPlaceholders})
    )`;
    params.push(...options.tags);
  }

  // Prefilter on the persisted decayed-score index (CLAUDE.md: "Persisted decay
  // scores for efficient sorting", idx_memories_decayed_score). decayed_score is
  // NULL until updateDecayScores() persists it (addMemory leaves it unset), so
  // COALESCE back to raw salience for un-scored rows — identical to rowToMemory's
  // `decayed_score ?? salience`. Without the COALESCE, NULL sorts last under DESC
  // and would bury freshly-written high-salience memories out of the prefilter.
  sql += ' ORDER BY COALESCE(m.decayed_score, m.salience) DESC, m.last_accessed DESC LIMIT ?';
  params.push(limit);

  const rows = db.prepare(sql).all(...params) as Record<string, unknown>[];
  const scoringContext: SearchScoringContext = {
    db,
    config,
    detectedCategory,
    queryTags,
    vectorResults,
    query: options.query,
  };

  // FTS-derived per-row scores (legacy: used directly; RRF: kept for explanations)
  const ftsScores = new Map<number, number>();
  for (const row of rows) {
    const id = row.id as number;
    const rawRank = row.rank as number;
    ftsScores.set(id, rawRank ? 1 / (1 + Math.abs(rawRank)) : 0.3);
  }

  // Resolve ranker engine. Honour caller-supplied config.ranker if present
  // (tests and explicit callers can pin engine), otherwise fall back to the
  // env/file resolver in cloud/config.
  const rankerConfig: RankerConfig = config.ranker ?? getRankerConfig();

  let sortedResults: SearchResult[];
  if (rankerConfig.engine === 'rrf') {
    sortedResults = scoreWithRrf({
      rows,
      ftsScores,
      vectorResults,
      query: options.query,
      options,
      db,
      config,
      rankerConfig,
      limit,
      includeExplanation: execution.includeExplanation,
    });
  } else {
    sortedResults = scoreLegacy({
      rows,
      vectorResults,
      detectedCategory,
      queryTags,
      db,
      config,
      includeDecayed: options.includeDecayed ?? false,
      includeExplanation: execution.includeExplanation,
      scoringContext,
    });
  }

  if (execution.enableSideEffects) {
    const topResults = sortedResults.slice(0, 5);
    for (const result of topResults) {
      reinforceFromSearch(result.memory.id);
    }

    if (topResults.length >= 2) {
      for (let i = 0; i < topResults.length; i++) {
        for (let j = i + 1; j < topResults.length; j++) {
          const idA = topResults[i].memory.id;
          const idB = topResults[j].memory.id;
          const existing = db.prepare(
            'SELECT strength FROM memory_links WHERE (source_id = ? AND target_id = ?) OR (source_id = ? AND target_id = ?)'
          ).get(idA, idB, idB, idA) as { strength: number } | undefined;

          if (existing) {
            const newStrength = Math.min(1.0, existing.strength + 0.03);
            db.prepare(
              'UPDATE memory_links SET strength = ? WHERE (source_id = ? AND target_id = ?) OR (source_id = ? AND target_id = ?)'
            ).run(newStrength, idA, idB, idB, idA);
          } else {
            try {
              db.prepare(
                'INSERT INTO memory_links (source_id, target_id, relationship, strength) VALUES (?, ?, ?, ?)'
              ).run(idA, idB, 'related', 0.2);
            } catch (e) {
              if (!(e instanceof Error && e.message.includes('UNIQUE constraint'))) {
                console.warn('[shieldcortex] Unexpected error linking co-returned memories:', e);
              }
            }
          }
        }
      }
    }

    if (sortedResults.length > 0 && options.query && options.query.length > 30) {
      const topResult = sortedResults[0];
      const queryWords = new Set(options.query.toLowerCase().split(/\s+/).filter(w => w.length > 3));
      const contentWords = new Set(topResult.memory.content.toLowerCase().split(/\s+/));
      const newWords = [...queryWords].filter(w => !contentWords.has(w));

      if (newWords.length > queryWords.size * 0.3 && options.query.length > 50) {
        try {
          enrichMemory(topResult.memory.id, options.query, 'search');
        } catch {
          // enrichment is best-effort
        }
      }
    }
  }

  const finalResults = sortedResults.slice(0, limit);

  // Per-result contradiction links, then their counterpart titles. The title
  // lookup was an N+1-within-N+1 (one SELECT title per contradiction per
  // result); collect every counterpart id first and resolve all titles with a
  // single `WHERE id IN (...)`, then read from the id→title map below.
  const contradictionsByResult = new Map<number, Array<{ strength: number; other_id: number }>>();
  const counterpartIds = new Set<number>();
  for (const result of finalResults) {
    const contradictions = db.prepare(`
      SELECT ml.strength,
        CASE WHEN ml.source_id = ? THEN ml.target_id ELSE ml.source_id END as other_id
      FROM memory_links ml
      WHERE ml.relationship = 'contradicts'
        AND (ml.source_id = ? OR ml.target_id = ?)
    `).all(result.memory.id, result.memory.id, result.memory.id) as Array<{ strength: number; other_id: number }>;
    if (contradictions.length > 0) {
      contradictionsByResult.set(result.memory.id, contradictions);
      for (const c of contradictions) counterpartIds.add(c.other_id);
    }
  }

  const counterpartTitles = new Map<number, string | undefined>();
  if (counterpartIds.size > 0) {
    const ids = [...counterpartIds];
    const placeholders = ids.map(() => '?').join(',');
    const titleRows = db.prepare(
      `SELECT id, title FROM memories WHERE id IN (${placeholders})`,
    ).all(...ids) as Array<{ id: number; title?: string }>;
    for (const tr of titleRows) counterpartTitles.set(tr.id, tr.title);
  }

  for (const result of finalResults) {
    const contradictions = contradictionsByResult.get(result.memory.id);
    if (contradictions && contradictions.length > 0) {
      result.contradictions = contradictions.map((contradiction) => ({
        memoryId: contradiction.other_id,
        title: counterpartTitles.get(contradiction.other_id) || 'Unknown',
        score: contradiction.strength,
      }));
      if (result.explanation) {
        result.explanation.reasons.push(`${contradictions.length} contradiction link${contradictions.length === 1 ? '' : 's'} attached`);
      }
    }
  }

  if (source) {
    const db2 = getDatabase();
    // ACL lookup was an N+1 (one `SELECT source, sensitivity_level WHERE id = ?`
    // per result); fetch all result rows in one `WHERE id IN (...)` and read the
    // per-result source/sensitivity from the map. checkAccess/logAccessDenial
    // logic and filter order are unchanged.
    const aclIds = finalResults.map((result) => result.memory.id);
    const aclRows = new Map<number, Record<string, unknown>>();
    if (aclIds.length > 0) {
      const placeholders = aclIds.map(() => '?').join(',');
      const fetched = db2.prepare(
        `SELECT id, source, sensitivity_level FROM memories WHERE id IN (${placeholders})`,
      ).all(...aclIds) as Record<string, unknown>[];
      for (const row of fetched) aclRows.set(row.id as number, row);
    }
    return finalResults.filter(result => {
      const row = aclRows.get(result.memory.id);
      const policy = checkAccess(
        { id: result.memory.id, source: row?.source as string | null, sensitivity_level: row?.sensitivity_level as string | null },
        source,
        'read',
      );
      if (!policy.canRead) {
        logAccessDenial(result.memory.id, source, policy.reason);
        return false;
      }
      return true;
    });
  }

  return finalResults;
}

// ── Scoring backends ─────────────────────────────────────────────────────
//
// `scoreLegacy` and `scoreWithRrf` produce the same shape (`SearchResult[]`,
// already filtered by salience and sorted by relevanceScore) so the rest of
// `searchMemoriesInternal` (side effects, contradiction enrichment, ACL
// filter) can stay engine-agnostic.

interface ScoreLegacyInput {
  rows: Record<string, unknown>[];
  vectorResults: Map<number, number>;
  detectedCategory: ReturnType<typeof detectQueryCategory>;
  queryTags: string[];
  db: ReturnType<typeof getDatabase>;
  config: MemoryConfig;
  includeDecayed: boolean;
  includeExplanation: boolean;
  scoringContext: SearchScoringContext;
}

function scoreLegacy(input: ScoreLegacyInput): SearchResult[] {
  const {
    rows, vectorResults, detectedCategory, queryTags, db, config,
    includeDecayed, includeExplanation, scoringContext,
  } = input;

  const results: SearchResult[] = rows.map((row) => {
    const memory = rowToMemory(row);
    const decayedScore = calculateDecayedScore(memory, config);
    memory.decayedScore = decayedScore;

    const rawRank = row.rank as number;
    const ftsScore = rawRank ? 1 / (1 + Math.abs(rawRank)) : 0.3;
    const hoursSinceAccess = (Date.now() - new Date(memory.lastAccessed).getTime()) / (1000 * 60 * 60);
    const recencyBoost = hoursSinceAccess < 1 ? 0.1 : (hoursSinceAccess < 24 ? 0.05 : 0);
    const categoryBoost = detectedCategory && memory.category === detectedCategory ? 0.1 : 0;
    const linkBoost = calculateLinkBoost(memory.id, db);
    const tagBoost = calculateTagScore(queryTags, memory.tags);
    const activationBoost = getActivationBoost(memory.id);
    const vectorSimilarity = vectorResults.get(memory.id) || 0;
    const vectorBoost = vectorSimilarity * 0.3;
    const priorityBoost = calculatePriority(memory) * 0.05;
    const contradictionCount = (db.prepare(
      `SELECT COUNT(*) as count FROM memory_links WHERE relationship = 'contradicts' AND (source_id = ? OR target_id = ?)`,
    ).get(memory.id, memory.id) as { count: number }).count;
    const contradictionPenalty = Math.min(0.12, contradictionCount * 0.03);
    const eligibilityReasons: string[] = [];
    if (memory.status === 'archived') eligibilityReasons.push('Archived memories are excluded from normal recall');
    if (memory.status === 'suppressed') eligibilityReasons.push('Suppressed memories are excluded from normal recall');
    if (memory.cloudExcluded) eligibilityReasons.push('Excluded from cloud sync');
    if (memory.trustScore < 0.7) eligibilityReasons.push(`Low trust source (${memory.trustScore.toFixed(2)})`);
    if (contradictionCount > 0) eligibilityReasons.push(`${contradictionCount} contradiction link${contradictionCount === 1 ? '' : 's'} attached`);
    const relevanceScore = (
      ftsScore * 0.25 +
      vectorBoost +
      decayedScore * 0.2 +
      priorityBoost +
      recencyBoost + categoryBoost + linkBoost + tagBoost + activationBoost -
      contradictionPenalty
    );

    const result: SearchResult = {
      memory,
      relevanceScore,
      recallEligibility: {
        eligible: eligibilityReasons.length === 0,
        reasons: eligibilityReasons,
      },
    };
    if (includeExplanation) {
      result.explanation = buildSearchExplanation(memory, scoringContext, {
        ftsScore,
        vectorSimilarity,
        vectorBoost,
        decayedScore,
        priorityBoost,
        recencyBoost,
        categoryBoost,
        linkBoost,
        tagBoost,
        activationBoost,
        contradictionPenalty,
        finalScore: relevanceScore,
      });
      if (result.explanation) {
        result.explanation.eligibility = result.recallEligibility;
      }
    }
    return result;
  });

  return results
    .filter((result) => includeDecayed || result.memory.decayedScore >= config.salienceThreshold)
    .sort((a, b) => b.relevanceScore - a.relevanceScore);
}

interface ScoreWithRrfInput {
  rows: Record<string, unknown>[];
  ftsScores: Map<number, number>;
  vectorResults: Map<number, number>;
  query: string;
  options: SearchOptions;
  db: ReturnType<typeof getDatabase>;
  config: MemoryConfig;
  rankerConfig: RankerConfig;
  limit: number;
  includeExplanation: boolean;
}

/**
 * RRF retrieval path: build per-retriever rank lists from the FTS rows
 * already produced by the SQL prelude, the cosine-similarity vector hits,
 * and a fresh `graphRankFromQuery` call. Hand them to `runHybridRanker`,
 * which fuses with RRF and applies post-fusion multiplicative boosts.
 *
 * Vector and graph rank lists may surface ids the FTS WHERE clause would
 * have filtered out (category/type/status/tags/minSalience). Those are
 * dropped at memory-map build time so the same filters apply across all
 * three retrievers, keeping search behaviour predictable.
 */
function scoreWithRrf(input: ScoreWithRrfInput): SearchResult[] {
  const {
    rows, ftsScores, vectorResults, query, options, db,
    config, rankerConfig, limit, includeExplanation,
  } = input;

  // Memory map starts with FTS rows (already passed all SQL filters).
  const memoryMap = new Map<number, Memory>();
  const ftsIds: number[] = [];
  for (const row of rows) {
    const memory = rowToMemory(row);
    memoryMap.set(memory.id, memory);
    ftsIds.push(memory.id);
  }

  // Vector and graph rank lists may contain ids the FTS WHERE would have
  // filtered out — fetch + filter to enforce the same constraints.
  const sortedVectorIds = Array.from(vectorResults.entries())
    .sort((a, b) => b[1] - a[1])
    .map(([id]) => id);

  const graphLimit = Math.max(limit * 3, 50);
  const graphResults = query && query.trim()
    ? graphRankFromQuery(query, db, { project: options.project, limit: graphLimit })
    : [];
  const candidateGraphIds = graphResults.map((r) => r.memoryId);

  // Batch-hydrate every candidate not already covered by the FTS rows in ONE
  // query (was an N+1: one `SELECT * WHERE id = ?` per vector/graph candidate).
  // considerCandidate then reads from this prefetched map, keeping the exact
  // per-id filter semantics, list order, and memoryMap side effect.
  const candidateIdsToFetch = new Set<number>();
  for (const id of sortedVectorIds) if (!memoryMap.has(id)) candidateIdsToFetch.add(id);
  for (const id of candidateGraphIds) if (!memoryMap.has(id)) candidateIdsToFetch.add(id);
  const prefetchedRows = new Map<number, Record<string, unknown>>();
  if (candidateIdsToFetch.size > 0) {
    const ids = [...candidateIdsToFetch];
    const placeholders = ids.map(() => '?').join(',');
    const fetched = db.prepare(
      `SELECT * FROM memories WHERE id IN (${placeholders})`,
    ).all(...ids) as Record<string, unknown>[];
    for (const row of fetched) prefetchedRows.set(row.id as number, row);
  }

  const considerCandidate = (id: number): boolean => {
    if (memoryMap.has(id)) return true;
    const row = prefetchedRows.get(id);
    if (!row) return false;
    const memory = rowToMemory(row);
    if (!candidatePassesFilters(memory, options)) return false;
    memoryMap.set(memory.id, memory);
    return true;
  };

  const vectorIds = sortedVectorIds.filter(considerCandidate);
  const graphIds = candidateGraphIds.filter(considerCandidate);

  return runHybridRanker({
    rankLists: [
      { name: 'fts', ids: ftsIds, weight: rankerConfig.weights.fts },
      { name: 'vector', ids: vectorIds, weight: rankerConfig.weights.vector },
      { name: 'graph', ids: graphIds, weight: rankerConfig.weights.graph },
    ],
    memories: memoryMap,
    vectorSimilarities: vectorResults,
    ftsScores,
    query,
    db,
    config,
    rrfK: rankerConfig.rrfK,
    includeExplanation,
    includeDecayed: options.includeDecayed ?? false,
    limit,
  });
}

/**
 * Mirror the WHERE-clause filters from the FTS SQL so that vector/graph
 * candidates not returned by FTS are held to the same standard. Project
 * scoping is already handled at the source (`vectorSearch` and
 * `graphRankFromQuery`) so it isn't duplicated here.
 */
function candidatePassesFilters(memory: Memory, options: SearchOptions): boolean {
  if (options.category && memory.category !== options.category) return false;
  if (options.type && memory.type !== options.type) return false;
  if (!options.includeArchived && memory.status === 'archived') return false;
  if (!options.includeSuppressed && memory.status === 'suppressed') return false;
  if (options.minSalience !== undefined && memory.salience < options.minSalience) return false;
  if (options.tags && options.tags.length > 0) {
    const hasTag = options.tags.some((tag) => memory.tags.includes(tag));
    if (!hasTag) return false;
  }
  return true;
}

/**
 * Search memories using full-text search, vector similarity, and filters
 * Now uses hybrid search combining FTS5 keywords with semantic vector matching
 */
export async function searchMemories(
  options: SearchOptions,
  config: MemoryConfig = DEFAULT_CONFIG,
  source?: DefenceSource,
): Promise<SearchResult[]> {
  return searchMemoriesInternal(options, config, source, {
    enableSideEffects: true,
    includeExplanation: false,
  });
}

export async function searchMemoriesExplained(
  options: SearchOptions,
  config: MemoryConfig = DEFAULT_CONFIG,
  source?: DefenceSource,
): Promise<SearchResult[]> {
  return searchMemoriesInternal(options, config, source, {
    enableSideEffects: false,
    includeExplanation: true,
  });
}

/**
 * Recall with embedding-based vector similarity fallback.
 *
 * 1. First tries FTS5 search (existing searchMemories)
 * 2. If FTS5 returns < 3 results, also runs embedding similarity search
 * 3. Merges results (FTS5 first, then embedding results not already in FTS5 set)
 * 4. Caps at `limit` (default 15)
 * 5. The `threshold` (default 0.3) filters out low-similarity embedding results
 */
export async function recallWithEmbeddings(
  query: string,
  options?: {
    limit?: number;
    project?: string;
    threshold?: number;
    existingResults?: SearchResult[];
    queryEmbedding?: Float32Array | null;
  },
): Promise<Memory[]> {
  const limit = options?.limit ?? 15;
  const threshold = options?.threshold ?? 0.3;

  // Step 1: Try FTS5 search first
  let ftsResults: SearchResult[] = options?.existingResults ?? [];
  if (ftsResults.length === 0) {
    try {
      ftsResults = await searchMemories({
        query,
        project: options?.project,
        limit,
        includeGlobal: true,
      });
    } catch (e) {
      // FTS search failed — continue to embedding fallback
      console.warn('[shieldcortex] FTS search failed in recallWithEmbeddings:', (e as Error).message);
    }
  }

  const ftsMemories = ftsResults.map(r => r.memory);

  // Step 2: If FTS5 returns >= 3 results, no need for embedding fallback
  if (ftsMemories.length >= 3) {
    return ftsMemories.slice(0, limit);
  }

  // Step 3: Run embedding similarity search as fallback
  try {
    const { initEmbeddings } = await import('./embedding.js');

    const ready = await initEmbeddings();
    if (!ready) {
      return ftsMemories.slice(0, limit);
    }

    // Get candidate memories from the database (not already in FTS results)
    const ftsIds = new Set(ftsMemories.map(m => m.id));
    const db = getDatabase();

    let sql = 'SELECT id, title, content FROM memories WHERE 1=1';
    const params: unknown[] = [];

    if (options?.project) {
      sql += ` AND (project = ? OR scope = 'global')`;
      params.push(options.project);
    }

    // Prefilter the embedding-fallback candidate pool on the persisted decayed
    // score (COALESCE to raw salience for rows not yet scored — see the FTS
    // prefilter above for the NULL rationale).
    sql += ' ORDER BY COALESCE(decayed_score, salience) DESC, last_accessed DESC LIMIT 200';

    const candidates = db.prepare(sql).all(...params) as Array<{ id: number; title: string; content: string }>;

    // Filter out memories already returned by FTS
    const newCandidates = candidates.filter(c => !ftsIds.has(c.id));

    if (newCandidates.length === 0) {
      return ftsMemories.slice(0, limit);
    }

    const queryEmbedding = options?.queryEmbedding ?? await getCachedQueryEmbedding(query);
    if (!queryEmbedding) {
      return ftsMemories.slice(0, limit);
    }

    // Find similar memories using embeddings
    const remainingSlots = limit - ftsMemories.length;
    const similar = await findSimilarMemories(query, newCandidates, remainingSlots, queryEmbedding);

    // Filter by threshold, then hydrate the survivors in ONE query. Was an N+1
    // (one `SELECT * WHERE id = ?` per hit); now a single `WHERE id IN (...)`
    // with an id→row map, mapping the threshold-passing ids through it so the
    // original similarity order (and the skip-missing-row behaviour) is kept.
    const hitIds = similar.filter((hit) => hit.score >= threshold).map((hit) => hit.id);
    const embeddingMemories: Memory[] = [];
    if (hitIds.length > 0) {
      const placeholders = hitIds.map(() => '?').join(',');
      const rowsById = new Map<number, Record<string, unknown>>();
      const fetched = db.prepare(
        `SELECT * FROM memories WHERE id IN (${placeholders})`,
      ).all(...hitIds) as Record<string, unknown>[];
      for (const row of fetched) rowsById.set(row.id as number, row);
      for (const id of hitIds) {
        const row = rowsById.get(id);
        if (row) embeddingMemories.push(rowToMemory(row));
      }
    }

    // Step 4: Merge — FTS results first, then embedding results
    const merged = [...ftsMemories, ...embeddingMemories];
    return merged.slice(0, limit);
  } catch (e) {
    // Embedding fallback failed — return whatever FTS found
    console.warn('[shieldcortex] Embedding fallback failed:', (e as Error).message);
    return ftsMemories.slice(0, limit);
  }
}
