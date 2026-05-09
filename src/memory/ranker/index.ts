/**
 * Hybrid retrieval orchestrator — Step A.3 of v4.15.
 *
 * Glues the three retrievers (FTS via SQLite FTS5, vector via embeddings,
 * graph via `graphRankFromQuery`) into a single ranking by feeding their
 * rank lists into Reciprocal Rank Fusion (`reciprocalRankFusion`), then
 * applying the existing per-memory boosts (recency, category, link, tag,
 * activation, contradiction) as **multiplicative tweaks on top of the
 * RRF score** rather than additive components in a fixed-weight sum.
 *
 *   finalScore = rrfScore
 *     × (1 + 0.05 × priority)                // priority: 0–1
 *     × (1 + recencyBoost)                   // 0 / 0.05 / 0.1
 *     × (1 + 0.1 × categoryMatch)            // 0 or 1
 *     × (1 + linkBoost)                      // 0–0.15
 *     × (1 + tagBoost)                       // 0–0.1
 *     × (1 + activationBoost)                // 0–?
 *     × (1 - contradictionPenalty)           // 0–0.12
 *
 * Why multiplicative on top of RRF rather than additive:
 *   - RRF is rank-based, so its raw score scale is small and consistent.
 *   - Multiplicative boosts preserve the *relative* RRF order while
 *     letting context modulate it — they don't drown out the underlying
 *     retrieval signal the way fixed additive weights do.
 *   - Contradiction penalty is multiplicative (`1 - p`) so it shrinks
 *     score proportionally rather than potentially flipping sign.
 *
 * The module is split intentionally: `runHybridRanker` is pure-ish (it
 * accepts already-loaded rank lists + a memory map) so it can be unit
 * tested without standing up the embedding model or the FTS pipeline.
 * Step A.4 will add the DB-backed `hybridSearch` wrapper that builds
 * those inputs from a `SearchOptions`.
 */

import type Database from 'better-sqlite3';
import { reciprocalRankFusion, type RankList, type RrfResult } from './rrf.js';
import { calculateDecayedScore, calculatePriority } from '../decay.js';
import { getActivationBoost as defaultActivationBoost } from '../activation.js';
import {
  buildSearchExplanation,
  calculateLinkBoost,
  calculateTagScore,
  detectQueryCategory,
  extractQueryTags,
  type SearchScoringContext,
} from '../search.js';
import type { Memory, MemoryConfig, SearchResult } from '../types.js';

export interface HybridRankerWeights {
  fts: number;
  vector: number;
  graph: number;
}

export const DEFAULT_HYBRID_WEIGHTS: HybridRankerWeights = {
  fts: 0.4,
  vector: 0.6,
  graph: 0.3,
};

/** Cormack et al. (2009) recommended RRF smoothing constant. */
export const DEFAULT_RRF_K = 60;
const DEFAULT_LIMIT = 20;

export interface HybridRankerInput {
  /** Rank lists from FTS, vector, graph. Any subset is allowed. */
  rankLists: readonly RankList[];
  /** Memory id → Memory record. The caller pre-loads these. */
  memories: Map<number, Memory>;
  /** Memory id → cosine similarity (used only for explanation breakdowns). */
  vectorSimilarities?: Map<number, number>;
  /** Memory id → normalised FTS score (used only for explanation breakdowns). */
  ftsScores?: Map<number, number>;
  /** Original user query — drives category detection and tag extraction. */
  query: string;
  /** SQLite handle — used for memory_links lookups. */
  db: Database.Database;
  /** Memory config. `salienceThreshold` gates the includeDecayed filter. */
  config: MemoryConfig;
  /** Override RRF k constant. Default 60. */
  rrfK?: number;
  /** Attach a `SearchExplanation` to each `SearchResult`. */
  includeExplanation?: boolean;
  /** Skip the decay-threshold filter. */
  includeDecayed?: boolean;
  /** Cap result count. Default 20. */
  limit?: number;
  /**
   * Override the activation-boost lookup. Defaults to the module-level
   * cache in `../activation.js`. Tests inject a stub.
   */
  activationBoostFn?: (memoryId: number) => number;
}

interface ScoredCandidate {
  memory: Memory;
  rrfScore: number;
  finalScore: number;
  decayedScore: number;
  contributions: RrfResult['contributions'];
  values: ScoreValues;
  eligibilityReasons: string[];
  matchedCategory: boolean;
}

interface ScoreValues {
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
  contradictionPenalty: number;
  finalScore: number;
}

export function runHybridRanker(input: HybridRankerInput): SearchResult[] {
  const fused = reciprocalRankFusion(input.rankLists, { k: input.rrfK ?? DEFAULT_RRF_K });
  if (fused.length === 0) return [];

  const limit = input.limit ?? DEFAULT_LIMIT;
  const includeDecayed = input.includeDecayed ?? false;
  const includeExplanation = input.includeExplanation ?? false;
  const activationBoostFn = input.activationBoostFn ?? defaultActivationBoost;

  const detectedCategory = input.query ? detectQueryCategory(input.query) : null;
  const queryTags = input.query ? extractQueryTags(input.query) : [];

  const scoringContext: SearchScoringContext = {
    db: input.db,
    config: input.config,
    detectedCategory,
    queryTags,
    vectorResults: input.vectorSimilarities ?? new Map(),
    query: input.query,
  };

  const scored: ScoredCandidate[] = [];
  for (const fusedItem of fused) {
    const memory = input.memories.get(fusedItem.id);
    if (!memory) continue;

    const decayedScore = calculateDecayedScore(memory, input.config);
    memory.decayedScore = decayedScore;

    const candidate = scoreCandidate({
      memory,
      rrfScore: fusedItem.score,
      contributions: fusedItem.contributions,
      decayedScore,
      detectedCategory,
      queryTags,
      vectorSimilarity: input.vectorSimilarities?.get(memory.id) ?? 0,
      ftsScore: input.ftsScores?.get(memory.id) ?? 0,
      db: input.db,
      activationBoostFn,
    });
    scored.push(candidate);
  }

  const filtered = includeDecayed
    ? scored
    : scored.filter((c) => c.decayedScore >= input.config.salienceThreshold);

  filtered.sort(
    (a, b) =>
      b.finalScore - a.finalScore ||
      a.memory.id - b.memory.id, // stable tie-break
  );

  const capped = filtered.slice(0, limit);
  return capped.map((c) => buildSearchResult(c, scoringContext, includeExplanation));
}

interface ScoreCandidateInput {
  memory: Memory;
  rrfScore: number;
  contributions: RrfResult['contributions'];
  decayedScore: number;
  detectedCategory: ReturnType<typeof detectQueryCategory>;
  queryTags: string[];
  vectorSimilarity: number;
  ftsScore: number;
  db: Database.Database;
  activationBoostFn: (memoryId: number) => number;
}

function scoreCandidate(input: ScoreCandidateInput): ScoredCandidate {
  const { memory } = input;
  const hoursSinceAccess =
    (Date.now() - new Date(memory.lastAccessed).getTime()) / (1000 * 60 * 60);
  const recencyBoost = hoursSinceAccess < 1 ? 0.1 : hoursSinceAccess < 24 ? 0.05 : 0;
  const matchedCategory =
    input.detectedCategory !== null && memory.category === input.detectedCategory;
  const categoryBoost = matchedCategory ? 0.1 : 0;
  const linkBoost = calculateLinkBoost(memory.id, input.db);
  const tagBoost = calculateTagScore(input.queryTags, memory.tags);
  const activationBoost = input.activationBoostFn(memory.id);
  const priority = calculatePriority(memory);
  const priorityBoost = priority * 0.05;

  const contradictionCount = (
    input.db
      .prepare(
        `SELECT COUNT(*) as count FROM memory_links
         WHERE relationship = 'contradicts' AND (source_id = ? OR target_id = ?)`,
      )
      .get(memory.id, memory.id) as { count: number }
  ).count;
  const contradictionPenalty = Math.min(0.12, contradictionCount * 0.03);

  const multiplier =
    (1 + priorityBoost) *
    (1 + recencyBoost) *
    (1 + categoryBoost) *
    (1 + linkBoost) *
    (1 + tagBoost) *
    (1 + activationBoost) *
    (1 - contradictionPenalty);

  const finalScore = input.rrfScore * multiplier;

  const eligibilityReasons: string[] = [];
  if (memory.status === 'archived') eligibilityReasons.push('Archived memories are excluded from normal recall');
  if (memory.status === 'suppressed') eligibilityReasons.push('Suppressed memories are excluded from normal recall');
  if (memory.cloudExcluded) eligibilityReasons.push('Excluded from cloud sync');
  if (memory.trustScore < 0.7) eligibilityReasons.push(`Low trust source (${memory.trustScore.toFixed(2)})`);
  if (contradictionCount > 0) {
    eligibilityReasons.push(
      `${contradictionCount} contradiction link${contradictionCount === 1 ? '' : 's'} attached`,
    );
  }

  return {
    memory,
    rrfScore: input.rrfScore,
    finalScore,
    decayedScore: input.decayedScore,
    contributions: input.contributions,
    values: {
      ftsScore: input.ftsScore,
      vectorSimilarity: input.vectorSimilarity,
      vectorBoost: input.vectorSimilarity * 0.3, // for explanation breakdown only
      decayedScore: input.decayedScore,
      priorityBoost,
      recencyBoost,
      categoryBoost,
      linkBoost,
      tagBoost,
      activationBoost,
      contradictionPenalty,
      finalScore,
    },
    eligibilityReasons,
    matchedCategory,
  };
}

function buildSearchResult(
  c: ScoredCandidate,
  ctx: SearchScoringContext,
  includeExplanation: boolean,
): SearchResult {
  const result: SearchResult = {
    memory: c.memory,
    relevanceScore: c.finalScore,
    recallEligibility: {
      eligible: c.eligibilityReasons.length === 0,
      reasons: c.eligibilityReasons,
    },
  };
  if (includeExplanation) {
    const explanation = buildSearchExplanation(c.memory, ctx, c.values);
    if (explanation) {
      explanation.eligibility = result.recallEligibility;
      result.explanation = explanation;
    }
  }
  return result;
}
