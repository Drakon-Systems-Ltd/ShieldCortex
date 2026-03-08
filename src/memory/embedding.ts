/**
 * Embedding-based similarity search for memory recall.
 * Uses all-MiniLM-L6-v2 via @huggingface/transformers (worker thread).
 * Falls back gracefully if model loading fails.
 *
 * This module wraps the existing embeddings infrastructure (src/embeddings/)
 * and provides a higher-level API for recall-time similarity search.
 */

import { generateEmbedding, cosineSimilarity as rawCosineSimilarity, preloadModel, isModelLoaded } from '../embeddings/index.js';

let initialized = false;
let initFailed = false;
const QUERY_CACHE_TTL_MS = 10 * 60 * 1000;
const QUERY_CACHE_MAX = 64;
const queryEmbeddingCache = new Map<string, { embedding: Float32Array; expiresAt: number }>();

function isExpectedEmbeddingDisable(message: string): boolean {
  return message.includes('SHIELDCORTEX_SKIP_EMBEDDINGS=1');
}

function normalizeQuery(text: string): string {
  return text.trim().toLowerCase().replace(/\s+/g, ' ');
}

function cloneEmbedding(embedding: Float32Array): Float32Array {
  return new Float32Array(embedding);
}

function pruneQueryCache(now: number): void {
  for (const [key, entry] of queryEmbeddingCache) {
    if (entry.expiresAt <= now) {
      queryEmbeddingCache.delete(key);
    }
  }

  while (queryEmbeddingCache.size > QUERY_CACHE_MAX) {
    const oldestKey = queryEmbeddingCache.keys().next().value;
    if (!oldestKey) break;
    queryEmbeddingCache.delete(oldestKey);
  }
}

/**
 * Lazy-load the embedding model. Cache the pipeline.
 * Returns false on failure (doesn't crash).
 */
export async function initEmbeddings(): Promise<boolean> {
  if (initialized) return true;
  if (initFailed) return false;

  try {
    await preloadModel();
    initialized = true;
    return true;
  } catch (e) {
    const message = (e as Error).message;
    if (!isExpectedEmbeddingDisable(message)) {
      console.warn('[shieldcortex] Embedding init failed, vector recall disabled:', message);
    }
    initFailed = false; // Allow retry on next call
    return false;
  }
}

/**
 * Generate embedding for text. Truncate to first ~256 tokens (~2000 chars).
 * Returns null on failure.
 */
export async function embedText(text: string): Promise<Float32Array | null> {
  try {
    // The worker already truncates to 2000 chars (~256 tokens)
    const embedding = await generateEmbedding(text);
    return embedding;
  } catch (e) {
    const message = (e as Error).message;
    if (!isExpectedEmbeddingDisable(message)) {
      console.warn('[shieldcortex] embedText failed:', message);
    }
    return null;
  }
}

/**
 * Standard cosine similarity between two embedding vectors.
 */
export function cosineSimilarity(a: Float32Array, b: Float32Array): number {
  if (a.length !== b.length) return 0;
  return rawCosineSimilarity(a, b);
}

/**
 * Cache repeated query embeddings in-process to avoid re-embedding the same
 * recall queries during one MCP/API session.
 */
export async function getCachedQueryEmbedding(query: string): Promise<Float32Array | null> {
  const normalized = normalizeQuery(query);
  if (!normalized) return null;

  const now = Date.now();
  const cached = queryEmbeddingCache.get(normalized);
  if (cached && cached.expiresAt > now) {
    queryEmbeddingCache.delete(normalized);
    queryEmbeddingCache.set(normalized, cached);
    return cloneEmbedding(cached.embedding);
  }

  if (cached) {
    queryEmbeddingCache.delete(normalized);
  }

  const embedding = await embedText(query);
  if (!embedding) return null;

  queryEmbeddingCache.set(normalized, {
    embedding: cloneEmbedding(embedding),
    expiresAt: now + QUERY_CACHE_TTL_MS,
  });
  pruneQueryCache(now);
  return embedding;
}

export function clearQueryEmbeddingCache(): void {
  queryEmbeddingCache.clear();
}

/**
 * Embed the query, compute similarity against all memory embeddings,
 * return top K (default 10) sorted by score desc.
 *
 * Non-throwing: returns empty array on failure.
 */
export async function findSimilarMemories(
  query: string,
  memories: Array<{ id: number; title: string; content: string }>,
  topK: number = 10,
  queryEmbedding?: Float32Array | null,
): Promise<Array<{ id: number; score: number }>> {
  try {
    const activeQueryEmbedding = queryEmbedding ?? await getCachedQueryEmbedding(query);
    if (!activeQueryEmbedding) return [];

    // We need embeddings for each memory — caller should provide pre-computed
    // embeddings via the cache. For memories without cached embeddings, we
    // compute on the fly (text = title + content).
    const { getOrComputeEmbedding } = await import('./embedding-cache.js');

    const scored: Array<{ id: number; score: number }> = [];

    for (const mem of memories) {
      const memEmbedding = await getOrComputeEmbedding(
        mem.id,
        `${mem.title}\n${mem.content}`,
      );
      if (!memEmbedding) continue;

      const score = cosineSimilarity(activeQueryEmbedding, memEmbedding);
      scored.push({ id: mem.id, score });
    }

    scored.sort((a, b) => b.score - a.score);
    return scored.slice(0, topK);
  } catch (e) {
    console.warn('[shieldcortex] findSimilarMemories failed:', (e as Error).message);
    return [];
  }
}
