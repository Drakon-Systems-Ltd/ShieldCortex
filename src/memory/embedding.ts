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
    console.warn('[shieldcortex] Embedding init failed, vector recall disabled:', (e as Error).message);
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
    console.warn('[shieldcortex] embedText failed:', (e as Error).message);
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
 * Embed the query, compute similarity against all memory embeddings,
 * return top K (default 10) sorted by score desc.
 *
 * Non-throwing: returns empty array on failure.
 */
export async function findSimilarMemories(
  query: string,
  memories: Array<{ id: number; title: string; content: string }>,
  topK: number = 10,
): Promise<Array<{ id: number; score: number }>> {
  try {
    const queryEmbedding = await embedText(query);
    if (!queryEmbedding) return [];

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

      const score = cosineSimilarity(queryEmbedding, memEmbedding);
      scored.push({ id: mem.id, score });
    }

    scored.sort((a, b) => b.score - a.score);
    return scored.slice(0, topK);
  } catch (e) {
    console.warn('[shieldcortex] findSimilarMemories failed:', (e as Error).message);
    return [];
  }
}
