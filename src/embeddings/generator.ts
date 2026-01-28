import { pipeline, env } from '@huggingface/transformers';
import type { FeatureExtractionPipeline } from '@huggingface/transformers';

// Configure for operation
env.allowRemoteModels = true;
env.allowLocalModels = true;

let embeddingPipeline: FeatureExtractionPipeline | null = null;
let isLoading = false;
let loadPromise: Promise<FeatureExtractionPipeline> | null = null;

/**
 * Lazy-load the embedding model
 * Model: all-MiniLM-L6-v2 (22MB, 384 dimensions)
 * Uses @huggingface/transformers (successor to @xenova/transformers)
 * with better ARM64 Linux support
 */
async function getEmbeddingPipeline(): Promise<FeatureExtractionPipeline> {
  if (embeddingPipeline) return embeddingPipeline;

  if (isLoading && loadPromise) {
    return loadPromise;
  }

  isLoading = true;
  loadPromise = pipeline('feature-extraction', 'Xenova/all-MiniLM-L6-v2') as unknown as Promise<FeatureExtractionPipeline>;

  try {
    embeddingPipeline = await loadPromise;
    return embeddingPipeline;
  } finally {
    isLoading = false;
    loadPromise = null;
  }
}

/**
 * Generate embedding vector for text
 * @param text - Text to embed (title + content recommended)
 * @returns Float32Array of 384 dimensions
 */
export async function generateEmbedding(text: string): Promise<Float32Array> {
  const extractor = await getEmbeddingPipeline();

  // Truncate to ~512 tokens worth (~2000 chars) for model limits
  const truncated = text.slice(0, 2000);

  const output = await extractor(truncated, {
    pooling: 'mean',
    normalize: true,
  });

  // Handle both Tensor objects (new @huggingface/transformers) and plain objects
  const data = typeof output.tolist === 'function'
    ? new Float32Array(output.tolist().flat(Infinity) as number[])
    : new Float32Array(output.data as ArrayLike<number>);
  return data;
}

/**
 * Calculate cosine similarity between two embeddings
 * @returns Similarity score 0-1 (1 = identical)
 */
export function cosineSimilarity(a: Float32Array, b: Float32Array): number {
  if (a.length !== b.length) {
    throw new Error(`Embedding dimension mismatch: ${a.length} vs ${b.length}`);
  }

  let dotProduct = 0;
  let normA = 0;
  let normB = 0;

  for (let i = 0; i < a.length; i++) {
    dotProduct += a[i] * b[i];
    normA += a[i] * a[i];
    normB += b[i] * b[i];
  }

  const magnitude = Math.sqrt(normA) * Math.sqrt(normB);
  if (magnitude === 0) return 0;

  return dotProduct / magnitude;
}

/**
 * Check if embedding model is loaded
 */
export function isModelLoaded(): boolean {
  return embeddingPipeline !== null;
}

/**
 * Preload the model (call during startup if desired)
 */
export async function preloadModel(): Promise<void> {
  await getEmbeddingPipeline();
}
