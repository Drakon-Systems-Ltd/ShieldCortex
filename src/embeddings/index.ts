export { generateEmbedding, cosineSimilarity, isModelLoaded, preloadModel, disposeModel } from './generator.js';
export {
  inspectEmbeddingModelCache,
  quarantineEmbeddingOnnx,
  formatModelCacheDoctorMessage,
  EMBEDDING_ONNX_EXPECTED_BYTES,
  EMBEDDING_ONNX_EXPECTED_SHA256,
  EMBEDDING_MODEL_ID,
  resolveEmbeddingModelPaths,
  defaultEmbeddingCacheRoot,
  isCorruptModelLoadError,
} from './model-cache.js';
export { hasAttemptedModelCacheHeal } from './model-cache.js';
export { markModelCacheHealAttempted } from './model-cache.js';
export { resetModelCacheHealLatchForTests } from './model-cache.js';
