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
  hasAttemptedModelCacheHeal,
  markModelCacheHealAttempted,
} from './model-cache.js';
// resetModelCacheHealLatchForTests stays module-private for tests (import from model-cache.js directly).
