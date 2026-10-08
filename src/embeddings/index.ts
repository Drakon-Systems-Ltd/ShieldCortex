export { generateEmbedding, cosineSimilarity, isModelLoaded, preloadModel, disposeModel } from './generator.js';
export {
  inspectEmbeddingModelCache,
  inspectEmbeddingHookReady,
  EMBEDDING_REQUIRED_SIBLINGS,
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
  inspectEmbeddingModelForDoctor,
  OFFLINE_EMBEDDINGS_DOC_URL,
} from './model-cache.js';
export {
  resolveEmbeddingModelConfig,
  resolveEmbeddingCacheRoot,
  EmbeddingConfigError,
  MODEL_DIR_ENV,
  EMBEDDINGS_OFFLINE_ENV,
  type EmbeddingModelConfig,
} from './model-config.js';
// resetModelCacheHealLatchForTests stays module-private for tests (import from model-cache.js directly).
