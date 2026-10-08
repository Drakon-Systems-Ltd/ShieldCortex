/**
 * Worker thread for ONNX embedding model.
 * Runs model loading and inference off the main thread so the event loop
 * stays responsive for MCP JSON-RPC messages.
 *
 * The ONNX runtime does synchronous C++ work during model loading and
 * inference that blocks the Node.js event loop. setTimeout/Promise.race
 * timeouts can't fire while the event loop is frozen. Running in a
 * worker_threads Worker solves this — the main thread stays free.
 */
import { parentPort } from 'worker_threads';
import {
  applyEmbeddingModelConfig,
  resolveEmbeddingModelConfig,
  type EmbeddingModelConfig,
} from './model-config.js';

// Lazy-loaded to catch import failures gracefully
// eslint-disable-next-line @typescript-eslint/no-explicit-any
let pipelineFn: any = null;
let loadError: string | null = null;
let modelConfig: EmbeddingModelConfig | null = null;

async function initTransformers(): Promise<void> {
  if (pipelineFn) return;
  if (loadError) throw new Error(loadError);

  // #632: cache root, offline flag and HF_ENDPOINT mirror are resolved (and
  // validated) before the library is even imported, so a bad value can never
  // reach a transport. Invalid config fails closed — no fallback root or host.
  let config: EmbeddingModelConfig;
  try {
    config = resolveEmbeddingModelConfig();
  } catch (err: unknown) {
    loadError = `Embedding configuration invalid: ${err instanceof Error ? err.message : String(err)}`;
    throw new Error(loadError);
  }

  try {
    const mod = await import('@huggingface/transformers');
    applyEmbeddingModelConfig(mod.env, config);
    modelConfig = config;
    pipelineFn = mod.pipeline;
  } catch (err: unknown) {
    loadError = err instanceof Error ? err.message : String(err);
    throw new Error(`Failed to load @huggingface/transformers: ${loadError}`);
  }
}

// eslint-disable-next-line @typescript-eslint/no-explicit-any
let extractor: any = null;

async function loadModel(): Promise<void> {
  if (extractor) return;
  await initTransformers();
  // dtype is pinned explicitly. Omitting it makes transformers.js print
  //   dtype not specified for "model". Using the default dtype (fp32) ...
  // to the console on every model load — a dependency warning that surfaced in
  // user-facing `remember`/`scan` output on a healthy install (#129). fp32 is
  // exactly what it was defaulting to on CPU, so behaviour is unchanged; the
  // defence judge worker pins its dtype the same way.
  //
  // #383: a truncated/corrupt on-disk weight used to fail every launch forever
  // against the same bad bytes. Quarantine once, then let transformers.js
  // re-download. A second failure surfaces — we never loop.
  //
  // #632: offline mode adds local_files_only on top of allowRemoteModels=false
  // and never takes the heal path — renaming a provisioned weight aside to
  // attempt a download that is forbidden would only destroy the operator's copy.
  const config = modelConfig!;
  const offlineOptions = config.offline ? { local_files_only: true } : {};
  const {
    isCorruptModelLoadError,
    quarantineEmbeddingOnnx,
    hasAttemptedModelCacheHeal,
    markModelCacheHealAttempted,
  } = await import('./model-cache.js');
  try {
    extractor = await pipelineFn(
      'feature-extraction',
      'Xenova/all-MiniLM-L6-v2',
      { dtype: 'fp32', ...offlineOptions },
    );
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : String(err);
    if (!isCorruptModelLoadError(message)) throw err;
    if (config.offline) {
      throw new Error(
        `Embedding model cache looks corrupt (${message}). SHIELDCORTEX_EMBEDDINGS_OFFLINE is set, ` +
        'so the file was left in place and not re-downloaded — replace it with a verified copy ' +
        '(docs/offline-embeddings.md).',
      );
    }
    // One heal per worker process — never pile up .bak files or hammer the network.
    if (hasAttemptedModelCacheHeal()) {
      throw new Error(
        `Embedding model cache still corrupt after one heal attempt: ${message}`,
      );
    }
    markModelCacheHealAttempted();
    const q = quarantineEmbeddingOnnx({ reason: 'load-failed', cacheRoot: config.cacheRoot });
    parentPort?.postMessage({
      type: 'error',
      error:
        `Embedding model cache looked corrupt (${message}). ` +
        `${q.detail}. Attempting one re-download (process heal latch armed).`,
    });
    extractor = await pipelineFn(
      'feature-extraction',
      'Xenova/all-MiniLM-L6-v2',
      { dtype: 'fp32', ...offlineOptions },
    );
  }
}

async function embed(text: string): Promise<number[]> {
  if (!extractor) await loadModel();

  const truncated = text.slice(0, 2000);
  const output = await extractor(truncated, {
    pooling: 'mean',
    normalize: true,
  });

  let result: number[];
  if (output.data && (output.data as ArrayLike<number>).length > 0) {
    result = Array.from(output.data as ArrayLike<number>);
  } else if (typeof output.tolist === 'function') {
    result = (output.tolist().flat(Infinity) as number[]);
  } else {
    throw new Error('Cannot extract embedding from tensor');
  }

  // Release ONNX native memory
  if (output && typeof (output as { dispose?: () => void }).dispose === 'function') {
    (output as { dispose: () => void }).dispose();
  }

  return result;
}

// Catch uncaught errors so the worker doesn't exit silently with code 0
process.on('uncaughtException', (err) => {
  parentPort?.postMessage({ type: 'error', error: `Uncaught: ${err.message}` });
});
process.on('unhandledRejection', (reason) => {
  const msg = reason instanceof Error ? reason.message : String(reason);
  parentPort?.postMessage({ type: 'error', error: `Unhandled rejection: ${msg}` });
});

parentPort!.on('message', async (msg: { id: number; type: string; text?: string }) => {
  try {
    if (msg.type === 'load') {
      await loadModel();
      parentPort!.postMessage({ id: msg.id, ok: true });
    } else if (msg.type === 'embed') {
      const data = await embed(msg.text!);
      parentPort!.postMessage({ id: msg.id, ok: true, data });
    } else if (msg.type === 'ping') {
      parentPort!.postMessage({ id: msg.id, ok: true });
    }
  } catch (err: unknown) {
    const message = err instanceof Error ? err.message : String(err);
    parentPort!.postMessage({ id: msg.id, ok: false, error: message });
  }
});

// Signal ready — worker is alive and listening for messages
parentPort!.postMessage({ type: 'ready' });
