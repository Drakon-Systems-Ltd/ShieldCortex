/**
 * Embedding generator using a worker thread for ONNX operations.
 *
 * The ONNX runtime does synchronous C++ work that blocks the Node.js event loop.
 * setTimeout/Promise.race timeouts can't fire while blocked. Moving ONNX to a
 * Worker thread keeps the main thread responsive for MCP messages.
 */
import { Worker } from 'worker_threads';
import { join, dirname } from 'path';
import { fileURLToPath } from 'url';

const __dirname = dirname(fileURLToPath(import.meta.url));

const MODEL_LOAD_TIMEOUT_MS = 30_000;
const INFERENCE_TIMEOUT_MS = 10_000;

let worker: Worker | null = null;
let workerReady = false;
let msgId = 0;
const pending = new Map<number, { resolve: (v: unknown) => void; reject: (e: Error) => void; timer: ReturnType<typeof setTimeout> }>();

function getWorkerPath(): string {
  // In dist/ after compilation, worker.js lives alongside generator.js
  return join(__dirname, 'worker.js');
}

function ensureWorker(): Worker {
  if (worker) return worker;

  worker = new Worker(getWorkerPath());

  worker.on('message', (msg: { id?: number; type?: string; ok?: boolean; data?: number[]; error?: string }) => {
    if (msg.type === 'ready') {
      workerReady = true;
      return;
    }
    if (msg.id == null) return;
    const p = pending.get(msg.id);
    if (!p) return;
    pending.delete(msg.id);
    clearTimeout(p.timer);
    if (msg.ok) {
      p.resolve(msg.data);
    } else {
      p.reject(new Error(msg.error || 'Worker error'));
    }
  });

  worker.on('error', (err) => {
    console.error('[shieldcortex] Embedding worker error:', err.message);
    // Reject all pending
    for (const [id, p] of pending) {
      clearTimeout(p.timer);
      p.reject(new Error('Worker crashed: ' + err.message));
      pending.delete(id);
    }
    worker = null;
    workerReady = false;
  });

  worker.on('exit', (code) => {
    if (code !== 0) {
      console.error(`[shieldcortex] Embedding worker exited with code ${code}`);
    }
    worker = null;
    workerReady = false;
    // Reject all pending
    for (const [id, p] of pending) {
      clearTimeout(p.timer);
      p.reject(new Error(`Worker exited with code ${code}`));
      pending.delete(id);
    }
  });

  return worker;
}

function sendMessage(type: string, text?: string, timeoutMs?: number): Promise<unknown> {
  if (process.env.SHIELDCORTEX_SKIP_EMBEDDINGS === '1') {
    return Promise.reject(new Error('Embeddings disabled via SHIELDCORTEX_SKIP_EMBEDDINGS=1'));
  }

  const w = ensureWorker();
  const id = ++msgId;
  const timeout = timeoutMs || INFERENCE_TIMEOUT_MS;

  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => {
      pending.delete(id);
      reject(new Error(`${type} timed out after ${timeout}ms`));
      // Kill the hung worker so next call gets a fresh one
      if (worker) {
        worker.terminate();
        worker = null;
        workerReady = false;
      }
    }, timeout);

    pending.set(id, { resolve, reject, timer });
    w.postMessage({ id, type, text });
  });
}

/**
 * Generate embedding vector for text
 * @returns Float32Array of 384 dimensions
 */
export async function generateEmbedding(text: string): Promise<Float32Array> {
  const data = await sendMessage('embed', text, INFERENCE_TIMEOUT_MS) as number[];
  return new Float32Array(data);
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
 * Check if embedding model is loaded (worker is alive and ready)
 */
export function isModelLoaded(): boolean {
  return worker !== null && workerReady;
}

/**
 * Preload the model in the worker thread
 */
export async function preloadModel(): Promise<void> {
  await sendMessage('load', undefined, MODEL_LOAD_TIMEOUT_MS);
}

/**
 * Dispose the worker thread and release resources.
 */
export async function disposeModel(): Promise<void> {
  if (worker) {
    await worker.terminate();
    worker = null;
    workerReady = false;
  }
  pending.clear();
}
