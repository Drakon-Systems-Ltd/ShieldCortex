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
import { existsSync } from 'fs';

const __dirname = dirname(fileURLToPath(import.meta.url));

const MODEL_LOAD_TIMEOUT_MS = 120_000;
const INFERENCE_TIMEOUT_MS = 30_000;
const WORKER_UNAVAILABLE_MSG = 'Embedding worker unavailable. Run `npm run build` so dist/embeddings/worker.js exists.';
const WORKER_DISPOSED_MSG = 'Embedding worker disposed';
const WORKER_TIMEOUT_KILL_MSG = 'Embedding worker terminated after a timed-out request';

/**
 * Why a worker instance is gone.
 *
 * 'disposed'/'timeout' are kills we asked for: worker.terminate() reports exit
 * code 1, and reporting that as a crash told users a clean `embed-backfill`
 * had failed. 'crashed'/'exited' are the worker's own doing and stay loud.
 */
type RetireReason = 'disposed' | 'timeout' | 'crashed' | 'exited';

interface PendingRequest {
  resolve: (v: unknown) => void;
  reject: (e: Error) => void;
  timer: ReturnType<typeof setTimeout>;
}

/**
 * One live worker plus everything that describes only that instance. Handlers
 * close over their own handle, so a retired worker's late exit/error event can
 * never null out — or reject the requests of — the worker that replaced it.
 */
interface WorkerHandle {
  worker: Worker;
  ready: boolean;
  retiredReason: RetireReason | null;
  pending: Map<number, PendingRequest>;
}

let current: WorkerHandle | null = null;
let msgId = 0;
let resolvedWorkerPath: string | null | undefined;
let loggedMissingWorker = false;

function getWorkerPath(): string {
  if (resolvedWorkerPath !== undefined) {
    if (resolvedWorkerPath === null) {
      throw new Error(WORKER_UNAVAILABLE_MSG);
    }
    return resolvedWorkerPath;
  }

  const candidates = [
    // In dist/ after compilation, worker.js lives alongside generator.js
    join(__dirname, 'worker.js'),
    // In source-mode development/tests, fall back to built artifact if present.
    join(process.cwd(), 'dist', 'embeddings', 'worker.js'),
  ];

  for (const candidate of candidates) {
    if (existsSync(candidate)) {
      resolvedWorkerPath = candidate;
      return candidate;
    }
  }

  resolvedWorkerPath = null;
  if (!loggedMissingWorker) {
    console.warn(`[shieldcortex] ${WORKER_UNAVAILABLE_MSG}`);
    loggedMissingWorker = true;
  }
  throw new Error(WORKER_UNAVAILABLE_MSG);
}

/** A kill we asked for — its non-zero exit code is not news. */
function isIntentional(reason: RetireReason | null): boolean {
  return reason === 'disposed' || reason === 'timeout';
}

function intentionalMessage(reason: RetireReason | null): string {
  return reason === 'timeout' ? WORKER_TIMEOUT_KILL_MSG : WORKER_DISPOSED_MSG;
}

/** Detach a handle from the module. Keeps the first reason — it is the cause. */
function retire(handle: WorkerHandle, reason: RetireReason): void {
  if (!handle.retiredReason) handle.retiredReason = reason;
  handle.ready = false;
  if (current === handle) current = null;
}

/** Reject every request this handle still owns. Never touches another worker's. */
function settleAll(handle: WorkerHandle, message: string): void {
  for (const [id, p] of handle.pending) {
    handle.pending.delete(id);
    clearTimeout(p.timer);
    p.reject(new Error(message));
  }
}

/**
 * Terminations we have started and not yet seen finish. worker.terminate()
 * settles when the thread is actually gone, so awaiting this is the only
 * honest way to call a disposal complete — including a kill the timeout path
 * started, which disposeModel() has to wait out rather than step over.
 */
let terminationBarrier: Promise<void> = Promise.resolve();

/**
 * Kill a worker for a reason we chose, and record the kill so later disposals
 * and later admissions wait for the thread to actually exit.
 */
function terminateHandle(handle: WorkerHandle, reason: RetireReason, message: string): void {
  // Retire before terminating so the exit this causes is not reported as a
  // crash, and settle in-flight requests explicitly — clearing the map left
  // them to whatever the exit handler said, i.e. a phantom crash.
  retire(handle, reason);
  settleAll(handle, message);
  // Failure to terminate is swallowed, not thrown: disposal runs inside
  // shutdown handlers that call process.exit() on the next line, and the
  // worker's own exit handler still reports anything genuinely unexpected.
  const done = handle.worker.terminate().then(
    () => undefined,
    () => undefined,
  );
  terminationBarrier = Promise.all([terminationBarrier, done]).then(() => undefined);
}

function ensureWorker(): WorkerHandle {
  if (current) return current;

  const handle: WorkerHandle = {
    worker: new Worker(getWorkerPath()),
    ready: false,
    retiredReason: null,
    pending: new Map(),
  };
  current = handle;

  handle.worker.on('message', (msg: { id?: number; type?: string; ok?: boolean; data?: number[]; error?: string }) => {
    if (msg.type === 'ready') {
      handle.ready = true;
      return;
    }
    if (msg.type === 'error') {
      console.error('[shieldcortex] Embedding worker reported error:', msg.error);
      return;
    }
    if (msg.id == null) return;
    const p = handle.pending.get(msg.id);
    if (!p) return;
    handle.pending.delete(msg.id);
    clearTimeout(p.timer);
    if (msg.ok) {
      p.resolve(msg.data);
    } else {
      p.reject(new Error(msg.error || 'Worker error'));
    }
  });

  handle.worker.on('error', (err) => {
    // A real error is never softened, even on a worker we had already retired.
    console.error('[shieldcortex] Embedding worker error:', err.message);
    retire(handle, 'crashed');
    settleAll(handle, 'Worker crashed: ' + err.message);
  });

  handle.worker.on('exit', (code) => {
    const intentional = isIntentional(handle.retiredReason);
    if (!intentional && code !== 0) {
      console.error(`[shieldcortex] Embedding worker exited with code ${code}`);
    }
    const message = intentional
      ? intentionalMessage(handle.retiredReason)
      : `Worker exited with code ${code}`;
    retire(handle, 'exited');
    settleAll(handle, message);
  });

  return handle;
}

function sendMessage(type: string, text?: string, timeoutMs?: number): Promise<unknown> {
  if (process.env.SHIELDCORTEX_SKIP_EMBEDDINGS === '1') {
    return Promise.reject(new Error('Embeddings disabled via SHIELDCORTEX_SKIP_EMBEDDINGS=1'));
  }

  const handle = ensureWorker();
  const id = ++msgId;
  const timeout = timeoutMs || INFERENCE_TIMEOUT_MS;

  return new Promise((resolve, reject) => {
    const timer = setTimeout(() => {
      handle.pending.delete(id);
      // The timeout itself still fails loudly — only the kill we do about it
      // is treated as intentional, so it is not re-reported as a crash.
      reject(new Error(`${type} timed out after ${timeout}ms`));
      terminateHandle(handle, 'timeout', WORKER_TIMEOUT_KILL_MSG);
    }, timeout);

    handle.pending.set(id, { resolve, reject, timer });
    handle.worker.postMessage({ id, type, text });
  });
}

/**
 * A lifecycle is the stretch between two disposeModel() calls. Work is admitted
 * into whichever lifecycle is current when it is CALLED — not when it later
 * gets its turn to run — and from there:
 *
 *  - work whose lifecycle a disposal cancelled settles as disposed instead of
 *    reaching ensureWorker() and resurrecting the worker just shut down;
 *  - work admitted after that disposal belongs to the NEXT lifecycle and waits
 *    on the terminations outstanding when that lifecycle opened (`barrier`)
 *    before it touches a worker, so it can neither race the old worker's exit
 *    nor stand a replacement up beside it. It still runs afterwards — unless a
 *    further disposal cancels its lifecycle in turn.
 *
 * Dispose is a boundary, not a process-wide off switch.
 */
interface Lifecycle {
  cancelled: boolean;
  /** Terminations that were still outstanding when this lifecycle opened. */
  barrier: Promise<void>;
}

let lifecycle: Lifecycle = { cancelled: false, barrier: Promise.resolve() };

/**
 * Gate work on the lifecycle it was admitted into, then hand off to `send`
 * with no await in between: a disposal landing in that gap would otherwise get
 * exactly the replacement worker it is trying to prevent.
 */
async function runInLifecycle<T>(admitted: Lifecycle, send: () => Promise<T>): Promise<T> {
  if (admitted.cancelled) throw new Error(WORKER_DISPOSED_MSG);
  await admitted.barrier;
  if (admitted.cancelled) throw new Error(WORKER_DISPOSED_MSG);
  return send();
}

// Single ONNX worker cannot safely run concurrent embeds — queue them.
let embedChain: Promise<unknown> = Promise.resolve();

/**
 * Generate embedding vector for text
 * @returns Float32Array of 384 dimensions
 */
export async function generateEmbedding(text: string): Promise<Float32Array> {
  const admitted = lifecycle;
  const run = (): Promise<Float32Array> =>
    runInLifecycle(admitted, async () => {
      const data = await sendMessage('embed', text, INFERENCE_TIMEOUT_MS) as number[];
      return new Float32Array(data);
    });
  // Serialize: each call waits for prior embed (success or fail).
  const next = embedChain.then(run, run);
  // Keep chain alive without surfacing rejection to later waiters twice.
  embedChain = next.then(
    () => undefined,
    () => undefined,
  );
  return next;
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
  return current !== null && current.ready;
}

/**
 * Preload the model in the worker thread
 *
 * Admitted exactly like an embed: a preload cannot slip past the boundary and
 * stand a worker up beside one that is still being disposed.
 */
export async function preloadModel(): Promise<void> {
  await runInLifecycle(lifecycle, () => sendMessage('load', undefined, MODEL_LOAD_TIMEOUT_MS));
}

/**
 * Dispose the worker thread and release resources.
 *
 * The boundary is drawn synchronously by the CALL, not by whenever the
 * termination it starts gets to run: work already admitted is cancelled, and
 * work admitted afterwards belongs to the next lifecycle — it waits for this
 * termination rather than racing it, then proceeds unless a further disposal
 * cancels it too.
 *
 * Resolves only once every termination outstanding at the call has finished —
 * this one, a concurrent disposer's, or a kill the timeout path started — so a
 * second shutdown handler cannot reach process.exit() while a worker we killed
 * is still running.
 */
export async function disposeModel(): Promise<void> {
  // Close the current lifecycle first: settling the in-flight request below
  // releases the embed queue, and everything already on it must see the
  // boundary. Done even with no live worker, since queued work may not have
  // started one yet — that is exactly the call that would resurrect it.
  lifecycle.cancelled = true;

  const handle = current;
  if (handle) terminateHandle(handle, 'disposed', WORKER_DISPOSED_MSG);

  // Snapshot after our own kill is registered, so this call waits for that as
  // well as for anything already in flight. The lifecycle we open next is
  // gated on the same snapshot.
  const barrier = terminationBarrier;
  lifecycle = { cancelled: false, barrier };
  await barrier;
}
