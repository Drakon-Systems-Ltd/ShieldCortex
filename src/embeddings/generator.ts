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
/**
 * The exact message a disposal settles cancelled work with.
 *
 * One of THREE things a disposal must carry — see {@link WorkerDisposedError}.
 * The message is what an operator reads and what a near miss is measured
 * against; it is no longer sufficient on its own to make a caller go quiet.
 *
 * Exported so that a caller testing this axis tests the string this module
 * actually produces instead of its own copy of it. Deliberately NOT
 * re-exported from `./index.js`: the barrel is the embedding API other layers
 * consume and stays as it is — this is an internal contract between the
 * generator and the callers that observe its disposals, so they import it
 * from here.
 */
export const WORKER_DISPOSED_MSG = 'Embedding worker disposed';

/**
 * The `code` a disposal error carries, for callers that never see the class.
 *
 * `scripts/lib/save-memory.mjs` is a plain .mjs that loads this contract out of
 * `dist/` at runtime; a future caller may only have the error object. A code is
 * the half of the brand such a caller can check without importing anything.
 */
export const WORKER_DISPOSED_CODE = 'SHIELDCORTEX_EMBEDDING_WORKER_DISPOSED';

/**
 * Registry key for the structural brand — the other half.
 *
 * `Symbol.for` resolves through the cross-realm global symbol registry, so this
 * is the SAME symbol in every module instance: the compiled `dist/` copy a hook
 * loads, the source copy the MCP server runs, and a transpiled sandbox copy in
 * a test are three separate modules whose classes are three separate
 * identities. `instanceof` cannot span them; this can.
 *
 * Exported as the key rather than only as the symbol so a caller in another
 * language runtime — or a test with no import at all — can rebuild it. That
 * openness is deliberate and is the reason this is a collision contract rather
 * than an attestation: rebuildable by anyone who means to, hit by nobody who
 * does not.
 */
export const WORKER_DISPOSED_BRAND_KEY = 'shieldcortex.embeddings.worker-disposed';
const WORKER_DISPOSED_BRAND = Symbol.for(WORKER_DISPOSED_BRAND_KEY);

/**
 * What a disposal settles cancelled work with.
 *
 * The message alone used to BE the contract, and that made the sentence itself
 * a suppression key: any layer under an embed — a SQLite driver, a wrapper, a
 * stale copy of the string — could raise an `Error` reading `Embedding worker
 * disposed` and every caller would treat a genuine failure as a clean shutdown.
 * A disposal now carries the exact message AND the code AND the registry brand,
 * all three, checked by {@link isWorkerDisposedError}.
 *
 * What that is, precisely: a cross-module classification contract against
 * ACCIDENTAL collision — the failure that actually happened. It is not proof of
 * where an error came from and does not try to be. Both halves of the brand are
 * exported constants and `Symbol.for` is a public registry, so anything that
 * wants to be classified as a disposal can be; the point is that nothing does
 * so by accident, which a bare sentence could not promise.
 *
 * Nothing else this module raises is branded — not the timeout, not the kill
 * the timeout performs, not a kill that failed, not a crash. Those are failures
 * and stay loud.
 */
export class WorkerDisposedError extends Error {
  readonly code: string = WORKER_DISPOSED_CODE;

  constructor() {
    super(WORKER_DISPOSED_MSG);
    this.name = 'WorkerDisposedError';
    // Non-enumerable: this must not travel through JSON, a structured clone or
    // a spread and turn a copy of the error into something that gets silenced.
    Object.defineProperty(this, WORKER_DISPOSED_BRAND, { value: true, enumerable: false });
  }
}

const WORKER_TIMEOUT_KILL_MSG = 'Embedding worker terminated after a timed-out request';

/**
 * What a request that could not even be handed to the thread settles with.
 *
 * `postMessage()` is documented to throw for a value the structured clone
 * algorithm refuses, and a throw there means nothing was sent: the worker is
 * untouched, the thread will never answer, and the request is the only
 * casualty. Loud and unbranded, like every other failure in this file.
 */
const SEND_FAILED_MSG = 'Embedding worker request could not be sent';

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
  /**
   * Proof this thread is gone, set by its OWN `exit` event and by nothing else.
   *
   * Distinct from `retiredReason`, which only records that we STOPPED USING a
   * worker — a retirement is a decision, an exit is an observation, and the one
   * invariant in this file that needs the observation is
   * {@link noteTerminationFailure}: a `terminate()` failure reported after this
   * is true has no exit left to clear it, because `exit` fires once.
   */
  exited: boolean;
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

/**
 * True for work `disposeModel()` cancelled, and for nothing raised by accident.
 *
 * A real `Error`, the exact message, the code and the registry brand: all four,
 * because message equality alone is a contract anything under a caller can
 * satisfy without meaning to. The timeout kill, a failed kill, a crash, a
 * timeout, and any message that merely starts with or mentions disposal are
 * failures and stay loud at every caller. The one classifier every caller
 * shares, so "silent" can never widen in one of them without widening here.
 *
 * A deliberate imitation still passes, and is meant to: the constants are
 * exported and the symbol is a registry key, so a `dist/` build, a source copy
 * and a transpiled sandbox copy — three module identities `instanceof` cannot
 * span — agree about one error object. Accidental collision is the axis; forgery
 * is not, and this must not be read as evidence of provenance.
 */
export function isWorkerDisposedError(e: unknown): boolean {
  if (!(e instanceof Error) || e.message !== WORKER_DISPOSED_MSG) return false;
  const branded = e as unknown as { code?: unknown; [key: symbol]: unknown };
  return branded.code === WORKER_DISPOSED_CODE && branded[WORKER_DISPOSED_BRAND] === true;
}

/** A kill we asked for — its non-zero exit code is not news. */
function isIntentional(reason: RetireReason | null): boolean {
  return reason === 'disposed' || reason === 'timeout';
}

/**
 * The error a kill we asked for settles its requests with.
 *
 * Only the disposal branch is branded. A timeout kill reads as what it is —
 * collateral of a request that failed — and must stay loud at every caller.
 */
function intentionalError(reason: RetireReason | null): Error {
  return reason === 'timeout' ? new Error(WORKER_TIMEOUT_KILL_MSG) : new WorkerDisposedError();
}

/** Detach a handle from the module. Keeps the first reason — it is the cause. */
function retire(handle: WorkerHandle, reason: RetireReason): void {
  if (!handle.retiredReason) handle.retiredReason = reason;
  handle.ready = false;
  if (current === handle) current = null;
}

/**
 * Reject every request this handle still owns. Never touches another worker's.
 *
 * `error` is a factory, not an error: each caller gets its own object, so a
 * stack trace belongs to one rejection and nothing is shared across them.
 */
function settleAll(handle: WorkerHandle, error: () => Error): void {
  for (const [id, p] of handle.pending) {
    handle.pending.delete(id);
    clearTimeout(p.timer);
    p.reject(error());
  }
}

const TERMINATION_FAILED_MSG = 'Embedding worker could not be terminated and may still be running';

/**
 * Retired handles whose `terminate()` FAILED, so their thread may still be alive.
 *
 * `worker.terminate()` is documented to return a promise and not to throw, and
 * in practice it does neither wrong — but "the kill I asked for definitely
 * happened" is the assumption every other invariant in this file rests on, and
 * it is exactly the assumption a host that swallows the failure would let us
 * keep. A failed kill means a thread that may still hold the ONNX model, the
 * file handles and the CPU, and standing a second worker up beside it is the
 * one outcome worse than refusing to work at all.
 *
 * So it is tracked per HANDLE, not as a process-wide flag:
 *
 *  - while the set is non-empty, admitted work fails immediately and loudly
 *    (see {@link runInLifecycle}) rather than reaching {@link ensureWorker};
 *  - a handle leaves the set only on its OWN `exit` event, which is the proof
 *    the failed kill did not give us. That listener closes over its handle, so
 *    a late event from some other worker can never clear this one;
 *  - nothing else clears it. Not a timer, not `disposeModel()` — a disposal
 *    cannot make a thread we failed to kill go away.
 *
 * Hence "no permanent latch": a thread that dies of its own accord a second
 * later releases the module, and a process that never sees that exit stays
 * refused, which is the honest answer.
 */
const terminationFailures = new Set<WorkerHandle>();

/**
 * Record a kill that did not happen, and say so once, where it happened.
 *
 * The two events can arrive in EITHER order, and they mean opposite things:
 *
 *  - failure first, exit later (or never) — the thread may still be running,
 *    which is the whole hazard. Tracked, so work is refused until that exit;
 *  - exit first, failure later — the host awaited the real termination and
 *    reported the failure afterwards. The thread is provably gone. Tracking it
 *    here would be permanent by construction: `exit` fires once, and the only
 *    thing that clears a fault is the exit that has already been and gone, so
 *    every embed and preload for the rest of the process would be refused on
 *    behalf of a thread that is not there.
 *
 * Still reported in both cases — a kill that came back a failure is worth
 * knowing about however it landed — and never awaited: after a proven exit
 * this says its line and returns, so nothing downstream blocks on it.
 */
function noteTerminationFailure(handle: WorkerHandle, reason: RetireReason, cause: unknown): void {
  const detail = cause instanceof Error ? cause.message : String(cause);
  if (handle.exited) {
    console.error(
      `[shieldcortex] Embedding worker reported a failed ${reason} kill after that thread had `
      + `already exited — the thread is gone, so new work is not refused: ${detail}`,
    );
    return;
  }
  terminationFailures.add(handle);
  console.error(
    `[shieldcortex] ${TERMINATION_FAILED_MSG} (${reason} kill): ${detail}`,
  );
}

/**
 * Refuse work while any thread we failed to kill may still be running.
 *
 * Deliberately not branded: this is a failure, not a shutdown, and every caller
 * that silences disposals must go loud about this one.
 */
function assertNoTerminationFailure(): void {
  if (terminationFailures.size === 0) return;
  throw new Error(`${TERMINATION_FAILED_MSG} — refusing new embedding work until that thread exits`);
}

/**
 * Terminations we have started and not yet seen finish. worker.terminate()
 * settles when the thread is actually gone, so awaiting this is the only
 * honest way to call a disposal complete — including a kill the timeout path
 * started, which disposeModel() has to wait out rather than step over.
 *
 * A kill that FAILED is finished as far as this barrier is concerned — there is
 * nothing left to wait for — and unfinished as far as {@link terminationFailures}
 * is concerned, because the thread may still be there. Two different facts; a
 * waiter that conflated them would hang for ever on a terminate() that threw.
 */
let terminationBarrier: Promise<void> = Promise.resolve();

/**
 * How many terminations this process has ever started.
 *
 * The barrier is REPLACED by each new kill, so a waiter holding the promise it
 * read a moment ago is holding a barrier that a later termination is not in.
 * That is exactly what the timeout path does — it starts a kill nobody asked
 * for, in between an admission and its turn to run — so a counter is what lets
 * {@link awaitTerminations} tell "the barrier I awaited is current" from "a
 * kill started while I was waiting on the old one".
 */
let terminationsStarted = 0;

/**
 * Wait until no termination this process started is still running.
 *
 * Re-reads the barrier after every await instead of snapshotting it once: a
 * snapshot is only correct if no further kill can start while the waiter is
 * parked, and a timeout can. The loop ends as soon as an await finishes with
 * the counter unchanged, i.e. nothing new was started while it waited.
 *
 * Bounded in practice because `worker.terminate()` always settles and a
 * termination is only started by a disposal or a timed-out request — this does
 * not spin, it parks on a promise per outstanding kill.
 */
async function awaitTerminations(): Promise<void> {
  for (let seen = -1; seen !== terminationsStarted;) {
    seen = terminationsStarted;
    await terminationBarrier;
  }
}

/**
 * Kill a worker for a reason we chose, and record the kill so later disposals
 * and later admissions wait for the thread to actually exit.
 */
function terminateHandle(handle: WorkerHandle, reason: 'disposed' | 'timeout'): void {
  // Retire before terminating so the exit this causes is not reported as a
  // crash, and settle in-flight requests explicitly — clearing the map left
  // them to whatever the exit handler said, i.e. a phantom crash.
  retire(handle, reason);
  settleAll(handle, () => intentionalError(reason));
  // Counted BEFORE the terminate() call, so the kill is visible to anything
  // that reads the barrier in the same turn — including a queued caller
  // released by the very rejection this function just performed.
  terminationsStarted += 1;
  // Failure to terminate is never thrown out of here: disposal runs inside
  // shutdown handlers that call process.exit() on the next line, and the
  // timeout path runs inside a timer callback, where an escaping throw is an
  // uncaught exception that skips the rejection the timed-out caller is waiting
  // for. Both forms are caught — a synchronous throw and a rejected promise —
  // because `terminate()` is a host API and either would be within its rights.
  //
  // Swallowed is NOT the same as ignored: the handle is recorded as a thread we
  // may have failed to kill, which is what stops a replacement being built
  // beside it. `Promise.resolve()` first, so a host returning something other
  // than a promise cannot throw from `.then` either.
  let done: Promise<void>;
  try {
    done = Promise.resolve(handle.worker.terminate()).then(
      () => undefined,
      (err) => noteTerminationFailure(handle, reason, err),
    );
  } catch (err) {
    noteTerminationFailure(handle, reason, err);
    // Nothing is still running that a waiter could wait for, so the barrier
    // gets a settled promise rather than a hole: the counter above is already
    // bumped, and a barrier that never resolved would strand every admitted
    // caller in awaitTerminations() instead of failing them.
    done = Promise.resolve();
  }
  terminationBarrier = Promise.all([terminationBarrier, done]).then(() => undefined);
}

function ensureWorker(): WorkerHandle {
  if (current) return current;

  const handle: WorkerHandle = {
    worker: new Worker(getWorkerPath()),
    ready: false,
    retiredReason: null,
    exited: false,
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
    settleAll(handle, () => new Error('Worker crashed: ' + err.message));
  });

  handle.worker.on('exit', (code) => {
    const reason = handle.retiredReason;
    const intentional = isIntentional(reason);
    // The proof a failed kill did not give us: THIS thread is gone. Keyed on the
    // handle this listener closed over, so a late event from a worker we
    // replaced cannot clear a fault that belongs to another one.
    //
    // Recorded on the handle as well as used to clear, because a failure report
    // can arrive AFTER this event and there is no second exit behind it. See
    // {@link noteTerminationFailure}.
    handle.exited = true;
    terminationFailures.delete(handle);
    if (!intentional && code !== 0) {
      console.error(`[shieldcortex] Embedding worker exited with code ${code}`);
    }
    retire(handle, 'exited');
    settleAll(handle, () => (intentional
      ? intentionalError(reason)
      : new Error(`Worker exited with code ${code}`)));
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
      // Register the kill BEFORE the caller is told, not after. Settling this
      // request releases the embed queue, and everything already on it has to
      // find this termination in the barrier — a queued embed that ran first
      // would call ensureWorker() and stand a replacement up beside a thread
      // we are still killing.
      // try/finally, not a bare call: the rejection below is this request's
      // only remaining path to its caller, and it must not depend on what
      // terminateHandle() does internally. terminateHandle() already contains
      // its own failures; this makes the guarantee local to the one place where
      // losing it strands a caller for the lifetime of the process.
      try {
        terminateHandle(handle, 'timeout');
      } finally {
        // The timeout itself still fails loudly — only the kill we do about it
        // is treated as intentional, so it is not re-reported as a crash.
        reject(new Error(`${type} timed out after ${timeout}ms`));
      }
    }, timeout);

    handle.pending.set(id, { resolve, reject, timer });
    try {
      handle.worker.postMessage({ id, type, text });
    } catch (err) {
      // The request never left this thread, so nothing will ever answer it —
      // and the timer above is now armed on behalf of a request that does not
      // exist. Left installed it fires on its own schedule and calls
      // terminateHandle() on whichever worker this handle is by then, settling
      // that worker's unrelated requests with the timeout kill's collateral
      // error. Both halves of the registration are undone in the same turn the
      // send failed, before anything can await.
      handle.pending.delete(id);
      clearTimeout(timer);
      // The worker itself is NOT retired: a postMessage that threw never
      // reached it, so it is exactly as healthy as it was a line ago and the
      // next request reuses it.
      const detail = err instanceof Error ? err.message : String(err);
      reject(new Error(`${SEND_FAILED_MSG} (${type}): ${detail}`));
    }
  });
}

/**
 * A lifecycle is the stretch between two disposeModel() calls. Work is admitted
 * into whichever lifecycle is current when it is CALLED — not when it later
 * gets its turn to run — and from there:
 *
 *  - work whose lifecycle a disposal cancelled settles as disposed instead of
 *    reaching ensureWorker() and resurrecting the worker just shut down;
 *  - work admitted while a thread we failed to kill may still be running fails
 *    loudly and at once, again without reaching ensureWorker(). See
 *    {@link terminationFailures}: that one is not a boundary, it is a fault;
 *  - all other work waits out every termination still running when it gets its
 *    turn before it touches a worker, so it can neither race a dying worker's
 *    exit nor stand a replacement up beside it. It still runs afterwards —
 *    unless a further disposal cancels its lifecycle in turn.
 *
 * The wait is deliberately NOT a snapshot taken when the lifecycle opened. A
 * timeout starts a termination inside a lifecycle, with no disposal involved
 * and no new lifecycle to carry it: work admitted before that timeout would
 * hold a barrier the kill is not in, and the first queued caller released by
 * the timed-out request would build the replacement. See
 * {@link awaitTerminations}.
 *
 * Dispose is a boundary, not a process-wide off switch.
 */
interface Lifecycle {
  cancelled: boolean;
}

let lifecycle: Lifecycle = { cancelled: false };

/**
 * Gate work on the lifecycle it was admitted into, then hand off to `send`
 * with no await in between: a disposal landing in that gap would otherwise get
 * exactly the replacement worker it is trying to prevent.
 */
async function runInLifecycle<T>(admitted: Lifecycle, send: () => Promise<T>): Promise<T> {
  if (admitted.cancelled) throw new WorkerDisposedError();
  // Before the wait, so work admitted after a failed kill is refused at once
  // rather than parking first...
  assertNoTerminationFailure();
  await awaitTerminations();
  if (admitted.cancelled) throw new WorkerDisposedError();
  // ...and again after it, because a kill can start AND fail while a caller is
  // parked here — that is precisely the timeout path — and because a rejected
  // terminate() records its failure one microtask after the barrier is armed.
  // Cancellation is checked first in both places: a caller whose lifecycle a
  // disposal closed asked for exactly this, and gets the quiet answer.
  assertNoTerminationFailure();
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
 *
 * Never throws, and that is a requirement rather than an observation: every
 * caller is a shutdown path whose next statement is `process.exit(0)`. A
 * `terminate()` that fails is recorded (see {@link terminationFailures}) and
 * this call still returns — it cannot make such a thread go away, and refusing
 * to return would only hang the shutdown on top of it.
 */
export async function disposeModel(): Promise<void> {
  // Close the current lifecycle first: settling the in-flight request below
  // releases the embed queue, and everything already on it must see the
  // boundary. Done even with no live worker, since queued work may not have
  // started one yet — that is exactly the call that would resurrect it.
  lifecycle.cancelled = true;

  const handle = current;
  if (handle) terminateHandle(handle, 'disposed');

  // Snapshotted AFTER our own kill is registered, so this call waits for that
  // as well as for anything already in flight — and only for those. A caller
  // shutting down must not be held open indefinitely by kills that start later;
  // work admitted later waits for those itself, in runInLifecycle().
  const barrier = terminationBarrier;
  lifecycle = { cancelled: false };
  await barrier;
}
