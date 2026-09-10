import fs from 'fs';
import os from 'os';
import path from 'path';
import { spawnSync } from 'child_process';
import { afterAll, beforeAll, describe, expect, it } from '@jest/globals';
import ts from 'typescript';

/**
 * A successful `memories embed-backfill` embedded 106/106 missing rows and
 * exited 0 — and still printed
 *   [shieldcortex] Embedding worker exited with code 1
 * because disposeModel() calls worker.terminate(), whose exit code is 1, and
 * the exit handler logged unconditionally. False crash UX after a clean repair.
 *
 * These tests run generator.ts against a FAKE worker (never the real ONNX
 * model): the source is transpiled into a throwaway ESM sandbox next to a
 * stub worker.js, and driven from a child process so the real
 * console.error/stderr surface — the thing the user actually saw — is what we
 * assert on. Each scenario gets its own process, so module state is isolated.
 * (generator.ts imports node builtins only — a future relative import would
 * have to be copied into the sandbox alongside it.)
 *
 * TWO lines of the source are rewritten on the way in, and both rewrites throw
 * if their target ever moves rather than silently dropping the coverage:
 *
 *  - INFERENCE_TIMEOUT_MS becomes env-overridable, so the timeout scenario can
 *    drive the real timeout path in under a second instead of 30. Every other
 *    scenario leaves the env unset and runs the shipped 30s value.
 *  - the `worker_threads` import is redirected to a test-owned shim, so a
 *    scenario can make `Worker#terminate()` FAIL — the one thing a real Worker
 *    will not do on request — and can make `Worker#postMessage()` throw, which
 *    a real one does only for a payload the structured clone algorithm refuses.
 *    With none of the shim's knobs set it re-exports the real class by
 *    identity, so every other scenario in this file is driving
 *    `worker_threads.Worker` itself and nothing else.
 *
 * Both live in test-owned files. The generator carries no seam for either.
 */

const repoRoot = path.resolve(process.cwd());
const GENERATOR_SRC = path.join(repoRoot, 'src', 'embeddings', 'generator.ts');
const RESULT_PREFIX = '__RESULT__ ';

/**
 * The disposal contract, written out as literals — here and nowhere else.
 *
 * Every other caller in the repository imports these from `generator.ts`, so a
 * change to any of the three fails HERE, once, instead of quietly agreeing with
 * itself everywhere. All three matter to a consumer:
 *
 *  - the message is what an operator reads;
 *  - the `code` is what a caller with no access to the class can check;
 *  - the brand KEY is a `Symbol.for` registry name, which is what makes the
 *    brand survive a module boundary. A hook's `dist/` build and this file's
 *    transpiled sandbox copy are two different module instances: `instanceof`
 *    across them is false, and a registry symbol is the same symbol.
 */
const DISPOSED_MSG = 'Embedding worker disposed';
const DISPOSED_CODE = 'SHIELDCORTEX_EMBEDDING_WORKER_DISPOSED';
const DISPOSED_BRAND_KEY = 'shieldcortex.embeddings.worker-disposed';

const TIMEOUT_DECL = 'const INFERENCE_TIMEOUT_MS = 30_000;';
const TIMEOUT_DECL_TEST =
  'const INFERENCE_TIMEOUT_MS = Number(process.env.SC_TEST_INFERENCE_TIMEOUT_MS) || 30_000;';

const WORKER_IMPORT = "import { Worker } from 'worker_threads';";
const WORKER_IMPORT_TEST = "import { Worker } from './worker-threads-shim.js';";

/**
 * What the module says when a kill it asked for did not happen.
 *
 * Pinned as a literal here for the same reason the disposal contract is: this
 * sentence is what an operator reads and what every caller of an embed sees
 * instead of a vector, so a change to it fails here rather than agreeing with
 * itself. Deliberately NOT the disposal brand — a thread we could not kill is
 * a failure, and a failure is loud everywhere.
 */
const TERMINATION_FAILED = 'Embedding worker could not be terminated';

/**
 * What the module says when the kill it asked for was reported as failed AFTER
 * that thread had provably exited.
 *
 * A different sentence from {@link TERMINATION_FAILED} on purpose, and pinned
 * separately, because the two say opposite things about what happens next: one
 * refuses every subsequent embed and preload until an exit arrives, and this
 * one is a note about a kill whose exit has ALREADY arrived. Reporting the
 * failure is still right — a host that could not kill a thread is worth
 * knowing about — but there is nothing left to refuse work on behalf of.
 */
const TERMINATION_FAILED_AFTER_EXIT = 'after that thread had already exited';

/**
 * What a request that could not even be handed to the thread settles with.
 *
 * `postMessage()` throwing means nothing was sent, so the worker is untouched
 * and the request is the only casualty. Loud and unbranded: a send that failed
 * is a failure, not a shutdown.
 */
const SEND_FAILED = 'Embedding worker request could not be sent';

/**
 * A `Worker` whose `terminate()` or `postMessage()` fails, and nothing else.
 *
 * Test-owned, written into the sandbox beside the transpiled generator. The
 * real class is what a scenario gets unless one of the knobs below selects a
 * fault — not a pass-through wrapper around it, the class itself, so the
 * scenarios that say nothing about failure are driving exactly what they were
 * driving before this shim existed.
 *
 *   SC_TEST_TERMINATE_MODE           'sync-throw' | 'async-reject'
 *                                    | 'reject-after-exit' | 'reject-before-exit'
 *   SC_TEST_TERMINATE_RECOVER_INDEX  1-based spawn whose thread dies ANYWAY,
 *                                    a short while after its terminate() failed
 *   SC_TEST_TERMINATE_RECOVER_MS     how long after
 *   SC_TEST_TERMINATE_KILL_FLAG      'reject-before-exit' only: the thread of
 *                                    spawn N dies when `<flag>.N` exists, so the
 *                                    driver decides WHEN the exit arrives
 *   SC_TEST_POSTMESSAGE_FAIL_COUNT   how many postMessage() calls throw, from
 *                                    the first, counted across the process
 *
 * The two orderings a failed kill can arrive in are both deterministic here,
 * and they are opposite hazards:
 *
 *  - 'reject-before-exit' reports the failure while the thread is genuinely
 *    still running. Work must be refused, and released only by that thread's
 *    own exit — which the driver triggers by hand rather than by a timer, so
 *    the refusal window is observed instead of raced;
 *  - 'reject-after-exit' really kills the thread and reports the failure only
 *    once that handle's `exit` event has been delivered. There is no exit left
 *    to clear a fault installed at that point, so a fault installed there is
 *    permanent — for a thread that is provably gone.
 *
 * A failing terminate() that does not recover genuinely leaves the thread
 * running: that is the whole hazard, and it is why those scenarios end with an
 * explicit process.exit(0) rather than an empty event loop.
 */
const WORKER_SHIM = [
  "import { Worker as RealWorker } from 'worker_threads';",
  "import { existsSync } from 'fs';",
  '',
  "const MODE = process.env.SC_TEST_TERMINATE_MODE || '';",
  'const RECOVER_INDEX = Number(process.env.SC_TEST_TERMINATE_RECOVER_INDEX || 0);',
  'const RECOVER_MS = Number(process.env.SC_TEST_TERMINATE_RECOVER_MS || 0);',
  "const KILL_FLAG = process.env.SC_TEST_TERMINATE_KILL_FLAG || '';",
  'const SEND_FAILURES = Number(process.env.SC_TEST_POSTMESSAGE_FAIL_COUNT || 0);',
  '',
  'let spawnCount = 0;',
  'let sendFailuresLeft = SEND_FAILURES;',
  '',
  'class FaultInjectingWorker extends RealWorker {',
  '  #index;',
  '  #failed = false;',
  '  constructor(...args) {',
  '    super(...args);',
  '    this.#index = ++spawnCount;',
  '  }',
  '  postMessage(...args) {',
  '    // A synchronous send failure — what a payload the structured clone',
  '    // algorithm refuses raises. Counted across the process rather than per',
  '    // worker, so a scenario can fail exactly the first request and leave the',
  '    // worker itself untouched: postMessage throwing means nothing was sent.',
  '    if (sendFailuresLeft > 0) {',
  '      sendFailuresLeft -= 1;',
  "      throw new Error('fake postMessage failure');",
  '    }',
  '    return super.postMessage(...args);',
  '  }',
  '  terminate() {',
  '    // The send knob is independent of this one: a scenario that only fails',
  '    // postMessage() gets a terminate() that really works.',
  '    if (!MODE) return super.terminate();',
  '    // One failure per worker: a retry is a different question, and the',
  '    // recovery path below needs a terminate() that can still work.',
  '    if (this.#failed) return super.terminate();',
  '    this.#failed = true;',
  "    if (MODE === 'reject-after-exit') {",
  "      // The kill LANDS. The failure is reported only once this handle's own",
  "      // exit event has been delivered: this listener is registered inside",
  "      // terminate(), i.e. after the module's own (attached at construction),",
  '      // and an emitter calls listeners in registration order.',
  "      const exited = new Promise((resolve) => { this.once('exit', resolve); });",
  '      super.terminate();',
  "      return exited.then(() => { throw new Error('fake terminate failure (after exit)'); });",
  '    }',
  "    if (MODE === 'reject-before-exit') {",
  '      // The thread stays alive until the driver says otherwise, so the window',
  '      // in which the module is refusing work is one a driver can step into.',
  '      if (KILL_FLAG) {',
  "        const flag = KILL_FLAG + '.' + this.#index;",
  '        const poll = setInterval(() => {',
  '          if (!existsSync(flag)) return;',
  '          clearInterval(poll);',
  '          super.terminate();',
  '        }, 10);',
  '      }',
  "      return Promise.reject(new Error('fake terminate failure (before exit)'));",
  '    }',
  '    if (this.#index === RECOVER_INDEX) {',
  '      // The thread dies on its own later. Its exit event is the only thing',
  "      // that may clear this handle's fault.",
  '      setTimeout(() => { super.terminate(); }, RECOVER_MS);',
  '    }',
  "    if (MODE === 'sync-throw') throw new Error('fake terminate failure (sync)');",
  "    return Promise.reject(new Error('fake terminate failure (async)'));",
  '  }',
  '}',
  '',
  '// Identity, not delegation: with no fault selected this IS worker_threads.Worker.',
  'export const Worker = MODE || SEND_FAILURES > 0 ? FaultInjectingWorker : RealWorker;',
  '',
].join('\n');

/**
 * Stub worker. Behaviour is selected by the text of the embed request so the
 * driver can steer it without any extra channel:
 *  - __CRASH_EXIT__  : die with a non-zero exit code, unprompted
 *  - __CRASH_THROW__ : die from an uncaught error, unprompted
 *  - __HANG__        : accept the request and never answer
 *  - __BLOCK_EXIT__  : never answer, and block the thread in native code so
 *                      terminate() cannot land for ~600ms. The blocking child
 *                      announces itself in SC_FAKE_WORKER_BLOCK once the
 *                      thread is committed, so the driver never disposes
 *                      during the killable JS window before the block.
 * A 'load' request hangs the same way whenever the file named by
 * SC_FAKE_WORKER_HANG_LOAD exists, so the driver can catch preloadModel()
 * mid-flight and then flip the same worker back to answering.
 * Every instance appends its threadId to SC_FAKE_WORKER_LOG on startup, so the
 * driver can count how many workers were spawned. A hanging instance also
 * heartbeats its threadId into SC_FAKE_WORKER_BEAT every 10ms: an intentional
 * kill is silent by design, so the moment the heartbeat stops is the only
 * observable proof that that thread is gone.
 */
const FAKE_WORKER = [
  "import { parentPort, threadId } from 'worker_threads';",
  "import { appendFileSync, existsSync } from 'fs';",
  "import { spawnSync } from 'child_process';",
  '',
  'const mark = (file, line) => {',
  '  if (!file) return;',
  "  try { appendFileSync(file, line + '\\n'); } catch { /* sandbox torn down */ }",
  '};',
  '',
  '// Runs in a child process, so it only reports the block once this thread is',
  '// already inside the uninterruptible native call that spawned it.',
  "const BLOCK_CHILD = 'require(\"fs\").appendFileSync(process.env.SC_FAKE_WORKER_BLOCK, \"blocking\"); Atomics.wait(new Int32Array(new SharedArrayBuffer(4)), 0, 0, 600);';",
  '',
  'mark(process.env.SC_FAKE_WORKER_LOG, threadId);',
  '',
  "parentPort.postMessage({ type: 'ready' });",
  '',
  "parentPort.on('message', (msg) => {",
  "  const text = typeof msg?.text === 'string' ? msg.text : '';",
  "  // A flagged 'load' never answers, so a model load can be caught in flight.",
  "  if (msg?.type === 'load' && existsSync(process.env.SC_FAKE_WORKER_HANG_LOAD || '')) return;",
  "  if (text.includes('__CRASH_EXIT__')) { process.exit(3); }",
  "  if (text.includes('__CRASH_THROW__')) {",
  "    setTimeout(() => { throw new Error('fake worker boom'); }, 10);",
  '    return;',
  '  }',
  "  if (text.includes('__BLOCK_EXIT__')) {",
  '    // Uninterruptible native wait: V8 can interrupt a JS loop or an',
  '    // Atomics.wait, but not a spawnSync, so terminate() genuinely takes',
  '    // ~600ms and a caller that returns early is visible in the clock.',
  "    spawnSync(process.execPath, ['-e', BLOCK_CHILD]);",
  '    return;',
  '  }',
  "  if (text.includes('__HANG__')) {",
  '    if (process.env.SC_FAKE_WORKER_BEAT) {',
  '      setInterval(() => mark(process.env.SC_FAKE_WORKER_BEAT, threadId), 10);',
  '    }',
  '    return;',
  '  }',
  '  parentPort.postMessage({ id: msg.id, ok: true, data: [0.1, 0.2, 0.3] });',
  '});',
  '',
].join('\n');

const DRIVER = [
  "import fs from 'fs';",
  "import { setTimeout as delay } from 'timers/promises';",
  "import { generateEmbedding, disposeModel, isModelLoaded, preloadModel } from './generator.js';",
  // The disposal CONTRACT, taken as a namespace on purpose: a named import of an
  // export the module does not have is a link-time SyntaxError, which would fail
  // every scenario in this file for one missing symbol instead of failing the
  // scenario that asks for it.
  "import * as contract from './generator.js';",
  '',
  // The one place these literals are spelled out is the TypeScript constants
  // above; the driver receives them rather than keeping a second copy.
  `const MESSAGE = ${JSON.stringify(DISPOSED_MSG)};`,
  `const CODE = ${JSON.stringify(DISPOSED_CODE)};`,
  `const BRAND = Symbol.for(${JSON.stringify(DISPOSED_BRAND_KEY)});`,
  '',
  'const scenario = process.argv[2];',
  "const out = (obj) => fs.writeSync(1, '__RESULT__ ' + JSON.stringify(obj) + '\\n');",
  "process.on('unhandledRejection', (e) => { out({ fatal: e instanceof Error ? e.message : String(e) }); process.exit(1); });",
  'const msgOf = (e) => (e instanceof Error ? e.message : String(e));',
  "const settle = (p) => p.then(() => ({ state: 'resolved', message: '' }), (e) => ({ state: 'rejected', message: msgOf(e) }));",
  "const settleDims = (p) => p.then((v) => ({ state: 'resolved', message: '', dims: v.length }), (e) => ({ state: 'rejected', message: msgOf(e), dims: -1 }));",
  "const hung = { state: 'hung', message: '', dims: -1 };",
  'const readLines = (file) => {',
  '  try {',
  "    return fs.readFileSync(file, 'utf8').split('\\n').filter(Boolean);",
  '  } catch { return []; }',
  '};',
  'const spawnedIds = () => readLines(process.env.SC_FAKE_WORKER_LOG);',
  'const spawned = () => spawnedIds().length;',
  'const beatsFrom = (id) => readLines(process.env.SC_FAKE_WORKER_BEAT).filter((l) => l === id).length;',
  '// Wait on a condition, never on a guess. Returns false if it never held, so',
  '// a scenario that stops testing its dimension fails instead of passing.',
  'const waitFor = async (pred, ms = 5000) => {',
  '  const deadline = Date.now() + ms;',
  '  while (Date.now() < deadline) {',
  '    if (pred()) return true;',
  '    await delay(5);',
  '  }',
  '  return false;',
  '};',
  '// Tee console.error so the driver can await a log line the module emits,',
  '// while the real stderr the user sees still carries it.',
  'const logged = [];',
  'const realError = console.error;',
  "console.error = (...args) => { logged.push(args.map(String).join(' ')); realError(...args); };",
  'const sawLog = (re) => logged.some((line) => re.test(line));',
  '',
  "if (scenario === 'dispose-after-success') {",
  "  const vec = await generateEmbedding('hello world');",
  '  const loadedBefore = isModelLoaded();',
  '  await disposeModel();',
  '  await delay(300); // give any late exit event time to log',
  '  out({ dims: vec.length, loadedBefore, loadedAfter: isModelLoaded(), spawned: spawned() });',
  "} else if (scenario === 'unexpected-exit') {",
  '  let rejected = false;',
  "  let message = '';",
  "  try { await generateEmbedding('__CRASH_EXIT__'); } catch (e) { rejected = true; message = msgOf(e); }",
  '  await delay(300);',
  '  out({ rejected, message, loadedAfter: isModelLoaded(), spawned: spawned() });',
  "} else if (scenario === 'dispose-with-pending') {",
  "  const settled = settle(generateEmbedding('__HANG__'));",
  '  await waitFor(() => spawned() >= 1); // the stub worker has the request',
  '  const startedAt = Date.now();',
  '  await disposeModel();',
  '  const disposeMs = Date.now() - startedAt;',
  "  const outcome = await Promise.race([settled, delay(2000).then(() => ({ state: 'hung', message: '' }))]);",
  '  out({ ...outcome, disposeMs, loadedAfter: isModelLoaded(), spawned: spawned() });',
  "} else if (scenario === 'dispose-cancels-queued') {",
  "  const active = settle(generateEmbedding('__HANG__'));",
  "  const queuedA = settle(generateEmbedding('queued-a'));",
  "  const queuedB = settle(generateEmbedding('queued-b'));",
  '  await waitFor(() => spawned() >= 1); // the active request owns a live worker',
  '  await disposeModel();',
  '  const outcomes = await Promise.race([',
  '    Promise.all([active, queuedA, queuedB]),',
  "    delay(3000).then(() => 'hung'),",
  '  ]);',
  '  await delay(300); // a worker resurrected by queued work appears in this window',
  '  out({ outcomes, spawned: spawned(), loadedAfter: isModelLoaded() });',
  "} else if (scenario === 'concurrent-dispose') {",
  "  const blocked = settle(generateEmbedding('__BLOCK_EXIT__'));",
  '  const reachedBlock = await waitFor(() => readLines(process.env.SC_FAKE_WORKER_BLOCK).length > 0);',
  '  const startedAt = Date.now();',
  '  const firstCall = disposeModel().then(() => Date.now() - startedAt);',
  '  const secondCall = disposeModel().then(() => Date.now() - startedAt);',
  '  const [firstMs, secondMs] = await Promise.all([firstCall, secondCall]);',
  '  const outcome = await blocked;',
  '  await delay(200);',
  '  out({',
  '    reachedBlock,',
  '    firstMs,',
  '    secondMs,',
  '    blockedState: outcome.state,',
  '    blockedMessage: outcome.message,',
  '    spawned: spawned(),',
  '    loadedAfter: isModelLoaded(),',
  '  });',
  "} else if (scenario === 'timeout-then-replacement') {",
  "  let timeoutMessage = '';",
  "  try { await generateEmbedding('__HANG__'); } catch (e) { timeoutMessage = msgOf(e); }",
  '  const staleId = spawnedIds()[0];',
  '  const beatsBeforeReplacement = beatsFrom(staleId);',
  '  let second = -1;',
  "  let secondError = '';",
  '  // The replacement is created here — after the timed-out kill has landed,',
  '  // because this call waits it out. The dead thread\'s exit event still',
  '  // arrives around now and must not poison worker B.',
  "  try { second = (await generateEmbedding('ok-after-timeout')).length; } catch (e) { secondError = msgOf(e); }",
  '  const loadedRightAfterReplacement = isModelLoaded();',
  '  // The kill we asked for logs nothing, so wait for the dead thread to stop',
  '  // heartbeating rather than sleeping and hoping its exit event landed.',
  '  let lastBeats = beatsFrom(staleId);',
  '  let quietSince = Date.now();',
  '  const staleWorkerGone = await waitFor(() => {',
  '    const now = beatsFrom(staleId);',
  '    if (now !== lastBeats) { lastBeats = now; quietSince = Date.now(); return false; }',
  '    return Date.now() - quietSince > 150;',
  '  });',
  '  const loadedAfterStaleExit = isModelLoaded();',
  '  let third = -1;',
  "  let thirdError = '';",
  "  try { third = (await generateEmbedding('ok-3')).length; } catch (e) { thirdError = msgOf(e); }",
  '  const spawnedAfterThird = spawned();',
  '  await disposeModel();',
  '  out({',
  '    timeoutMessage,',
  '    beatsBeforeReplacement,',
  '    second,',
  '    secondError,',
  '    loadedRightAfterReplacement,',
  '    staleWorkerGone,',
  '    loadedAfterStaleExit,',
  '    third,',
  '    thirdError,',
  '    spawned: spawnedAfterThird,',
  '  });',
  "} else if (scenario === 'new-request-after-dispose') {",
  "  const before = (await generateEmbedding('ok-1')).length;",
  '  await disposeModel();',
  '  const loadedAfterDispose = isModelLoaded();',
  '  let after = -1;',
  "  let afterError = '';",
  "  try { after = (await generateEmbedding('ok-2')).length; } catch (e) { afterError = msgOf(e); }",
  '  const loadedAfterRestart = isModelLoaded();',
  '  await disposeModel();',
  '  await delay(300);',
  '  out({',
  '    before,',
  '    after,',
  '    afterError,',
  '    loadedAfterDispose,',
  '    loadedAfterRestart,',
  '    loadedAtEnd: isModelLoaded(),',
  '    spawned: spawned(),',
  '  });',
  "} else if (scenario === 'stale-exit-isolation') {",
  "  const first = await generateEmbedding('ok-1');",
  "  let crashMessage = '';",
  '  let second = -1;',
  "  let secondError = '';",
  '  try {',
  "    second = (await generateEmbedding('__CRASH_THROW__').then(",
  "      () => { throw new Error('crash embed unexpectedly resolved'); },",
  '      (e) => {',
  '        crashMessage = msgOf(e);',
  "        return generateEmbedding('ok-2'); // worker B is created here, before worker A's exit event lands",
  '      },',
  '    )).length;',
  '  } catch (e) { secondError = msgOf(e); }',
  '  const loadedRightAfterReplacement = isModelLoaded();',
  "  // Worker A's exit handler logging is the event itself, not a proxy for it:",
  '  // wait for that line instead of sleeping past where it usually lands. That',
  "  // line exists because a 'crashed' worker logs both error and exit; deduping",
  '  // the pair would flip this gate to false and fail here — fail-closed, but a',
  '  // test-coupling failure, not a product regression.',
  '  const staleExitObserved = await waitFor(() => sawLog(/Embedding worker exited with code/));',
  '  const loadedAfterStaleExit = isModelLoaded();',
  '  let third = -1;',
  "  let thirdError = '';",
  "  try { third = (await generateEmbedding('ok-3')).length; } catch (e) { thirdError = msgOf(e); }",
  '  const spawnedAfterThird = spawned();',
  '  await disposeModel();',
  '  out({',
  '    first: first.length,',
  '    crashMessage,',
  '    second,',
  '    secondError,',
  '    loadedRightAfterReplacement,',
  '    staleExitObserved,',
  '    loadedAfterStaleExit,',
  '    third,',
  '    thirdError,',
  '    spawned: spawnedAfterThird,',
  '  });',
  "} else if (scenario === 'dispose-then-generate') {",
  "  const first = (await generateEmbedding('ok-1')).length;",
  '  // Same synchronous turn, dispose deliberately not awaited: the boundary is',
  '  // drawn by the CALL, so this request belongs to the lifecycle it opened and',
  '  // must run once the termination it inherited is done — not be cancelled.',
  '  const disposal = disposeModel();',
  "  const admitted = settleDims(generateEmbedding('ok-2'));",
  '  await disposal;',
  '  const after = await Promise.race([admitted, delay(3000).then(() => hung)]);',
  '  // Same ordering again, but a second dispose closes the lifecycle this one',
  '  // was admitted into: now it must be cancelled rather than started.',
  '  const firstOfPair = disposeModel();',
  "  const cancelled = settleDims(generateEmbedding('ok-3'));",
  '  const secondOfPair = disposeModel();',
  '  await Promise.all([firstOfPair, secondOfPair]);',
  '  const cancelledOutcome = await Promise.race([cancelled, delay(3000).then(() => hung)]);',
  '  await delay(300); // a worker woken by cancelled work would appear here',
  '  out({',
  '    first,',
  '    afterState: after.state,',
  '    afterDims: after.dims,',
  '    afterMessage: after.message,',
  '    cancelledState: cancelledOutcome.state,',
  '    cancelledMessage: cancelledOutcome.message,',
  '    spawned: spawned(),',
  '    loadedAtEnd: isModelLoaded(),',
  '  });',
  "} else if (scenario === 'dispose-during-slow-termination') {",
  "  const blocked = settleDims(generateEmbedding('__BLOCK_EXIT__'));",
  '  const reachedBlock = await waitFor(() => readLines(process.env.SC_FAKE_WORKER_BLOCK).length > 0);',
  '  const startedAt = Date.now();',
  '  const first = disposeModel().then(() => Date.now() - startedAt);',
  '  await delay(150); // well inside the block: that termination is still running',
  "  const queuedA = settleDims(generateEmbedding('queued-a'));",
  "  const queuedB = settleDims(generateEmbedding('queued-b'));",
  '  await delay(100); // work that raced the termination would own a worker by now',
  '  const spawnedMidTermination = spawned();',
  '  const second = disposeModel().then(() => Date.now() - startedAt);',
  '  const [firstMs, secondMs] = await Promise.all([first, second]);',
  '  const outcomes = await Promise.race([',
  '    Promise.all([blocked, queuedA, queuedB]),',
  "    delay(3000).then(() => 'hung'),",
  '  ]);',
  '  await delay(300);',
  '  out({',
  '    reachedBlock,',
  '    firstMs,',
  '    secondMs,',
  '    spawnedMidTermination,',
  '    outcomes,',
  '    spawned: spawned(),',
  '    loadedAfter: isModelLoaded(),',
  '  });',
  "} else if (scenario === 'preload-settles-on-dispose') {",
  "  fs.writeFileSync(process.env.SC_FAKE_WORKER_HANG_LOAD, 'hang');",
  '  const load = settle(preloadModel());',
  '  await waitFor(() => spawned() >= 1);',
  "  const embed = settle(generateEmbedding('__HANG__'));",
  '  const workerId = spawnedIds()[0];',
  '  // The load is still unanswered, so the embed reaching the worker proves both',
  '  // requests are pending on the same handle when the disposal lands.',
  '  const embedReachedWorker = await waitFor(() => beatsFrom(workerId) > 0);',
  '  await disposeModel();',
  "  const outcomes = await Promise.race([Promise.all([load, embed]), delay(3000).then(() => 'hung')]);",
  '  // Disposal has completed, so a preload now is new work, not resurrection.',
  '  fs.rmSync(process.env.SC_FAKE_WORKER_HANG_LOAD, { force: true });',
  "  let reloadError = '';",
  '  try { await preloadModel(); } catch (e) { reloadError = msgOf(e); }',
  '  const loadedAfterReload = isModelLoaded();',
  '  await disposeModel();',
  '  await delay(300);',
  '  out({',
  '    embedReachedWorker,',
  '    outcomes,',
  '    reloadError,',
  '    loadedAfterReload,',
  '    spawned: spawned(),',
  '    loadedAtEnd: isModelLoaded(),',
  '  });',
  "} else if (scenario === 'preload-during-slow-dispose') {",
  "  const blocked = settle(generateEmbedding('__BLOCK_EXIT__'));",
  '  const reachedBlock = await waitFor(() => readLines(process.env.SC_FAKE_WORKER_BLOCK).length > 0);',
  '  const first = disposeModel();',
  '  await delay(150); // still inside the block: that termination is still running',
  '  const load = settle(preloadModel());',
  '  await delay(100); // a preload that raced the termination would own a worker by now',
  '  const spawnedMidTermination = spawned();',
  '  const second = disposeModel();',
  '  await Promise.all([first, second]);',
  "  const outcomes = await Promise.race([Promise.all([blocked, load]), delay(3000).then(() => 'hung')]);",
  '  await delay(300);',
  '  out({',
  '    reachedBlock,',
  '    spawnedMidTermination,',
  '    outcomes,',
  '    spawned: spawned(),',
  '    loadedAtEnd: isModelLoaded(),',
  '  });',
  "} else if (scenario === 'dispose-waits-for-timeout-kill') {",
  "  let timeoutMessage = '';",
  "  const blocked = generateEmbedding('__BLOCK_EXIT__').catch((e) => { timeoutMessage = msgOf(e); });",
  '  const reachedBlock = await waitFor(() => readLines(process.env.SC_FAKE_WORKER_BLOCK).length > 0);',
  '  await blocked; // the inference timeout fires while the worker is uninterruptible',
  '  const startedAt = Date.now();',
  '  await disposeModel(); // a kill this call did not start, but must still wait out',
  '  const disposeMs = Date.now() - startedAt;',
  '  let after = -1;',
  "  let afterError = '';",
  "  try { after = (await generateEmbedding('ok-after')).length; } catch (e) { afterError = msgOf(e); }",
  '  await disposeModel();',
  '  await delay(300);',
  '  out({',
  '    reachedBlock,',
  '    timeoutMessage,',
  '    disposeMs,',
  '    after,',
  '    afterError,',
  '    spawned: spawned(),',
  '    loadedAtEnd: isModelLoaded(),',
  '  });',
  "} else if (scenario === 'timeout-blocks-replacement') {",
  '  // A timeout starts a termination nobody asked for, and the blocked worker',
  '  // cannot die for ~600ms — so between the timeout firing and the thread',
  '  // actually exiting there is a kill this process started and has not seen',
  '  // finish. Work ALREADY ADMITTED to the lifecycle is what makes that window',
  '  // dangerous: it is past the gate, and the moment the timed-out request',
  '  // rejects it is released with a replacement worker one call away.',
  "  const blocked = settleDims(generateEmbedding('__BLOCK_EXIT__'));",
  '  const reachedBlock = await waitFor(() => readLines(process.env.SC_FAKE_WORKER_BLOCK).length > 0);',
  '  // Admitted BEFORE the timeout fires, so these two are already inside this',
  '  // lifecycle and are queued only behind the request that is about to fail.',
  "  const queuedA = settleDims(generateEmbedding('queued-a'));",
  "  const queuedB = settleDims(generateEmbedding('queued-b'));",
  '  const timedOut = await blocked; // the kill is registered and still running',
  '  const killStartedAt = Date.now();',
  '  // Admitted mid-termination: a preload is the other way a replacement gets',
  '  // built, and it does not go through the embed queue at all.',
  '  const load = settle(preloadModel());',
  '  await delay(150); // work that stepped over the kill would own a worker by now',
  '  const spawnedMidTermination = spawned();',
  '  const outcomes = await Promise.race([',
  '    Promise.all([queuedA, queuedB, load]),',
  "    delay(3000).then(() => 'hung'),",
  '  ]);',
  '  const settledMs = Date.now() - killStartedAt;',
  '  const spawnedAfterSettle = spawned();',
  '  await disposeModel();',
  '  await delay(300);',
  '  out({',
  '    reachedBlock,',
  '    timeoutMessage: timedOut.message,',
  '    spawnedMidTermination,',
  '    settledMs,',
  '    outcomes,',
  '    spawnedAfterSettle,',
  '    loadedAtEnd: isModelLoaded(),',
  '  });',
  "} else if (scenario === 'terminate-fails') {",
  '  // terminate() FAILS — the kill we asked for did not happen and the thread',
  '  // is still running. Everything downstream has to survive that: the',
  '  // timed-out caller still gets its own error, work already admitted is not',
  '  // stranded, nothing builds a replacement beside a worker that may still be',
  '  // alive, and disposeModel() still returns.',
  "  const blocked = settleDims(generateEmbedding('__HANG__'));",
  '  await waitFor(() => spawned() >= 1);',
  '  const workerId = spawnedIds()[0];',
  '  const embedReachedWorker = await waitFor(() => beatsFrom(workerId) > 0);',
  '  // Admitted BEFORE the timeout fires: already past the gate, queued only',
  '  // behind the request whose kill is about to fail.',
  "  const queuedA = settleDims(generateEmbedding('queued-a'));",
  "  const queuedB = settleDims(generateEmbedding('queued-b'));",
  '  const timedOut = await blocked;',
  '  // Admitted after the failure, and it skips the embed queue entirely.',
  '  const load = settle(preloadModel());',
  '  await delay(150); // work that stepped over the failure would own a worker by now',
  '  const spawnedAfterFault = spawned();',
  '  const outcomes = await Promise.race([',
  '    Promise.all([queuedA, queuedB, load]),',
  "    delay(3000).then(() => 'hung'),",
  '  ]);',
  '  const beatsAfterFault = beatsFrom(workerId); // the thread really is still running',
  "  let disposeError = '';",
  '  try {',
  '    await Promise.race([',
  '      disposeModel(),',
  "      delay(3000).then(() => { throw new Error('disposeModel() never settled'); }),",
  '    ]);',
  '  } catch (e) { disposeError = msgOf(e); }',
  "  const afterDispose = await settleDims(generateEmbedding('after-dispose'));",
  '  out({',
  '    embedReachedWorker,',
  '    timeoutState: timedOut.state,',
  '    timeoutMessage: timedOut.message,',
  '    spawnedAfterFault,',
  '    outcomes,',
  '    beatsAfterFault,',
  '    disposeError,',
  '    afterDisposeState: afterDispose.state,',
  '    afterDisposeMessage: afterDispose.message,',
  '    spawnedAtEnd: spawned(),',
  '    loadedAtEnd: isModelLoaded(),',
  '  });',
  '  // The thread we could not kill is still heartbeating and would hold this',
  '  // process open for ever. Exiting explicitly is the honest end of a run',
  '  // whose subject is a worker that outlived its kill.',
  '  process.exit(0);',
  "} else if (scenario === 'terminate-failure-clears-on-exit') {",
  '  // Same failure, except this thread dies on its own shortly afterwards. Its',
  '  // exit is the proof the fault was about, so it clears — and a later',
  '  // failure on the NEXT worker blocks again, which is what makes the clear a',
  "  // per-handle fact rather than a one-way unlatch of the module.",
  "  const blocked = settleDims(generateEmbedding('__HANG__'));",
  '  await waitFor(() => spawned() >= 1);',
  '  const firstId = spawnedIds()[0];',
  '  await waitFor(() => beatsFrom(firstId) > 0);',
  '  const timedOut = await blocked;',
  "  const duringFault = await settleDims(generateEmbedding('during-fault'));",
  '  const spawnedDuringFault = spawned();',
  '  // An intentional kill is silent, so the moment the heartbeat stops is the',
  '  // only observable proof that thread is gone.',
  '  let lastBeats = beatsFrom(firstId);',
  '  let quietSince = Date.now();',
  '  const staleWorkerGone = await waitFor(() => {',
  '    const now = beatsFrom(firstId);',
  '    if (now !== lastBeats) { lastBeats = now; quietSince = Date.now(); return false; }',
  '    return Date.now() - quietSince > 150;',
  '  });',
  '  await delay(100); // the exit event lands in this window',
  "  const afterExit = await settleDims(generateEmbedding('after-exit'));",
  '  const spawnedAfterExit = spawned();',
  '  // Worker B, and its kill fails too — with no recovery this time.',
  "  const blockedAgain = settleDims(generateEmbedding('__HANG__'));",
  '  const timedOutAgain = await blockedAgain;',
  "  const afterSecondFault = await settleDims(generateEmbedding('after-second-fault'));",
  '  out({',
  '    timeoutMessage: timedOut.message,',
  '    duringFaultState: duringFault.state,',
  '    duringFaultMessage: duringFault.message,',
  '    spawnedDuringFault,',
  '    staleWorkerGone,',
  '    afterExitState: afterExit.state,',
  '    afterExitDims: afterExit.dims,',
  '    afterExitMessage: afterExit.message,',
  '    spawnedAfterExit,',
  '    secondTimeoutMessage: timedOutAgain.message,',
  '    afterSecondFaultState: afterSecondFault.state,',
  '    afterSecondFaultMessage: afterSecondFault.message,',
  '    spawnedAtEnd: spawned(),',
  '    loadedAtEnd: isModelLoaded(),',
  '  });',
  '  process.exit(0); // worker B outlived its kill and holds the loop open',
  "} else if (scenario === 'terminate-rejects-after-exit') {",
  '  // The OTHER ordering. The kill lands — the thread is provably gone — and',
  '  // the host reports the failure afterwards. A fault recorded at that point',
  '  // has no exit left to clear it (`exit` fires once, and it already has), so',
  '  // it would refuse every embed and preload for the rest of the process on',
  '  // behalf of a thread that is not there. Two rounds, on two different',
  '  // handles, so a recovery is a property of the module and not a one-off.',
  '  const rounds = [];',
  '  for (let i = 0; i < 2; i++) {',
  "    const blocked = settleDims(generateEmbedding('__HANG__'));",
  '    await waitFor(() => spawned() >= i + 1);',
  '    const workerId = spawnedIds()[i];',
  '    const reachedWorker = await waitFor(() => beatsFrom(workerId) > 0);',
  '    const timedOut = await blocked;',
  '    // The rejection is delivered a microtask after that exit; parking here',
  '    // is what puts it before the next admission rather than beside it.',
  '    await delay(100);',
  "    const after = await settleDims(generateEmbedding('after-' + i));",
  '    const load = await settle(preloadModel());',
  '    rounds.push({',
  '      reachedWorker,',
  '      timeoutMessage: timedOut.message,',
  '      afterState: after.state,',
  '      afterDims: after.dims,',
  '      afterMessage: after.message,',
  '      loadState: load.state,',
  '      loadMessage: load.message,',
  '      spawnedAfterRound: spawned(),',
  '    });',
  '  }',
  '  await disposeModel();',
  '  await delay(200);',
  '  out({ rounds, spawned: spawned(), loadedAtEnd: isModelLoaded() });',
  "} else if (scenario === 'terminate-fault-clears-before-exit') {",
  '  // The ordering the module already claimed, made deterministic: the failure',
  '  // is reported while that thread is genuinely still running, so work is',
  '  // refused — and released only by that thread\'s OWN exit, which this driver',
  '  // asks for by hand instead of waiting out a timer. Two rounds, so the',
  '  // clear is proven to be per handle rather than a one-way unlatch.',
  '  const flag = process.env.SC_TEST_TERMINATE_KILL_FLAG;',
  '  const rounds = [];',
  '  for (let i = 0; i < 2; i++) {',
  "    const blocked = settleDims(generateEmbedding('__HANG__'));",
  '    await waitFor(() => spawned() >= i + 1);',
  '    const workerId = spawnedIds()[i];',
  '    const reachedWorker = await waitFor(() => beatsFrom(workerId) > 0);',
  '    const timedOut = await blocked;',
  "    const duringFault = await settleDims(generateEmbedding('during-' + i));",
  '    const spawnedDuringFault = spawned();',
  '    const beatsDuringFault = beatsFrom(workerId); // it really is still there',
  "    fs.writeFileSync(flag + '.' + (i + 1), 'die');",
  '    // An intentional kill is silent, so the moment the heartbeat stops is the',
  '    // only observable proof that thread is gone.',
  '    let lastBeats = beatsFrom(workerId);',
  '    let quietSince = Date.now();',
  '    const workerGone = await waitFor(() => {',
  '      const now = beatsFrom(workerId);',
  '      if (now !== lastBeats) { lastBeats = now; quietSince = Date.now(); return false; }',
  '      return Date.now() - quietSince > 150;',
  '    });',
  '    await delay(100); // the exit event lands in this window',
  "    const afterExit = await settleDims(generateEmbedding('after-' + i));",
  '    rounds.push({',
  '      reachedWorker,',
  '      timeoutMessage: timedOut.message,',
  '      duringFaultState: duringFault.state,',
  '      duringFaultMessage: duringFault.message,',
  '      spawnedDuringFault,',
  '      beatsDuringFault,',
  '      workerGone,',
  '      afterExitState: afterExit.state,',
  '      afterExitDims: afterExit.dims,',
  '      afterExitMessage: afterExit.message,',
  '      spawnedAfterExit: spawned(),',
  '    });',
  '  }',
  '  out({ rounds, spawned: spawned(), loadedAtEnd: isModelLoaded() });',
  '  // The last worker is idle and alive, and no scenario step kills it: this',
  '  // run is about kills that failed, so ending it explicitly is the honest',
  '  // close rather than waiting on a loop that will not empty.',
  '  process.exit(0);',
  "} else if (scenario === 'send-failure-cleanup') {",
  '  // postMessage() throws for the FIRST request only. That request never',
  '  // reached the thread, so the worker is healthy — and the timeout timer the',
  '  // request armed a line earlier must not still be there to kill it.',
  "  const sendFailed = await settleDims(generateEmbedding('send-fails'));",
  "  const okDuringWindow = await settleDims(generateEmbedding('ok-1'));",
  '  const spawnedDuringWindow = spawned();',
  '  // Past the point an abandoned timer would have fired.',
  '  await delay(Number(process.env.SC_TEST_INFERENCE_TIMEOUT_MS) + 300);',
  "  const okAfterWindow = await settleDims(generateEmbedding('ok-2'));",
  '  const spawnedAtEnd = spawned();',
  '  await disposeModel();',
  '  await delay(200);',
  '  out({',
  '    sendFailedState: sendFailed.state,',
  '    sendFailedMessage: sendFailed.message,',
  '    okDuringWindowState: okDuringWindow.state,',
  '    okDuringWindowDims: okDuringWindow.dims,',
  '    spawnedDuringWindow,',
  '    okAfterWindowState: okAfterWindow.state,',
  '    okAfterWindowDims: okAfterWindow.dims,',
  '    okAfterWindowMessage: okAfterWindow.message,',
  '    spawnedAtEnd,',
  '    loadedAtEnd: isModelLoaded(),',
  '  });',
  "} else if (scenario === 'send-failure-spares-later-request') {",
  '  // What an abandoned timer does to OTHER work: it terminates the worker a',
  '  // later request is sitting on, and settles that request with the timeout',
  "  // kill's collateral error, early, instead of with its own timeout.",
  "  const sendFailed = await settleDims(generateEmbedding('send-fails'));",
  '  const timeout = Number(process.env.SC_TEST_INFERENCE_TIMEOUT_MS);',
  '  await delay(Math.floor(timeout / 2)); // an abandoned timer fires mid-flight',
  '  const startedAt = Date.now();',
  "  const hung = await settleDims(generateEmbedding('__HANG__'));",
  '  const hungMs = Date.now() - startedAt;',
  '  await delay(200);',
  '  out({',
  '    sendFailedState: sendFailed.state,',
  '    sendFailedMessage: sendFailed.message,',
  '    hungState: hung.state,',
  '    hungMessage: hung.message,',
  '    hungMs,',
  '    spawnedAtEnd: spawned(),',
  '    loadedAtEnd: isModelLoaded(),',
  '  });',
  "} else if (scenario === 'disposal-error-brand') {",
  '  // What a disposal actually THROWS, at each of the three places one is',
  '  // raised, and what the shared classifier says about near misses a layer',
  '  // below could produce by accident.',
  '  const seen = {};',
  '  const describe = (e) => ({',
  '    isError: e instanceof Error,',
  "    name: e && e.name ? String(e.name) : '',",
  "    code: e && e.code !== undefined ? String(e.code) : '',",
  '    message: msgOf(e),',
  '    branded: Boolean(e && e[BRAND] === true),',
  '    classified: contract.isWorkerDisposedError(e),',
  '  });',
  '  const capture = (label, p) => p.then(',
  "    () => { seen[label] = { state: 'resolved' }; },",
  "    (e) => { seen[label] = { state: 'rejected', ...describe(e) }; },",
  '  );',
  "  const inFlight = capture('inFlight', generateEmbedding('__HANG__'));",
  '  await waitFor(() => spawned() >= 1); // the stub worker owns that request',
  "  const queued = capture('queued', generateEmbedding('queued'));",
  '  await disposeModel();',
  '  await Promise.all([inFlight, queued]);',
  '  // Admitted into the lifecycle the disposal above opened, then overtaken by',
  '  // a second disposal before it ever reaches a worker: the third and last',
  '  // place a disposal error is raised.',
  '  const firstOfPair = disposeModel();',
  "  const cancelled = capture('cancelled', generateEmbedding('ok-3'));",
  '  const secondOfPair = disposeModel();',
  '  await Promise.all([firstOfPair, secondOfPair, cancelled]);',
  '  out({',
  '    contract: {',
  "      message: String(contract.WORKER_DISPOSED_MSG ?? ''),",
  "      code: String(contract.WORKER_DISPOSED_CODE ?? ''),",
  "      brandKey: String(contract.WORKER_DISPOSED_BRAND_KEY ?? ''),",
  "      constructs: typeof contract.WorkerDisposedError === 'function'",
  '        ? describe(new contract.WorkerDisposedError())',
  '        : null,',
  '    },',
  '    inFlight: seen.inFlight,',
  '    queued: seen.queued,',
  '    cancelled: seen.cancelled,',
  '    probes: {',
  '      // The exact sentence, and nothing else — what a database driver, a',
  '      // wrapper or a stale copy of the string could raise by accident.',
  '      messageOnly: contract.isWorkerDisposedError(new Error(MESSAGE)),',
  '      // Minted HERE, with no access to the class: the brand is a registry',
  '      // symbol, so a second copy of the module (a dist build beside a',
  '      // transpiled one) is recognised without sharing an identity.',
  '      structural: contract.isWorkerDisposedError(',
  '        Object.assign(new Error(MESSAGE), { code: CODE, [BRAND]: true }),',
  '      ),',
  '      brandWithoutCode: contract.isWorkerDisposedError(',
  '        Object.assign(new Error(MESSAGE), { [BRAND]: true }),',
  '      ),',
  '      codeWithoutBrand: contract.isWorkerDisposedError(',
  '        Object.assign(new Error(MESSAGE), { code: CODE }),',
  '      ),',
  '      wrongMessage: contract.isWorkerDisposedError(',
  "        Object.assign(new Error(MESSAGE + ' while writing the vector'), { code: CODE, [BRAND]: true }),",
  '      ),',
  '      notAnError: contract.isWorkerDisposedError({ message: MESSAGE, code: CODE, [BRAND]: true }),',
  '      plainString: contract.isWorkerDisposedError(MESSAGE),',
  '    },',
  '  });',
  '} else {',
  "  out({ error: 'unknown scenario: ' + scenario });",
  '  process.exitCode = 2;',
  '}',
  '',
].join('\n');

let sandbox: string;

interface ScenarioRun {
  status: number | null;
  stdout: string;
  stderr: string;
  result: Record<string, unknown>;
}

let scenarioRuns = 0;

function runScenario(name: string, extraEnv: Record<string, string> = {}): ScenarioRun {
  // Per RUN, not per scenario. One scenario is driven twice — once for each way
  // a terminate() can fail — and a filename keyed only on the scenario would
  // give the second run the first one's spawn log, so `spawned()` would count
  // workers from a process that had already exited.
  const tag = `${name}-${++scenarioRuns}`;
  const env = {
    ...process.env,
    SC_FAKE_WORKER_LOG: path.join(sandbox, `spawned-${tag}.log`),
    SC_FAKE_WORKER_BEAT: path.join(sandbox, `beats-${tag}.log`),
    SC_FAKE_WORKER_BLOCK: path.join(sandbox, `blocking-${tag}.log`),
    SC_FAKE_WORKER_HANG_LOAD: path.join(sandbox, `hang-load-${tag}.flag`),
    ...extraEnv,
  };
  delete env.SHIELDCORTEX_SKIP_EMBEDDINGS; // the jest runner sets this to 1 globally
  const proc = spawnSync(process.execPath, [path.join(sandbox, 'driver.mjs'), name], {
    encoding: 'utf8',
    env,
    cwd: sandbox, // keep the real dist/embeddings/worker.js fallback out of reach
    timeout: 15_000, // a hung/leaked worker must fail the test, not stall the suite
  });
  const stdout = proc.stdout ?? '';
  const line = stdout.split('\n').find((l) => l.startsWith(RESULT_PREFIX));
  return {
    status: proc.status,
    stdout,
    stderr: proc.stderr ?? '',
    result: line ? JSON.parse(line.slice(RESULT_PREFIX.length)) : {},
  };
}

describe('embedding worker — intentional disposal is not a crash', () => {
  beforeAll(() => {
    sandbox = fs.mkdtempSync(path.join(os.tmpdir(), 'sc-embed-dispose-'));
    fs.writeFileSync(
      path.join(sandbox, 'package.json'),
      JSON.stringify({ name: 'sc-embed-dispose-sandbox', version: '0.0.0', type: 'module', private: true }),
    );
    const source = fs.readFileSync(GENERATOR_SRC, 'utf8');
    if (!source.includes(TIMEOUT_DECL)) {
      throw new Error(
        `worker-dispose-honesty: cannot find \`${TIMEOUT_DECL}\` in generator.ts — ` +
          'the timeout scenario would silently stop exercising the timeout path.',
      );
    }
    if (!source.includes(WORKER_IMPORT)) {
      throw new Error(
        `worker-dispose-honesty: cannot find \`${WORKER_IMPORT}\` in generator.ts — ` +
          'the termination-failure scenarios would silently stop failing terminate().',
      );
    }
    const transpiled = ts.transpileModule(
      source
        .replace(TIMEOUT_DECL, TIMEOUT_DECL_TEST)
        .replace(WORKER_IMPORT, WORKER_IMPORT_TEST),
      {
        fileName: 'generator.ts',
        compilerOptions: { module: ts.ModuleKind.ESNext, target: ts.ScriptTarget.ES2022 },
      },
    ).outputText;
    fs.writeFileSync(path.join(sandbox, 'generator.js'), transpiled);
    fs.writeFileSync(path.join(sandbox, 'worker-threads-shim.js'), WORKER_SHIM);
    fs.writeFileSync(path.join(sandbox, 'worker.js'), FAKE_WORKER);
    fs.writeFileSync(path.join(sandbox, 'driver.mjs'), DRIVER);
  });

  afterAll(() => {
    if (sandbox) fs.rmSync(sandbox, { recursive: true, force: true });
  });

  it('disposeModel() after a successful embed reports no worker crash', () => {
    const run = runScenario('dispose-after-success');

    expect(run.result).toMatchObject({ dims: 3, loadedBefore: true, loadedAfter: false, spawned: 1 });
    expect(run.stderr).not.toMatch(/Embedding worker exited with code/);
    expect(run.stderr).not.toMatch(/Embedding worker error/);
    expect(run.status).toBe(0);
  }, 30_000);

  it('an unexpected non-zero worker exit stays loud and rejects the pending call', () => {
    const run = runScenario('unexpected-exit');

    expect(run.result.rejected).toBe(true);
    expect(String(run.result.message)).toMatch(/exited with code 3/);
    expect(run.result.loadedAfter).toBe(false);
    expect(run.stderr).toMatch(/Embedding worker exited with code 3/);
    expect(run.status).toBe(0);
  }, 30_000);

  it('disposeModel() settles an in-flight request instead of dropping it', () => {
    const run = runScenario('dispose-with-pending');

    expect(run.result.state).toBe('rejected');
    // Pinned exactly, not by pattern: shutdown callers (src/memory/store.ts,
    // scripts/lib/save-memory.mjs) classify this by equality on top of the
    // brand, so the two ends of that contract are held by behaviour at both.
    expect(run.result.message).toBe(DISPOSED_MSG);
    expect(String(run.result.message)).not.toMatch(/exited with code/);
    expect(run.stderr).not.toMatch(/Embedding worker exited with code/);
    expect(run.status).toBe(0);
  }, 30_000);

  it('disposeModel() cancels queued embeds instead of letting them resurrect a worker', () => {
    const run = runScenario('dispose-cancels-queued');

    const outcomes = run.result.outcomes as Array<{ state: string; message: string }>;
    expect(Array.isArray(outcomes)).toBe(true); // 'hung' means something never settled
    expect(outcomes).toHaveLength(3);
    for (const outcome of outcomes) {
      expect(outcome.state).toBe('rejected');
      expect(outcome.message).toMatch(/dispos/i);
    }
    expect(run.result.spawned).toBe(1); // no replacement woken by queued work
    expect(run.result.loadedAfter).toBe(false);
    expect(run.stderr).not.toMatch(/Embedding worker exited with code/);
    expect(run.status).toBe(0); // a leaked worker would hold the event loop open
  }, 30_000);

  it('concurrent disposeModel() callers all wait for the same termination', () => {
    const run = runScenario('concurrent-dispose');

    expect(run.result.reachedBlock).toBe(true); // worker really is mid-block
    const firstMs = run.result.firstMs as number;
    const secondMs = run.result.secondMs as number;
    expect(firstMs).toBeGreaterThan(300); // the block makes termination measurable
    expect(secondMs).toBeGreaterThan(300); // returning early would land near 0
    expect(Math.abs(firstMs - secondMs)).toBeLessThan(200);
    expect(run.result.blockedState).toBe('rejected');
    expect(String(run.result.blockedMessage)).toMatch(/dispos/i);
    expect(run.result).toMatchObject({ spawned: 1, loadedAfter: false });
    expect(run.status).toBe(0);
  }, 30_000);

  it('a timed-out request fails loudly while its kill stays silent and replaceable', () => {
    const run = runScenario('timeout-then-replacement', { SC_TEST_INFERENCE_TIMEOUT_MS: '400' });

    expect(String(run.result.timeoutMessage)).toMatch(/embed timed out after 400ms/);
    expect(run.result.beatsBeforeReplacement as number).toBeGreaterThan(0); // heartbeat gate is live
    expect(run.result).toMatchObject({
      second: 3,
      secondError: '',
      loadedRightAfterReplacement: true,
      staleWorkerGone: true,
      loadedAfterStaleExit: true,
      third: 3,
      thirdError: '',
      spawned: 2,
    });
    expect(run.stderr).not.toMatch(/Embedding worker exited with code/);
    expect(run.stderr).not.toMatch(/Embedding worker error/);
    expect(run.status).toBe(0);
  }, 30_000);

  it('a request made after disposal completes starts one fresh worker', () => {
    const run = runScenario('new-request-after-dispose');

    expect(run.result).toMatchObject({
      before: 3,
      after: 3,
      afterError: '',
      loadedAfterDispose: false,
      loadedAfterRestart: true,
      loadedAtEnd: false,
      spawned: 2,
    });
    expect(run.stderr).not.toMatch(/Embedding worker exited with code/);
    expect(run.status).toBe(0);
  }, 30_000);

  it('a request made in the same turn as disposeModel() belongs to the next lifecycle', () => {
    const run = runScenario('dispose-then-generate');

    // Admitted after the dispose CALL: it waits out that termination and runs.
    expect(run.result.afterMessage).toBe('');
    expect(run.result).toMatchObject({ first: 3, afterState: 'resolved', afterDims: 3 });
    // Admitted after a dispose and then overtaken by another: cancelled.
    expect(run.result.cancelledState).toBe('rejected');
    expect(String(run.result.cancelledMessage)).toMatch(/dispos/i);
    expect(run.result).toMatchObject({ spawned: 2, loadedAtEnd: false });
    expect(run.stderr).not.toMatch(/Embedding worker exited with code/);
    expect(run.status).toBe(0);
  }, 30_000);

  it('a second disposeModel() cancels work admitted while the first termination runs', () => {
    const run = runScenario('dispose-during-slow-termination');

    expect(run.result.reachedBlock).toBe(true); // worker really is mid-block
    // The whole point: that work waited on the termination instead of racing it.
    expect(run.result.spawnedMidTermination).toBe(1);
    const outcomes = run.result.outcomes as Array<{ state: string; message: string }>;
    expect(Array.isArray(outcomes)).toBe(true); // 'hung' means something never settled
    expect(outcomes).toHaveLength(3);
    for (const outcome of outcomes) {
      expect(outcome.state).toBe('rejected');
      expect(outcome.message).toMatch(/dispos/i);
    }
    expect(run.result.firstMs as number).toBeGreaterThan(300);
    expect(run.result.secondMs as number).toBeGreaterThan(300); // no early return
    expect(run.result).toMatchObject({ spawned: 1, loadedAfter: false });
    expect(run.stderr).not.toMatch(/Embedding worker exited with code/);
    expect(run.status).toBe(0); // a leaked worker would hold the event loop open
  }, 30_000);

  it('disposeModel() settles a pending preload alongside a pending embed', () => {
    const run = runScenario('preload-settles-on-dispose');

    expect(run.result.embedReachedWorker).toBe(true); // both really were in flight
    const outcomes = run.result.outcomes as Array<{ state: string; message: string }>;
    expect(Array.isArray(outcomes)).toBe(true);
    expect(outcomes).toHaveLength(2);
    for (const outcome of outcomes) {
      expect(outcome.state).toBe('rejected');
      expect(outcome.message).toMatch(/dispos/i);
    }
    // A preload after the disposal completed is new work, not resurrection.
    expect(run.result).toMatchObject({
      reloadError: '',
      loadedAfterReload: true,
      spawned: 2,
      loadedAtEnd: false,
    });
    expect(run.stderr).not.toMatch(/Embedding worker exited with code/);
    expect(run.status).toBe(0);
  }, 30_000);

  it('preloadModel() during a disposal waits for it and is cancelled by the next one', () => {
    const run = runScenario('preload-during-slow-dispose');

    expect(run.result.reachedBlock).toBe(true);
    expect(run.result.spawnedMidTermination).toBe(1); // preload did not race the kill
    const outcomes = run.result.outcomes as Array<{ state: string; message: string }>;
    expect(Array.isArray(outcomes)).toBe(true);
    expect(outcomes).toHaveLength(2);
    for (const outcome of outcomes) {
      expect(outcome.state).toBe('rejected');
      expect(outcome.message).toMatch(/dispos/i);
    }
    expect(run.result).toMatchObject({ spawned: 1, loadedAtEnd: false });
    expect(run.stderr).not.toMatch(/Embedding worker exited with code/);
    expect(run.status).toBe(0);
  }, 30_000);

  it('disposeModel() waits for a timeout kill it did not start', () => {
    const run = runScenario('dispose-waits-for-timeout-kill', { SC_TEST_INFERENCE_TIMEOUT_MS: '200' });

    expect(run.result.reachedBlock).toBe(true);
    expect(String(run.result.timeoutMessage)).toMatch(/embed timed out after 200ms/);
    // The blocked worker needs ~600ms to die; claiming completion before that
    // lands near 0. Measured from after the timeout already fired.
    expect(run.result.disposeMs as number).toBeGreaterThan(150);
    expect(run.result).toMatchObject({ after: 3, afterError: '', spawned: 2, loadedAtEnd: false });
    expect(run.stderr).not.toMatch(/Embedding worker exited with code/); // no fake crash
    expect(run.stderr).not.toMatch(/Embedding worker error/);
    expect(run.status).toBe(0);
  }, 30_000);

  it("a retired worker's delayed exit cannot invalidate its replacement", () => {
    const run = runScenario('stale-exit-isolation');

    expect(String(run.result.crashMessage)).toMatch(/fake worker boom/);
    expect(run.result).toMatchObject({
      first: 3,
      second: 3,
      secondError: '',
      third: 3,
      thirdError: '',
      loadedRightAfterReplacement: true,
      staleExitObserved: true, // the stale exit really was delivered
      loadedAfterStaleExit: true,
      spawned: 2,
    });
    expect(run.stderr).toMatch(/Embedding worker error: fake worker boom/);
    expect(run.status).toBe(0);
  }, 30_000);

  it('a timeout kill blocks the replacement every admitted caller would build', () => {
    const run = runScenario('timeout-blocks-replacement', { SC_TEST_INFERENCE_TIMEOUT_MS: '200' });

    expect(run.result.reachedBlock).toBe(true); // the worker really is uninterruptible
    expect(String(run.result.timeoutMessage)).toMatch(/embed timed out after 200ms/);
    // The blocker itself: a timeout starts a termination the DISPOSAL path did
    // not, and every caller already admitted to this lifecycle — two queued
    // embeds and a preload that skips the queue entirely — must see it before
    // it can call ensureWorker(). One worker, not two.
    expect(run.result.spawnedMidTermination).toBe(1);
    // ...and they waited rather than being dropped. The blocked thread needs
    // ~600ms to die and the timeout fires at 200ms, so work that stepped over
    // the kill would settle here at once instead.
    expect(run.result.settledMs as number).toBeGreaterThan(150);
    const outcomes = run.result.outcomes as Array<{ state: string; dims?: number }>;
    expect(Array.isArray(outcomes)).toBe(true); // 'hung' means something never settled
    expect(outcomes).toHaveLength(3);
    // Waiting is not refusing: once the kill lands, all three do their work.
    for (const outcome of outcomes) expect(outcome.state).toBe('resolved');
    expect(outcomes[0].dims).toBe(3);
    expect(outcomes[1].dims).toBe(3);
    // And on exactly one fresh worker, built after the old thread was gone.
    expect(run.result.spawnedAfterSettle).toBe(2);
    expect(run.result.loadedAtEnd).toBe(false);
    expect(run.stderr).not.toMatch(/Embedding worker exited with code/); // the kill was ours
    expect(run.stderr).not.toMatch(/Embedding worker error/);
    expect(run.status).toBe(0); // a leaked worker would hold the event loop open
  }, 30_000);

  it.each([
    ['a synchronous throw', 'sync-throw', 'fake terminate failure (sync)'],
    ['a rejected promise', 'async-reject', 'fake terminate failure (async)'],
  ])('survives a terminate() that fails with %s', (_label, mode, detail) => {
    const run = runScenario('terminate-fails', {
      SC_TEST_INFERENCE_TIMEOUT_MS: '200',
      SC_TEST_TERMINATE_MODE: mode,
    });

    expect(run.result.embedReachedWorker).toBe(true); // the worker really had the request
    // 1. The caller that started the kill still gets told, with its OWN error.
    //    A throw escaping the timer would skip this and strand the request.
    expect(run.result.timeoutState).toBe('rejected');
    expect(String(run.result.timeoutMessage)).toMatch(/embed timed out after 200ms/);
    // 2. Nothing was built beside a thread that may still be running — not by
    //    the two queued embeds, and not by the preload that skips the queue.
    expect(run.result.spawnedAfterFault).toBe(1);
    expect(run.result.spawnedAtEnd).toBe(1);
    // 3. Nothing was stranded either: the chain moved and all three settled,
    //    loudly, naming what actually went wrong.
    const outcomes = run.result.outcomes as Array<{ state: string; message: string }>;
    expect(Array.isArray(outcomes)).toBe(true); // 'hung' means something never settled
    expect(outcomes).toHaveLength(3);
    for (const outcome of outcomes) {
      expect(outcome.state).toBe('rejected');
      expect(outcome.message).toContain(TERMINATION_FAILED);
      expect(outcome.message).not.toMatch(/dispos/i); // a failure, never a shutdown
    }
    // 4. The hazard is real, not hypothetical: that thread is still beating.
    expect(run.result.beatsAfterFault as number).toBeGreaterThan(0);
    // 5. disposeModel() is a shutdown path — it returns, and it does not throw.
    expect(run.result.disposeError).toBe('');
    // 6. ...and a disposal is not a pardon: new work still fails, fast and loud.
    expect(run.result.afterDisposeState).toBe('rejected');
    expect(String(run.result.afterDisposeMessage)).toContain(TERMINATION_FAILED);
    expect(run.result.loadedAtEnd).toBe(false);
    // Said once, where it happened, naming the underlying failure.
    const faults = run.stderr.split('\n').filter((line) => line.includes(TERMINATION_FAILED));
    expect(faults).toHaveLength(1);
    expect(faults[0]).toContain(detail);
    expect(run.stderr).not.toMatch(/Embedding worker exited with code/); // it never exited
    expect(run.status).toBe(0);
  }, 30_000);

  it("clears a termination fault when that worker's own exit finally arrives", () => {
    const run = runScenario('terminate-failure-clears-on-exit', {
      SC_TEST_INFERENCE_TIMEOUT_MS: '200',
      SC_TEST_TERMINATE_MODE: 'sync-throw',
      SC_TEST_TERMINATE_RECOVER_INDEX: '1',
      SC_TEST_TERMINATE_RECOVER_MS: '250',
    });

    expect(String(run.result.timeoutMessage)).toMatch(/embed timed out after 200ms/);
    // Blocked while the thread might still be alive...
    expect(run.result.duringFaultState).toBe('rejected');
    expect(String(run.result.duringFaultMessage)).toContain(TERMINATION_FAILED);
    expect(run.result.spawnedDuringFault).toBe(1);
    // ...and released by that thread's own exit, not by a timer or a disposal.
    expect(run.result.staleWorkerGone).toBe(true);
    expect(run.result.afterExitMessage).toBe('');
    expect(run.result.afterExitState).toBe('resolved');
    expect(run.result.afterExitDims).toBe(3);
    expect(run.result.spawnedAfterExit).toBe(2);
    // The clear was scoped to the handle that exited: worker B's kill fails in
    // turn and the module blocks again. Nothing was latched open, and nothing
    // was latched shut. (An exit can only ever clear its own handle — the
    // module deletes the handle its exit listener closed over.)
    expect(String(run.result.secondTimeoutMessage)).toMatch(/embed timed out after 200ms/);
    expect(run.result.afterSecondFaultState).toBe('rejected');
    expect(String(run.result.afterSecondFaultMessage)).toContain(TERMINATION_FAILED);
    expect(run.result.spawnedAtEnd).toBe(2);
    expect(run.result.loadedAtEnd).toBe(false);
    // Two failures, two lines — one per handle, not one per blocked caller.
    const faults = run.stderr.split('\n').filter((line) => line.includes(TERMINATION_FAILED));
    expect(faults).toHaveLength(2);
    // Both kills were ours, including the one that eventually landed.
    expect(run.stderr).not.toMatch(/Embedding worker exited with code/);
    expect(run.stderr).not.toMatch(/Embedding worker error/);
    expect(run.status).toBe(0);
  }, 30_000);

  it('does not refuse work on behalf of a thread that reported its failed kill after exiting', () => {
    // The ordering the r10 review found. `terminate()` LANDS — the thread is
    // gone and its `exit` event has been delivered — and the host reports the
    // failure afterwards. `exit` fires once, so a fault installed at that point
    // has nothing left that can clear it, and every embed and preload for the
    // rest of the process is refused on behalf of a thread that is not there.
    const run = runScenario('terminate-rejects-after-exit', {
      SC_TEST_INFERENCE_TIMEOUT_MS: '200',
      SC_TEST_TERMINATE_MODE: 'reject-after-exit',
    });

    const rounds = run.result.rounds as Array<Record<string, unknown>>;
    expect(Array.isArray(rounds)).toBe(true);
    expect(rounds).toHaveLength(2);
    rounds.forEach((round, i) => {
      expect(round.reachedWorker).toBe(true); // the worker really had the request
      expect(String(round.timeoutMessage)).toMatch(/embed timed out after 200ms/);
      // The whole point: fresh work runs, because the thread it would have been
      // refused for is provably gone.
      expect(round.afterMessage).toBe('');
      expect(round.afterState).toBe('resolved');
      expect(round.afterDims).toBe(3);
      expect(round.loadMessage).toBe(''); // a preload skips the embed queue
      expect(round.loadState).toBe('resolved');
      // One replacement per round, and it is a DIFFERENT handle each time: the
      // recovery is a property of the module, not a single unlatch.
      expect(round.spawnedAfterRound).toBe(i + 2);
    });
    expect(run.result).toMatchObject({ spawned: 3, loadedAtEnd: false });

    // Still said, and said truthfully. Three kills reported a failure after
    // their thread had exited — two timeouts and the closing disposal — and
    // none of them refuses anything.
    const late = run.stderr.split('\n').filter((line) => line.includes(TERMINATION_FAILED_AFTER_EXIT));
    expect(late).toHaveLength(3);
    for (const line of late) expect(line).toContain('fake terminate failure (after exit)');
    expect(late.filter((line) => line.includes('timeout kill'))).toHaveLength(2);
    expect(late.filter((line) => line.includes('disposed kill'))).toHaveLength(1);
    // ...and not one of them was recorded as a thread that may still be running.
    expect(run.stderr).not.toContain(TERMINATION_FAILED);
    expect(run.stderr).not.toMatch(/Embedding worker exited with code/); // the kills were ours
    expect(run.stderr).not.toMatch(/Embedding worker error/);
    expect(run.status).toBe(0);
  }, 30_000);

  it('refuses work until the exit arrives when the failure is reported first', () => {
    // The opposite ordering, and the one that must NOT change: the failure is
    // reported while that thread is genuinely still running, so work is refused
    // until its own exit says otherwise. The kill is triggered by the driver
    // writing a file rather than by a timer, so the refusal window is stepped
    // into rather than raced.
    const run = runScenario('terminate-fault-clears-before-exit', {
      SC_TEST_INFERENCE_TIMEOUT_MS: '200',
      SC_TEST_TERMINATE_MODE: 'reject-before-exit',
      SC_TEST_TERMINATE_KILL_FLAG: path.join(sandbox, 'kill-flag'),
    });

    const rounds = run.result.rounds as Array<Record<string, unknown>>;
    expect(Array.isArray(rounds)).toBe(true);
    expect(rounds).toHaveLength(2);
    rounds.forEach((round, i) => {
      expect(round.reachedWorker).toBe(true);
      expect(String(round.timeoutMessage)).toMatch(/embed timed out after 200ms/);
      // Blocked while that thread might still be alive...
      expect(round.duringFaultState).toBe('rejected');
      expect(String(round.duringFaultMessage)).toContain(TERMINATION_FAILED);
      expect(String(round.duringFaultMessage)).not.toMatch(/dispos/i); // a failure, not a shutdown
      expect(round.beatsDuringFault as number).toBeGreaterThan(0); // it really is still there
      expect(round.spawnedDuringFault).toBe(i + 1); // nothing built beside it
      // ...and released by that thread's OWN exit, which the driver asked for.
      expect(round.workerGone).toBe(true);
      expect(round.afterExitMessage).toBe('');
      expect(round.afterExitState).toBe('resolved');
      expect(round.afterExitDims).toBe(3);
      expect(round.spawnedAfterExit).toBe(i + 2);
    });
    // Three handles, and the last of them is healthy and idle: this scenario
    // never disposes, so a module that had latched itself off would report
    // `false` here instead.
    expect(run.result).toMatchObject({ spawned: 3, loadedAtEnd: true });

    // Two faults, two lines — one per handle, and each of them the blocking
    // kind. Nothing here exited before its failure was reported.
    const faults = run.stderr.split('\n').filter((line) => line.includes(TERMINATION_FAILED));
    expect(faults).toHaveLength(2);
    for (const line of faults) expect(line).toContain('fake terminate failure (before exit)');
    expect(run.stderr).not.toContain(TERMINATION_FAILED_AFTER_EXIT);
    expect(run.stderr).not.toMatch(/Embedding worker exited with code/);
    expect(run.status).toBe(0);
  }, 30_000);

  it('cleans up after a postMessage() that throws, and keeps the worker it never reached', () => {
    // `postMessage()` throwing means nothing was sent: the request is the only
    // casualty and the worker is untouched. The timer armed a line earlier is
    // the hazard — left installed it fires on its own schedule and terminates
    // whichever worker is current by then.
    const run = runScenario('send-failure-cleanup', {
      SC_TEST_INFERENCE_TIMEOUT_MS: '400',
      SC_TEST_POSTMESSAGE_FAIL_COUNT: '1',
    });

    // 1. The caller is told, loudly, and told what actually happened.
    expect(run.result.sendFailedState).toBe('rejected');
    expect(String(run.result.sendFailedMessage)).toContain(SEND_FAILED);
    expect(String(run.result.sendFailedMessage)).toContain('fake postMessage failure');
    expect(String(run.result.sendFailedMessage)).not.toMatch(/dispos/i);
    // 2. The worker was never retired: the very next request uses it and works.
    expect(run.result.okDuringWindowState).toBe('resolved');
    expect(run.result.okDuringWindowDims).toBe(3);
    expect(run.result.spawnedDuringWindow).toBe(1);
    // 3. ...and it is STILL that same worker after the abandoned timer's
    //    deadline has passed. A stale timeout would have killed it in between,
    //    and this embed would be running on a replacement.
    expect(run.result.okAfterWindowMessage).toBe('');
    expect(run.result.okAfterWindowState).toBe('resolved');
    expect(run.result.okAfterWindowDims).toBe(3);
    expect(run.result).toMatchObject({ spawnedAtEnd: 1, loadedAtEnd: false });
    expect(run.stderr).not.toMatch(/Embedding worker exited with code/);
    expect(run.stderr).not.toMatch(/Embedding worker error/);
    expect(run.status).toBe(0);
  }, 30_000);

  it('does not let a failed send time out a later request', () => {
    // The other half of the damage. A stale timer does not merely kill a
    // worker — it settles the requests that worker owns with the timeout
    // kill's collateral error, early, in place of their own answer.
    const run = runScenario('send-failure-spares-later-request', {
      SC_TEST_INFERENCE_TIMEOUT_MS: '400',
      SC_TEST_POSTMESSAGE_FAIL_COUNT: '1',
    });

    expect(run.result.sendFailedState).toBe('rejected');
    expect(String(run.result.sendFailedMessage)).toContain(SEND_FAILED);
    // The later request gets its OWN timeout, at its own deadline...
    expect(run.result.hungState).toBe('rejected');
    expect(String(run.result.hungMessage)).toMatch(/embed timed out after 400ms/);
    // ...not the collateral of a kill performed on behalf of a request that
    // was never sent.
    expect(String(run.result.hungMessage)).not.toMatch(/terminated after a timed-out request/);
    // The clock says the same thing: the abandoned timer's deadline falls
    // halfway through this request, so a run that honoured it lands near 200ms.
    expect(run.result.hungMs as number).toBeGreaterThan(300);
    expect(run.result).toMatchObject({ spawnedAtEnd: 1, loadedAtEnd: false });
    expect(run.status).toBe(0);
  }, 30_000);

  it('settles cancelled work with a branded error, not a recognisable sentence', () => {
    const run = runScenario('disposal-error-brand');

    const disposal = {
      isError: true,
      name: 'WorkerDisposedError',
      code: DISPOSED_CODE,
      message: DISPOSED_MSG,
      branded: true,
      classified: true,
    };
    expect(run.result.contract).toEqual({
      message: DISPOSED_MSG,
      code: DISPOSED_CODE,
      brandKey: DISPOSED_BRAND_KEY,
      constructs: disposal,
    });

    // All three places a disposal is raised — the in-flight request the kill
    // settles, work already queued behind it, and work admitted into the next
    // lifecycle and then overtaken — carry the same brand. What that buys is
    // stated exactly by the probes below: a layer that merely knows the words
    // cannot make a caller go quiet. It is a collision contract, not an
    // attestation, and the `structural` probe mints an accepted disposal here
    // on purpose to say so.
    for (const label of ['inFlight', 'queued', 'cancelled']) {
      expect(run.result[label]).toEqual({ state: 'rejected', ...disposal });
    }

    expect(run.result.probes).toEqual({
      // The exact sentence and nothing else — a database driver, a wrapper or a
      // stale copy of the string. This is the one CASE called out: it used to
      // be enough to make a post-embedding failure disappear.
      messageOnly: false,
      // Minted in the driver with no access to the class: a registry symbol is
      // the same symbol in every module instance, so a `dist/` build's error is
      // recognised by this transpiled copy and vice versa.
      structural: true,
      // Each half of the brand alone is not the brand.
      brandWithoutCode: false,
      codeWithoutBrand: false,
      // Fully branded and still not this: the message must match whole.
      wrongMessage: false,
      // Shape is not identity.
      notAnError: false,
      plainString: false,
    });
    expect(run.status).toBe(0);
  }, 30_000);
});
