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
 * One line of the source is rewritten on the way in: INFERENCE_TIMEOUT_MS
 * becomes env-overridable, so the timeout scenario can drive the real timeout
 * path in under a second instead of 30. The rewrite throws if the declaration
 * ever moves, rather than silently dropping that coverage; every other
 * scenario leaves the env unset and runs the shipped 30s value.
 */

const repoRoot = path.resolve(process.cwd());
const GENERATOR_SRC = path.join(repoRoot, 'src', 'embeddings', 'generator.ts');
const RESULT_PREFIX = '__RESULT__ ';

const TIMEOUT_DECL = 'const INFERENCE_TIMEOUT_MS = 30_000;';
const TIMEOUT_DECL_TEST =
  'const INFERENCE_TIMEOUT_MS = Number(process.env.SC_TEST_INFERENCE_TIMEOUT_MS) || 30_000;';

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
 * Every instance appends its threadId to SC_FAKE_WORKER_LOG on startup, so the
 * driver can count how many workers were spawned. A hanging instance also
 * heartbeats its threadId into SC_FAKE_WORKER_BEAT every 10ms: an intentional
 * kill is silent by design, so the moment the heartbeat stops is the only
 * observable proof that that thread is gone.
 */
const FAKE_WORKER = [
  "import { parentPort, threadId } from 'worker_threads';",
  "import { appendFileSync } from 'fs';",
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
  "import { generateEmbedding, disposeModel, isModelLoaded } from './generator.js';",
  '',
  'const scenario = process.argv[2];',
  "const out = (obj) => fs.writeSync(1, '__RESULT__ ' + JSON.stringify(obj) + '\\n');",
  "process.on('unhandledRejection', (e) => { out({ fatal: e instanceof Error ? e.message : String(e) }); process.exit(1); });",
  'const msgOf = (e) => (e instanceof Error ? e.message : String(e));',
  "const settle = (p) => p.then(() => ({ state: 'resolved', message: '' }), (e) => ({ state: 'rejected', message: msgOf(e) }));",
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
  '  // The replacement is created here, while the timed-out worker is still',
  "  // terminating — its exit lands afterwards and must not poison worker B.",
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
  '  // wait for that line instead of sleeping past where it usually lands.',
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

function runScenario(name: string, extraEnv: Record<string, string> = {}): ScenarioRun {
  const env = {
    ...process.env,
    SC_FAKE_WORKER_LOG: path.join(sandbox, `spawned-${name}.log`),
    SC_FAKE_WORKER_BEAT: path.join(sandbox, `beats-${name}.log`),
    SC_FAKE_WORKER_BLOCK: path.join(sandbox, `blocking-${name}.log`),
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
    const transpiled = ts.transpileModule(source.replace(TIMEOUT_DECL, TIMEOUT_DECL_TEST), {
      fileName: 'generator.ts',
      compilerOptions: { module: ts.ModuleKind.ESNext, target: ts.ScriptTarget.ES2022 },
    }).outputText;
    fs.writeFileSync(path.join(sandbox, 'generator.js'), transpiled);
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
    expect(String(run.result.message)).toMatch(/dispos/i);
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
});
