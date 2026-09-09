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
 */

const repoRoot = path.resolve(process.cwd());
const GENERATOR_SRC = path.join(repoRoot, 'src', 'embeddings', 'generator.ts');
const RESULT_PREFIX = '__RESULT__ ';

/**
 * Stub worker. Behaviour is selected by the text of the embed request so the
 * driver can steer it without any extra channel:
 *  - __CRASH_EXIT__  : die with a non-zero exit code, unprompted
 *  - __CRASH_THROW__ : die from an uncaught error, unprompted
 *  - __HANG__        : accept the request and never answer
 * Every instance appends its threadId to SC_FAKE_WORKER_LOG on startup, so the
 * driver can count how many workers were spawned.
 */
const FAKE_WORKER = [
  "import { parentPort, threadId } from 'worker_threads';",
  "import { appendFileSync } from 'fs';",
  '',
  'if (process.env.SC_FAKE_WORKER_LOG) {',
  "  appendFileSync(process.env.SC_FAKE_WORKER_LOG, threadId + '\\n');",
  '}',
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
  "  if (text.includes('__HANG__')) return;",
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
  'const spawned = () => {',
  '  try {',
  "    return fs.readFileSync(process.env.SC_FAKE_WORKER_LOG, 'utf8').split('\\n').filter(Boolean).length;",
  '  } catch { return -1; }',
  '};',
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
  "  const inflight = generateEmbedding('__HANG__');",
  '  const settled = inflight.then(',
  "    () => ({ state: 'resolved', message: '' }),",
  "    (e) => ({ state: 'rejected', message: msgOf(e) }),",
  '  );',
  '  await delay(150); // let the stub worker receive the request',
  '  const startedAt = Date.now();',
  '  await disposeModel();',
  '  const disposeMs = Date.now() - startedAt;',
  "  const outcome = await Promise.race([settled, delay(2000).then(() => ({ state: 'hung', message: '' }))]);",
  '  out({ ...outcome, disposeMs, loadedAfter: isModelLoaded(), spawned: spawned() });',
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
  "  await delay(600); // worker A's delayed exit event arrives in this window",
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

function runScenario(name: string): ScenarioRun {
  const env = { ...process.env, SC_FAKE_WORKER_LOG: path.join(sandbox, `spawned-${name}.log`) };
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
    const transpiled = ts.transpileModule(fs.readFileSync(GENERATOR_SRC, 'utf8'), {
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
      loadedAfterStaleExit: true,
      spawned: 2,
    });
    expect(run.stderr).toMatch(/Embedding worker error: fake worker boom/);
    expect(run.status).toBe(0);
  }, 30_000);
});
