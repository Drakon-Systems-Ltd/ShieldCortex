/**
 * Shutdown cancels queued embedding jobs on purpose — that is the disposal
 * doing its job, not a failure.
 *
 * Round 2 made that cancellation SETTLE. Before it, queued embeds never
 * resolved before `process.exit(0)` and printed nothing; now every one of them
 * reaches its caller's catch, and with no allowlist entry each prints
 *   [shieldcortex] Failed to generate embedding: Error: Embedding worker disposed
 * once per queued job. The text is honest, the label is not — on exactly the
 * axis the disposal work exists to fix — and it scales with queue depth.
 *
 * Both embedding-job callers are pinned here, with no ONNX anywhere:
 *
 * - `store.ts` runs in-process against a stubbed `../embeddings/index.js`;
 * - `scripts/lib/save-memory.mjs` runs as a REAL hook process inside a hermetic
 *   package (see `./hook-package-fixture.js`) whose `dist/embeddings/*` modules
 *   are the fixture's and whose defence, database and disposal classifier are
 *   the real build's.
 *
 * The writer itself is unmodified and carries no test seam: it finds the
 * fixture's embedder the same way it finds the real one, by relative package
 * layout, and the last case below proves the retired injection variables now
 * do nothing even in a genuine jest runtime.
 *
 * The match is EXACT. A timeout, a timeout kill, a crash, an invalid vector, a
 * database error, or any message that merely mentions disposal stays loud.
 */
import fs from 'fs';
import os from 'os';
import path from 'path';
import { afterAll, afterEach, beforeAll, beforeEach, describe, expect, it, jest } from '@jest/globals';
import { WORKER_DISPOSED_MSG, isWorkerDisposedError } from '../embeddings/generator.js';
import {
  FIXTURE_VECTOR_BYTES,
  FIXTURE_VECTOR_HEAD,
  createHookPackage,
  repoRoot,
  runHook,
} from './hook-package-fixture.js';

// From the producer, not a second copy of it. The one literal pin lives at the
// producer end (`worker-dispose-honesty.test.ts` asserts the string a real
// disposal settles with), so a change to the contract fails there, once,
// instead of quietly agreeing with itself here.
const DISPOSED = WORKER_DISPOSED_MSG;

/** Messages that must NEVER be swallowed, each a near miss in its own way. */
const STILL_LOUD = [
  'embed timed out after 30000ms',                     // the timeout itself
  'Embedding worker terminated after a timed-out request', // collateral of one
  'Worker exited with code 3',                         // a real crash
  'Worker crashed: fake worker boom',
  'Embedding worker disposed while writing the vector', // merely starts the same
  'the worker was disposed',                            // merely mentions it
];

/**
 * Per-test budget for the cases that spawn a real hook process.
 *
 * The repo default is 10s, which is the right budget for an in-process test and
 * the wrong one for a case whose subject is a whole Node process doing a real
 * defence scan. The headroom is here so a slow machine reports the behaviour
 * under test rather than a timeout; none of the assertions are weakened for it.
 */
const HOOK_CASE_MS = 60_000;
/**
 * Every line the writer prints starts with this.
 *
 * A quiet case asserts the absence of it rather than an empty stderr: the
 * subject is what the WRITER said, and a future Node deprecation notice on the
 * child's stderr is not that. Nothing about the axis under test is weakened —
 * the writer has no other way to speak.
 */
const WRITER_PREFIX = '[shieldcortex save-memory]';
/** Building a package copies the whole build; only ever done once per suite. */
const PACKAGE_BUILD_MS = 120_000;

// --- store.ts seam: the embedder is a stub, never the real worker ----------
let embedFailure: Error | null = null;
let embedResult: unknown = new Float32Array(384);
let embedCalls = 0;

const generateEmbedding = jest.fn(async (_text: string): Promise<Float32Array> => {
  embedCalls += 1;
  if (embedFailure) throw embedFailure;
  return embedResult as Float32Array;
});

jest.unstable_mockModule('../embeddings/index.js', () => ({
  generateEmbedding,
  cosineSimilarity: () => 0,
  isModelLoaded: () => false,
  preloadModel: async () => {},
  disposeModel: async () => {},
}));

const { initDatabase, closeDatabase, getDatabase } = await import('../database/init.js');
const { addMemory, updateMemory, awaitPendingEmbeddings } = await import('../memory/store.js');

const PROJECT = 'embed-shutdown-noise';

let errors: string[] = [];
let warns: string[] = [];
let realError: typeof console.error;
let realWarn: typeof console.warn;

function captureConsole(): void {
  errors = [];
  warns = [];
  realError = console.error;
  realWarn = console.warn;
  console.error = (...args: unknown[]) => { errors.push(args.map(String).join(' ')); };
  console.warn = (...args: unknown[]) => { warns.push(args.map(String).join(' ')); };
}

function restoreConsole(): void {
  console.error = realError;
  console.warn = realWarn;
}

/** The refresh path is fire-and-forget — let its catch run. */
const flush = (): Promise<void> => new Promise((r) => setTimeout(r, 30));

describe('store.ts embedding jobs — shutdown cancellation is not a failure', () => {
  beforeEach(() => {
    closeDatabase();
    initDatabase(':memory:');
    embedFailure = null;
    embedResult = new Float32Array(384);
    embedCalls = 0;
    captureConsole();
  });

  afterEach(() => {
    restoreConsole();
    closeDatabase();
  });

  function add(title: string): { id: number } {
    return addMemory({
      title,
      content: `Body for ${title} — ordinary project note, nothing adversarial.`,
      category: 'note',
      project: PROJECT,
      type: 'long_term',
    });
  }

  async function addAndEmbed(title: string): Promise<void> {
    add(title);
    await awaitPendingEmbeddings();
  }

  it('says nothing when a queued job is cancelled by disposal', async () => {
    embedFailure = new Error(DISPOSED);

    await addAndEmbed('disposal is quiet');

    expect(embedCalls).toBe(1); // the job really ran — silence is not vacuum
    expect(errors).toEqual([]);
  });

  it('stays silent for every job a shutdown cancels, not just the first', async () => {
    embedFailure = new Error(DISPOSED);

    for (let i = 0; i < 5; i++) await addAndEmbed(`queued job ${i}`);

    expect(embedCalls).toBe(5);
    expect(errors).toEqual([]);
  });

  it.each(STILL_LOUD)('still reports %s', async (message) => {
    embedFailure = new Error(message);

    await addAndEmbed(`loud: ${message.slice(0, 20)}`);

    expect(errors.join('\n')).toMatch(/Failed to generate embedding/);
    expect(errors.join('\n')).toContain(message);
  });

  it('still reports a vector it cannot use', async () => {
    embedResult = null;

    await addAndEmbed('invalid vector');

    expect(warns.join('\n')).toMatch(/returned invalid result/);
  });

  it('still reports a database failure on the write', async () => {
    add('write fails');
    // The row is already in; only the vector write is blocked, and the message
    // is not the connection-closed one the store path deliberately ignores.
    getDatabase().pragma('query_only = true');

    await awaitPendingEmbeddings();
    getDatabase().pragma('query_only = false');

    expect(errors.join('\n')).toMatch(/Failed to store embedding/);
  });

  it('classifies the update-refresh path the same way', async () => {
    const created = addMemory({
      title: 'refresh path',
      content: 'Original content for the refresh path.',
      category: 'note',
      project: PROJECT,
      type: 'long_term',
    });
    await awaitPendingEmbeddings();
    errors = [];

    embedFailure = new Error(DISPOSED);
    updateMemory(created.id, { content: 'Rewritten content, first pass.' });
    await flush();
    expect(embedCalls).toBe(2); // the refresh really ran — silence is not vacuum
    expect(errors).toEqual([]);

    embedFailure = new Error('embed timed out after 30000ms');
    updateMemory(created.id, { content: 'Rewritten content, second pass.' });
    await flush();
    expect(embedCalls).toBe(3);
    expect(errors.join('\n')).toMatch(/Failed to regenerate embedding/);
  });
});

/**
 * The hook writer, as a real process.
 *
 * Every case below runs `scripts/lib/save-memory.mjs` unmodified inside a
 * hermetic package, and every one asserts on what the process SAID and what it
 * STORED. `events` is the non-vacuity control: it is what the fixture embedder
 * recorded, so a writer that stopped embedding altogether fails the quiet cases
 * instead of passing them by saying nothing.
 */
describe('hook writer (real process, hermetic package) — same classification', () => {
  let root: string;
  let pkg: string;

  beforeAll(() => {
    root = fs.mkdtempSync(path.join(os.tmpdir(), 'sc-embed-noise-'));
    pkg = createHookPackage(path.join(root, 'pkg'));
  }, PACKAGE_BUILD_MS);

  afterAll(() => {
    fs.rmSync(root, { recursive: true, force: true });
  });

  it('says nothing when the shutdown disposal cancels the embed', () => {
    const run = runHook({
      dir: root,
      pkgRoot: pkg,
      plan: { mode: 'fail', message: DISPOSED },
      title: 'HOOK disposal is quiet',
    });

    expect(run.events).toEqual(['generateEmbedding']); // it really ran
    expect(run.stderr).not.toContain(WRITER_PREFIX); // the writer said nothing at all
    expect(run.stderr).not.toContain(DISPOSED);
    expect(run.len).toBeNull(); // the vector is lost; the memory is not
  }, HOOK_CASE_MS);

  it.each(STILL_LOUD)('still reports %s', (message) => {
    const run = runHook({
      dir: root,
      pkgRoot: pkg,
      plan: { mode: 'fail', message },
      title: `HOOK loud ${message.slice(0, 20)}`,
    });

    expect(run.stderr).toMatch(/embedding failed for memory/);
    expect(run.stderr).toContain(message);
  }, HOOK_CASE_MS);

  it('reports a real timeout, and disposes the model it timed out on', () => {
    const run = runHook({
      dir: root,
      pkgRoot: pkg,
      plan: { mode: 'hang' },
      env: { SHIELDCORTEX_HOOK_EMBED_TIMEOUT_MS: '250' },
      title: 'HOOK real timeout',
    });

    // Not an injected message: the embed never settles, so this is the writer's
    // own Promise.race firing, and the disposal it triggers is the real call.
    expect(run.stderr).toContain('embedding failed for memory');
    expect(run.stderr).toContain('embedding timed out after 250ms');
    expect(run.events).toEqual(['generateEmbedding', 'disposeModel']);
    expect(run.len).toBeNull();
  }, HOOK_CASE_MS);

  it('says its one line when the worker is unavailable, and calls it that', () => {
    const run = runHook({
      dir: root,
      pkgRoot: pkg,
      plan: { mode: 'fail', message: 'Embedding worker unavailable. Run `npm run build` so dist/embeddings/worker.js exists.' },
      title: 'HOOK unavailable',
    });

    expect(run.stderr).toContain('embeddings unavailable');
    expect(run.stderr).toContain('Embedding worker unavailable');
    expect(run.stderr).not.toContain('embedding failed for memory'); // configuration, not failure
  }, HOOK_CASE_MS);

  it('still reports a vector it cannot use', () => {
    const run = runHook({
      dir: root,
      pkgRoot: pkg,
      plan: { mode: 'null' },
      title: 'HOOK no vector',
    });

    expect(run.stderr).toContain('embedding returned no vector');
    expect(run.len).toBeNull();
  }, HOOK_CASE_MS);

  it('still reports a failure raised at the write step', () => {
    const run = runHook({
      dir: root,
      pkgRoot: pkg,
      plan: { mode: 'unusable', message: 'vector buffer detached' },
      title: 'HOOK write fails',
    });

    expect(run.stderr).toContain('embedding failed for memory');
    expect(run.stderr).toContain('vector buffer detached');
    expect(run.len).toBeNull();
  }, HOOK_CASE_MS);

  it('awaits the vector and stores it before the process exits', () => {
    const run = runHook({ dir: root, pkgRoot: pkg, plan: { mode: 'vector' }, title: 'HOOK stores it' });

    // The fixture embedder settles across a setImmediate, so a writer that
    // scheduled this instead of awaiting it would exit with a NULL column.
    expect(run.events).toEqual(['generateEmbedding']);
    expect(run.len).toBe(FIXTURE_VECTOR_BYTES);
    expect(run.head).toBe(FIXTURE_VECTOR_HEAD);
    expect(run.stderr).not.toContain(WRITER_PREFIX);
  }, HOOK_CASE_MS);

  it('embeds nothing at all when embeddings are disabled', () => {
    const run = runHook({
      dir: root,
      pkgRoot: pkg,
      env: { SHIELDCORTEX_SKIP_EMBEDDINGS: '1' },
      title: 'HOOK disabled',
    });

    expect(run.events).toEqual([]); // the gate is before the embedder, not after
    expect(run.len).toBeNull();
    expect(run.stderr).not.toContain(WRITER_PREFIX);
  }, HOOK_CASE_MS);

  it('embeds nothing at all when the model cache is not ready', () => {
    const run = runHook({
      dir: root,
      pkgRoot: pkg,
      plan: { cacheReady: false },
      title: 'HOOK cold cache',
    });

    // #460: never download at session close. The health gate is what stands
    // between a hook and a HuggingFace fetch, and nothing may skip it.
    expect(run.events).toEqual([]);
    expect(run.len).toBeNull();
    expect(run.stderr).not.toContain(WRITER_PREFIX);
  }, HOOK_CASE_MS);
});

/**
 * The writer is a plain .mjs that cannot import the TypeScript contract, so it
 * borrows the compiled classifier out of `dist/embeddings/`. That is not a
 * fallback risk: without a build the defence pipeline is unavailable and this
 * writer drops the memory long before it embeds anything, so any embed that
 * could produce a disposal has the build loaded already. If the borrow fails
 * anyway, nothing is suppressed — a disposal prints one line, exactly the
 * pre-fix behaviour, which is the safe direction to fail in.
 *
 * That is also what makes "borrowed" testable rather than asserted: the same
 * writer, in a package whose build predates the contract, goes loud again. A
 * copy of the literal could not tell the two packages apart.
 */
describe('hook writer — the disposal contract is borrowed from the build', () => {
  let root: string;
  let stale: string;

  beforeAll(() => {
    root = fs.mkdtempSync(path.join(os.tmpdir(), 'sc-embed-contract-'));
    stale = createHookPackage(path.join(root, 'stale'), { classifier: 'missing' });
  }, PACKAGE_BUILD_MS);

  afterAll(() => {
    fs.rmSync(root, { recursive: true, force: true });
  });

  it('suppresses nothing when the build exports no classifier', () => {
    const run = runHook({
      dir: root,
      pkgRoot: stale,
      plan: { mode: 'fail', message: DISPOSED },
      title: 'HOOK stale build',
    });

    // Loud, and specifically loud about the disposal: proof that the quiet case
    // in the suite above came from the build's classifier, and not from a local
    // copy of the string that no missing export could ever disturb.
    expect(run.events).toEqual(['generateEmbedding']);
    expect(run.stderr).toContain('embedding failed for memory');
    expect(run.stderr).toContain(DISPOSED);
  }, HOOK_CASE_MS);
});

/**
 * `SHIELDCORTEX_TEST_SEAM`, `SHIELDCORTEX_HOOK_EMBED_FAKE` and
 * `SHIELDCORTEX_HOOK_EMBED_FAIL` used to be read by the writer itself, so a
 * hook whose environment happened to carry them — a shell profile, an agent
 * spawned by a test run — embedded whatever a test would have wanted, skipping
 * the SKIP_EMBEDDINGS and cache-health gates the rest of the path respects.
 * Fencing them behind more inherited variables only moved the boundary; they
 * are gone instead, and substitution now happens in the package a test builds.
 *
 * These two cases are what "gone" means, measured rather than asserted: with
 * every retired key set, and with the jest runtime markers those keys were
 * once fenced behind present too, the hook embeds exactly what its package
 * gives it and says exactly what the outcome was.
 */
describe('hook writer — no test seam survives into production', () => {
  const RETIRED_SEAM_ENV = {
    SHIELDCORTEX_TEST_SEAM: '1',
    SHIELDCORTEX_HOOK_EMBED_FAKE: '1',
    SHIELDCORTEX_HOOK_EMBED_FAIL: 'Worker exited with code 3',
    NODE_ENV: 'test',
    JEST_WORKER_ID: '1',
  };

  let root: string;
  let pkg: string;

  beforeAll(() => {
    root = fs.mkdtempSync(path.join(os.tmpdir(), 'sc-embed-noseam-'));
    pkg = createHookPackage(path.join(root, 'pkg'));
  }, PACKAGE_BUILD_MS);

  afterAll(() => {
    fs.rmSync(root, { recursive: true, force: true });
  });

  it('ignores every retired injection variable, inside a real test runtime', () => {
    const run = runHook({
      dir: root,
      pkgRoot: pkg,
      plan: { mode: 'vector' },
      env: RETIRED_SEAM_ENV,
      title: 'HOOK retired keys',
    });

    // The package's embedder ran, so the vector carries the fixture's marker
    // rather than the deleted seam's 0.42, and no injected failure appears.
    expect(run.events).toEqual(['generateEmbedding']);
    expect(run.head).toBe(FIXTURE_VECTOR_HEAD);
    expect(run.len).toBe(FIXTURE_VECTOR_BYTES);
    expect(run.stderr).not.toContain('Worker exited with code 3');
  }, HOOK_CASE_MS);

  it('cannot be made to fake a vector in the real package layout', () => {
    // The repository itself this time: the real dist, the real model-cache gate,
    // and a HOME with no model in it. The only way a vector could appear here
    // is a seam, and there is none.
    const run = runHook({
      dir: root,
      pkgRoot: repoRoot,
      env: RETIRED_SEAM_ENV,
      title: 'HOOK real layout',
    });

    expect(run.len).toBeNull();
    expect(run.events).toEqual([]);
    expect(run.stderr).not.toContain('Worker exited with code 3');
    expect(run.stderr).not.toContain('embedding failed for memory');
  }, HOOK_CASE_MS);
});

/**
 * Negative controls for the boundary every caller now shares.
 *
 * Whole-message equality on an `Error` is the whole contract, so the two ways a
 * near miss could still carry the exact text — a bare string, and something
 * that merely has a `message` property — must both be rejected. Neither can be
 * produced by `intentionalMessage()`, and if one day the classifier were
 * loosened to `err.message === MSG` without the `instanceof` guard, an
 * arbitrary object thrown by any layer could go quiet.
 */
describe('isWorkerDisposedError — negative controls', () => {
  it('accepts only a real Error carrying the exact message', () => {
    expect(isWorkerDisposedError(new Error(DISPOSED))).toBe(true);
  });

  it('rejects the exact sentinel as a plain string', () => {
    expect(isWorkerDisposedError(DISPOSED)).toBe(false);
  });

  it('rejects a message-shaped object that is not an Error', () => {
    expect(isWorkerDisposedError({ message: DISPOSED })).toBe(false);
    expect(isWorkerDisposedError({ message: DISPOSED, name: 'Error', stack: 'fake' })).toBe(false);
  });

  it('rejects an Error whose message merely contains the sentinel', () => {
    expect(isWorkerDisposedError(new Error(`${DISPOSED} while writing the vector`))).toBe(false);
    expect(isWorkerDisposedError(new Error(`worker: ${DISPOSED}`))).toBe(false);
  });

  it('rejects the empty and absent cases', () => {
    expect(isWorkerDisposedError(null)).toBe(false);
    expect(isWorkerDisposedError(undefined)).toBe(false);
    expect(isWorkerDisposedError(new Error(''))).toBe(false);
  });
});
