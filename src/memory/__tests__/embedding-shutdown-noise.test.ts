/**
 * The recall-side embedding wrappers must tell a shutdown from a failure.
 *
 * `disposeModel()` settles the work it cancels with exactly
 * `Embedding worker disposed`. `embedText` and `initEmbeddings` classify only
 * `SHIELDCORTEX_SKIP_EMBEDDINGS=1` as expected, so a recall or a preload that
 * is in flight when the server shuts down prints
 *   [shieldcortex] embedText failed: Embedding worker disposed
 *   [shieldcortex] Embedding init failed, vector recall disabled: Embedding worker disposed
 * — the text is honest, the label is not, on exactly the axis the disposal
 * work exists to fix.
 *
 * Behavioural, not source-level: the embeddings module is stubbed so each
 * message can be driven through the real wrapper, and the classifier under
 * test is the production one imported from `generator.ts` — not a copy of the
 * string kept alive in this file.
 *
 * The match is EXACT, and the message is not the whole of it: a cancellation is
 * a `WorkerDisposedError` the generator minted, brand and code included. A
 * timeout, the timeout kill, a crash, any message that merely starts with or
 * mentions disposal — and the exact sentence on a plain `Error` — stay loud.
 */
import { beforeEach, describe, expect, it, jest } from '@jest/globals';
import { WORKER_DISPOSED_MSG, WorkerDisposedError } from '../../embeddings/generator.js';

const DISPOSED = WORKER_DISPOSED_MSG;
const DISABLED = 'Embeddings disabled via SHIELDCORTEX_SKIP_EMBEDDINGS=1';

/** Messages that must NEVER be swallowed, each a near miss in its own way. */
const STILL_LOUD = [
  'embed timed out after 30000ms',                         // the timeout itself
  'Embedding worker terminated after a timed-out request', // collateral of one
  'Worker exited with code 3',                             // a real crash
  'Worker crashed: fake worker boom',
  'Embedding worker disposed while writing the vector',    // merely starts the same
  'the worker was disposed',                               // merely mentions it
  // The exact sentence, unbranded: what a layer under the embedder could raise
  // by accident. Only a disposal this module MINTED is a cancellation.
  DISPOSED,
];

let embedFailure: Error | null = null;
let preloadFailure: Error | null = null;
let embedCalls = 0;
let preloadCalls = 0;

const generateEmbedding = jest.fn(async (_text: string): Promise<Float32Array> => {
  embedCalls += 1;
  if (embedFailure) throw embedFailure;
  return new Float32Array(384);
});

const preloadModel = jest.fn(async (): Promise<void> => {
  preloadCalls += 1;
  if (preloadFailure) throw preloadFailure;
});

jest.unstable_mockModule('../../embeddings/index.js', () => ({
  generateEmbedding,
  cosineSimilarity: () => 0,
  isModelLoaded: () => false,
  preloadModel,
  disposeModel: async () => {},
}));

const { embedText, initEmbeddings } = await import('../embedding.js');

let warns: string[] = [];
let errors: string[] = [];

beforeEach(() => {
  embedFailure = null;
  preloadFailure = null;
  embedCalls = 0;
  preloadCalls = 0;
  warns = [];
  errors = [];
  jest.spyOn(console, 'warn').mockImplementation((...args: unknown[]) => {
    warns.push(args.map(String).join(' '));
  });
  jest.spyOn(console, 'error').mockImplementation((...args: unknown[]) => {
    errors.push(args.map(String).join(' '));
  });
});

describe('embedText — shutdown cancellation is not a failure', () => {
  it('says nothing when disposal cancels the embed', async () => {
    embedFailure = new WorkerDisposedError();

    const result = await embedText('what did we decide about the ingest queue?');

    expect(embedCalls).toBe(1); // the call really ran — silence is not vacuum
    expect(result).toBeNull();
    expect(warns).toEqual([]);
    expect(errors).toEqual([]);
  });

  it('stays silent for every cancelled recall, not just the first', async () => {
    embedFailure = new WorkerDisposedError();

    for (let i = 0; i < 5; i++) {
      expect(await embedText(`query ${i}`)).toBeNull();
    }

    expect(embedCalls).toBe(5);
    expect(warns).toEqual([]);
  });

  it('stays silent when embeddings are switched off (unchanged)', async () => {
    embedFailure = new Error(DISABLED);

    expect(await embedText('disabled host')).toBeNull();

    expect(embedCalls).toBe(1);
    expect(warns).toEqual([]);
  });

  it.each(STILL_LOUD)('still reports %s', async (message) => {
    embedFailure = new Error(message);

    expect(await embedText('loud case')).toBeNull();

    expect(warns.join('\n')).toMatch(/embedText failed/);
    expect(warns.join('\n')).toContain(message);
  });
});

describe('initEmbeddings — shutdown cancellation is not a failure', () => {
  it('says nothing when disposal cancels the preload', async () => {
    preloadFailure = new WorkerDisposedError();

    const ready = await initEmbeddings();

    expect(preloadCalls).toBe(1); // the preload really ran — silence is not vacuum
    expect(ready).toBe(false);
    expect(warns).toEqual([]);
    expect(errors).toEqual([]);
  });

  it('stays silent when embeddings are switched off (unchanged)', async () => {
    preloadFailure = new Error(DISABLED);

    expect(await initEmbeddings()).toBe(false);

    expect(preloadCalls).toBe(1);
    expect(warns).toEqual([]);
  });

  it.each(STILL_LOUD)('still reports %s', async (message) => {
    preloadFailure = new Error(message);

    expect(await initEmbeddings()).toBe(false);

    expect(warns.join('\n')).toMatch(/Embedding init failed, vector recall disabled/);
    expect(warns.join('\n')).toContain(message);
  });

  // Last on purpose: a successful init latches `initialized` for the rest of
  // this module's lifetime, so every failing case above has to run first.
  it('still reports success as success', async () => {
    expect(await initEmbeddings()).toBe(true);

    expect(preloadCalls).toBe(1);
    expect(warns).toEqual([]);
  });
});
