/**
 * The MCP server preloads the model in the background and reports what comes
 * back. Shutting the server down disposes the model, and a preload still in
 * flight then settles as `Embedding worker disposed` — on a cold cache that
 * window is as wide as MODEL_LOAD_TIMEOUT_MS (120s). Reporting it printed
 *   [shieldcortex] Model preload failed (worker heals a corrupt cache at most
 *   once per process; run `shieldcortex doctor` if this repeats): Embedding
 *   worker disposed
 * telling an operator to go run doctor over a perfectly clean shutdown.
 *
 * Behavioural: the preload is stubbed so each message reaches the real catch,
 * and the classifier deciding is the production one — the mock factory spreads
 * the real generator module and replaces only `preloadModel`.
 *
 * A genuine preload failure keeps the doctor guidance, verbatim.
 */
import fs from 'fs';
import path from 'path';
import { beforeEach, describe, expect, it, jest } from '@jest/globals';

const actualGenerator = await import('../generator.js');
const DISPOSED = actualGenerator.WORKER_DISPOSED_MSG;

/** Messages that must NEVER be swallowed, each a near miss in its own way. */
const STILL_LOUD = [
  'load timed out after 120000ms',                         // the load timeout
  'Embedding worker terminated after a timed-out request', // collateral of one
  'Worker exited with code 3',                             // a real crash
  'Embedding worker unavailable. Run `npm run build` so dist/embeddings/worker.js exists.',
  'Embedding worker disposed while loading the model',     // merely starts the same
  'the worker was disposed',                               // merely mentions it
];

let preloadFailure: unknown = null;
let preloadCalls = 0;

const preloadModel = jest.fn(async (): Promise<void> => {
  preloadCalls += 1;
  if (preloadFailure !== null) throw preloadFailure;
});

jest.unstable_mockModule('../generator.js', () => ({
  ...actualGenerator,
  preloadModel,
}));

const { startBackgroundPreload } = await import('../background-preload.js');

let errors: string[] = [];

beforeEach(() => {
  preloadFailure = null;
  preloadCalls = 0;
  errors = [];
  delete process.env.SHIELDCORTEX_SKIP_EMBEDDINGS;
  jest.spyOn(console, 'error').mockImplementation((...args: unknown[]) => {
    errors.push(args.map(String).join(' '));
  });
});

describe('background preload — a shutdown is not a preload failure', () => {
  it('says nothing when disposal cancels the preload', async () => {
    preloadFailure = new Error(DISPOSED);

    await startBackgroundPreload();

    expect(preloadCalls).toBe(1); // the preload really ran — silence is not vacuum
    expect(errors).toEqual([]);
  });

  it.each(STILL_LOUD)('still reports %s, with the doctor guidance', async (message) => {
    preloadFailure = new Error(message);

    await startBackgroundPreload();

    const printed = errors.join('\n');
    expect(printed).toContain('Model preload failed');
    expect(printed).toContain('run `shieldcortex doctor` if this repeats');
    expect(printed).toContain(message);
  });

  it('still reports a non-Error rejection', async () => {
    preloadFailure = 'model file vanished mid-load';

    await startBackgroundPreload();

    expect(errors.join('\n')).toContain('model file vanished mid-load');
  });

  it('says nothing when the preload succeeds', async () => {
    await startBackgroundPreload();

    expect(preloadCalls).toBe(1);
    expect(errors).toEqual([]);
  });

  it('does not preload at all when the host disabled embeddings', async () => {
    process.env.SHIELDCORTEX_SKIP_EMBEDDINGS = '1';

    await startBackgroundPreload();

    expect(preloadCalls).toBe(0);
    expect(errors).toEqual([]);
  });

  /**
   * Wiring pin, and the one assertion here that is static: src/index.ts starts
   * a real MCP server on import, so there is no practical way to drive its
   * startup path from a test. Everything the catch *does* is behavioural above
   * — this only stops the extraction from quietly becoming decorative while a
   * second inline catch grows back in the entry point.
   */
  it('is what the server entry actually uses', () => {
    const entry = fs.readFileSync(
      path.join(process.cwd(), 'src', 'index.ts'),
      'utf-8',
    );

    expect(entry).toContain('startBackgroundPreload()');
    expect(entry).not.toMatch(/preloadModel\(\)\s*\.catch/);
  });
});
