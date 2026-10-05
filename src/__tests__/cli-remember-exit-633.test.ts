/**
 * #633: `shieldcortex remember` wrote the memory, then aborted with exit 134.
 *
 *   {"success":true,"memory":{...}}
 *   terminate called after throwing an instance of 'Napi::Error'
 *
 * The write schedules a background embed. With a warm model cache the worker
 * thread has a live ONNX session by the time the CLI reaches process.exit(),
 * and exiting with that thread still up aborts in onnxruntime's native
 * teardown. Disabling embeddings made the same command exit 0, and terminating
 * the worker before exiting (what embed-backfill already does) made it exit 0
 * with the model loaded.
 *
 * No ONNX here: the embedder is stubbed and process.exit() is intercepted, so
 * what is pinned is the lifecycle the fix depends on — the worker is disposed
 * BEFORE the process exits, on the success path and on the failure path, and
 * the exit code is still the honest one.
 */
import fs from 'fs';
import os from 'os';
import path from 'path';
import { afterEach, beforeEach, describe, expect, it, jest } from '@jest/globals';

const events: string[] = [];

// When set, disposeModel() stays pending until the test releases it, so the
// exit can be checked against disposal COMPLETING, not merely starting.
let heldDisposal: Promise<void> | null = null;
let disposalEntered: (() => void) | null = null;

jest.unstable_mockModule('../embeddings/index.js', () => ({
  generateEmbedding: async () => {
    events.push('embed');
    return new Float32Array(384);
  },
  cosineSimilarity: () => 0,
  isModelLoaded: () => false,
  preloadModel: async () => {},
  disposeModel: async () => {
    events.push('dispose');
    disposalEntered?.();
    if (heldDisposal) await heldDisposal;
    events.push('disposed');
  },
}));

const { handleRememberCommand } = await import('../cli/remember.js');
const { closeDatabase } = await import('../database/init.js');

class ExitCalled extends Error {
  constructor(readonly code: number | undefined) {
    super(`process.exit(${code})`);
  }
}

describe('#633 remember disposes the embedding worker before exiting', () => {
  let dir: string;
  const savedDb = process.env.CLAUDE_MEMORY_DB;

  beforeEach(() => {
    events.length = 0;
    heldDisposal = null;
    disposalEntered = null;
    dir = fs.mkdtempSync(path.join(os.tmpdir(), 'sc-633-'));
    process.env.CLAUDE_MEMORY_DB = path.join(dir, 'memories.db');
    jest.spyOn(process, 'exit').mockImplementation(((code?: number) => {
      events.push(`exit:${code}`);
      throw new ExitCalled(code);
    }) as typeof process.exit);
    jest.spyOn(console, 'log').mockImplementation(() => {});
    jest.spyOn(console, 'error').mockImplementation(() => {});
  });

  afterEach(() => {
    jest.restoreAllMocks();
    try { closeDatabase(); } catch { /* already closed */ }
    if (savedDb === undefined) delete process.env.CLAUDE_MEMORY_DB;
    else process.env.CLAUDE_MEMORY_DB = savedDb;
    fs.rmSync(dir, { recursive: true, force: true });
  });

  it('a successful write disposes the worker, then exits 0', async () => {
    await expect(handleRememberCommand([
      'sc633 synthetic success',
      '--content', 'synthetic note for the exit lifecycle',
      '--project', 'sc633-synthetic',
      '--json',
    ])).rejects.toBeInstanceOf(ExitCalled);

    expect(events).toContain('embed');
    expect(events.filter((e) => e.startsWith('exit:'))).toEqual(['exit:0']);
    expect(events.indexOf('dispose')).toBeGreaterThan(-1);
    expect(events.indexOf('dispose')).toBeLessThan(events.indexOf('exit:0'));
  });

  it('a failed write still disposes the worker and still exits non-zero', async () => {
    await expect(handleRememberCommand([
      'sc633 synthetic empty',
      '--content', '',
      '--project', 'sc633-synthetic',
      '--json',
    ])).rejects.toBeInstanceOf(ExitCalled);

    expect(events.filter((e) => e.startsWith('exit:'))).toEqual(['exit:1']);
    expect(events.indexOf('dispose')).toBeGreaterThan(-1);
    expect(events.indexOf('dispose')).toBeLessThan(events.indexOf('exit:1'));
  });

  // Starting disposal is not enough: the worker is only gone once
  // disposeModel() resolves, so the exit has to wait for that.
  async function exitWaitsForDisposal(args: string[], code: number): Promise<void> {
    let release!: () => void;
    heldDisposal = new Promise<void>((resolve) => { release = resolve; });
    const entered = new Promise<void>((resolve) => { disposalEntered = resolve; });

    const run = handleRememberCommand(args);
    run.catch(() => {}); // observed below; avoid an unhandled rejection meanwhile

    await entered;
    await new Promise((resolve) => setImmediate(resolve));
    expect(events.filter((e) => e.startsWith('exit:'))).toEqual([]);

    release();
    await expect(run).rejects.toBeInstanceOf(ExitCalled);
    expect(events.filter((e) => e.startsWith('exit:'))).toEqual([`exit:${code}`]);
    expect(events.indexOf('disposed')).toBeLessThan(events.indexOf(`exit:${code}`));
  }

  it('a successful write exits 0 only after disposal completes', async () => {
    await exitWaitsForDisposal([
      'sc633 synthetic held success',
      '--content', 'synthetic note for the awaited-disposal lifecycle',
      '--project', 'sc633-synthetic',
      '--json',
    ], 0);
    expect(events).toContain('embed');
  });

  it('a failed write exits 1 only after disposal completes', async () => {
    await exitWaitsForDisposal([
      'sc633 synthetic held empty',
      '--content', '',
      '--project', 'sc633-synthetic',
      '--json',
    ], 1);
  });
});
