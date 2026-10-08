/**
 * #632 — the configuration mapping against the INSTALLED transformers.js, not
 * a stand-in. `fetch` is replaced, so no request leaves the process: the
 * mirror case records the URL the library would have requested and answers
 * 404; the offline case asserts the library never calls fetch at all.
 */
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it, jest } from '@jest/globals';

import { applyEmbeddingModelConfig, resolveEmbeddingModelConfig } from '../model-config.js';
import { EMBEDDING_MODEL_ID } from '../model-cache.js';

describe('#632 mapping onto the installed transformers.js', () => {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  let tf: any;
  let snapshot: Record<string, unknown>;
  let root: string;
  let fetchSpy: ReturnType<typeof jest.spyOn>;
  const savedToken = process.env.HF_TOKEN;

  beforeEach(async () => {
    tf = await import('@huggingface/transformers');
    snapshot = {
      allowRemoteModels: tf.env.allowRemoteModels,
      allowLocalModels: tf.env.allowLocalModels,
      cacheDir: tf.env.cacheDir,
      remoteHost: tf.env.remoteHost,
    };
    root = mkdtempSync(join(tmpdir(), 'sc-632-tf-'));
  });

  afterEach(() => {
    Object.assign(tf.env, snapshot);
    fetchSpy?.mockRestore();
    if (savedToken === undefined) delete process.env.HF_TOKEN;
    else process.env.HF_TOKEN = savedToken;
    rmSync(root, { recursive: true, force: true });
  });

  it('library does not read HF_ENDPOINT itself — the default host is huggingface.co', () => {
    expect(snapshot.remoteHost).toBe('https://huggingface.co/');
  });

  it('mirror: requests go to <HF_ENDPOINT path>/<model>/resolve/main/… with no HF token attached', async () => {
    process.env.HF_TOKEN = 'hf_s3cr3t';
    const urls: string[] = [];
    const headers: Array<Headers | undefined> = [];
    fetchSpy = jest.spyOn(globalThis, 'fetch').mockImplementation(async (input, init) => {
      urls.push(String(input));
      headers.push(init?.headers as Headers | undefined);
      return new Response('not found', { status: 404 });
    });
    applyEmbeddingModelConfig(tf.env, resolveEmbeddingModelConfig({
      SHIELDCORTEX_MODEL_DIR: root,
      HF_ENDPOINT: 'https://mirror.example/hf',
    }));
    await expect(tf.pipeline('feature-extraction', EMBEDDING_MODEL_ID, { dtype: 'fp32' })).rejects.toThrow();
    expect(urls.length).toBeGreaterThan(0);
    // The library fetches config/tokenizer files concurrently; order is not fixed.
    expect(urls).toContain(`https://mirror.example/hf/${EMBEDDING_MODEL_ID}/resolve/main/config.json`);
    expect(urls.every((u) => u.startsWith('https://mirror.example/hf/'))).toBe(true);
    for (const h of headers) expect(h?.get?.('Authorization') ?? null).toBeNull();
  });

  it('offline: an empty cache fails locally and fetch is never called', async () => {
    fetchSpy = jest.spyOn(globalThis, 'fetch').mockImplementation(() => {
      throw new Error('offline mode must not fetch');
    });
    applyEmbeddingModelConfig(tf.env, resolveEmbeddingModelConfig({
      SHIELDCORTEX_MODEL_DIR: root,
      SHIELDCORTEX_EMBEDDINGS_OFFLINE: '1',
      HF_ENDPOINT: 'https://mirror.example/hf',
    }));
    await expect(
      tf.pipeline('feature-extraction', EMBEDDING_MODEL_ID, { dtype: 'fp32', local_files_only: true }),
    ).rejects.toThrow(/not found locally|allowRemoteModels=false|local_files_only/);
    expect(fetchSpy).not.toHaveBeenCalled();
  });
});
