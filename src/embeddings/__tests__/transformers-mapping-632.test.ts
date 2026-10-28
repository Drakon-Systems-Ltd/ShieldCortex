/**
 * #632 — the configuration mapping against the INSTALLED transformers.js, not
 * a stand-in. `fetch` is replaced, so no request leaves the process: the
 * mirror case records the URL the library would have requested and answers
 * 404; the offline case asserts the library never calls fetch at all.
 */
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
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
      localModelPath: tf.env.localModelPath,
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

  /**
   * F2 (review r1): getModelFile reads the FileCache at cacheDir AND
   * localModelPath (the package's own models/ dir by default) before the
   * offline gate. A stand-in for that package-local copy is pointed at a
   * throwaway dir here — node_modules is never written — and must not be able
   * to satisfy, or shadow, a file under an explicit root. config.json is the
   * probe: AutoConfig keeps every JSON field, so the sentinel shows which
   * root was read without loading a model.
   */
  describe('an explicit SHIELDCORTEX_MODEL_DIR is the only local root', () => {
    let fallback: string;
    const writeConfig = (base: string, sentinel: string) => {
      const dir = join(base, EMBEDDING_MODEL_ID);
      mkdirSync(dir, { recursive: true });
      writeFileSync(join(dir, 'config.json'), JSON.stringify({ model_type: 'bert', sc_sentinel: sentinel }));
    };

    beforeEach(() => {
      fallback = mkdtempSync(join(tmpdir(), 'sc-632-tf-fallback-'));
      tf.env.localModelPath = `${fallback}/`;
      writeConfig(fallback, 'package-local-fallback');
      fetchSpy = jest.spyOn(globalThis, 'fetch').mockImplementation(() => {
        throw new Error('offline mode must not fetch');
      });
    });

    afterEach(() => {
      rmSync(fallback, { recursive: true, force: true });
    });

    const offlineExplicit = () => applyEmbeddingModelConfig(tf.env, resolveEmbeddingModelConfig({
      SHIELDCORTEX_MODEL_DIR: root,
      SHIELDCORTEX_EMBEDDINGS_OFFLINE: '1',
    }));

    it('a file present only in the fallback cannot satisfy a missing configured file', async () => {
      // The root has tokenizer siblings but lacks config.json; the fallback has it.
      mkdirSync(join(root, EMBEDDING_MODEL_ID), { recursive: true });
      writeFileSync(join(root, EMBEDDING_MODEL_ID, 'tokenizer_config.json'), '{}');
      offlineExplicit();
      await expect(tf.AutoConfig.from_pretrained(EMBEDDING_MODEL_ID, { local_files_only: true }))
        .rejects.toThrow(/not found locally/);
      expect(fetchSpy).not.toHaveBeenCalled();
    });

    it('when both roots have the file, the configured root is the one read', async () => {
      writeConfig(root, 'configured-root');
      offlineExplicit();
      const config = await tf.AutoConfig.from_pretrained(EMBEDDING_MODEL_ID, { local_files_only: true });
      expect(config.sc_sentinel).toBe('configured-root');
      expect(fetchSpy).not.toHaveBeenCalled();
    });

    it('library-contract control: without the mapping the fallback DOES fill the gap', async () => {
      // What the pre-fix mapping did: only cacheDir moved. Shows the seam is real.
      tf.env.cacheDir = root;
      tf.env.allowRemoteModels = false;
      const config = await tf.AutoConfig.from_pretrained(EMBEDDING_MODEL_ID, { local_files_only: true });
      expect(config.sc_sentinel).toBe('package-local-fallback');
    });

    it('the default root leaves the library localModelPath untouched', () => {
      applyEmbeddingModelConfig(tf.env, resolveEmbeddingModelConfig({}, root));
      expect(tf.env.localModelPath).toBe(`${fallback}/`);
    });
  });
});
