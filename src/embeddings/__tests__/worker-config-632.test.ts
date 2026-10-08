/**
 * #632 — the real embeddings worker module, driven through its message port.
 *
 * `worker_threads` is replaced with a fake port and `@huggingface/transformers`
 * with a fake `env` + `pipeline`, so these scenarios exercise worker.ts's own
 * configuration and heal logic with no model, no ONNX runtime and no network.
 * Each scenario re-imports a fresh module graph (fresh heal latch).
 */
import { existsSync, mkdirSync, mkdtempSync, readdirSync, rmSync, writeFileSync } from 'node:fs';
import { homedir, tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import { afterEach, beforeEach, describe, expect, it, jest } from '@jest/globals';

const ENV_KEYS = ['SHIELDCORTEX_MODEL_DIR', 'SHIELDCORTEX_EMBEDDINGS_OFFLINE', 'HF_ENDPOINT'] as const;
const ONNX_REL = join('Xenova', 'all-MiniLM-L6-v2', 'onnx', 'model.onnx');
const CORRUPT = 'Load model from x failed:Protobuf parsing failed.';

type Handler = (msg: { id: number; type: string; text?: string }) => Promise<void>;

interface Harness {
  sent: Array<Record<string, unknown>>;
  fakeEnv: Record<string, unknown>;
  calls: Array<{ options: Record<string, unknown>; envAtCall: Record<string, unknown> }>;
  transformersImported: () => boolean;
  load: () => Promise<Record<string, unknown>>;
}

async function bootWorker(pipelineImpl: (call: number) => Promise<unknown>): Promise<Harness> {
  jest.resetModules();
  const handlers: Handler[] = [];
  const sent: Array<Record<string, unknown>> = [];
  const fakeEnv: Record<string, unknown> = {
    allowRemoteModels: true,
    allowLocalModels: false,
    cacheDir: '/library/default/.cache/',
    localModelPath: '/library/default/models/',
    remoteHost: 'https://huggingface.co/',
  };
  const calls: Harness['calls'] = [];
  let imported = false;

  jest.unstable_mockModule('worker_threads', () => ({
    parentPort: {
      on: (event: string, h: Handler) => { if (event === 'message') handlers.push(h); },
      postMessage: (m: Record<string, unknown>) => { sent.push(m); },
    },
  }));
  jest.unstable_mockModule('@huggingface/transformers', () => {
    imported = true;
    return {
      env: fakeEnv,
      pipeline: async (_task: string, _model: string, options: Record<string, unknown>) => {
        calls.push({ options, envAtCall: { ...fakeEnv } });
        return pipelineImpl(calls.length);
      },
      default: {},
    };
  });

  await import('../worker.js');
  expect(sent[sent.length - 1]).toEqual({ type: 'ready' });
  return {
    sent,
    fakeEnv,
    calls,
    transformersImported: () => imported,
    load: async () => {
      await handlers[0]({ id: 1, type: 'load' });
      return sent.find((m) => m.id === 1)!;
    },
  };
}

describe('#632 embeddings worker configuration', () => {
  const saved: Record<string, string | undefined> = {};
  let scratch: string;
  let fetchSpy: ReturnType<typeof jest.spyOn>;
  let listenerSnapshot: { ue: unknown[]; ur: unknown[] };

  beforeEach(() => {
    for (const k of ENV_KEYS) saved[k] = process.env[k];
    for (const k of ENV_KEYS) delete process.env[k];
    scratch = mkdtempSync(join(tmpdir(), 'sc-632-worker-'));
    fetchSpy = jest.spyOn(globalThis, 'fetch').mockImplementation(() => {
      throw new Error('worker test must not fetch');
    });
    listenerSnapshot = {
      ue: process.listeners('uncaughtException'),
      ur: process.listeners('unhandledRejection'),
    };
  });

  afterEach(() => {
    // worker.ts installs process-level handlers on import; drop ours.
    for (const l of process.listeners('uncaughtException')) {
      if (!listenerSnapshot.ue.includes(l)) process.removeListener('uncaughtException', l);
    }
    for (const l of process.listeners('unhandledRejection')) {
      if (!listenerSnapshot.ur.includes(l)) process.removeListener('unhandledRejection', l);
    }
    expect(fetchSpy).not.toHaveBeenCalled();
    fetchSpy.mockRestore();
    for (const k of ENV_KEYS) {
      if (saved[k] === undefined) delete process.env[k];
      else process.env[k] = saved[k];
    }
    rmSync(scratch, { recursive: true, force: true });
  });

  function seedOnnx(root: string): string {
    const p = join(root, ONNX_REL);
    mkdirSync(dirname(p), { recursive: true });
    writeFileSync(p, 'provisioned-bytes');
    return p;
  }

  it('default: home cache root, remote allowed, library host untouched, unchanged pipeline options', async () => {
    const h = await bootWorker(async () => ({}));
    expect(await h.load()).toEqual({ id: 1, ok: true });
    expect(h.calls).toHaveLength(1);
    expect(h.calls[0].options).toEqual({ dtype: 'fp32' });
    expect(h.calls[0].envAtCall).toEqual({
      allowRemoteModels: true,
      allowLocalModels: true,
      // Only a string handed to the fake library — nothing under it is read.
      cacheDir: join(homedir(), '.cache', 'shieldcortex', 'models'),
      // Default root: the library's package-local fallback is left as it was.
      localModelPath: '/library/default/models/',
      remoteHost: 'https://huggingface.co/',
    });
  });

  it('SHIELDCORTEX_MODEL_DIR: loader and online heal both use the configured root', async () => {
    const root = join(scratch, 'models');
    const onnx = seedOnnx(root);
    process.env.SHIELDCORTEX_MODEL_DIR = root;
    const h = await bootWorker(async (n) => {
      if (n === 1) throw new Error(CORRUPT);
      return {};
    });
    expect(await h.load()).toEqual({ id: 1, ok: true });
    expect(h.calls).toHaveLength(2);
    expect(h.calls[0].envAtCall.cacheDir).toBe(root);
    // F2: the explicit root is also the loader's local-model root.
    expect(h.calls[0].envAtCall.localModelPath).toBe(root);
    // The online heal quarantined the weight under the SAME root it loaded from.
    expect(existsSync(onnx)).toBe(false);
    expect(readdirSync(dirname(onnx)).some((f) => f.startsWith('model.onnx.bak-load-failed-'))).toBe(true);
    expect(h.sent.some((m) => m.type === 'error' && /Attempting one re-download/.test(String(m.error)))).toBe(true);
  });

  it('offline: remote disabled, local_files_only set, corrupt cache left in place, no retry', async () => {
    const root = join(scratch, 'models');
    const onnx = seedOnnx(root);
    process.env.SHIELDCORTEX_MODEL_DIR = root;
    process.env.SHIELDCORTEX_EMBEDDINGS_OFFLINE = '1';
    process.env.HF_ENDPOINT = 'https://mirror.example/hf';
    const h = await bootWorker(async () => { throw new Error(CORRUPT); });
    const res = await h.load();
    expect(res.ok).toBe(false);
    expect(String(res.error)).toMatch(/SHIELDCORTEX_EMBEDDINGS_OFFLINE is set, so the file was left in place and not re-downloaded/);
    expect(h.calls).toHaveLength(1);
    expect(h.calls[0].options).toEqual({ dtype: 'fp32', local_files_only: true });
    expect(h.calls[0].envAtCall.allowRemoteModels).toBe(false);
    expect(h.calls[0].envAtCall.cacheDir).toBe(root);
    expect(readdirSync(dirname(onnx))).toEqual(['model.onnx']);
    expect(h.sent.some((m) => m.type === 'error')).toBe(false);
  });

  it('offline: a non-corruption failure (file not found locally) surfaces as-is without a heal', async () => {
    process.env.SHIELDCORTEX_EMBEDDINGS_OFFLINE = 'yes';
    const h = await bootWorker(async () => {
      throw new Error('`local_files_only=true` or `env.allowRemoteModels=false` and file was not found locally');
    });
    const res = await h.load();
    expect(res.ok).toBe(false);
    expect(String(res.error)).toMatch(/not found locally/);
    expect(h.calls).toHaveLength(1);
  });

  it('HF_ENDPOINT is mapped onto env.remoteHost with its path prefix', async () => {
    process.env.HF_ENDPOINT = 'https://mirror.example/hf';
    const h = await bootWorker(async () => ({}));
    expect((await h.load()).ok).toBe(true);
    expect(h.calls[0].envAtCall.remoteHost).toBe('https://mirror.example/hf/');
    expect(h.calls[0].envAtCall.allowRemoteModels).toBe(true);
  });

  it.each([
    ['HF_ENDPOINT', 'https://user:s3cr3t-token@mirror.example/hf'],
    ['SHIELDCORTEX_MODEL_DIR', 'relative/models'],
    ['SHIELDCORTEX_EMBEDDINGS_OFFLINE', 'maybe'],
  ])('invalid %s fails closed before the library is imported', async (key, value) => {
    process.env[key] = value;
    const h = await bootWorker(async () => ({}));
    const res = await h.load();
    expect(res.ok).toBe(false);
    expect(String(res.error)).toMatch(new RegExp(`^Embedding configuration invalid: ${key}`));
    expect(String(res.error)).not.toContain('s3cr3t-token');
    expect(h.transformersImported()).toBe(false);
    expect(h.calls).toHaveLength(0);
    expect(h.fakeEnv.cacheDir).toBe('/library/default/.cache/');
  });

  // F1 (review r1): the worker's load error never carries a rejected value.
  it.each([
    ['secret-like relative', 'sk-live-SECRETMARKER/models'],
    ['embedded newline', '/srv/models\nFORGED_STATUS SECRETMARKER'],
    ['ESC sequence', 'models\u001b[2JSECRETMARKER'],
    ['over-long', `/SECRETMARKER${'x'.repeat(5000)}`],
  ])('invalid SHIELDCORTEX_MODEL_DIR (%s) is refused without echoing it', async (_label, value) => {
    process.env.SHIELDCORTEX_MODEL_DIR = value;
    const h = await bootWorker(async () => ({}));
    const res = await h.load();
    expect(res.ok).toBe(false);
    const error = String(res.error);
    expect(error).toMatch(/^Embedding configuration invalid: SHIELDCORTEX_MODEL_DIR /);
    expect(error).not.toContain('SECRETMARKER');
    expect(error).not.toMatch(/[\u0000-\u001f\u007f-\u009f]/);
    expect(error.length).toBeLessThan(300);
    expect(h.transformersImported()).toBe(false);
  });
});
