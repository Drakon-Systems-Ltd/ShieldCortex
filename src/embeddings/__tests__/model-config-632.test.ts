/**
 * #632 — one resolver for the embedding cache root, offline flag and mirror,
 * consumed consistently by cache inspection, quarantine and doctor.
 *
 * Every cache here is a throwaway directory; the live ~/.cache model is never
 * read. Sparse files stand in for the 90 MB weight.
 */
import {
  closeSync,
  existsSync,
  ftruncateSync,
  mkdirSync,
  mkdtempSync,
  openSync,
  readdirSync,
  rmSync,
  statSync,
  writeFileSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join } from 'node:path';
import Database from 'better-sqlite3';
import { afterEach, beforeEach, describe, expect, it, jest } from '@jest/globals';

import { checkSemanticCoverageAt } from '../../cli/doctor.js';
import {
  EmbeddingConfigError,
  MODEL_DIR_MAX_LENGTH,
  applyEmbeddingModelConfig,
  defaultEmbeddingCacheRoot,
  resolveEmbeddingCacheRoot,
  resolveEmbeddingMirror,
  resolveEmbeddingModelConfig,
  resolveEmbeddingsOffline,
} from '../model-config.js';
import {
  EMBEDDING_MODEL_ID,
  EMBEDDING_ONNX_EXPECTED_BYTES,
  EMBEDDING_ONNX_EXPECTED_SHA256,
  inspectEmbeddingHookReady,
  inspectEmbeddingModelCache,
  inspectEmbeddingModelForDoctor,
  quarantineEmbeddingOnnx,
  resolveEmbeddingModelPaths,
  writeModelCacheSidecar,
} from '../model-cache.js';

const HOME = '/home/someone';

function writeSparseOnnx(root: string, bytes: number): string {
  const { onnxPath } = resolveEmbeddingModelPaths(root);
  mkdirSync(join(onnxPath, '..'), { recursive: true });
  const fd = openSync(onnxPath, 'w');
  try {
    writeFileSync(fd, Buffer.from([1, 2, 3, 4]));
    ftruncateSync(fd, bytes);
  } finally {
    closeSync(fd);
  }
  return onnxPath;
}

function writeTrustedSidecar(root: string): void {
  const { onnxPath, sidecarPath } = resolveEmbeddingModelPaths(root);
  const st = statSync(onnxPath);
  writeModelCacheSidecar(sidecarPath, {
    sha256: EMBEDDING_ONNX_EXPECTED_SHA256,
    bytes: EMBEDDING_ONNX_EXPECTED_BYTES,
    modelId: EMBEDDING_MODEL_ID,
    verifiedAt: '2026-10-01T00:00:00.000Z',
    mtimeMs: st.mtimeMs,
    ino: st.ino,
  });
}

function writeSiblings(root: string): void {
  const { modelDir } = resolveEmbeddingModelPaths(root);
  writeFileSync(join(modelDir, 'config.json'), '{}');
  writeFileSync(join(modelDir, 'tokenizer.json'), '{"x":1}');
  writeFileSync(join(modelDir, 'tokenizer_config.json'), '{}');
}

describe('#632 resolver semantics', () => {
  it('defaults to ~/.cache/shieldcortex/models when unset or empty', () => {
    expect(resolveEmbeddingCacheRoot({}, HOME)).toEqual({
      cacheRoot: '/home/someone/.cache/shieldcortex/models',
      source: 'default',
    });
    expect(resolveEmbeddingCacheRoot({ SHIELDCORTEX_MODEL_DIR: '' }, HOME).source).toBe('default');
    expect(defaultEmbeddingCacheRoot(HOME)).toBe('/home/someone/.cache/shieldcortex/models');
  });

  it('accepts absolute paths (normalised) and expands ~ and ~/', () => {
    expect(resolveEmbeddingCacheRoot({ SHIELDCORTEX_MODEL_DIR: '/srv/models/../m/' }, HOME)).toEqual({
      cacheRoot: '/srv/m',
      source: 'SHIELDCORTEX_MODEL_DIR',
    });
    expect(resolveEmbeddingCacheRoot({ SHIELDCORTEX_MODEL_DIR: '~' }, HOME).cacheRoot).toBe(HOME);
    expect(resolveEmbeddingCacheRoot({ SHIELDCORTEX_MODEL_DIR: '~/m' }, HOME).cacheRoot).toBe('/home/someone/m');
  });

  it.each([
    ['relative', 'models'],
    ['dot-relative', './models'],
    ['~user', '~bob/models'],
    ['whitespace', ' /srv/m'],
    ['NUL byte', '/srv/\0m'],
  ])('rejects a %s SHIELDCORTEX_MODEL_DIR', (_label, value) => {
    expect(() => resolveEmbeddingCacheRoot({ SHIELDCORTEX_MODEL_DIR: value }, HOME)).toThrow(EmbeddingConfigError);
  });

  // F1 (review r1): a rejected value is never echoed, whatever it holds.
  it.each([
    ['secret-like relative', 'sk-live-SECRETMARKER/models'],
    ['relative with an embedded newline', 'models\nFORGED_STATUS SECRETMARKER'],
    ['relative with an ESC sequence', 'models\u001b[2JSECRETMARKER'],
    ['absolute with an embedded newline', '/srv/models\nFORGED_STATUS SECRETMARKER'],
    ['absolute with an OSC/BEL sequence', '/srv/\u001b]0;SECRETMARKER\u0007m'],
    ['absolute with a C1 control', '/srv/\u009bSECRETMARKER'],
    ['absolute with a bidi override', '/srv/\u202eSECRETMARKER'],
    ['over-long relative', `SECRETMARKER${'x'.repeat(MODEL_DIR_MAX_LENGTH)}`],
    ['over-long absolute', `/SECRETMARKER${'x'.repeat(MODEL_DIR_MAX_LENGTH)}`],
    ['~user with a secret', '~SECRETMARKER/models'],
    ['whitespace-padded secret', ' /srv/SECRETMARKER '],
  ])('rejects %s without echoing it', (_label, value) => {
    let caught: unknown;
    try {
      resolveEmbeddingCacheRoot({ SHIELDCORTEX_MODEL_DIR: value }, HOME);
    } catch (err) {
      caught = err;
    }
    expect(caught).toBeInstanceOf(EmbeddingConfigError);
    const msg = (caught as Error).message;
    expect(msg).toMatch(/^SHIELDCORTEX_MODEL_DIR /);
    expect(msg).not.toContain('SECRETMARKER');
    expect(msg).not.toMatch(/[\u0000-\u001f\u007f-\u009f\u202e]/);
    expect(msg.length).toBeLessThan(200);
  });

  it('an invalid offline value is not echoed either', () => {
    expect(() => resolveEmbeddingsOffline({ SHIELDCORTEX_EMBEDDINGS_OFFLINE: 'SECRETMARKER' }))
      .toThrow(/^SHIELDCORTEX_EMBEDDINGS_OFFLINE must be one of .*\(value not shown\)$/);
  });

  it('offline flag: explicit truthy/falsy words only', () => {
    expect(resolveEmbeddingsOffline({})).toBe(false);
    for (const v of ['1', 'true', 'YES', ' on ']) {
      expect(resolveEmbeddingsOffline({ SHIELDCORTEX_EMBEDDINGS_OFFLINE: v })).toBe(true);
    }
    for (const v of ['', '0', 'false', 'No', 'off']) {
      expect(resolveEmbeddingsOffline({ SHIELDCORTEX_EMBEDDINGS_OFFLINE: v })).toBe(false);
    }
    expect(() => resolveEmbeddingsOffline({ SHIELDCORTEX_EMBEDDINGS_OFFLINE: 'enabled' })).toThrow(EmbeddingConfigError);
  });

  it('maps HF_ENDPOINT to a remoteHost with the path prefix kept', () => {
    expect(resolveEmbeddingMirror({})).toBeNull();
    expect(resolveEmbeddingMirror({ HF_ENDPOINT: '' })).toBeNull();
    expect(resolveEmbeddingMirror({ HF_ENDPOINT: 'https://mirror.example' })).toBe('https://mirror.example/');
    expect(resolveEmbeddingMirror({ HF_ENDPOINT: 'https://mirror.example/hf' })).toBe('https://mirror.example/hf/');
    expect(resolveEmbeddingMirror({ HF_ENDPOINT: 'https://mirror.example:8443/a/b/' })).toBe('https://mirror.example:8443/a/b/');
    expect(resolveEmbeddingMirror({ HF_ENDPOINT: 'http://127.0.0.1:8080/hf' })).toBe('http://127.0.0.1:8080/hf/');
    expect(resolveEmbeddingMirror({ HF_ENDPOINT: 'http://localhost:8080' })).toBe('http://localhost:8080/');
  });

  it.each([
    ['credentials', 'https://user:s3cr3t-token@mirror.example/hf'],
    ['bare userinfo', 'https://s3cr3t-token@mirror.example/hf'],
    ['query', 'https://mirror.example/hf?token=s3cr3t-token'],
    ['bare query', 'https://mirror.example/hf?'],
    ['fragment', 'https://mirror.example/hf#s3cr3t-token'],
    ['plain http to a remote host', 'http://mirror.example/hf'],
    ['ftp', 'ftp://mirror.example/hf'],
    ['file', 'file:///srv/s3cr3t-token'],
    ['not a URL', 's3cr3t-token'],
  ])('rejects HF_ENDPOINT with %s and never echoes the value', (_label, value) => {
    let caught: unknown;
    try {
      resolveEmbeddingMirror({ HF_ENDPOINT: value });
    } catch (err) {
      caught = err;
    }
    expect(caught).toBeInstanceOf(EmbeddingConfigError);
    expect((caught as Error).message).toMatch(/^HF_ENDPOINT rejected/);
    expect((caught as Error).message).not.toContain('s3cr3t-token');
    expect((caught as Error).message).not.toContain('mirror.example');
  });

  it('applyEmbeddingModelConfig: defaults leave the library host alone; offline disables remote', () => {
    const env = { allowRemoteModels: true, allowLocalModels: false, cacheDir: '', remoteHost: 'https://huggingface.co/' };
    applyEmbeddingModelConfig(env, resolveEmbeddingModelConfig({}, HOME));
    expect(env).toEqual({
      allowRemoteModels: true,
      allowLocalModels: true,
      cacheDir: '/home/someone/.cache/shieldcortex/models',
      remoteHost: 'https://huggingface.co/',
    });
    // Default root: the library's own localModelPath is not touched (F2 scope).
    expect('localModelPath' in env).toBe(false);
    applyEmbeddingModelConfig(env, resolveEmbeddingModelConfig({
      SHIELDCORTEX_EMBEDDINGS_OFFLINE: '1',
      SHIELDCORTEX_MODEL_DIR: '/srv/m',
      HF_ENDPOINT: 'https://mirror.example/hf',
    }, HOME));
    expect(env.allowRemoteModels).toBe(false);
    expect(env.cacheDir).toBe('/srv/m');
    // F2: an explicit root is the loader's ONLY local root.
    expect((env as Record<string, unknown>).localModelPath).toBe('/srv/m');
    expect(env.remoteHost).toBe('https://mirror.example/hf/');
  });
});

describe('#632 cache inspection and quarantine follow SHIELDCORTEX_MODEL_DIR', () => {
  let root: string;
  const saved = process.env.SHIELDCORTEX_MODEL_DIR;

  beforeEach(() => {
    root = mkdtempSync(join(tmpdir(), 'sc-632-root-'));
    process.env.SHIELDCORTEX_MODEL_DIR = root;
  });

  afterEach(() => {
    if (saved === undefined) delete process.env.SHIELDCORTEX_MODEL_DIR;
    else process.env.SHIELDCORTEX_MODEL_DIR = saved;
    rmSync(root, { recursive: true, force: true });
  });

  it('inspect, hook-ready and quarantine all use the configured root', async () => {
    const onnx = writeSparseOnnx(root, EMBEDDING_ONNX_EXPECTED_BYTES);
    writeTrustedSidecar(root);
    writeSiblings(root);

    const insp = await inspectEmbeddingModelCache();
    expect(insp.status).toBe('ok');
    expect(insp.onnxPath).toBe(onnx);
    expect(resolveEmbeddingModelPaths().onnxPath).toBe(onnx);
    expect(await inspectEmbeddingHookReady()).toEqual({ ready: true, reason: 'ok', missing: [] });

    const q = quarantineEmbeddingOnnx({ reason: 'test', stamp: 'S' });
    expect(q.quarantinedPath).toBe(`${onnx}.bak-test-S`);
    expect(existsSync(onnx)).toBe(false);
  });

  it('an explicit cacheRoot argument still wins over the env', async () => {
    const other = mkdtempSync(join(tmpdir(), 'sc-632-other-'));
    try {
      const onnx = writeSparseOnnx(other, 10);
      const insp = await inspectEmbeddingModelCache({ cacheRoot: other });
      expect(insp.onnxPath).toBe(onnx);
      expect(insp.status).toBe('size_mismatch');
      expect((await inspectEmbeddingModelCache()).status).toBe('missing');
    } finally {
      rmSync(other, { recursive: true, force: true });
    }
  });

  it('an invalid root is reported as misconfigured and nothing is renamed — never another directory', async () => {
    process.env.SHIELDCORTEX_MODEL_DIR = 'relative/models';
    const insp = await inspectEmbeddingModelCache();
    expect(insp.status).toBe('misconfigured');
    expect(insp.onnxPath).toBe('');
    expect(insp.detail).toMatch(/SHIELDCORTEX_MODEL_DIR must be an absolute path/);
    expect(insp.detail).not.toContain('relative/models');
    expect((await inspectEmbeddingHookReady()).ready).toBe(false);
    const q = quarantineEmbeddingOnnx({ reason: 'test' });
    expect(q.quarantinedPath).toBeNull();
    expect(q.detail).toMatch(/SHIELDCORTEX_MODEL_DIR/);
    expect(() => resolveEmbeddingModelPaths()).toThrow(EmbeddingConfigError);
  });
});

describe('#632 doctor honesty', () => {
  let root: string;
  let fetchSpy: ReturnType<typeof jest.spyOn>;

  beforeEach(() => {
    root = mkdtempSync(join(tmpdir(), 'sc-632-doc-'));
    fetchSpy = jest.spyOn(globalThis, 'fetch').mockImplementation(() => {
      throw new Error('doctor must not touch the network');
    });
  });

  afterEach(() => {
    expect(fetchSpy).not.toHaveBeenCalled();
    fetchSpy.mockRestore();
    rmSync(root, { recursive: true, force: true });
  });

  const env = (extra: Record<string, string> = {}) => ({ SHIELDCORTEX_MODEL_DIR: root, ...extra });

  it('ready cache passes as files-only — never claims inference is active', async () => {
    writeSparseOnnx(root, EMBEDDING_ONNX_EXPECTED_BYTES);
    writeTrustedSidecar(root);
    writeSiblings(root);
    const r = await inspectEmbeddingModelForDoctor({ env: env({ SHIELDCORTEX_EMBEDDINGS_OFFLINE: '1' }) });
    expect(r.status).toBe('pass');
    expect(r.message).toMatch(/files only, inference not exercised/);
    expect(r.message).not.toMatch(/inference (is )?(active|working|ready)/i);
    expect(r.message).toMatch(/offline: SHIELDCORTEX_EMBEDDINGS_OFFLINE is set/);
    expect(r.message).toContain(`model dir from SHIELDCORTEX_MODEL_DIR: ${resolveEmbeddingModelPaths(root).modelDir}`);
  });

  it('default online + missing keeps the existing info wording and downloads nothing', async () => {
    const r = await inspectEmbeddingModelForDoctor({ env: env() });
    expect(r.status).toBe('info');
    expect(r.message).toMatch(/^model not cached — will download on first recall/);
    expect(readdirSync(root)).toEqual([]);
  });

  it('missing + offline is a warning with provisioning guidance, not a download promise', async () => {
    const r = await inspectEmbeddingModelForDoctor({ env: env({ SHIELDCORTEX_EMBEDDINGS_OFFLINE: 'true' }) });
    expect(r.status).toBe('warn');
    expect(r.message).toMatch(/offline mode forbids downloading/);
    expect(r.message).not.toMatch(/will download/);
    expect(r.fix).toMatch(/docs\/offline-embeddings\.md/);
    expect(r.fix).not.toMatch(/guard|auto-?memory|protect/i);
  });

  it('valid weight but missing tokenizer siblings: offline warns, online says they will be fetched', async () => {
    writeSparseOnnx(root, EMBEDDING_ONNX_EXPECTED_BYTES);
    writeTrustedSidecar(root);
    const off = await inspectEmbeddingModelForDoctor({ env: env({ SHIELDCORTEX_EMBEDDINGS_OFFLINE: '1' }) });
    expect(off.status).toBe('warn');
    expect(off.message).toMatch(/tokenizer\.json.*missing and offline mode forbids fetching/);
    const on = await inspectEmbeddingModelForDoctor({ env: env() });
    expect(on.status).toBe('info');
    expect(on.message).toMatch(/will download on first recall/);
  });

  it('corrupt + offline does not advise a re-download; online keeps the heal advice', async () => {
    writeSparseOnnx(root, 50_000);
    const off = await inspectEmbeddingModelForDoctor({ env: env({ SHIELDCORTEX_EMBEDDINGS_OFFLINE: '1' }) });
    expect(off.status).toBe('warn');
    expect(off.message).toMatch(/corrupt.*offline mode will not re-download/);
    expect(off.fix).toMatch(/^Replace .*model\.onnx with a verified copy/);
    const on = await inspectEmbeddingModelForDoctor({ env: env() });
    expect(on.fix).toMatch(/quarantine the bad weight and re-download/);
  });

  it('a mirror is named when online, and invalid config is a warning that hides the secret', async () => {
    const mirrored = await inspectEmbeddingModelForDoctor({ env: env({ HF_ENDPOINT: 'https://mirror.example/hf' }) });
    expect(mirrored.message).toMatch(/downloads from HF_ENDPOINT mirror https:\/\/mirror\.example\/hf\//);

    const bad = await inspectEmbeddingModelForDoctor({ env: env({ HF_ENDPOINT: 'https://u:s3cr3t-token@mirror.example' }) });
    expect(bad.status).toBe('warn');
    expect(bad.message).toMatch(/configuration is invalid — HF_ENDPOINT rejected/);
    expect(`${bad.message} ${bad.fix}`).not.toContain('s3cr3t-token');

    const badDir = await inspectEmbeddingModelForDoctor({ env: { SHIELDCORTEX_MODEL_DIR: 'rel' } });
    expect(badDir.status).toBe('warn');
    expect(badDir.message).toMatch(/SHIELDCORTEX_MODEL_DIR must be an absolute path/);
  });

  it.each([
    ['secret-like relative', 'sk-live-SECRETMARKER/models'],
    ['embedded newline', `${'/srv'}/models\nFORGED_STATUS SECRETMARKER`],
    ['ESC sequence', 'models\u001b[2JSECRETMARKER'],
    ['over-long', `/SECRETMARKER${'x'.repeat(MODEL_DIR_MAX_LENGTH)}`],
  ])('F1: doctor and hook readiness never print a rejected MODEL_DIR (%s)', async (_label, value) => {
    const r = await inspectEmbeddingModelForDoctor({ env: { SHIELDCORTEX_MODEL_DIR: value } });
    expect(r.status).toBe('warn');
    const ready = await inspectEmbeddingHookReady({ env: { SHIELDCORTEX_MODEL_DIR: value } });
    expect(ready).toMatchObject({ ready: false, misconfigured: true });
    for (const text of [r.message, r.fix ?? '', ready.reason]) {
      expect(text).not.toContain('SECRETMARKER');
      expect(text).not.toMatch(/[\u0000-\u001f\u007f-\u009f]/);
      expect(text.length).toBeLessThan(400);
    }
  });

  it('F1: an accepted but very long root is shown bounded', async () => {
    const longRoot = join(root, 'd'.repeat(240), 'e'.repeat(240));
    const r = await inspectEmbeddingModelForDoctor({ env: { SHIELDCORTEX_MODEL_DIR: longRoot, SHIELDCORTEX_EMBEDDINGS_OFFLINE: '1' } });
    expect(r.status).toBe('warn');
    expect(r.message).toContain('…');
    expect(r.message).not.toContain(longRoot);
    expect(r.message.length).toBeLessThan(600);
    expect((r.fix ?? '').length).toBeLessThan(1200);
  });

  // Grok r1: the offline fix named insp.cacheDir (already the model dir) as the
  // place to copy the model directory INTO — that nests a copy the loader never reads.
  it('offline missing / incomplete fixes put the files inside the model dir, never nest it', async () => {
    const { modelDir } = resolveEmbeddingModelPaths(root);
    const missing = await inspectEmbeddingModelForDoctor({ env: env({ SHIELDCORTEX_EMBEDDINGS_OFFLINE: '1' }) });
    writeSparseOnnx(root, EMBEDDING_ONNX_EXPECTED_BYTES);
    writeTrustedSidecar(root);
    const incomplete = await inspectEmbeddingModelForDoctor({ env: env({ SHIELDCORTEX_EMBEDDINGS_OFFLINE: '1' }) });
    for (const r of [missing, incomplete]) {
      expect(r.status).toBe('warn');
      expect(r.fix).toContain(`sit directly in ${modelDir}/ (config.json, tokenizer.json, tokenizer_config.json, onnx/model.onnx)`);
      expect(r.fix).toContain(`the cache root is ${root}.`);
      expect(r.fix).not.toMatch(/^Copy (a|the complete) [^.]*(cache|directory) into /);
      expect(r.fix).toMatch(/docs\/offline-embeddings\.md/);
    }
    expect(incomplete.fix).toMatch(/^Add the missing file\(s\) \(config\.json, tokenizer\.json, tokenizer_config\.json\)/);
  });
});

/** F3 (review r1): readiness validates the configuration the worker will use. */
describe('#632 hook readiness and coverage advice follow the full configuration', () => {
  let root: string;
  let fetchSpy: ReturnType<typeof jest.spyOn>;

  beforeEach(() => {
    root = mkdtempSync(join(tmpdir(), 'sc-632-ready-'));
    fetchSpy = jest.spyOn(globalThis, 'fetch').mockImplementation(() => {
      throw new Error('readiness/coverage must not touch the network');
    });
  });

  afterEach(() => {
    expect(fetchSpy).not.toHaveBeenCalled();
    fetchSpy.mockRestore();
    rmSync(root, { recursive: true, force: true });
  });

  function completeCache(): void {
    writeSparseOnnx(root, EMBEDDING_ONNX_EXPECTED_BYTES);
    writeTrustedSidecar(root);
    writeSiblings(root);
  }

  /** 12 rows, 6 without a vector — well over the 10% coverage warning. */
  function coverageDb(): string {
    const dbPath = join(root, 'memories.db');
    if (existsSync(dbPath)) return dbPath;
    const db = new Database(dbPath);
    try {
      db.exec('CREATE TABLE memories (id INTEGER PRIMARY KEY, embedding BLOB)');
      const ins = db.prepare('INSERT INTO memories (embedding) VALUES (?)');
      for (let i = 0; i < 12; i++) ins.run(i % 2 ? Buffer.from([1, 2, 3, 4]) : null);
    } finally {
      db.close();
    }
    return dbPath;
  }

  it.each([
    ['HF_ENDPOINT', 'not-a-url'],
    ['SHIELDCORTEX_EMBEDDINGS_OFFLINE', 'maybe'],
  ])('complete cache + invalid %s: hook readiness refuses, as doctor and the worker do', async (key, value) => {
    completeCache();
    const env = { SHIELDCORTEX_MODEL_DIR: root, [key]: value };
    // Valid control: the same cache is ready.
    expect(await inspectEmbeddingHookReady({ env: { SHIELDCORTEX_MODEL_DIR: root } }))
      .toEqual({ ready: true, reason: 'ok', missing: [] });
    const ready = await inspectEmbeddingHookReady({ env });
    expect(ready).toMatchObject({ ready: false, misconfigured: true, missing: [] });
    expect(ready.reason).toMatch(new RegExp(`^misconfigured: ${key}`));
    expect(ready.reason).not.toContain(value);
    const doc = await inspectEmbeddingModelForDoctor({ env });
    expect(doc.status).toBe('warn');
    expect(doc.message).toMatch(/configuration is invalid/);
  });

  it('an explicit cacheRoot still wins over MODEL_DIR, but the offline flag and mirror are still validated', async () => {
    completeCache();
    expect(await inspectEmbeddingHookReady({ cacheRoot: root, env: { SHIELDCORTEX_MODEL_DIR: 'relative' } }))
      .toEqual({ ready: true, reason: 'ok', missing: [] });
    expect(await inspectEmbeddingHookReady({ cacheRoot: root, env: { HF_ENDPOINT: 'ftp://x' } }))
      .toMatchObject({ ready: false, misconfigured: true });
    expect(await inspectEmbeddingHookReady({ cacheRoot: root, env: { SHIELDCORTEX_EMBEDDINGS_OFFLINE: 'perhaps' } }))
      .toMatchObject({ ready: false, misconfigured: true });
  });

  it('coverage control: valid online config + complete cache still advises the backfill', async () => {
    completeCache();
    const r = await checkSemanticCoverageAt(coverageDb(), { env: { SHIELDCORTEX_MODEL_DIR: root } });
    expect(r.status).toBe('warn');
    expect(r.fix).toMatch(/embed-backfill --execute/);
  });

  it.each([
    ['HF_ENDPOINT', 'not-a-url'],
    ['SHIELDCORTEX_EMBEDDINGS_OFFLINE', 'maybe'],
    ['SHIELDCORTEX_MODEL_DIR', 'relative/SECRETMARKER'],
  ])('coverage: invalid %s never presents embed-backfill as the repair', async (key, value) => {
    completeCache();
    const r = await checkSemanticCoverageAt(coverageDb(), { env: { SHIELDCORTEX_MODEL_DIR: root, [key]: value } });
    expect(r.fix).toBeUndefined();
    expect(r.message).toMatch(/configuration is invalid — coverage skipped/);
    expect(r.message).not.toContain('SECRETMARKER');
    expect(r.message).not.toContain(value);
  });

  it('coverage: offline + valid weight + missing tokenizer skips the impossible backfill advice', async () => {
    writeSparseOnnx(root, EMBEDDING_ONNX_EXPECTED_BYTES);
    writeTrustedSidecar(root);
    const env = { SHIELDCORTEX_MODEL_DIR: root, SHIELDCORTEX_EMBEDDINGS_OFFLINE: '1' };
    const r = await checkSemanticCoverageAt(coverageDb(), { env });
    expect(r.fix).toBeUndefined();
    expect(r.message).toMatch(/tokenizer\.json.*missing and offline mode will not fetch them — coverage skipped/);
  });

  it('coverage: offline missing weight does not claim a backfill would download it', async () => {
    const r = await checkSemanticCoverageAt(coverageDb(), {
      env: { SHIELDCORTEX_MODEL_DIR: root, SHIELDCORTEX_EMBEDDINGS_OFFLINE: '1' },
    });
    expect(r.fix).toBeUndefined();
    expect(r.message).toMatch(/is missing and offline mode will not download it/);
    expect(r.message).not.toMatch(/would download/);
    // Online keeps the pre-#632 wording.
    const on = await checkSemanticCoverageAt(coverageDb(), { env: { SHIELDCORTEX_MODEL_DIR: root } });
    expect(on.message).toMatch(/\(that would download model\.onnx\)/);
    expect(dirname(dirname(resolveEmbeddingModelPaths(root).modelDir))).toBe(root);
  });
});
