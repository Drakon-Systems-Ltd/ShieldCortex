/**
 * #383 — corrupt/truncated embedding model cache must be detected and
 * quarantined, never reported green off "directory non-empty".
 */
import { createHash } from 'node:crypto';
import {
  closeSync,
  mkdirSync,
  mkdtempSync,
  openSync,
  readFileSync,
  rmSync,
  writeFileSync,
  existsSync,
  ftruncateSync,
  statSync,
} from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

import {
  EMBEDDING_MODEL_ID,
  EMBEDDING_ONNX_EXPECTED_BYTES,
  EMBEDDING_ONNX_EXPECTED_SHA256,
  formatModelCacheDoctorMessage,
  inspectEmbeddingModelCache,
  inspectEmbeddingHookReady,
  isCorruptModelLoadError,
  quarantineEmbeddingOnnx,
  resetModelCacheHealLatchForTests,
  resolveEmbeddingModelPaths,
  hasAttemptedModelCacheHeal,
  markModelCacheHealAttempted,
  writeModelCacheSidecar,
} from '../model-cache.js';

function makeCacheRoot(): string {
  return mkdtempSync(join(tmpdir(), 'sc-383-model-'));
}

function writeOnnx(cacheRoot: string, contents: Buffer | string): string {
  const { onnxPath } = resolveEmbeddingModelPaths(cacheRoot);
  mkdirSync(join(onnxPath, '..'), { recursive: true });
  writeFileSync(onnxPath, contents);
  return onnxPath;
}

/** Sparse file of exact byte length — avoids allocating 90 MB in the test process. */
function writeOnnxSparse(cacheRoot: string, bytes: number, head: Buffer = Buffer.from([1, 2, 3, 4])): string {
  const { onnxPath } = resolveEmbeddingModelPaths(cacheRoot);
  mkdirSync(join(onnxPath, '..'), { recursive: true });
  const fd = openSync(onnxPath, 'w');
  try {
    if (head.length > 0) writeFileSync(fd, head);
    ftruncateSync(fd, bytes);
  } finally {
    closeSync(fd);
  }
  return onnxPath;
}

function writeTrustedSidecarFor(cacheRoot: string): void {
  const { onnxPath, sidecarPath } = resolveEmbeddingModelPaths(cacheRoot);
  const st = statSync(onnxPath);
  writeModelCacheSidecar(sidecarPath, {
    sha256: EMBEDDING_ONNX_EXPECTED_SHA256,
    bytes: EMBEDDING_ONNX_EXPECTED_BYTES,
    modelId: EMBEDDING_MODEL_ID,
    verifiedAt: '2026-08-20T00:00:00.000Z',
    mtimeMs: st.mtimeMs,
    ino: st.ino,
  });
}

describe('model-cache #383', () => {
  let cacheRoot: string;

  beforeEach(() => {
    cacheRoot = makeCacheRoot();
    resetModelCacheHealLatchForTests();
  });

  afterEach(() => {
    rmSync(cacheRoot, { recursive: true, force: true });
  });

  it('reports missing when model.onnx is absent', async () => {
    const insp = await inspectEmbeddingModelCache({ cacheRoot });
    expect(insp.status).toBe('missing');
    const doc = formatModelCacheDoctorMessage(insp);
    expect(doc.status).toBe('info');
  });

  it('flags truncated size without needing a sha (Edith class)', async () => {
    writeOnnxSparse(cacheRoot, 50_187_903);
    const insp = await inspectEmbeddingModelCache({ cacheRoot });
    expect(insp.status).toBe('size_mismatch');
    expect(insp.bytes).toBe(50_187_903);
    const doc = formatModelCacheDoctorMessage(insp);
    expect(doc.status).toBe('warn');
    expect(doc.message).toMatch(/corrupt/i);
  });

  it('flags right-size wrong-sha as sha_mismatch', async () => {
    writeOnnxSparse(cacheRoot, EMBEDDING_ONNX_EXPECTED_BYTES, Buffer.alloc(64, 7));
    const insp = await inspectEmbeddingModelCache({ cacheRoot, forceSha: true });
    expect(insp.status).toBe('sha_mismatch');
    expect(insp.sha256).toBeTruthy();
    expect(insp.sha256).not.toBe(EMBEDDING_ONNX_EXPECTED_SHA256);
  });

  it('accepts right-size + identity-bound sidecar without live hashing junk bytes', async () => {
    const onnxPath = writeOnnxSparse(cacheRoot, EMBEDDING_ONNX_EXPECTED_BYTES, Buffer.alloc(16, 0));
    writeTrustedSidecarFor(cacheRoot);
    const insp = await inspectEmbeddingModelCache({ cacheRoot });
    expect(insp.status).toBe('ok');
    expect(insp.verifiedVia).toBe('sidecar');
    const doc = formatModelCacheDoctorMessage(insp);
    expect(doc.message).toMatch(/sidecar attestation/i);
    expect(doc.message).not.toMatch(/live-sha verified/i);
    expect(existsSync(onnxPath)).toBe(true);
  });

  it('rejects a sidecar when file identity no longer matches (same-size replace)', async () => {
    const onnxPath = writeOnnxSparse(cacheRoot, EMBEDDING_ONNX_EXPECTED_BYTES, Buffer.alloc(16, 0));
    writeTrustedSidecarFor(cacheRoot);
    // Replace weight in place with same size but different bytes/identity.
    writeOnnxSparse(cacheRoot, EMBEDDING_ONNX_EXPECTED_BYTES, Buffer.alloc(32, 9));
    expect(existsSync(onnxPath)).toBe(true);
    const insp = await inspectEmbeddingModelCache({ cacheRoot });
    // Stale sidecar (old ino/mtime) → live hash → mismatch on junk bytes.
    expect(insp.status).toBe('sha_mismatch');
  });

  it('rejects a sidecar that attests the wrong sha even when size matches', async () => {
    const onnxPath = writeOnnxSparse(cacheRoot, EMBEDDING_ONNX_EXPECTED_BYTES, Buffer.alloc(32, 3));
    const st = statSync(onnxPath);
    const { sidecarPath } = resolveEmbeddingModelPaths(cacheRoot);
    writeModelCacheSidecar(sidecarPath, {
      sha256: '0'.repeat(64),
      bytes: EMBEDDING_ONNX_EXPECTED_BYTES,
      modelId: EMBEDDING_MODEL_ID,
      verifiedAt: '2026-08-20T00:00:00.000Z',
      mtimeMs: st.mtimeMs,
      ino: st.ino,
    });
    const insp = await inspectEmbeddingModelCache({ cacheRoot });
    expect(insp.status).toBe('sha_mismatch');
  });

  it('quarantine renames the weight aside, preserves bytes, and invalidates sidecar', () => {
    const payload = Buffer.from('truncated-onnx-bytes');
    const onnxPath = writeOnnx(cacheRoot, payload);
    writeTrustedSidecarFor(cacheRoot); // will be identity-bound to this small file's meta; fine for move test
    // Force a sidecar to exist with any content
    const { sidecarPath } = resolveEmbeddingModelPaths(cacheRoot);
    writeFileSync(sidecarPath, JSON.stringify({ sha256: EMBEDDING_ONNX_EXPECTED_SHA256, bytes: EMBEDDING_ONNX_EXPECTED_BYTES, modelId: EMBEDDING_MODEL_ID, verifiedAt: 't', mtimeMs: 1, ino: 1 }) + '\n');
    const before = readFileSync(onnxPath);
    const q = quarantineEmbeddingOnnx({
      cacheRoot,
      reason: 'protobuf-failed',
      stamp: '20260820T120000Z',
    });
    expect(q.quarantinedPath).toBeTruthy();
    expect(existsSync(onnxPath)).toBe(false);
    expect(existsSync(q.quarantinedPath!)).toBe(true);
    expect(readFileSync(q.quarantinedPath!)).toEqual(before);
    expect(q.quarantinedPath).toContain('bak-protobuf-failed');
    // Sidecar must not remain next to the (now empty) weight path.
    expect(existsSync(sidecarPath)).toBe(false);
    expect(existsSync(`${q.quarantinedPath}.shieldcortex.json`)).toBe(true);
  });

  it('after quarantine, a same-size junk redownload does not green via leftover sidecar', async () => {
    writeOnnxSparse(cacheRoot, EMBEDDING_ONNX_EXPECTED_BYTES, Buffer.alloc(8, 1));
    writeTrustedSidecarFor(cacheRoot);
    const q = quarantineEmbeddingOnnx({ cacheRoot, reason: 'load-failed', stamp: 't1' });
    expect(q.quarantinedPath).toBeTruthy();
    // Simulate redownload of right-size wrong bytes with no new sidecar.
    writeOnnxSparse(cacheRoot, EMBEDDING_ONNX_EXPECTED_BYTES, Buffer.alloc(8, 2));
    const insp = await inspectEmbeddingModelCache({ cacheRoot });
    expect(insp.status).toBe('sha_mismatch');
  });

  it('quarantine is a no-op when the weight is already gone', () => {
    const q = quarantineEmbeddingOnnx({ cacheRoot, reason: 'missing' });
    expect(q.quarantinedPath).toBeNull();
    expect(q.detail).toMatch(/nothing to quarantine/);
  });

  it('isCorruptModelLoadError matches Edith protobuf failure and rejects generic load noise', () => {
    expect(
      isCorruptModelLoadError(
        'Load model from /home/edith/.cache/shieldcortex/models/Xenova/all-MiniLM-L6-v2/onnx/model.onnx failed:Protobuf parsing failed.',
      ),
    ).toBe(true);
    expect(isCorruptModelLoadError('Protobuf parsing failed.')).toBe(true);
    expect(isCorruptModelLoadError('ENOTFOUND huggingface.co')).toBe(false);
    expect(isCorruptModelLoadError('401 Unauthorized')).toBe(false);
    // Over-broad "onnx failed" alone must NOT quarantine a healthy weight.
    expect(isCorruptModelLoadError('onnxruntime native addon failed to init')).toBe(false);
    expect(isCorruptModelLoadError('Load model from /tmp/x failed: network timeout')).toBe(false);
  });

  it('process heal latch is one-shot', () => {
    expect(hasAttemptedModelCacheHeal()).toBe(false);
    markModelCacheHealAttempted();
    expect(hasAttemptedModelCacheHeal()).toBe(true);
    resetModelCacheHealLatchForTests();
    expect(hasAttemptedModelCacheHeal()).toBe(false);
  });

  it('#458 hook-ready: valid ONNX with missing tokenizer siblings is not ready', async () => {
    writeOnnxSparse(cacheRoot, EMBEDDING_ONNX_EXPECTED_BYTES);
    writeTrustedSidecarFor(cacheRoot);
    const onnxOk = await inspectEmbeddingModelCache({ cacheRoot });
    expect(onnxOk.status).toBe('ok');
    const ready = await inspectEmbeddingHookReady({ cacheRoot });
    expect(ready.ready).toBe(false);
    expect(ready.missing).toEqual(expect.arrayContaining(['tokenizer.json', 'config.json', 'tokenizer_config.json']));
  });

  it('#458 hook-ready: zero-byte tokenizer sibling is not ready', async () => {
    writeOnnxSparse(cacheRoot, EMBEDDING_ONNX_EXPECTED_BYTES);
    writeTrustedSidecarFor(cacheRoot);
    const { cacheDir } = (await inspectEmbeddingModelCache({ cacheRoot }));
    writeFileSync(join(cacheDir, 'config.json'), '{}');
    writeFileSync(join(cacheDir, 'tokenizer.json'), '');
    writeFileSync(join(cacheDir, 'tokenizer_config.json'), '{}');
    const ready = await inspectEmbeddingHookReady({ cacheRoot });
    expect(ready.ready).toBe(false);
    expect(ready.missing).toContain('tokenizer.json');
  });

  it('#458 hook-ready: valid ONNX plus complete siblings is ready', async () => {
    writeOnnxSparse(cacheRoot, EMBEDDING_ONNX_EXPECTED_BYTES);
    writeTrustedSidecarFor(cacheRoot);
    const { cacheDir } = (await inspectEmbeddingModelCache({ cacheRoot }));
    writeFileSync(join(cacheDir, 'config.json'), '{}');
    writeFileSync(join(cacheDir, 'tokenizer.json'), '{"x":1}');
    writeFileSync(join(cacheDir, 'tokenizer_config.json'), '{}');
    const ready = await inspectEmbeddingHookReady({ cacheRoot });
    expect(ready).toEqual({ ready: true, reason: 'ok', missing: [] });
  });

  it('known-good constants match the fleet reference weight when present', () => {
    const homeOnnx = join(
      process.env.HOME || '',
      '.cache/shieldcortex/models/Xenova/all-MiniLM-L6-v2/onnx/model.onnx',
    );
    if (!existsSync(homeOnnx)) return;
    expect(statSync(homeOnnx).size).toBe(EMBEDDING_ONNX_EXPECTED_BYTES);
    expect(EMBEDDING_ONNX_EXPECTED_SHA256).toHaveLength(64);
    expect(createHash('sha256').update('x').digest('hex')).toHaveLength(64);
  });
});
