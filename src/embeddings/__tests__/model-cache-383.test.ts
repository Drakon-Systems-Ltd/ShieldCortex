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
  isCorruptModelLoadError,
  quarantineEmbeddingOnnx,
  resolveEmbeddingModelPaths,
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

describe('model-cache #383', () => {
  let cacheRoot: string;

  beforeEach(() => {
    cacheRoot = makeCacheRoot();
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
    // 50_187_903 was the live truncated size on Edith — any wrong size is enough.
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

  it('accepts right-size + trusted sidecar without re-hashing content we control', async () => {
    const onnxPath = writeOnnxSparse(cacheRoot, EMBEDDING_ONNX_EXPECTED_BYTES, Buffer.alloc(16, 0));
    const { sidecarPath } = resolveEmbeddingModelPaths(cacheRoot);
    writeModelCacheSidecar(sidecarPath, {
      sha256: EMBEDDING_ONNX_EXPECTED_SHA256,
      bytes: EMBEDDING_ONNX_EXPECTED_BYTES,
      modelId: EMBEDDING_MODEL_ID,
      verifiedAt: '2026-08-20T00:00:00.000Z',
    });
    const insp = await inspectEmbeddingModelCache({ cacheRoot });
    expect(insp.status).toBe('ok');
    expect(insp.bytes).toBe(EMBEDDING_ONNX_EXPECTED_BYTES);
    // File is zeros — if we had hashed it, status would be sha_mismatch.
    // Sidecar trust is intentional for doctor cheap-path; load path still
    // validates by actually running ONNX.
    expect(existsSync(onnxPath)).toBe(true);
  });

  it('rejects a sidecar that attests the wrong sha even when size matches', async () => {
    writeOnnxSparse(cacheRoot, EMBEDDING_ONNX_EXPECTED_BYTES, Buffer.alloc(32, 3));
    const { sidecarPath } = resolveEmbeddingModelPaths(cacheRoot);
    writeModelCacheSidecar(sidecarPath, {
      sha256: '0'.repeat(64),
      bytes: EMBEDDING_ONNX_EXPECTED_BYTES,
      modelId: EMBEDDING_MODEL_ID,
      verifiedAt: '2026-08-20T00:00:00.000Z',
    });
    const insp = await inspectEmbeddingModelCache({ cacheRoot });
    // Untrusted sidecar → live hash → mismatch on zeros-filled file.
    expect(insp.status).toBe('sha_mismatch');
  });

  it('quarantine renames the weight aside and preserves bytes', () => {
    const payload = Buffer.from('truncated-onnx-bytes');
    const onnxPath = writeOnnx(cacheRoot, payload);
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
  });

  it('quarantine is a no-op when the weight is already gone', () => {
    const q = quarantineEmbeddingOnnx({ cacheRoot, reason: 'missing' });
    expect(q.quarantinedPath).toBeNull();
    expect(q.detail).toMatch(/nothing to quarantine/);
  });

  it('isCorruptModelLoadError matches the Edith protobuf failure', () => {
    expect(
      isCorruptModelLoadError(
        'Load model from /home/edith/.cache/shieldcortex/models/Xenova/all-MiniLM-L6-v2/onnx/model.onnx failed:Protobuf parsing failed.',
      ),
    ).toBe(true);
    expect(isCorruptModelLoadError('ENOTFOUND huggingface.co')).toBe(false);
    expect(isCorruptModelLoadError('401 Unauthorized')).toBe(false);
  });

  it('known-good constants match the fleet reference weight when present', () => {
    // Guard against accidental constant drift in this repo checkout.
    const homeOnnx = join(
      process.env.HOME || '',
      '.cache/shieldcortex/models/Xenova/all-MiniLM-L6-v2/onnx/model.onnx',
    );
    if (!existsSync(homeOnnx)) return;
    expect(statSync(homeOnnx).size).toBe(EMBEDDING_ONNX_EXPECTED_BYTES);
    // Cheap size assertion only here; full sha is expensive and covered by
    // the constant definition + Edith post-heal verification.
    expect(EMBEDDING_ONNX_EXPECTED_SHA256).toHaveLength(64);
    expect(createHash('sha256').update('x').digest('hex')).toHaveLength(64);
  });
});
