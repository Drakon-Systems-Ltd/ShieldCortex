/**
 * #383 — embedding model cache integrity + heal helpers.
 *
 * Xenova/all-MiniLM-L6-v2 is cached under
 *   ~/.cache/shieldcortex/models/Xenova/all-MiniLM-L6-v2/onnx/model.onnx
 *
 * A truncated download (Edith, May→Aug 2026) left a ~50 MB file that every
 * launch retried forever. Doctor only checked "directory non-empty", so the
 * box looked healthy while semantic search/dedup were silently dead.
 *
 * Contract:
 *  - known size + sha256 of the upstream fp32 ONNX weight
 *  - inspect never throws
 *  - quarantine renames aside (keeps the bad bytes for forensics)
 *  - one re-download attempt is the caller's job (worker load path)
 */
import { createHash } from 'node:crypto';
import {
  createReadStream,
  existsSync,
  mkdirSync,
  readFileSync,
  renameSync,
  statSync,
  writeFileSync,
} from 'node:fs';
import { homedir } from 'node:os';
import { dirname, join } from 'node:path';
import { finished } from 'node:stream/promises';

/** HuggingFace / transformers.js model id we pin for memory embeddings. */
export const EMBEDDING_MODEL_ID = 'Xenova/all-MiniLM-L6-v2';

/**
 * Known-good fp32 ONNX weight for Xenova/all-MiniLM-L6-v2.
 * Verified on multiple healthy fleet hosts (TARS + post-heal Edith).
 * If upstream ever republishes a different weight, bump both constants
 * together and regenerate fixtures — do not "accept any parseable file".
 */
export const EMBEDDING_ONNX_EXPECTED_BYTES = 90_387_606;
export const EMBEDDING_ONNX_EXPECTED_SHA256 =
  '759c3cd2b7fe7e93933ad23c4c9181b7396442a2ed746ec7c1d46192c469c46e';

/** Relative path under the transformers.js cacheDir. */
export const EMBEDDING_ONNX_RELATIVE = join(
  'Xenova',
  'all-MiniLM-L6-v2',
  'onnx',
  'model.onnx',
);

export type ModelCacheStatus =
  | 'missing'
  | 'ok'
  | 'size_mismatch'
  | 'sha_mismatch'
  | 'unreadable';

export interface ModelCacheInspection {
  status: ModelCacheStatus;
  cacheDir: string;
  onnxPath: string;
  bytes?: number;
  sha256?: string;
  expectedBytes: number;
  expectedSha256: string;
  detail?: string;
}

export interface ModelCachePaths {
  cacheRoot: string;
  modelDir: string;
  onnxPath: string;
  sidecarPath: string;
}

export function defaultEmbeddingCacheRoot(home = homedir()): string {
  return join(home, '.cache', 'shieldcortex', 'models');
}

export function resolveEmbeddingModelPaths(cacheRoot = defaultEmbeddingCacheRoot()): ModelCachePaths {
  const onnxPath = join(cacheRoot, EMBEDDING_ONNX_RELATIVE);
  return {
    cacheRoot,
    modelDir: join(cacheRoot, 'Xenova', 'all-MiniLM-L6-v2'),
    onnxPath,
    sidecarPath: `${onnxPath}.shieldcortex.json`,
  };
}

export interface ModelCacheSidecar {
  sha256: string;
  bytes: number;
  modelId: string;
  verifiedAt: string;
}

function isNodeError(err: unknown): err is NodeJS.ErrnoException {
  return Boolean(err) && typeof err === 'object' && 'code' in (err as object);
}

/** Streaming sha256 — 90 MB must not be slurped into a single Buffer. */
export async function sha256File(filePath: string): Promise<string> {
  const hash = createHash('sha256');
  const stream = createReadStream(filePath);
  stream.on('data', (chunk: string | Buffer) => {
    hash.update(typeof chunk === 'string' ? Buffer.from(chunk) : chunk);
  });
  await finished(stream);
  return hash.digest('hex');
}

export function readModelCacheSidecar(sidecarPath: string): ModelCacheSidecar | null {
  try {
    if (!existsSync(sidecarPath)) return null;
    const raw = JSON.parse(readFileSync(sidecarPath, 'utf8')) as Partial<ModelCacheSidecar>;
    if (
      typeof raw.sha256 !== 'string' ||
      typeof raw.bytes !== 'number' ||
      typeof raw.modelId !== 'string' ||
      typeof raw.verifiedAt !== 'string'
    ) {
      return null;
    }
    return {
      sha256: raw.sha256,
      bytes: raw.bytes,
      modelId: raw.modelId,
      verifiedAt: raw.verifiedAt,
    };
  } catch {
    return null;
  }
}

export function writeModelCacheSidecar(sidecarPath: string, sidecar: ModelCacheSidecar): void {
  mkdirSync(dirname(sidecarPath), { recursive: true });
  writeFileSync(sidecarPath, `${JSON.stringify(sidecar, null, 2)}\n`, { mode: 0o600 });
}

/**
 * Fast path: size must match. Sha is checked when:
 *  - size already mismatches (skip — status is size_mismatch), or
 *  - no trusted sidecar, or
 *  - sidecar disagrees with expected constants, or
 *  - opts.forceSha is true (doctor --deep / post-download verify).
 *
 * A matching sidecar written by us after a verified load lets doctor stay
 * cheap on the happy path without re-hashing 90 MB every run.
 */
export async function inspectEmbeddingModelCache(
  opts: {
    cacheRoot?: string;
    forceSha?: boolean;
    now?: () => Date;
  } = {},
): Promise<ModelCacheInspection> {
  const paths = resolveEmbeddingModelPaths(opts.cacheRoot ?? defaultEmbeddingCacheRoot());
  const base = {
    cacheDir: paths.modelDir,
    onnxPath: paths.onnxPath,
    expectedBytes: EMBEDDING_ONNX_EXPECTED_BYTES,
    expectedSha256: EMBEDDING_ONNX_EXPECTED_SHA256,
  };

  if (!existsSync(paths.onnxPath)) {
    return { ...base, status: 'missing', detail: 'model.onnx not present' };
  }

  let bytes: number;
  try {
    bytes = statSync(paths.onnxPath).size;
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    return { ...base, status: 'unreadable', detail: msg };
  }

  if (bytes !== EMBEDDING_ONNX_EXPECTED_BYTES) {
    return {
      ...base,
      status: 'size_mismatch',
      bytes,
      detail: `model.onnx is ${bytes} bytes; expected ${EMBEDDING_ONNX_EXPECTED_BYTES}`,
    };
  }

  const sidecar = readModelCacheSidecar(paths.sidecarPath);
  const sidecarTrusted =
    sidecar != null &&
    sidecar.bytes === EMBEDDING_ONNX_EXPECTED_BYTES &&
    sidecar.sha256 === EMBEDDING_ONNX_EXPECTED_SHA256 &&
    sidecar.modelId === EMBEDDING_MODEL_ID;

  if (sidecarTrusted && !opts.forceSha) {
    return {
      ...base,
      status: 'ok',
      bytes,
      sha256: sidecar.sha256,
      detail: 'size + sidecar sha match',
    };
  }

  try {
    const sha256 = await sha256File(paths.onnxPath);
    if (sha256 !== EMBEDDING_ONNX_EXPECTED_SHA256) {
      return {
        ...base,
        status: 'sha_mismatch',
        bytes,
        sha256,
        detail: `model.onnx sha256 ${sha256.slice(0, 12)}… does not match known-good`,
      };
    }
    // Refresh sidecar so subsequent doctor runs stay cheap.
    try {
      writeModelCacheSidecar(paths.sidecarPath, {
        sha256,
        bytes,
        modelId: EMBEDDING_MODEL_ID,
        verifiedAt: (opts.now ?? (() => new Date()))().toISOString(),
      });
    } catch {
      // Sidecar is an optimisation; integrity already passed.
    }
    return { ...base, status: 'ok', bytes, sha256, detail: 'size + sha match' };
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    return { ...base, status: 'unreadable', bytes, detail: msg };
  }
}

/**
 * Move a suspect weight aside. Keeps the bad bytes for forensics.
 * Returns the quarantine path, or null if the file was already gone / rename failed.
 */
export function quarantineEmbeddingOnnx(
  opts: {
    cacheRoot?: string;
    reason?: string;
    stamp?: string;
  } = {},
): { quarantinedPath: string | null; onnxPath: string; detail: string } {
  const paths = resolveEmbeddingModelPaths(opts.cacheRoot ?? defaultEmbeddingCacheRoot());
  if (!existsSync(paths.onnxPath)) {
    return {
      quarantinedPath: null,
      onnxPath: paths.onnxPath,
      detail: 'nothing to quarantine',
    };
  }

  const stamp =
    opts.stamp ??
    new Date().toISOString().replace(/[:.]/g, '-').replace(/Z$/, 'Z');
  const reason = (opts.reason ?? 'suspect').replace(/[^a-zA-Z0-9._-]+/g, '-').slice(0, 48);
  const dest = `${paths.onnxPath}.bak-${reason}-${stamp}`;

  try {
    renameSync(paths.onnxPath, dest);
    // Sidecar is meaningless without the weight it attests.
    if (existsSync(paths.sidecarPath)) {
      try {
        renameSync(paths.sidecarPath, `${dest}.shieldcortex.json`);
      } catch {
        /* ignore */
      }
    }
    return {
      quarantinedPath: dest,
      onnxPath: paths.onnxPath,
      detail: `quarantined to ${dest}`,
    };
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    // EEXIST: pick a unique suffix once.
    if (isNodeError(err) && err.code === 'EEXIST') {
      const dest2 = `${dest}-${process.pid}`;
      try {
        renameSync(paths.onnxPath, dest2);
        return {
          quarantinedPath: dest2,
          onnxPath: paths.onnxPath,
          detail: `quarantined to ${dest2}`,
        };
      } catch (err2) {
        const msg2 = err2 instanceof Error ? err2.message : String(err2);
        return { quarantinedPath: null, onnxPath: paths.onnxPath, detail: msg2 };
      }
    }
    return { quarantinedPath: null, onnxPath: paths.onnxPath, detail: msg };
  }
}

/** Load failures that mean "the on-disk weight is garbage", not "network/auth". */
export function isCorruptModelLoadError(message: string): boolean {
  const m = message.toLowerCase();
  if (m.includes('protobuf parsing failed') || m.includes('protobuf')) return true;
  if (m.includes('invalid flatbuffer')) return true;
  if (m.includes('failed to load model from') || m.includes('load model from')) return true;
  if (m.includes('onnx') && m.includes('failed')) return true;
  if (m.includes('file is too small') || m.includes('unexpected eof')) return true;
  if (m.includes('truncated')) return true;
  return false;
}

export function formatModelCacheDoctorMessage(insp: ModelCacheInspection): {
  status: 'pass' | 'warn' | 'info' | 'fail';
  message: string;
  fix?: string;
} {
  switch (insp.status) {
    case 'missing':
      return {
        status: 'info',
        message: 'model not cached — will download on first recall',
      };
    case 'ok':
      return {
        status: 'pass',
        message: `model cached and verified (${insp.bytes ?? EMBEDDING_ONNX_EXPECTED_BYTES} bytes, sha ok)`,
      };
    case 'size_mismatch':
    case 'sha_mismatch':
      return {
        status: 'warn',
        message:
          `embedding model cache is corrupt (${insp.detail ?? insp.status}) — semantic search/dedup may be degraded until it is re-downloaded`,
        fix:
          'Remove the bad weight (or let the next preload quarantine it) and re-run a recall, or: ' +
          `mv "${insp.onnxPath}" "${insp.onnxPath}.bak-manual" && shieldcortex doctor`,
      };
    case 'unreadable':
      return {
        status: 'warn',
        message: `embedding model cache unreadable — ${insp.detail ?? 'unknown error'}`,
        fix: `Check permissions on ${insp.cacheDir}`,
      };
    default: {
      const _exhaustive: never = insp.status;
      return { status: 'warn', message: `unexpected model cache status: ${_exhaustive}` };
    }
  }
}
