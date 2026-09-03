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
 *  - sidecar is always invalidated when the weight is quarantined
 *  - one heal attempt per process (caller uses the latch)
 *  - doctor wording never claims a live sha when only a sidecar attested
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
  type Stats,
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

export type ModelCacheOkVia = 'sidecar' | 'live_sha';

export interface ModelCacheInspection {
  status: ModelCacheStatus;
  cacheDir: string;
  onnxPath: string;
  bytes?: number;
  sha256?: string;
  expectedBytes: number;
  expectedSha256: string;
  detail?: string;
  /** Present only when status === 'ok'. */
  verifiedVia?: ModelCacheOkVia;
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
  /** File identity binding — stale sidecar must not green-lie after replace. */
  mtimeMs: number;
  ino: number;
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
      typeof raw.verifiedAt !== 'string' ||
      typeof raw.mtimeMs !== 'number' ||
      typeof raw.ino !== 'number'
    ) {
      return null;
    }
    return {
      sha256: raw.sha256,
      bytes: raw.bytes,
      modelId: raw.modelId,
      verifiedAt: raw.verifiedAt,
      mtimeMs: raw.mtimeMs,
      ino: raw.ino,
    };
  } catch {
    return null;
  }
}

export function writeModelCacheSidecar(sidecarPath: string, sidecar: ModelCacheSidecar): void {
  mkdirSync(dirname(sidecarPath), { recursive: true });
  writeFileSync(sidecarPath, `${JSON.stringify(sidecar, null, 2)}\n`, { mode: 0o600 });
}

function sidecarMatchesFile(sidecar: ModelCacheSidecar, st: Stats): boolean {
  return (
    sidecar.bytes === st.size &&
    sidecar.bytes === EMBEDDING_ONNX_EXPECTED_BYTES &&
    sidecar.sha256 === EMBEDDING_ONNX_EXPECTED_SHA256 &&
    sidecar.modelId === EMBEDDING_MODEL_ID &&
    sidecar.mtimeMs === st.mtimeMs &&
    sidecar.ino === st.ino
  );
}

/**
 * Fast path: size must match. Sha is checked when:
 *  - size already mismatches (skip — status is size_mismatch), or
 *  - no trusted sidecar bound to this inode/mtime, or
 *  - opts.forceSha is true (doctor --deep / post-download verify).
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

  let st: Stats;
  try {
    st = statSync(paths.onnxPath);
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    return { ...base, status: 'unreadable', detail: msg };
  }

  const bytes = st.size;
  if (bytes !== EMBEDDING_ONNX_EXPECTED_BYTES) {
    return {
      ...base,
      status: 'size_mismatch',
      bytes,
      detail: `model.onnx is ${bytes} bytes; expected ${EMBEDDING_ONNX_EXPECTED_BYTES}`,
    };
  }

  const sidecar = readModelCacheSidecar(paths.sidecarPath);
  const sidecarTrusted = sidecar != null && sidecarMatchesFile(sidecar, st);

  if (sidecarTrusted && !opts.forceSha) {
    return {
      ...base,
      status: 'ok',
      bytes,
      sha256: sidecar!.sha256,
      verifiedVia: 'sidecar',
      detail: 'size + sidecar attestation match file identity',
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
      // Re-stat after hash in case something replaced the file mid-read.
      const st2 = statSync(paths.onnxPath);
      if (st2.size !== EMBEDDING_ONNX_EXPECTED_BYTES) {
        return {
          ...base,
          status: 'size_mismatch',
          bytes: st2.size,
          detail: 'model.onnx size changed during verification',
        };
      }
      writeModelCacheSidecar(paths.sidecarPath, {
        sha256,
        bytes: st2.size,
        modelId: EMBEDDING_MODEL_ID,
        verifiedAt: (opts.now ?? (() => new Date()))().toISOString(),
        mtimeMs: st2.mtimeMs,
        ino: st2.ino,
      });
    } catch {
      // Sidecar is an optimisation; integrity already passed.
    }
    return {
      ...base,
      status: 'ok',
      bytes,
      sha256,
      verifiedVia: 'live_sha',
      detail: 'size + live sha match',
    };
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    return { ...base, status: 'unreadable', bytes, detail: msg };
  }
}

/** Files transformers.js fetches from HuggingFace if absent, even when model.onnx is valid. */
export const EMBEDDING_REQUIRED_SIBLINGS = [
  'config.json',
  'tokenizer.json',
  'tokenizer_config.json',
] as const;

/**
 * Hook-safe local completeness: ONNX integrity PLUS tokenizer/config siblings.
 * inspectEmbeddingModelCache() alone is not enough — a valid model.onnx with
 * missing tokenizer.json still enters the worker with allowRemoteModels=true.
 */
export async function inspectEmbeddingHookReady(
  opts: { cacheRoot?: string } = {},
): Promise<{ ready: boolean; reason: string; missing: string[] }> {
  const insp = await inspectEmbeddingModelCache(opts);
  if (insp.status !== 'ok') {
    return { ready: false, reason: insp.status, missing: [] };
  }
  const missing: string[] = [];
  for (const name of EMBEDDING_REQUIRED_SIBLINGS) {
    const p = join(insp.cacheDir, name);
    try {
      if (!existsSync(p) || statSync(p).size === 0) missing.push(name);
    } catch {
      missing.push(name);
    }
  }
  if (missing.length) {
    return { ready: false, reason: `missing siblings: ${missing.join(', ')}`, missing };
  }
  return { ready: true, reason: 'ok', missing: [] };
}

function moveSidecarAside(sidecarPath: string, destWeightPath: string): void {
  if (!existsSync(sidecarPath)) return;
  const dest = `${destWeightPath}.shieldcortex.json`;
  try {
    renameSync(sidecarPath, dest);
  } catch {
    // Last resort: overwrite sidecar with an invalid marker so it can never
    // attest the next weight. Prefer rename; this is the honesty backstop.
    try {
      writeFileSync(
        sidecarPath,
        `${JSON.stringify({ invalidated: true, at: new Date().toISOString() })}\n`,
        { mode: 0o600 },
      );
    } catch {
      /* ignore — inspect will live-hash if sidecar is unreadable/untrusted */
    }
  }
}

/**
 * Move a suspect weight aside. Keeps the bad bytes for forensics.
 * Always invalidates the sidecar when the weight moves (main + EEXIST paths).
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
  // Suffix only — never path-join the reason. Strip dots so ".." cannot appear.
  const reason = (opts.reason ?? 'suspect').replace(/[^a-zA-Z0-9_-]+/g, '-').slice(0, 48);
  const dest = `${paths.onnxPath}.bak-${reason}-${stamp}`;

  const tryRename = (target: string): boolean => {
    try {
      renameSync(paths.onnxPath, target);
      moveSidecarAside(paths.sidecarPath, target);
      return true;
    } catch (err) {
      if (isNodeError(err) && err.code === 'EEXIST') return false;
      throw err;
    }
  };

  try {
    if (tryRename(dest)) {
      return {
        quarantinedPath: dest,
        onnxPath: paths.onnxPath,
        detail: `quarantined to ${dest}`,
      };
    }
    const dest2 = `${dest}-${process.pid}`;
    if (tryRename(dest2)) {
      return {
        quarantinedPath: dest2,
        onnxPath: paths.onnxPath,
        detail: `quarantined to ${dest2}`,
      };
    }
    return {
      quarantinedPath: null,
      onnxPath: paths.onnxPath,
      detail: 'quarantine rename failed (destination exists)',
    };
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    return { quarantinedPath: null, onnxPath: paths.onnxPath, detail: msg };
  }
}

/**
 * Load failures that mean "the on-disk weight is garbage", not network/auth.
 * Kept tight on purpose: over-broad matching would quarantine a healthy weight
 * on transient native errors (review blocker).
 */
export function isCorruptModelLoadError(message: string): boolean {
  const m = message.toLowerCase();
  if (m.includes('protobuf parsing failed')) return true;
  if (m.includes('invalid flatbuffer')) return true;
  if (m.includes('unexpected eof')) return true;
  if (m.includes('file is too small')) return true;
  if (m.includes('truncated')) return true;
  // transformers.js phrasing when the ONNX protobuf itself will not parse:
  // "Load model from <path> failed:Protobuf parsing failed."
  // Require both the load-from cue AND a parse/integrity cue.
  if (m.includes('load model from') && (m.includes('protobuf') || m.includes('parse'))) {
    return true;
  }
  return false;
}

/** Process-level latch: at most one quarantine+redownload heal per worker. */
let healAttemptedThisProcess = false;

export function hasAttemptedModelCacheHeal(): boolean {
  return healAttemptedThisProcess;
}

export function markModelCacheHealAttempted(): void {
  healAttemptedThisProcess = true;
}

/** Test-only reset. */
export function resetModelCacheHealLatchForTests(): void {
  healAttemptedThisProcess = false;
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
      if (insp.verifiedVia === 'live_sha') {
        return {
          status: 'pass',
          message: `model cached and live-sha verified (${insp.bytes ?? EMBEDDING_ONNX_EXPECTED_BYTES} bytes)`,
        };
      }
      return {
        status: 'pass',
        message:
          `model cached; size + sidecar attestation ok (${insp.bytes ?? EMBEDDING_ONNX_EXPECTED_BYTES} bytes) ` +
          `— not a live content hash this run`,
      };
    case 'size_mismatch':
    case 'sha_mismatch':
      return {
        status: 'warn',
        message:
          `embedding model cache is corrupt (${insp.detail ?? insp.status}) — semantic search/dedup may be degraded until it is re-downloaded`,
        fix:
          'Let the next preload quarantine the bad weight and re-download, or: ' +
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
