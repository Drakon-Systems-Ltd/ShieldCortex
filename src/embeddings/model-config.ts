/**
 * #632 — where the embedding model lives, and whether it may be fetched.
 *
 * One resolver, consumed by the embedding worker, cache inspection/quarantine
 * and the doctor checks, so an operator's configuration can never mean one
 * directory to the loader and another to the diagnostics.
 *
 *   SHIELDCORTEX_MODEL_DIR           transformers.js cache ROOT. The model still
 *                                    lives at <root>/Xenova/all-MiniLM-L6-v2/.
 *                                    Unset or empty → ~/.cache/shieldcortex/models.
 *                                    `~` and `~/…` expand to the home directory.
 *                                    Relative paths, `~user`, surrounding
 *                                    whitespace, control characters and values
 *                                    over MODEL_DIR_MAX_LENGTH are rejected: a
 *                                    hook and the MCP server run from different
 *                                    working directories, so a relative root
 *                                    would resolve differently per caller.
 *                                    An explicit root is the ONLY local source
 *                                    the loader reads (see
 *                                    applyEmbeddingModelConfig).
 *   SHIELDCORTEX_EMBEDDINGS_OFFLINE  1/true/yes/on → never fetch the embedding
 *                                    model, including the corrupt-cache heal.
 *                                    Unset/empty/0/false/no/off → online
 *                                    (the default). Anything else is rejected.
 *   HF_ENDPOINT                      Optional mirror. transformers.js does not
 *                                    read it; it is validated here and mapped to
 *                                    `env.remoteHost`. https only (http only for
 *                                    loopback); no credentials, query or
 *                                    fragment. The path prefix is kept.
 *
 * Invalid configuration fails closed: the worker refuses to load rather than
 * falling back to another directory or to huggingface.co. A rejected value is
 * never echoed — it may be a mistaken secret, or carry terminal controls — the
 * error names only the variable and the reason. Accepted values are free of
 * control characters and are still bounded for display (boundForDisplay).
 */
import { homedir } from 'node:os';
import { isAbsolute, join, resolve } from 'node:path';

export const MODEL_DIR_ENV = 'SHIELDCORTEX_MODEL_DIR';
export const EMBEDDINGS_OFFLINE_ENV = 'SHIELDCORTEX_EMBEDDINGS_OFFLINE';
export const MIRROR_ENV = 'HF_ENDPOINT';

export class EmbeddingConfigError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'EmbeddingConfigError';
  }
}

export interface EmbeddingModelConfig {
  cacheRoot: string;
  /** 'argument' — an explicit cacheRoot passed by a caller, which wins over the env. */
  cacheRootSource: 'default' | typeof MODEL_DIR_ENV | 'argument';
  offline: boolean;
  /** null → leave the library's own default host in place. */
  remoteHost: string | null;
}

type Env = Record<string, string | undefined>;

export function defaultEmbeddingCacheRoot(home = homedir()): string {
  return join(home, '.cache', 'shieldcortex', 'models');
}

/** PATH_MAX on Linux; anything longer is not a usable directory anyway. */
export const MODEL_DIR_MAX_LENGTH = 4096;

// C0, DEL and C1 controls, plus the line/paragraph separators and bidi
// overrides that can rewrite how a terminal shows the rest of a line.
const DISPLAY_UNSAFE = /[\p{Cc}\u2028\u2029\u202A-\u202E\u2066-\u2069]/u;

/** Longest configured path/host a diagnostic prints in full. */
export const DISPLAY_MAX_LENGTH = 200;

/**
 * Bound an ACCEPTED path or host for a diagnostic. Accepted values are already
 * control-free; this only keeps an extreme length from flooding a terminal.
 */
export function boundForDisplay(value: string, max = DISPLAY_MAX_LENGTH): string {
  if (value.length <= max) return value;
  const half = Math.floor((max - 1) / 2);
  return `${value.slice(0, half)}…${value.slice(value.length - half)}`;
}

export function resolveEmbeddingCacheRoot(
  env: Env = process.env,
  home = homedir(),
): { cacheRoot: string; source: EmbeddingModelConfig['cacheRootSource'] } {
  const raw = env[MODEL_DIR_ENV];
  if (raw === undefined || raw === '') {
    return { cacheRoot: defaultEmbeddingCacheRoot(home), source: 'default' };
  }
  // Checked before anything else, and no message below interpolates `raw`.
  if (raw.length > MODEL_DIR_MAX_LENGTH) {
    throw new EmbeddingConfigError(
      `${MODEL_DIR_ENV} is longer than ${MODEL_DIR_MAX_LENGTH} characters (value not shown)`,
    );
  }
  if (DISPLAY_UNSAFE.test(raw)) {
    throw new EmbeddingConfigError(
      `${MODEL_DIR_ENV} contains a control character (value not shown)`,
    );
  }
  if (raw.trim() !== raw) {
    throw new EmbeddingConfigError(`${MODEL_DIR_ENV} has leading or trailing whitespace (value not shown)`);
  }
  let expanded = raw;
  if (raw === '~') {
    expanded = home;
  } else if (raw.startsWith('~/')) {
    expanded = join(home, raw.slice(2));
  } else if (raw.startsWith('~')) {
    throw new EmbeddingConfigError(
      `${MODEL_DIR_ENV} must be absolute or start with ~/ (~user is not expanded; value not shown)`,
    );
  }
  if (!isAbsolute(expanded)) {
    throw new EmbeddingConfigError(
      `${MODEL_DIR_ENV} must be an absolute path or start with ~/ (relative path rejected; value not shown)`,
    );
  }
  return { cacheRoot: resolve(expanded), source: MODEL_DIR_ENV };
}

const TRUE_VALUES = new Set(['1', 'true', 'yes', 'on']);
const FALSE_VALUES = new Set(['', '0', 'false', 'no', 'off']);

export function resolveEmbeddingsOffline(env: Env = process.env): boolean {
  const raw = env[EMBEDDINGS_OFFLINE_ENV];
  if (raw === undefined) return false;
  const v = raw.trim().toLowerCase();
  if (TRUE_VALUES.has(v)) return true;
  if (FALSE_VALUES.has(v)) return false;
  throw new EmbeddingConfigError(
    `${EMBEDDINGS_OFFLINE_ENV} must be one of 1/true/yes/on or 0/false/no/off (value not shown)`,
  );
}

const LOOPBACK_HOSTS = new Set(['localhost', '127.0.0.1', '[::1]']);

/**
 * Map HF_ENDPOINT onto a transformers.js `remoteHost`. Returns null when unset.
 * transformers.js joins `remoteHost` + `{model}/resolve/{revision}/` + file,
 * stripping one slash at each seam, so a trailing slash is normalised on and
 * `https://mirror/hf` fetches `https://mirror/hf/Xenova/…`.
 */
export function resolveEmbeddingMirror(env: Env = process.env): string | null {
  const raw = env[MIRROR_ENV];
  if (raw === undefined || raw === '') return null;
  const invalid = (why: string): EmbeddingConfigError =>
    new EmbeddingConfigError(`${MIRROR_ENV} rejected: ${why} (value not shown)`);
  // Checked on the raw string: URL drops a bare trailing "?" or "#".
  if (raw.includes('?')) throw invalid('query strings are not allowed');
  if (raw.includes('#')) throw invalid('fragments are not allowed');
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    throw invalid('not a valid absolute URL');
  }
  if (url.username || url.password || /^[a-z][a-z0-9+.-]*:\/\/[^/]*@/i.test(raw)) {
    throw invalid('credentials in the URL are not allowed');
  }
  if (url.protocol === 'http:') {
    if (!LOOPBACK_HOSTS.has(url.hostname)) {
      throw invalid('http is only allowed for loopback hosts; use https');
    }
  } else if (url.protocol !== 'https:') {
    throw invalid('only https URLs are supported');
  }
  const path = url.pathname.endsWith('/') ? url.pathname : `${url.pathname}/`;
  return `${url.origin}${path}`;
}

/** Throws EmbeddingConfigError on any invalid setting. */
export function resolveEmbeddingModelConfig(
  env: Env = process.env,
  home = homedir(),
): EmbeddingModelConfig {
  const { cacheRoot, source } = resolveEmbeddingCacheRoot(env, home);
  const offline = resolveEmbeddingsOffline(env);
  const remoteHost = resolveEmbeddingMirror(env);
  return { cacheRoot, cacheRootSource: source, offline, remoteHost };
}

/** The slice of transformers.js `env` this module writes. */
export interface TransformersEnvLike {
  allowRemoteModels: boolean;
  allowLocalModels: boolean;
  cacheDir: string;
  localModelPath?: string;
  [key: string]: unknown;
}

/**
 * transformers.js 3.x (utils/hub.js getModelFile) reads a model file from TWO
 * local roots before it considers the network: the FileCache at `cacheDir`,
 * then `localModelPath`, which defaults to the package's own `models/`
 * directory. local_files_only / allowRemoteModels=false only gate the remote
 * step after both miss. So with an explicit root, `cacheDir` alone is not
 * authoritative: a missing file could be satisfied from inside node_modules
 * while doctor and the hook inspect only <root>. An explicit root therefore
 * becomes `localModelPath` too, and both lookups land under it.
 *
 * allowLocalModels stays true: the library rejects local_files_only with local
 * models disabled. The default root keeps the library's localModelPath, exactly
 * as before #632.
 */
export function applyEmbeddingModelConfig(
  target: TransformersEnvLike,
  config: EmbeddingModelConfig,
): void {
  target.allowRemoteModels = !config.offline;
  target.allowLocalModels = true;
  target.cacheDir = config.cacheRoot;
  if (config.cacheRootSource !== 'default') target.localModelPath = config.cacheRoot;
  if (config.remoteHost !== null) target.remoteHost = config.remoteHost;
}
