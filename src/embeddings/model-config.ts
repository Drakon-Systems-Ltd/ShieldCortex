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
 *                                    whitespace and NUL bytes are rejected: a
 *                                    hook and the MCP server run from different
 *                                    working directories, so a relative root
 *                                    would resolve differently per caller.
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
 * falling back to another directory or to huggingface.co. Error text never
 * echoes the HF_ENDPOINT value.
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
  cacheRootSource: 'default' | typeof MODEL_DIR_ENV;
  offline: boolean;
  /** null → leave the library's own default host in place. */
  remoteHost: string | null;
}

type Env = Record<string, string | undefined>;

export function defaultEmbeddingCacheRoot(home = homedir()): string {
  return join(home, '.cache', 'shieldcortex', 'models');
}

export function resolveEmbeddingCacheRoot(
  env: Env = process.env,
  home = homedir(),
): { cacheRoot: string; source: EmbeddingModelConfig['cacheRootSource'] } {
  const raw = env[MODEL_DIR_ENV];
  if (raw === undefined || raw === '') {
    return { cacheRoot: defaultEmbeddingCacheRoot(home), source: 'default' };
  }
  if (raw.includes('\0')) {
    throw new EmbeddingConfigError(`${MODEL_DIR_ENV} contains a NUL byte`);
  }
  if (raw.trim() !== raw) {
    throw new EmbeddingConfigError(`${MODEL_DIR_ENV} has leading or trailing whitespace`);
  }
  let expanded = raw;
  if (raw === '~') {
    expanded = home;
  } else if (raw.startsWith('~/')) {
    expanded = join(home, raw.slice(2));
  } else if (raw.startsWith('~')) {
    throw new EmbeddingConfigError(
      `${MODEL_DIR_ENV} must be absolute or start with ~/ (~user is not expanded)`,
    );
  }
  if (!isAbsolute(expanded)) {
    throw new EmbeddingConfigError(
      `${MODEL_DIR_ENV} must be an absolute path (got a relative path: ${raw})`,
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
    `${EMBEDDINGS_OFFLINE_ENV} must be one of 1/true/yes/on or 0/false/no/off`,
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
  [key: string]: unknown;
}

export function applyEmbeddingModelConfig(
  target: TransformersEnvLike,
  config: EmbeddingModelConfig,
): void {
  target.allowRemoteModels = !config.offline;
  target.allowLocalModels = true;
  target.cacheDir = config.cacheRoot;
  if (config.remoteHost !== null) target.remoteHost = config.remoteHost;
}
