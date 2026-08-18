/**
 * Shared project-key derivation for ShieldCortex hooks.
 *
 * Resolution order:
 *   1. Env override: SHIELDCORTEX_PROJECT_KEY
 *   2. Config override: ~/.shieldcortex/config.json → projectKey (string)
 *   3. Config alias: ~/.shieldcortex/config.json → projectAliases[basename]
 *   4. Git origin remote: walk up from cwd, parse owner/repo from origin URL
 *   5. Cwd basename (legacy behaviour), skipping noise directories
 *
 * Returns `null` if no project can be derived (hooks should treat that as
 * "don't emit project-scoped output").
 */

import { existsSync, readFileSync, statSync } from 'fs';
import { join, dirname } from 'path';
import { homedir } from 'os';

const SKIP_DIRECTORIES = [
  'src', 'lib', 'dist', 'build', 'out',
  'node_modules', '.git', '.next', '.cache',
  'test', 'tests', '__tests__', 'spec',
  'bin', 'scripts', 'config', 'public', 'static',
];

function resolveHome() {
  // Prefer env vars over os.homedir(): on POSIX Node ignores $HOME mutations
  // because libuv uses getpwuid. Tests (and users who `env HOME=...`) rely on
  // the env var path.
  return process.env.HOME || process.env.USERPROFILE || homedir();
}

function configPath() {
  // Resolved per-call so tests that swap HOME between assertions get a fresh
  // path without having to re-import the module.
  return join(resolveHome(), '.shieldcortex', 'config.json');
}

function loadConfig() {
  try {
    const p = configPath();
    if (!existsSync(p)) return {};
    return JSON.parse(readFileSync(p, 'utf-8'));
  } catch {
    return {};
  }
}

function basenameFromCwd(path) {
  if (!path) return null;
  const segments = path.split(/[/\\]/).filter(Boolean);
  for (let i = segments.length - 1; i >= 0; i--) {
    const segment = segments[i];
    if (SKIP_DIRECTORIES.includes(segment.toLowerCase())) continue;
    if (segment.startsWith('.')) continue;
    return segment;
  }
  return null;
}

function findGitDir(startPath) {
  let current = startPath;
  const root = '/';
  for (let i = 0; i < 40 && current && current !== root; i++) {
    const candidate = join(current, '.git');
    if (existsSync(candidate)) return candidate;
    const parent = dirname(current);
    if (parent === current) break;
    current = parent;
  }
  return null;
}

function parseOriginUrl(url) {
  if (!url) return null;
  const trimmed = url.trim();

  // git@host:owner/repo(.git)
  const sshMatch = trimmed.match(/^[^@]+@[^:]+:([^/]+)\/(.+?)(?:\.git)?$/);
  if (sshMatch) return { owner: sshMatch[1], repo: sshMatch[2] };

  // https://host/owner/repo(.git) or ssh://git@host/owner/repo(.git)
  const urlMatch = trimmed.match(/^[a-z]+:\/\/[^/]+\/(.+?)\/([^/]+?)(?:\.git)?$/i);
  if (urlMatch) return { owner: urlMatch[1], repo: urlMatch[2] };

  return null;
}

function readOriginFromGitConfig(gitPath) {
  try {
    // Handle worktree / submodule: .git may be a FILE pointing at the real
    // gitdir. When it's a directory (normal repo), just use it as-is.
    let realGitDir = gitPath;
    const stats = statSync(gitPath);
    if (stats.isFile()) {
      const content = readFileSync(gitPath, 'utf-8');
      if (content.startsWith('gitdir:')) {
        realGitDir = content.slice('gitdir:'.length).trim();
      } else {
        return null;
      }
    }
    const configPath = join(realGitDir, 'config');
    if (!existsSync(configPath)) return null;
    const content = readFileSync(configPath, 'utf-8');
    const section = content.match(/\[remote\s+"origin"\][^[]*/);
    if (!section) return null;
    const urlMatch = section[0].match(/\burl\s*=\s*(.+)/);
    if (!urlMatch) return null;
    return parseOriginUrl(urlMatch[1]);
  } catch {
    return null;
  }
}

/**
 * Derive the project key for a given working directory.
 * @param {string} cwd
 * @returns {string | null}
 */
export function deriveProjectKey(cwd) {
  if (process.env.SHIELDCORTEX_PROJECT_KEY) {
    return process.env.SHIELDCORTEX_PROJECT_KEY;
  }

  const config = loadConfig();
  if (typeof config.projectKey === 'string' && config.projectKey.trim()) {
    return config.projectKey.trim();
  }

  const basename = basenameFromCwd(cwd);

  if (config.projectAliases && typeof config.projectAliases === 'object' && basename) {
    const alias = config.projectAliases[basename];
    if (typeof alias === 'string' && alias.trim()) return alias.trim();
  }

  const gitDir = cwd ? findGitDir(cwd) : null;
  if (gitDir) {
    const origin = readOriginFromGitConfig(gitDir);
    if (origin?.owner && origin?.repo) {
      return `${origin.owner}-${origin.repo}`;
    }
  }

  // Hot path post-#42 fix: this branch should only fire outside any git repo
  // or when origin parsing fails. If users see this often after upgrading,
  // the helper itself needs another look.
  //
  // OpenClaw's default agent cwd is often ~/.openclaw/workspace — basename
  // "workspace" collides with canonical keys like edith-vitaetpax-edith-workspace
  // (Edith: doctor KEY warn returns after every update). Refuse bare generic
  // basenames unless the operator aliased them explicitly above.
  const GENERIC_BASENAMES = new Set(['workspace', 'openclaw', 'home', 'tmp', 'temp']);
  if (basename && GENERIC_BASENAMES.has(basename.toLowerCase())) {
    if (process.env.SHIELDCORTEX_DEBUG) {
      process.stderr.write(`[shieldcortex deriveProjectKey] refusing generic basename=${basename} cwd=${cwd}\n`);
    }
    return null;
  }
  if (process.env.SHIELDCORTEX_DEBUG) {
    process.stderr.write(`[shieldcortex deriveProjectKey] basename fallback for cwd=${cwd}\n`);
  }
  return basename;
}

// Exposed for tests
export const __internal = {
  parseOriginUrl,
  basenameFromCwd,
  readOriginFromGitConfig,
};
