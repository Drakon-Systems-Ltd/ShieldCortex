/**
 * TypeScript port of scripts/lib/project-key.mjs.
 *
 * Both the MCP-server side (this module) and the hook scripts must agree on
 * how a cwd maps to a project key — otherwise writes and reads fall under
 * different scopes and recall silently misses (issue #42).
 *
 * Resolution order:
 *   1. SHIELDCORTEX_PROJECT_KEY env override
 *   2. CLAUDE_MEMORY_PROJECT env override (legacy alias for SC env var)
 *   3. ~/.shieldcortex/config.json projectKey
 *   4. ~/.shieldcortex/config.json projectAliases[basename]
 *   5. Git origin owner-repo (walk up from cwd)
 *   6. Cwd basename (legacy behaviour), skipping noise directories
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

function resolveHome(): string {
  return process.env.HOME || process.env.USERPROFILE || homedir();
}

function configPath(): string {
  return join(resolveHome(), '.shieldcortex', 'config.json');
}

function loadConfig(): Record<string, unknown> {
  try {
    const p = configPath();
    if (!existsSync(p)) return {};
    return JSON.parse(readFileSync(p, 'utf-8'));
  } catch {
    return {};
  }
}

export function basenameFromCwd(path: string | null | undefined): string | null {
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

function findGitDir(startPath: string): string | null {
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

function parseOriginUrl(url: string): { owner: string; repo: string } | null {
  if (!url) return null;
  const trimmed = url.trim();
  const sshMatch = trimmed.match(/^[^@]+@[^:]+:([^/]+)\/(.+?)(?:\.git)?$/);
  if (sshMatch) return { owner: sshMatch[1], repo: sshMatch[2] };
  const urlMatch = trimmed.match(/^[a-z]+:\/\/[^/]+\/(.+?)\/([^/]+?)(?:\.git)?$/i);
  if (urlMatch) return { owner: urlMatch[1], repo: urlMatch[2] };
  return null;
}

function readOriginFromGitConfig(gitPath: string): { owner: string; repo: string } | null {
  try {
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
    const cfgPath = join(realGitDir, 'config');
    if (!existsSync(cfgPath)) return null;
    const content = readFileSync(cfgPath, 'utf-8');
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
 * Derive the project key for a given working directory. Mirrors
 * scripts/lib/project-key.mjs::deriveProjectKey so MCP-server-side and
 * hook-side keys agree.
 */
export function deriveProjectKey(cwd: string | null | undefined): string | null {
  if (process.env.SHIELDCORTEX_PROJECT_KEY) {
    return process.env.SHIELDCORTEX_PROJECT_KEY;
  }
  if (process.env.CLAUDE_MEMORY_PROJECT) {
    const v = process.env.CLAUDE_MEMORY_PROJECT.trim();
    if (v) return v;
  }

  const config = loadConfig();
  const projectKey = (config as { projectKey?: unknown }).projectKey;
  if (typeof projectKey === 'string' && projectKey.trim()) {
    return projectKey.trim();
  }

  const basename = basenameFromCwd(cwd);

  const aliases = (config as { projectAliases?: Record<string, unknown> }).projectAliases;
  if (aliases && typeof aliases === 'object' && basename) {
    const alias = aliases[basename];
    if (typeof alias === 'string' && alias.trim()) return alias.trim();
  }

  const gitDir = cwd ? findGitDir(cwd) : null;
  if (gitDir) {
    const origin = readOriginFromGitConfig(gitDir);
    if (origin?.owner && origin?.repo) {
      return `${origin.owner}-${origin.repo}`;
    }
  }

  // OpenClaw default cwd is often ~/.openclaw/workspace — bare "workspace"
  // collides with canonical keys like edith-vitaetpax-edith-workspace.
  // Refuse generic basenames unless projectAliases mapped them above.
  const GENERIC_BASENAMES = new Set(['workspace', 'openclaw', 'home', 'tmp', 'temp']);
  if (basename && GENERIC_BASENAMES.has(basename.toLowerCase())) {
    return null;
  }

  return basename;
}

export const __internal = {
  parseOriginUrl,
  basenameFromCwd,
  readOriginFromGitConfig,
};
