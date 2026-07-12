/**
 * Discover every ShieldCortex install on the host (#76, requirement 4).
 *
 * A version bump can leave a multi-install "layer split": a rollout repairs
 * install A (e.g. the global npm prefix) while an MCP client entry still spawns
 * install B (e.g. a per-user prefix or an editor-pinned path). `repair` healing
 * only its own install then reports all-clear while the spawning install stays
 * broken — the exact honesty gap this closes.
 *
 * Sources, in order of authority:
 *   1. the running install itself (`resolveSelfInstallDir`);
 *   2. every `shieldcortex` on PATH (`which -a` / `where`);
 *   3. every install referenced by an MCP config entry — Claude Code
 *      (~/.claude.json) and Codex (~/.codex/config.toml).
 *
 * Only paths that actually mention `shieldcortex` are accepted, so a foreign
 * MCP server (e.g. mcpServers.memory pointing at somebody else's binary) is
 * never mistaken for ours.
 */

import fs from 'fs';
import path from 'path';
import os from 'os';
import { execSync } from 'child_process';
import { resolveSelfInstallDir } from './native-binding.js';

export interface DiscoveredInstall {
  /** The install root (the dir whose node_modules/better-sqlite3 to rebuild). */
  path: string;
  /** Where this install was discovered (self / PATH / claude.json / codex). */
  sources: string[];
}

export interface DiscoveryDeps {
  home: () => string;
  selfInstallDir: () => string;
  whichAll: () => string[];
  readFile: (p: string) => string;
  realpath: (p: string) => string;
  exists: (p: string) => boolean;
}

function defaultWhichAll(): string[] {
  try {
    const cmd = process.platform === 'win32' ? 'where shieldcortex' : 'which -a shieldcortex';
    return execSync(cmd, { encoding: 'utf-8', stdio: ['ignore', 'pipe', 'ignore'] })
      .split('\n')
      .map((l) => l.trim())
      .filter(Boolean);
  } catch {
    return [];
  }
}

function resolveDeps(deps: Partial<DiscoveryDeps>): DiscoveryDeps {
  return {
    home: deps.home ?? (() => os.homedir()),
    selfInstallDir: deps.selfInstallDir ?? resolveSelfInstallDir,
    whichAll: deps.whichAll ?? defaultWhichAll,
    readFile: deps.readFile ?? ((p) => fs.readFileSync(p, 'utf-8')),
    realpath: deps.realpath ?? ((p) => fs.realpathSync(p)),
    exists: deps.exists ?? ((p) => fs.existsSync(p)),
  };
}

/**
 * Derive a ShieldCortex install ROOT from a path that points somewhere inside an
 * install (a bin symlink, or a `dist/index.js` entry). Returns null when the
 * path is not recognisably a ShieldCortex path.
 *
 * Exported for unit testing the derivation in isolation.
 */
export function installRootFromPath(candidate: string, deps: Partial<DiscoveryDeps> = {}): string | null {
  const d = resolveDeps(deps);
  if (!candidate || !/shieldcortex/i.test(candidate)) return null;

  let real = candidate;
  try {
    real = d.realpath(candidate);
  } catch {
    // Unresolvable symlink — fall back to the raw path (still parseable).
  }

  // `.../shieldcortex/dist/index.js` → install root `.../shieldcortex`.
  if (path.basename(real) === 'index.js' && path.basename(path.dirname(real)) === 'dist') {
    return path.resolve(path.dirname(real), '..');
  }
  return null;
}

/** Candidate path strings referenced by ~/.claude.json's memory MCP entry. */
function claudeJsonCandidates(deps: DiscoveryDeps): string[] {
  const file = path.join(deps.home(), '.claude.json');
  try {
    const json = JSON.parse(deps.readFile(file)) as {
      mcpServers?: { memory?: { command?: unknown; args?: unknown } };
    };
    const mem = json.mcpServers?.memory;
    if (!mem) return [];
    const out: string[] = [];
    if (typeof mem.command === 'string') out.push(mem.command);
    if (Array.isArray(mem.args)) for (const a of mem.args) if (typeof a === 'string') out.push(a);
    return out;
  } catch {
    return [];
  }
}

/** Candidate path strings referenced by ~/.codex/config.toml (any shieldcortex string). */
function codexTomlCandidates(deps: DiscoveryDeps): string[] {
  const file = path.join(deps.home(), '.codex', 'config.toml');
  try {
    const text = deps.readFile(file);
    const out: string[] = [];
    const re = /["']([^"']*shieldcortex[^"']*)["']/gi;
    let m: RegExpExecArray | null;
    while ((m = re.exec(text)) !== null) out.push(m[1]);
    return out;
  } catch {
    return [];
  }
}

/**
 * Discover every ShieldCortex install on the host, deduped by real path, each
 * tagged with the sources that referenced it.
 */
export function discoverShieldcortexInstalls(deps: Partial<DiscoveryDeps> = {}): DiscoveredInstall[] {
  const d = resolveDeps(deps);
  const byRealPath = new Map<string, Set<string>>();

  const record = (root: string | null, source: string) => {
    if (!root) return;
    let key = root;
    try {
      key = d.realpath(root);
    } catch {
      // Use the raw root as the dedup key if it can't be resolved.
    }
    const set = byRealPath.get(key) ?? new Set<string>();
    set.add(source);
    byRealPath.set(key, set);
  };

  // 1. The running install — always included (it's what most commands act on).
  record(d.selfInstallDir(), 'self');

  // 2. Every shieldcortex on PATH.
  for (const binPath of d.whichAll()) {
    const root = installRootFromPath(binPath, deps);
    if (root && d.exists(path.join(root, 'node_modules', 'better-sqlite3'))) record(root, 'PATH');
  }

  // 3. MCP config references.
  for (const candidate of claudeJsonCandidates(d)) {
    const root = installRootFromPath(candidate, deps);
    if (root && d.exists(path.join(root, 'node_modules', 'better-sqlite3'))) record(root, 'claude.json');
  }
  for (const candidate of codexTomlCandidates(d)) {
    const root = installRootFromPath(candidate, deps);
    if (root && d.exists(path.join(root, 'node_modules', 'better-sqlite3'))) record(root, 'codex');
  }

  return [...byRealPath.entries()]
    .map(([p, sources]) => ({ path: p, sources: [...sources].sort() }))
    .sort((a, b) => a.path.localeCompare(b.path));
}
