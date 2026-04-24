/**
 * Deep-clean / residue detection for ShieldCortex ↔ OpenClaw integration.
 *
 * The standard `uninstall` and `uninstallPlugin` code paths only fire when
 * the on-disk artefacts they expected are still present. Partial uninstalls,
 * manual cleanups, and version-to-version shape changes left orphaned config
 * entries in `~/.openclaw/openclaw.json` and `~/.openclaw/workspace/.clawhub/lock.json`
 * that kept producing "plugin references without files" and "missing skill file"
 * warnings until purged by hand (see incident notes 2026-04-23/24).
 *
 * This module scans every known residue location once, independently of disk
 * state, and offers a single surgical clean-up pass.
 *
 * Scope: read/write of JSON config files + directory removal under the user's
 * home directory. No network, no sudo, no shell invocation.
 */

import fs from 'fs';
import path from 'path';
import os from 'os';
import { execSync } from 'child_process';

const PLUGIN_ID = 'shieldcortex-realtime';
const HOOK_NAME = 'cortex-memory';

/**
 * Resolve the real user's home directory (mirrors openclaw.ts behaviour so the
 * two modules agree on which home to touch under sudo).
 */
function resolveHome(): string {
  const sudoUser = process.env.SUDO_USER;
  if (sudoUser) {
    try {
      const entry = execSync(`getent passwd ${sudoUser}`, {
        encoding: 'utf-8',
        timeout: 5000,
      }).trim();
      const homeDir = entry.split(':')[5];
      if (homeDir && fs.existsSync(homeDir)) return homeDir;
    } catch {
      // getent not available (macOS)
    }
  }
  return os.homedir();
}

type Removal =
  | { kind: 'delete-config-key'; file: string; keyPath: string[] }
  | { kind: 'filter-config-array'; file: string; keyPath: string[]; contains: string }
  | { kind: 'delete-directory'; path: string };

export interface ResiduePath {
  description: string;
  removal: Removal;
  present: boolean;
}

export interface ResidueReport {
  paths: ResiduePath[];
  dirtyCount: number;
  cleanCount: number;
}

export interface CleanOptions {
  dryRun?: boolean;
}

export interface CleanResult {
  removed: string[];
  errors: Array<{ description: string; error: string }>;
}

function readJsonOrNull(file: string): Record<string, unknown> | null {
  if (!fs.existsSync(file)) return null;
  try {
    const parsed = JSON.parse(fs.readFileSync(file, 'utf-8'));
    return typeof parsed === 'object' && parsed !== null
      ? (parsed as Record<string, unknown>)
      : null;
  } catch {
    return null;
  }
}

function writeJson(file: string, data: unknown): void {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  fs.writeFileSync(file, JSON.stringify(data, null, 2) + '\n', 'utf-8');
}

function getPath(root: unknown, keyPath: string[]): unknown {
  let node: unknown = root;
  for (const key of keyPath) {
    if (typeof node !== 'object' || node === null) return undefined;
    node = (node as Record<string, unknown>)[key];
  }
  return node;
}

function deletePath(root: Record<string, unknown>, keyPath: string[]): boolean {
  if (keyPath.length === 0) return false;
  let node: Record<string, unknown> = root;
  for (let i = 0; i < keyPath.length - 1; i++) {
    const next = node[keyPath[i]];
    if (typeof next !== 'object' || next === null) return false;
    node = next as Record<string, unknown>;
  }
  const leaf = keyPath[keyPath.length - 1];
  if (leaf in node) {
    delete node[leaf];
    return true;
  }
  return false;
}

function filterArrayAtPath(
  root: Record<string, unknown>,
  keyPath: string[],
  contains: string,
): boolean {
  const target = getPath(root, keyPath);
  if (!Array.isArray(target)) return false;
  const before = target.length;
  const filtered = target.filter(
    (entry) => !(typeof entry === 'string' && entry.includes(contains)),
  );
  if (filtered.length === before) return false;
  // Re-walk and assign back so we don't rely on aliasing
  let node: Record<string, unknown> = root;
  for (let i = 0; i < keyPath.length - 1; i++) {
    node = node[keyPath[i]] as Record<string, unknown>;
  }
  node[keyPath[keyPath.length - 1]] = filtered;
  return true;
}

/**
 * Build the full list of known residue locations and whether each one is
 * currently populated. Pure read — no mutation.
 */
export function scanForResidue(): ResidueReport {
  const home = resolveHome();
  const openclawJson = path.join(home, '.openclaw', 'openclaw.json');
  const clawhubLock = path.join(home, '.openclaw', 'workspace', '.clawhub', 'lock.json');

  const cfg = readJsonOrNull(openclawJson) ?? {};
  const lock = readJsonOrNull(clawhubLock) ?? {};

  const paths: ResiduePath[] = [];

  // ── openclaw.json: plugins ─────────────────────────────
  paths.push({
    description: `openclaw.json: .plugins.installs["${PLUGIN_ID}"]`,
    removal: { kind: 'delete-config-key', file: openclawJson, keyPath: ['plugins', 'installs', PLUGIN_ID] },
    present: !!getPath(cfg, ['plugins', 'installs', PLUGIN_ID]),
  });
  paths.push({
    description: `openclaw.json: .plugins.entries["${PLUGIN_ID}"]`,
    removal: { kind: 'delete-config-key', file: openclawJson, keyPath: ['plugins', 'entries', PLUGIN_ID] },
    present: !!getPath(cfg, ['plugins', 'entries', PLUGIN_ID]),
  });
  paths.push({
    description: `openclaw.json: .plugins.allow[] contains "${PLUGIN_ID}"`,
    removal: { kind: 'filter-config-array', file: openclawJson, keyPath: ['plugins', 'allow'], contains: PLUGIN_ID },
    present: ((): boolean => {
      const arr = getPath(cfg, ['plugins', 'allow']);
      return Array.isArray(arr) && arr.some((e) => typeof e === 'string' && e.includes(PLUGIN_ID));
    })(),
  });
  paths.push({
    description: `openclaw.json: .plugins.load.paths[] contains "${PLUGIN_ID}"`,
    removal: { kind: 'filter-config-array', file: openclawJson, keyPath: ['plugins', 'load', 'paths'], contains: PLUGIN_ID },
    present: ((): boolean => {
      const arr = getPath(cfg, ['plugins', 'load', 'paths']);
      return Array.isArray(arr) && arr.some((e) => typeof e === 'string' && e.includes(PLUGIN_ID));
    })(),
  });

  // ── openclaw.json: hooks (both modern and legacy shapes) ─
  paths.push({
    description: 'openclaw.json: .hooks.shieldcortex',
    removal: { kind: 'delete-config-key', file: openclawJson, keyPath: ['hooks', 'shieldcortex'] },
    present: !!getPath(cfg, ['hooks', 'shieldcortex']),
  });
  paths.push({
    description: 'openclaw.json: .hooks.internal.installs.shieldcortex',
    removal: { kind: 'delete-config-key', file: openclawJson, keyPath: ['hooks', 'internal', 'installs', 'shieldcortex'] },
    present: !!getPath(cfg, ['hooks', 'internal', 'installs', 'shieldcortex']),
  });
  paths.push({
    description: 'openclaw.json: .hooks.internal.entries.shieldcortex',
    removal: { kind: 'delete-config-key', file: openclawJson, keyPath: ['hooks', 'internal', 'entries', 'shieldcortex'] },
    present: !!getPath(cfg, ['hooks', 'internal', 'entries', 'shieldcortex']),
  });
  paths.push({
    description: 'openclaw.json: .hooks.internal.allow[] contains "shieldcortex"',
    removal: { kind: 'filter-config-array', file: openclawJson, keyPath: ['hooks', 'internal', 'allow'], contains: 'shieldcortex' },
    present: ((): boolean => {
      const arr = getPath(cfg, ['hooks', 'internal', 'allow']);
      return Array.isArray(arr) && arr.some((e) => typeof e === 'string' && e.includes('shieldcortex'));
    })(),
  });

  // ── clawhub lock ────────────────────────────────────────
  paths.push({
    description: 'clawhub/lock.json: .skills.shieldcortex',
    removal: { kind: 'delete-config-key', file: clawhubLock, keyPath: ['skills', 'shieldcortex'] },
    present: !!getPath(lock, ['skills', 'shieldcortex']),
  });

  // ── filesystem ──────────────────────────────────────────
  const dirs = [
    path.join(home, '.openclaw', 'hooks', HOOK_NAME),
    path.join(home, '.openclaw', 'hooks', 'internal', HOOK_NAME),
    path.join(home, '.openclaw', 'hooks', 'shieldcortex'),
    path.join(home, '.claude', 'hooks', HOOK_NAME),
    path.join(home, '.claude', 'hooks', 'internal', HOOK_NAME),
    path.join(home, '.openclaw', 'extensions', PLUGIN_ID),
  ];

  for (const dir of dirs) {
    paths.push({
      description: dir,
      removal: { kind: 'delete-directory', path: dir },
      present: fs.existsSync(dir),
    });
  }

  const dirtyCount = paths.filter((p) => p.present).length;
  const cleanCount = paths.length - dirtyCount;
  return { paths, dirtyCount, cleanCount };
}

/**
 * Apply all pending removals from a residue report. Config mutations for the
 * same file are batched so we write each JSON file at most once.
 */
export function cleanResidue(report: ResidueReport, options: CleanOptions = {}): CleanResult {
  const result: CleanResult = { removed: [], errors: [] };

  // Load each referenced config file once
  const configCache = new Map<string, Record<string, unknown>>();
  const loadConfig = (file: string): Record<string, unknown> => {
    if (!configCache.has(file)) {
      configCache.set(file, readJsonOrNull(file) ?? {});
    }
    return configCache.get(file)!;
  };

  const dirtyConfigFiles = new Set<string>();

  for (const entry of report.paths) {
    if (!entry.present) continue;

    try {
      const r = entry.removal;
      if (r.kind === 'delete-directory') {
        if (!options.dryRun) {
          fs.rmSync(r.path, { recursive: true, force: true });
        }
        result.removed.push(entry.description);
      } else if (r.kind === 'delete-config-key') {
        const cfg = loadConfig(r.file);
        if (deletePath(cfg, r.keyPath)) {
          dirtyConfigFiles.add(r.file);
          result.removed.push(entry.description);
        }
      } else if (r.kind === 'filter-config-array') {
        const cfg = loadConfig(r.file);
        if (filterArrayAtPath(cfg, r.keyPath, r.contains)) {
          dirtyConfigFiles.add(r.file);
          result.removed.push(entry.description);
        }
      }
    } catch (err) {
      result.errors.push({ description: entry.description, error: (err as Error).message });
    }
  }

  if (!options.dryRun) {
    for (const file of dirtyConfigFiles) {
      try {
        writeJson(file, configCache.get(file)!);
      } catch (err) {
        result.errors.push({ description: file, error: (err as Error).message });
      }
    }
  }

  return result;
}

/**
 * Best-effort restart of the OpenClaw gateway so the purged config takes
 * effect. Returns a structured report; never throws.
 *
 * Order of attempts:
 *   - Linux:  `systemctl --user restart openclaw-gateway`
 *   - macOS:  `launchctl kickstart -k gui/<uid>/ai.openclaw.gateway`
 *   - Fallback: skip with info message.
 */
export async function restartOpenClawGateway(): Promise<{
  attempted: boolean;
  restarted: boolean;
  method: string;
  detail?: string;
}> {
  const platform = process.platform;

  if (platform === 'linux') {
    try {
      execSync('systemctl --user restart openclaw-gateway', {
        encoding: 'utf-8',
        timeout: 10000,
        stdio: ['ignore', 'pipe', 'pipe'],
      });
      return { attempted: true, restarted: true, method: 'systemctl --user' };
    } catch (err) {
      return {
        attempted: true,
        restarted: false,
        method: 'systemctl --user',
        detail: (err as Error).message,
      };
    }
  }

  if (platform === 'darwin') {
    try {
      const uid = process.getuid ? process.getuid() : 0;
      execSync(`launchctl kickstart -k gui/${uid}/ai.openclaw.gateway`, {
        encoding: 'utf-8',
        timeout: 10000,
        stdio: ['ignore', 'pipe', 'pipe'],
      });
      return { attempted: true, restarted: true, method: 'launchctl kickstart' };
    } catch (err) {
      return {
        attempted: true,
        restarted: false,
        method: 'launchctl kickstart',
        detail: (err as Error).message,
      };
    }
  }

  return {
    attempted: false,
    restarted: false,
    method: 'unsupported-platform',
    detail: `Restart not implemented for platform: ${platform}`,
  };
}

/**
 * High-level entry point used by `shieldcortex uninstall --deep`.
 * Scans → cleans → (optionally) restarts gateway.
 */
export async function runDeepClean(options: { dryRun?: boolean; restartGateway?: boolean } = {}): Promise<{
  report: ResidueReport;
  result: CleanResult;
  gateway?: Awaited<ReturnType<typeof restartOpenClawGateway>>;
}> {
  const report = scanForResidue();
  const result = cleanResidue(report, { dryRun: options.dryRun });
  let gateway: Awaited<ReturnType<typeof restartOpenClawGateway>> | undefined;
  if (options.restartGateway && !options.dryRun && result.removed.length > 0) {
    gateway = await restartOpenClawGateway();
  }
  return { report, result, gateway };
}

// Exported for tests
export const _internals = {
  PLUGIN_ID,
  HOOK_NAME,
  resolveHome,
};
