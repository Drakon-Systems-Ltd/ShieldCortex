import fs from 'fs';
import path from 'path';

/**
 * Reading the OpenClaw realtime plugin's *actually-installed* version.
 *
 * OpenClaw 2026.6.1 moved authoritative plugin state into a SQLite index
 * (`~/.openclaw/state/openclaw.sqlite` → `installed_plugin_index`) and stopped
 * updating the legacy `~/.openclaw/plugins/installs.json` `version` field. So
 * after `openclaw plugins install @latest` bumps the plugin on disk, that
 * registry field goes stale — which made `shieldcortex doctor`/`update` (both
 * of which read it) report the old version.
 *
 * The install *path* in `installs.json` stays correct, and the package.json at
 * that path is ground truth — it's the code OpenClaw actually loads. So we read
 * the version from there, with a scan of `~/.openclaw/npm/projects/` as a
 * fallback for SQLite-only boxes that never had a legacy `installs.json`.
 */

const PLUGIN_ID = 'shieldcortex-realtime';
const PKG_SUBPATH = path.join('node_modules', '@drakon-systems', 'shieldcortex-realtime');

function installsJsonPath(home: string): string {
  return path.join(home, '.openclaw', 'plugins', 'installs.json');
}

function hasPackageJson(installPath: string): boolean {
  return fs.existsSync(path.join(installPath, 'package.json'));
}

/**
 * Resolve the realtime plugin's on-disk install directory (the one containing
 * its package.json), or null when no install can be found.
 */
export function resolveRealtimePluginInstallPath(home: string): string | null {
  // 1. installPath recorded in installs.json — reliable even when the sibling
  //    `version` field is stale (the path still points at the active install).
  try {
    const file = installsJsonPath(home);
    if (fs.existsSync(file)) {
      const json = JSON.parse(fs.readFileSync(file, 'utf-8')) as {
        installRecords?: Record<string, { installPath?: unknown }>;
      };
      const p = json.installRecords?.[PLUGIN_ID]?.installPath;
      if (typeof p === 'string' && hasPackageJson(p)) return p;
    }
  } catch {
    // fall through to the filesystem scan
  }

  // 2. Scan OpenClaw's npm projects dir for the installed package (covers boxes
  //    whose authoritative state is SQLite-only, with no legacy installs.json).
  try {
    const projects = path.join(home, '.openclaw', 'npm', 'projects');
    for (const dir of fs.readdirSync(projects)) {
      if (!dir.includes(PLUGIN_ID)) continue;
      const p = path.join(projects, dir, PKG_SUBPATH);
      if (hasPackageJson(p)) return p;
    }
  } catch {
    // no projects dir
  }

  return null;
}

/**
 * The realtime plugin's actually-installed version, read from the on-disk
 * package.json (ground truth). Falls back to the version recorded in
 * installs.json only when no on-disk install resolves. Returns null when the
 * plugin is neither installed nor registered.
 */
export function readInstalledRealtimePluginVersion(home: string): string | null {
  const installPath = resolveRealtimePluginInstallPath(home);
  if (installPath) {
    try {
      const pj = JSON.parse(fs.readFileSync(path.join(installPath, 'package.json'), 'utf-8')) as { version?: unknown };
      if (typeof pj.version === 'string') return pj.version;
    } catch {
      // fall through to the recorded version
    }
  }

  // Last resort: the version recorded in installs.json (may be stale on
  // OpenClaw >= 2026.6.1, but better than nothing on layouts we can't resolve).
  try {
    const json = JSON.parse(fs.readFileSync(installsJsonPath(home), 'utf-8')) as {
      installRecords?: Record<string, { version?: unknown; resolvedVersion?: unknown }>;
    };
    const rec = json.installRecords?.[PLUGIN_ID];
    const v = rec?.version ?? rec?.resolvedVersion;
    return typeof v === 'string' ? v : null;
  } catch {
    return null;
  }
}

// ── Managed-project manifest (the EOVERRIDE-drift surface) ──────────────────
//
// OpenClaw installs each plugin into its own npm "project" under
// `~/.openclaw/npm/projects/<name>-<hash>/`, whose generated package.json holds
// the managed `dependencies` (peer pins), `overrides` (imported from OpenClaw's
// bundled pnpm-workspace.yaml), and an `openclaw.managedPeerDependencies` block.
// That manifest — NOT the plugin's published package.json — is where the
// EOVERRIDE trap lives.

const PROJECTS_SUBDIR = path.join('.openclaw', 'npm', 'projects');

/**
 * The OpenClaw managed-project ROOT for the realtime plugin (the dir whose
 * package.json carries the managed dependencies/overrides), or null.
 *
 * The recorded install path may point at the project root OR the nested package
 * dir depending on layout, so we walk up to the direct child of `npm/projects`
 * rather than assuming a fixed depth.
 */
export function resolveRealtimeProjectDir(home: string): string | null {
  const projects = path.join(home, PROJECTS_SUBDIR);
  const installPath = resolveRealtimePluginInstallPath(home);
  if (installPath) {
    let cur = installPath;
    for (let i = 0; i < 8; i++) {
      if (path.dirname(cur) === projects) {
        return fs.existsSync(path.join(cur, 'package.json')) ? cur : null;
      }
      const parent = path.dirname(cur);
      if (parent === cur) break;
      cur = parent;
    }
  }
  // Fallback: scan the projects dir for the realtime project root.
  try {
    for (const dir of fs.readdirSync(projects)) {
      if (dir.includes(PLUGIN_ID) && fs.existsSync(path.join(projects, dir, 'package.json'))) {
        return path.join(projects, dir);
      }
    }
  } catch {
    // no projects dir
  }
  return null;
}

/** Read+parse the realtime managed-project manifest, or null. */
export function readRealtimeProjectManifest(home: string): Record<string, unknown> | null {
  const dir = resolveRealtimeProjectDir(home);
  if (!dir) return null;
  try {
    return JSON.parse(fs.readFileSync(path.join(dir, 'package.json'), 'utf-8')) as Record<string, unknown>;
  } catch {
    return null;
  }
}

/** A package pinned in BOTH `dependencies` and `overrides` at DIFFERENT
 * versions — the exact shape that makes npm's `assertRootOverrides` throw
 * `EOVERRIDE` on the next `openclaw plugins install` / `openclaw update`. */
export interface EoverrideRiskPin {
  name: string;
  dependencyVersion: string;
  overrideVersion: string;
}

/**
 * Find EOVERRIDE-risk pins in an OpenClaw managed-project manifest: packages
 * present as BOTH a direct dependency (a managed peer pin) AND a managed
 * override, with mismatched versions. OpenClaw never advances the dependency
 * pin while its bundled workspace overrides advance each release, so they drift
 * apart and npm refuses the install — disabling the plugin. Same-version
 * co-presence is accepted by npm and is NOT reported (only the drift is).
 *
 * Pure — takes a parsed manifest object so it can be unit-tested without disk.
 */
export function findEoverrideRiskPins(manifest: unknown): EoverrideRiskPin[] {
  if (!manifest || typeof manifest !== 'object') return [];
  const m = manifest as { dependencies?: unknown; overrides?: unknown };
  const deps = m.dependencies && typeof m.dependencies === 'object' ? (m.dependencies as Record<string, unknown>) : {};
  const overrides = m.overrides && typeof m.overrides === 'object' ? (m.overrides as Record<string, unknown>) : {};
  const risks: EoverrideRiskPin[] = [];
  for (const [name, depV] of Object.entries(deps)) {
    const ovV = overrides[name];
    // Only string↔string mismatches are the EOVERRIDE trap. Nested override
    // objects ({".": "x"}) aren't how OpenClaw pins these, so skip non-strings.
    if (typeof depV === 'string' && typeof ovV === 'string' && depV !== ovV) {
      risks.push({ name, dependencyVersion: depV, overrideVersion: ovV });
    }
  }
  return risks;
}

/** True when openclaw.json explicitly disables the realtime plugin
 * (`plugins.entries.shieldcortex-realtime.enabled === false`) — the state
 * OpenClaw leaves it in after an install failure auto-disables it. */
export function isRealtimePluginDisabledInConfig(home: string): boolean {
  try {
    const cfg = JSON.parse(fs.readFileSync(path.join(home, '.openclaw', 'openclaw.json'), 'utf-8')) as {
      plugins?: { entries?: Record<string, { enabled?: unknown }> };
    };
    return cfg.plugins?.entries?.[PLUGIN_ID]?.enabled === false;
  } catch {
    return false;
  }
}
