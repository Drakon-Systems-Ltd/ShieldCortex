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
