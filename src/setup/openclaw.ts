/**
 * Claude Code / OpenClaw hook + plugin installer.
 *
 * Copies the cortex-memory hook into the hooks directory and
 * the real-time plugin into the OpenClaw extensions directory.
 * Supports both Claude Code (native binary) and legacy OpenClaw (Node.js).
 */

import fs from 'fs';
import path from 'path';
import os from 'os';
import { execSync, spawnSync } from 'child_process';
import { fileURLToPath, pathToFileURL } from 'url';
import {
  resolveRealtimeProjectDir,
  resolveRealtimePluginInstallPath,
  readRealtimeProjectManifest,
  findEoverrideRiskPins,
  findLatentEoverridePins,
  stripManagedPinsFromManifest,
  isRealtimePluginDisabledInConfig,
} from '../integrations/openclaw-plugin-state.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const HOOK_NAME = 'cortex-memory';

// Hook source is in hooks/openclaw/cortex-memory/ relative to project root
// From dist/setup/, go up two levels to project root
const HOOK_SOURCE = path.resolve(__dirname, '..', '..', 'hooks', 'openclaw', HOOK_NAME);

// Plugin compiled output in plugins/openclaw/dist/ relative to project root.
// `SHIELDCORTEX_PLUGIN_SOURCE` overrides for hermetic tests so the install
// path doesn't need a prior `npm run build`.
const PLUGIN_SOURCE = process.env.SHIELDCORTEX_PLUGIN_SOURCE
  ? path.resolve(process.env.SHIELDCORTEX_PLUGIN_SOURCE)
  : path.resolve(__dirname, '..', '..', 'plugins', 'openclaw', 'dist');
const PLUGIN_PACKAGE_SOURCE = path.resolve(__dirname, '..', '..', 'plugins', 'openclaw');
const PLUGIN_DIR_NAME = 'shieldcortex-realtime';
const HOOK_FILES = ['HOOK.md', 'handler.ts', 'runtime.mjs'] as const;
const OPENCLAW_SKIP_NATIVE_INSTALL_ENV = 'SHIELDCORTEX_SKIP_NATIVE_OPENCLAW_INSTALL';

// REFACTOR (May 2026 audit): consolidate to 'native' | 'local' (with trusted boolean) | 'skipped'.
// Five modes is a smell — every one is a distinct state the doctor command must recognise.
// Don't ship blind: cross-cuts the install command's "What was installed" log + the
// postinstall script + doctor.ts. See src/__tests__/openclaw-install-mode-contract.test.ts
// for the contract that has to be migrated atomically.
type PluginInstallMode = 'native-package' | 'native-link' | 'trusted-local-copy' | 'untrusted-local-copy' | 'skipped';

// ==================== Docker/Container Detection ====================

/**
 * Detect whether ShieldCortex is running inside a Docker container
 * or similar isolated environment (Umbrel, Unraid, NixOS sandbox, etc.).
 *
 * In these environments, OpenClaw hook/plugin installation may crash or
 * produce broken state. We warn and skip by default.
 */
export function isDockerEnvironment(): boolean {
  // Standard Docker marker file
  try {
    if (fs.existsSync('/.dockerenv')) return true;
  } catch { /* ignore */ }
  // Explicit env overrides
  if (process.env.DOCKER === 'true' || process.env.DOCKER === '1') return true;
  if (process.env.container === 'docker') return true;
  // /proc/1/cgroup contains "docker" or "kubepods" on containerised systems
  try {
    const cgroup = fs.readFileSync('/proc/1/cgroup', 'utf-8');
    if (/docker|kubepods|containerd/i.test(cgroup)) return true;
  } catch { /* not Linux or not accessible */ }
  return false;
}

/**
 * Resolve the real user's home directory.
 *
 * When run under sudo, os.homedir() returns /root/.
 * We check SUDO_USER first and resolve their actual home.
 */
function resolveUserHome(): string {
  const sudoUser = process.env.SUDO_USER;
  if (sudoUser) {
    // Try getent passwd (reliable on Linux)
    try {
      const entry = execSync(`getent passwd ${sudoUser}`, {
        encoding: 'utf-8',
        timeout: 5000,
      }).trim();
      const homeDir = entry.split(':')[5];
      if (homeDir && fs.existsSync(homeDir)) {
        return homeDir;
      }
    } catch {
      // getent not available (macOS) — try tilde expansion
    }

    // Fallback: tilde expansion
    try {
      const homeDir = execSync(`eval echo ~${sudoUser}`, {
        encoding: 'utf-8',
        timeout: 5000,
      }).trim();
      if (homeDir && fs.existsSync(homeDir)) {
        return homeDir;
      }
    } catch {
      // Fall through to os.homedir()
    }
  }

  const home = os.homedir();

  // If we're root without SUDO_USER (e.g. after `sudo su -`),
  // search /home/* for a user who has .openclaw/ or .claude/ configured.
  if (home === '/root' || (process.getuid && process.getuid() === 0)) {
    try {
      const users = fs.readdirSync('/home');
      for (const username of users) {
        const userHome = path.join('/home', username);
        try {
          if (!fs.statSync(userHome).isDirectory()) continue;
        } catch { continue; }
        if (fs.existsSync(path.join(userHome, '.openclaw')) ||
            fs.existsSync(path.join(userHome, '.claude'))) {
          return userHome;
        }
      }
    } catch {
      // /home not readable
    }
  }

  return home;
}

/**
 * Check whether the OpenClaw binary is installed on this system.
 * Tries multiple detection methods to handle different install scenarios.
 */
function isOpenClawInstalled(): boolean {
  // Method 1: Check if 'openclaw' is in PATH
  try {
    execSync('which openclaw', { encoding: 'utf-8', timeout: 5000 });
    return true;
  } catch {
    // not in PATH
  }

  // Method 2: Check common global npm install locations
  const globalPaths = [
    '/usr/lib/node_modules/openclaw',
    '/usr/local/lib/node_modules/openclaw',
  ];
  // Also check npm global prefix
  try {
    const prefix = execSync('npm config get prefix', {
      encoding: 'utf-8',
      timeout: 5000,
    }).trim();
    if (prefix) {
      globalPaths.push(path.join(prefix, 'lib', 'node_modules', 'openclaw'));
    }
  } catch {
    // npm not available or timed out
  }

  for (const p of globalPaths) {
    if (fs.existsSync(p)) return true;
  }

  return false;
}

/**
 * Find ALL valid hook directories for install/uninstall/status.
 *
 * Only returns user-space directories that survive package updates.
 * Creates the hooks/ subdirectory if the parent config dir exists.
 */
export function findAllHooksDirs(): string[] {
  const home = resolveUserHome();
  const dirs: string[] = [];

  // If openclaw is installed but config dir doesn't exist yet, create it
  const openclawDir = path.join(home, '.openclaw');
  if (!fs.existsSync(openclawDir) && isOpenClawInstalled()) {
    try {
      fs.mkdirSync(openclawDir, { recursive: true });
    } catch {
      // Could not create config dir — will still try other candidates
    }
  }

  const candidates = [
    { config: '.openclaw', hooks: path.join(home, '.openclaw', 'hooks') },
    { config: '.claude', hooks: path.join(home, '.claude', 'hooks') },
  ];

  for (const { config, hooks } of candidates) {
    const configDir = path.join(home, config);
    if (fs.existsSync(configDir)) {
      if (!fs.existsSync(hooks)) {
        try {
          fs.mkdirSync(hooks, { recursive: true });
        } catch {
          continue;
        }
      }
      dirs.push(hooks);
    }
  }

  return dirs;
}

function preferredHookDir(hooksDir: string): string {
  return path.join(hooksDir, HOOK_NAME);
}

function legacyHookDirs(hooksDir: string): string[] {
  return [
    // Legacy: top-level "shieldcortex" directory created by old installers
    path.join(hooksDir, 'shieldcortex'),
    // Legacy: internal/cortex-memory path from v3 and early v4
    path.join(hooksDir, 'internal', HOOK_NAME),
  ];
}

function hasRequiredHookFiles(dir: string): boolean {
  return HOOK_FILES.every(file => fs.existsSync(path.join(dir, file)));
}

/**
 * The standard installed-hook destination: `~/.openclaw/hooks/cortex-memory`.
 * Resolves the real user's home (sudo-aware) so doctor/postinstall agree with
 * the install path.
 */
export function defaultHookDestDir(): string {
  return path.join(resolveUserHome(), '.openclaw', 'hooks', HOOK_NAME);
}

/**
 * Single source of truth for "the installed hook copy is out of date".
 *
 * The cortex-memory hook is installed by FILE COPY (see `copyHookFiles`) into
 * `~/.openclaw/hooks/cortex-memory/`. A package update does NOT automatically
 * re-copy it, so the installed `handler.ts` / `runtime.mjs` can drift behind
 * the package's `HOOK_SOURCE` version. This compares every HOOK_FILE in
 * `destDir` against the packaged source by content.
 *
 * Pure + synchronous (fs reads only, no writes, no side effects). Returns
 * `true` if any required file is missing from `destDir` OR differs byte-for-byte
 * from the packaged source. Returns `false` only when every file is present and
 * identical. On any unexpected read error it returns `true` (fail toward
 * "refresh needed") so a half-readable install is never reported as current.
 *
 * If the package's own `HOOK_SOURCE` is missing (corrupt/partial package), the
 * comparison is impossible, so this returns `false` — we can't claim the
 * install is stale relative to a source we can't read.
 */
export function hookFilesStale(destDir: string = defaultHookDestDir()): boolean {
  // No installed copy at all → definitely needs (re)install.
  if (!fs.existsSync(destDir)) return true;
  // No packaged source to compare against → can't prove staleness.
  if (!fs.existsSync(HOOK_SOURCE)) return false;

  for (const file of HOOK_FILES) {
    const srcPath = path.join(HOOK_SOURCE, file);
    const destPath = path.join(destDir, file);
    try {
      if (!fs.existsSync(srcPath)) {
        // Packaged source is missing this file — can't compare it; skip.
        continue;
      }
      if (!fs.existsSync(destPath)) return true; // installed copy missing a file
      const srcBuf = fs.readFileSync(srcPath);
      const destBuf = fs.readFileSync(destPath);
      if (!srcBuf.equals(destBuf)) return true; // content differs → stale
    } catch {
      // Unreadable file on either side — treat as stale so the user re-copies.
      // DELIBERATE ASYMMETRY with the inline staleness loop in
      // hooks/openclaw/cortex-memory/handler.ts (selfCheckAndHeal), which does
      // NOT flip `stale` on a read error: that runs in the long-lived gateway
      // and must stay quiet on transient errors. This path backs `doctor`, which
      // SHOULD nag on a half-readable install. Keep them divergent.
      return true;
    }
  }

  return false;
}

function copyHookFiles(sourceDir: string, destDir: string): void {
  fs.mkdirSync(destDir, { recursive: true });

  for (const file of HOOK_FILES) {
    const src = path.join(sourceDir, file);
    const dest = path.join(destDir, file);
    fs.copyFileSync(src, dest);

    try {
      fs.accessSync(dest, fs.constants.R_OK);
    } catch {
      console.error(`  Warning: ${dest} was copied but is not readable`);
    }
  }
}

function removeHookDir(dir: string): boolean {
  if (!fs.existsSync(dir)) return false;
  fs.rmSync(dir, { recursive: true, force: true });
  return true;
}

function cleanupLegacyHookParents(hooksDir: string): void {
  const internalDir = path.join(hooksDir, 'internal');
  if (!fs.existsSync(internalDir)) return;

  try {
    if (fs.readdirSync(internalDir).length === 0) {
      fs.rmdirSync(internalDir);
    }
  } catch {
    // Best-effort cleanup only
  }
}

function removeLegacyHookVariants(hooksDir: string): string[] {
  const removed: string[] = [];

  for (const legacyDir of legacyHookDirs(hooksDir)) {
    if (removeHookDir(legacyDir)) {
      removed.push(legacyDir);
    }
  }

  if (removed.length > 0) {
    cleanupLegacyHookParents(hooksDir);
  }

  return removed;
}

function detectLegacyHookVariants(hooksDir: string): string[] {
  return legacyHookDirs(hooksDir).filter(dir => fs.existsSync(dir));
}

// ==================== Cleanup Legacy Plugin ====================

/**
 * Remove genuinely-legacy plugin registration shapes from openclaw.json.
 *
 * The only known legacy shape that caused OpenClaw config validation
 * errors was `plugins.allow` entries containing full file paths to the
 * plugin (pre-v2026.3 format) rather than the bare plugin id. This
 * function strips those.
 *
 * v4.12.11 — used to also unconditionally delete
 * `plugins.entries['shieldcortex-realtime']` here. That key holds the
 * CURRENT-format registration (`{ enabled: true }`) that `trustLocalPlugin`
 * writes; deleting it on every install meant `trustLocalPlugin`'s
 * idempotency check always saw a missing entry and re-wrote the file —
 * defeating the v4.12.11 idempotency fix entirely. Removed.
 */
function cleanupLegacyPlugin(): void {
  const home = resolveUserHome();
  const configPath = path.join(home, '.openclaw', 'openclaw.json');
  if (!fs.existsSync(configPath)) return;

  try {
    const raw = fs.readFileSync(configPath, 'utf-8');
    const config = JSON.parse(raw);
    let changed = false;

    // Remove stale full-path entries from plugins.allow
    // (pre-v2026.3 format used raw file paths instead of plugin IDs)
    if (Array.isArray(config.plugins?.allow)) {
      const before = config.plugins.allow.length;
      config.plugins.allow = config.plugins.allow.filter(
        (e: string) => !e.includes(PLUGIN_DIR_NAME) || e === PLUGIN_DIR_NAME,
      );
      if (config.plugins.allow.length < before) changed = true;
    }

    if (config.plugins && Object.keys(config.plugins).length === 0) delete config.plugins;

    if (changed) {
      fs.writeFileSync(configPath, JSON.stringify(config, null, 2) + '\n', 'utf-8');
      console.log('Cleaned up legacy plugin entries from openclaw.json');
    }
  } catch {
    // Non-critical — don't fail the install
  }
}

function openClawConfigPath(): string {
  return path.join(resolveUserHome(), '.openclaw', 'openclaw.json');
}

/**
 * Pure idempotency check for the openclaw.json plugin registration.
 *
 * Returns true if the config needs to be rewritten — i.e. ANY of the
 * load-bearing fields differ from the desired state. Returns false when
 * the config already matches and a re-install would otherwise produce a
 * no-op write (which churned the gateway's config-watcher every
 * `shieldcortex openclaw install` pre-v4.12.11).
 *
 * Intentionally treats `installedAt` as transient — only differing on
 * that field does NOT force a write, otherwise this function would
 * always trip on its own previous timestamp.
 *
 * Exported for direct unit testing without booting the full installer.
 */
export function pluginInstallNeedsWrite(
  config: unknown,
  pluginId: string,
  _installDir: string,
  _version: string,
): boolean {
  if (!config || typeof config !== 'object') return true;
  const c = config as { plugins?: unknown };
  if (!c.plugins || typeof c.plugins !== 'object') return true;
  const plugins = c.plugins as { allow?: unknown; installs?: unknown; entries?: unknown };

  // `plugins.installs` is no longer user-authored config in OpenClaw 2026.5.x —
  // it migrated to `~/.openclaw/plugins/installs.json`. If a stale entry remains
  // in `openclaw.json`, OpenClaw will try to migrate it on the next config
  // write and (when state-dir permissions block migration) refuse the write
  // entirely. Treat its presence as drift so trustLocalPlugin can clean it up.
  const installs = plugins.installs as Record<string, unknown> | undefined;
  if (installs && pluginId in installs) return true;

  const allow = Array.isArray(plugins.allow) ? (plugins.allow as unknown[]) : [];
  if (!allow.includes(pluginId)) return true;
  const hasStale = allow.some((e) => typeof e === 'string' && e !== pluginId && e.includes(pluginId));
  if (hasStale) return true;

  const entries = (plugins.entries as Record<string, unknown> | undefined) ?? {};
  const entry = entries[pluginId] as { enabled?: unknown } | undefined;
  if (!entry || entry.enabled !== true) return true;

  return false;
}

/**
 * Register a locally-copied plugin in OpenClaw's user config.
 *
 * Writes (or updates) `plugins.allow` and `plugins.entries[pluginId]`. Does
 * NOT write `plugins.installs[pluginId]` — that key is OpenClaw-managed in
 * 2026.5.x+ (kept under `~/.openclaw/plugins/installs.json`). If we authored
 * it and OpenClaw can't migrate (state-dir permission edge case), it
 * refuses the next config write entirely; see
 * `dist/io-E69J4lLI.js:18897` in OpenClaw 2026.5.6 for the migration-block
 * error. Plugin discovery remains correct without `installs`: OpenClaw
 * picks up plugin files from `~/.openclaw/extensions/<id>/` and uses
 * `plugins.allow + plugins.entries[id].enabled` to gate execution.
 *
 * The `installDir` and `version` parameters are accepted for backward
 * compatibility with the old call sites but are no longer persisted.
 *
 * Also actively cleans any legacy `plugins.installs[shieldcortex-realtime]`
 * entry left over from older ShieldCortex versions, so customers upgrading
 * through us never trip OpenClaw's migration-block.
 */
function trustLocalPlugin(_installDir: string, _version: string): boolean {
  const configPath = openClawConfigPath();
  const configDir = path.dirname(configPath);
  const pluginId = PLUGIN_DIR_NAME; // "shieldcortex-realtime"

  try {
    if (!fs.existsSync(configDir)) {
      fs.mkdirSync(configDir, { recursive: true });
    }

    const raw = fs.existsSync(configPath) ? fs.readFileSync(configPath, 'utf-8') : '{}';
    const config = JSON.parse(raw);

    // Idempotency: skip the write if everything is already correct.
    if (!pluginInstallNeedsWrite(config, pluginId, _installDir, _version)) {
      return true;
    }

    const plugins = typeof config.plugins === 'object' && config.plugins !== null ? config.plugins : {};
    const allow = Array.isArray((plugins as { allow?: unknown }).allow)
      ? ((plugins as { allow?: string[] }).allow ?? [])
      : [];

    // Remove any stale full-path entries for this plugin in `allow`.
    const cleaned = allow.filter(
      (e: string) => !e.includes(PLUGIN_DIR_NAME) || e === pluginId,
    );
    if (!cleaned.includes(pluginId)) {
      cleaned.push(pluginId);
    }

    // Cleanup of legacy `plugins.installs[shieldcortex-realtime]` from
    // pre-v4.15 ShieldCortex versions. Other plugins' installs entries are
    // not touched — their migration is OpenClaw's concern.
    const existingInstalls = typeof plugins.installs === 'object' && plugins.installs !== null
      ? (plugins.installs as Record<string, unknown>)
      : null;
    let installsAfter: Record<string, unknown> | undefined;
    if (existingInstalls) {
      const { [pluginId]: _removed, ...rest } = existingInstalls;
      installsAfter = rest;
    }

    // Add entries to enable the plugin (preserving any user-set `config`
    // or other fields OpenClaw may have added).
    const entries = typeof plugins.entries === 'object' && plugins.entries !== null
      ? { ...(plugins.entries as Record<string, unknown>) }
      : {};
    const existingEntry = entries[pluginId];
    entries[pluginId] = (typeof existingEntry === 'object' && existingEntry !== null)
      ? { ...(existingEntry as Record<string, unknown>), enabled: true }
      : { enabled: true };

    const newPlugins: Record<string, unknown> = {
      ...plugins,
      allow: cleaned,
      entries,
    };
    if (installsAfter !== undefined) {
      // Only carry `installs` forward if there were OTHER plugins under it.
      // If our cleanup left the object empty, drop it entirely so OpenClaw
      // doesn't see a vestigial `installs: {}`.
      if (Object.keys(installsAfter).length > 0) {
        newPlugins.installs = installsAfter;
      } else {
        delete newPlugins.installs;
      }
    }

    config.plugins = newPlugins;

    fs.writeFileSync(configPath, JSON.stringify(config, null, 2) + '\n', 'utf-8');
    return true;
  } catch {
    return false;
  }
}

function tryNativeOpenClawPluginInstall(): PluginInstallMode | null {
  if (process.env[OPENCLAW_SKIP_NATIVE_INSTALL_ENV] === '1') return null;
  if (!isOpenClawInstalled()) return null;

  // Remove existing extensions copy so OpenClaw doesn't refuse with "plugin already exists"
  const extDir = findExtensionsDir();
  if (extDir) {
    const existingDir = path.join(extDir, PLUGIN_DIR_NAME);
    if (fs.existsSync(existingDir)) {
      try {
        fs.rmSync(existingDir, { recursive: true, force: true });
      } catch { /* best-effort cleanup */ }
    }
  }

  const env = { ...process.env, HOME: resolveUserHome() };
  const attempts: Array<{ args: string[]; label: string }> = [
    { args: ['plugins', 'install', '@drakon-systems/shieldcortex-realtime@latest'], label: 'package install' },
    { args: ['plugins', 'install', '--link', PLUGIN_PACKAGE_SOURCE], label: 'linked install' },
  ];

  for (const attempt of attempts) {
    const result = spawnSync('openclaw', attempt.args, {
      env,
      encoding: 'utf-8',
      timeout: 30000,
    });

    if (result.status === 0) {
      console.log(`Installed real-time plugin via OpenClaw ${attempt.label}.`);
      return attempt.label === 'package install' ? 'native-package' : 'native-link';
    }
  }

  return null;
}

// ==================== Plugin (Extensions Directory) ====================

/**
 * Find or create the OpenClaw global extensions directory.
 * Returns null if ~/.openclaw/ doesn't exist (OpenClaw not installed).
 */
function findExtensionsDir(): string | null {
  const home = resolveUserHome();
  const openclawDir = path.join(home, '.openclaw');
  if (!fs.existsSync(openclawDir)) return null;

  const extensionsDir = path.join(openclawDir, 'extensions');
  if (!fs.existsSync(extensionsDir)) {
    try {
      fs.mkdirSync(extensionsDir, { recursive: true });
    } catch {
      return null;
    }
  }

  return extensionsDir;
}

/**
 * Copy the real-time plugin to ~/.openclaw/extensions/shieldcortex-realtime/
 * so OpenClaw discovers it via the global extensions directory.
 */
function isPluginInLoadPaths(): boolean {
  const configPath = openClawConfigPath();
  if (!fs.existsSync(configPath)) return false;
  try {
    const config = JSON.parse(fs.readFileSync(configPath, 'utf-8'));
    const paths: unknown[] = config.plugins?.load?.paths ?? [];
    return paths.some(
      (p) => typeof p === 'string' && p.includes(PLUGIN_DIR_NAME),
    );
  } catch {
    return false;
  }
}

/**
 * Install the real-time plugin.
 * In Docker environments, skip with a warning — plugin install can crash
 * the gateway in containers where filesystem permissions differ.
 *
 * @param options.noPlugins  Skip plugin installation entirely (--no-plugins flag)
 */
function installPlugin(options: { noPlugins?: boolean } = {}): PluginInstallMode {
  if (options.noPlugins) {
    console.log('  Skipping plugin install (--no-plugins flag).');
    return 'skipped';
  }

  // Docker / container environments: warn and skip
  if (isDockerEnvironment()) {
    console.warn('  ⚠  Docker/container environment detected.');
    console.warn('  Skipping real-time plugin install to avoid gateway crash.');
    console.warn('  To install manually after confirming OpenClaw support:');
    console.warn('    DOCKER=false shieldcortex openclaw install');
    console.warn('  Or suppress this warning: shieldcortex openclaw install --no-plugins');
    return 'skipped';
  }

  // Previously this branch tried to "skip the extensions copy" when the npm
  // global path was on a list of "OpenClaw-searched" paths
  // (/usr/lib/node_modules, /usr/local/lib/node_modules,
  // /opt/homebrew/lib/node_modules). That premise was false: OpenClaw only
  // discovers plugins from its own stock dir and ~/.openclaw/extensions/, not
  // from arbitrary global node_modules entries. The branch deleted the
  // working extension dir and pointed `trustLocalPlugin` at a path OpenClaw
  // never reads, leaving every Mac homebrew (and Linux global) install with
  // an unregistered plugin and a "plugin not found" doctor warning.
  //
  // Now we always go through `tryNativeOpenClawPluginInstall()` first
  // (`openclaw plugins install <pkg>` registers correctly), then fall back
  // to copying into the extensions dir.

  const nativeInstall = tryNativeOpenClawPluginInstall();
  if (nativeInstall) {
    return nativeInstall;
  }

  // Native install (--link) registers via load.paths — skip the extensions
  // copy to avoid duplicate plugin ID warnings.
  if (isPluginInLoadPaths()) {
    console.log('Plugin already registered via load.paths, skipping extensions copy.');
    return 'native-link';
  }

  if (!fs.existsSync(PLUGIN_SOURCE)) {
    console.warn('  Warning: Plugin source not found, skipping plugin install');
    return 'skipped';
  }

  const extensionsDir = findExtensionsDir();
  if (!extensionsDir) return 'skipped';

  const destDir = path.join(extensionsDir, PLUGIN_DIR_NAME);
  try {
    fs.mkdirSync(destDir, { recursive: true });

    const requiredFiles = ['index.js', 'interceptor.js', 'intercept-ingest.js', 'openclaw.plugin.json'];
    for (const file of requiredFiles) {
      const src = path.join(PLUGIN_SOURCE, file);
      const dest = path.join(destDir, file);
      if (fs.existsSync(src)) {
        fs.copyFileSync(src, dest);
      } else {
        console.warn(`  Warning: ${file} not found in plugin source (${PLUGIN_SOURCE})`);
        if (file === 'openclaw.plugin.json') {
          console.warn('  OpenClaw will fail to load the plugin without this manifest.');
          console.warn('  This is a build issue — try rebuilding with: npm run build');
        }
      }
    }

    // Resolve shieldcortex module path and patch the plugin
    const indexDest = path.join(destDir, 'index.js');
    const packageRoot = path.resolve(__dirname, '..', '..');
    const distIndexUrl = pathToFileURL(path.join(packageRoot, 'dist', 'index.js')).href;
    const distDefenceUrl = pathToFileURL(path.join(packageRoot, 'dist', 'defence', 'index.js')).href;

    try {
      let pluginCode = fs.readFileSync(indexDest, 'utf-8');
      pluginCode = pluginCode.replace(/import\("shieldcortex"\)/g, `import("${distIndexUrl}")`);
      pluginCode = pluginCode.replace(/import\("shieldcortex\/defence"\)/g, `import("${distDefenceUrl}")`);

      try {
        const pkg = JSON.parse(fs.readFileSync(path.join(packageRoot, 'package.json'), 'utf-8'));
        pluginCode = pluginCode.replace(/version:\s*"[^"]*"/, `version: "${pkg.version}"`);
      } catch {
        // Keep existing version if package.json can't be read
      }

      fs.writeFileSync(indexDest, pluginCode, 'utf-8');
    } catch (e) {
      console.warn(`  Warning: Could not patch plugin imports/version: ${(e as Error).message}`);
    }

    // Write package.json with "type": "module" to prevent ESM reparsing warnings
    try {
      const pluginPkg = { name: 'shieldcortex-realtime-local', type: 'module', private: true };
      fs.writeFileSync(path.join(destDir, 'package.json'), JSON.stringify(pluginPkg, null, 2) + '\n', 'utf-8');
    } catch { /* non-critical */ }

    // Verify readability
    try {
      fs.accessSync(indexDest, fs.constants.R_OK);
    } catch {
      console.warn(`  Warning: ${indexDest} copied but not readable`);
    }

    // Sync the manifest version to the main package version so it never drifts
    let pluginVersion = 'unknown';
    try {
      const pkg = JSON.parse(fs.readFileSync(path.join(packageRoot, 'package.json'), 'utf-8'));
      pluginVersion = pkg.version ?? pluginVersion;

      const manifestPath = path.join(destDir, 'openclaw.plugin.json');
      if (fs.existsSync(manifestPath)) {
        const manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf-8'));
        manifest.version = pluginVersion;
        fs.writeFileSync(manifestPath, JSON.stringify(manifest, null, 2) + '\n', 'utf-8');
      }
    } catch { /* keep whatever version the manifest has */ }

    if (trustLocalPlugin(destDir, pluginVersion)) {
      console.log('Registered plugin in OpenClaw config (plugins.allow + installs)');
      console.log(`Installed real-time plugin to ${destDir}`);
      return 'trusted-local-copy';
    } else {
      console.warn('  Warning: Could not register plugin in OpenClaw config');
      console.log(`Installed real-time plugin to ${destDir}`);
      return 'untrusted-local-copy';
    }
  } catch (err) {
    const code = (err as NodeJS.ErrnoException).code;
    if (code === 'EACCES' || code === 'EPERM') {
      console.warn(`  Skipped plugin install (permission denied on ${destDir})`);
    } else {
      console.warn(`  Warning: Could not install plugin: ${(err as Error).message}`);
    }
    return 'skipped';
  }
}

/**
 * Remove the plugin from ~/.openclaw/extensions/shieldcortex-realtime/
 */
function uninstallPlugin(): boolean {
  const extensionsDir = findExtensionsDir();
  if (!extensionsDir) return false;

  const destDir = path.join(extensionsDir, PLUGIN_DIR_NAME);
  if (!fs.existsSync(destDir)) return false;

  try {
    const configPath = openClawConfigPath();
    if (fs.existsSync(configPath)) {
      const raw = fs.readFileSync(configPath, 'utf-8');
      const config = JSON.parse(raw);
      const pluginId = PLUGIN_DIR_NAME;

      // Idempotency: only write the config if there's actually something
      // to remove. Pre-v4.12.11 this rewrote openclaw.json every time
      // even when no SC entries existed (e.g. a re-run of `uninstall
      // --deep` after a previous successful uninstall).
      const allowHasIt = Array.isArray(config.plugins?.allow)
        && config.plugins.allow.some((e: unknown) => typeof e === 'string' && e.includes(pluginId));
      const installsHasIt = !!config.plugins?.installs?.[pluginId];
      const entriesHasIt = !!config.plugins?.entries?.[pluginId];
      const needsWrite = allowHasIt || installsHasIt || entriesHasIt;

      if (needsWrite) {
        if (Array.isArray(config.plugins?.allow)) {
          // Remove both old file-path entries and new short-name entries
          config.plugins.allow = config.plugins.allow.filter(
            (entry: string) => !entry.includes(pluginId),
          );
        }
        if (config.plugins?.installs?.[pluginId]) {
          delete config.plugins.installs[pluginId];
        }
        if (config.plugins?.entries?.[pluginId]) {
          delete config.plugins.entries[pluginId];
        }
        fs.writeFileSync(configPath, JSON.stringify(config, null, 2) + '\n', 'utf-8');
      }
    }
    fs.rmSync(destDir, { recursive: true });
    console.log(`Removed real-time plugin from ${destDir}`);
    return true;
  } catch {
    return false;
  }
}

/**
 * Check whether the plugin is installed in the extensions directory.
 *
 * Uses `openclaw.plugin.json` as the canonical marker — every OpenClaw plugin
 * ships one, whereas the entry file may be `index.ts` (raw TypeScript,
 * transpiled by OpenClaw at runtime — current shape of the published tarball)
 * OR `index.js` (locally-built / older releases). Checking only for `index.js`
 * caused `status` to report "not installed" immediately after a successful
 * `openclaw plugins install`.
 */
function pluginStatus(): { installed: boolean; path?: string; entry?: 'index.ts' | 'index.js' | 'managed' } {
  const extensionsDir = findExtensionsDir();
  if (extensionsDir) {
    const destDir = path.join(extensionsDir, PLUGIN_DIR_NAME);
    const manifestPath = path.join(destDir, 'openclaw.plugin.json');
    if (fs.existsSync(manifestPath)) {
      const jsEntry = path.join(destDir, 'index.js');
      const tsEntry = path.join(destDir, 'index.ts');
      if (fs.existsSync(jsEntry)) return { installed: true, path: destDir, entry: 'index.js' };
      if (fs.existsSync(tsEntry)) return { installed: true, path: destDir, entry: 'index.ts' };
      // Manifest present but no recognised entry — treat as broken install, not hidden.
      // Fall through to the managed-project probe below rather than declaring absent:
      // the same box may carry a healthy managed install even with a broken legacy dir.
    }
  }

  // Managed npm project install (~/.openclaw/npm/projects/drakon-systems-shieldcortex-realtime-<hash>/).
  // OpenClaw 2026.6.x installs the realtime plugin here, NOT under extensions/, so the
  // legacy path-probe above reports "no files on disk" on healthy managed boxes (#77).
  // Reuse the #74 reconciler's resolution (installs.json + npm/projects scan) — the same
  // resolution doctor/repair/selfcheck already trust — before declaring the plugin missing.
  const home = resolveUserHome();
  const installPath = resolveRealtimePluginInstallPath(home);
  if (installPath) {
    const projectDir = resolveRealtimeProjectDir(home) ?? installPath;
    return { installed: true, path: projectDir, entry: 'managed' };
  }

  return { installed: false };
}

/**
 * Check whether the plugin is registered in OpenClaw's config, independently
 * of what's on disk. A discrepancy between disk and config surfaces clearly
 * in `shieldcortex openclaw status`.
 *
 * `inLegacyInstalls` reports the presence of a stale
 * `plugins.installs[shieldcortex-realtime]` entry from pre-v4.15 ShieldCortex
 * versions. It's never load-bearing in OpenClaw 2026.5.x — `trustLocalPlugin`
 * cleans it up on the next install — but surfacing it helps users diagnose
 * config-write failures on the OpenClaw side until they re-run setup.
 */
function pluginConfigStatus(): { inAllow: boolean; inLegacyInstalls: boolean; inEntries: boolean } {
  const configPath = openClawConfigPath();
  if (!fs.existsSync(configPath)) return { inAllow: false, inLegacyInstalls: false, inEntries: false };
  try {
    const config = JSON.parse(fs.readFileSync(configPath, 'utf-8'));
    const plugins = config.plugins ?? {};
    const allow = Array.isArray(plugins.allow) ? plugins.allow : [];
    const inAllow = allow.some((e: unknown) => typeof e === 'string' && (e === PLUGIN_DIR_NAME || e.endsWith(`/${PLUGIN_DIR_NAME}`) || e.endsWith(`/${PLUGIN_DIR_NAME}/index.js`) || e.endsWith(`/${PLUGIN_DIR_NAME}/index.ts`)));
    const inLegacyInstalls = typeof plugins.installs === 'object' && plugins.installs !== null && PLUGIN_DIR_NAME in plugins.installs;
    const inEntries = typeof plugins.entries === 'object' && plugins.entries !== null && PLUGIN_DIR_NAME in plugins.entries;
    return { inAllow, inLegacyInstalls, inEntries };
  } catch {
    return { inAllow: false, inLegacyInstalls: false, inEntries: false };
  }
}

function localPluginTrustStatus(pluginPath: string | undefined): 'trusted' | 'untrusted' | 'unknown' {
  if (!pluginPath) return 'unknown';
  const jsEntry = path.join(pluginPath, 'index.js');
  const tsEntry = path.join(pluginPath, 'index.ts');
  const configPath = openClawConfigPath();
  if (!fs.existsSync(configPath)) return 'unknown';

  try {
    const config = JSON.parse(fs.readFileSync(configPath, 'utf-8'));
    const allow = config.plugins?.allow;
    if (Array.isArray(allow) && (allow.includes(PLUGIN_DIR_NAME) || allow.includes(jsEntry) || allow.includes(tsEntry))) {
      return 'trusted';
    }
    return 'untrusted';
  } catch {
    return 'unknown';
  }
}

// ==================== Commands ====================

/**
 * Install options for `shieldcortex openclaw install`.
 */
export interface OpenClawInstallOptions {
  /** Skip hook installation (--no-hooks flag) */
  noHooks?: boolean;
  /** Skip plugin installation (--no-plugins flag) */
  noPlugins?: boolean;
  /**
   * Best-effort restart of the OpenClaw gateway after install so the freshly
   * copied hook + plugin files are picked up without manual intervention.
   * Defaults to true. Set to false (or pass `--no-gateway-restart` from the
   * CLI) to skip the restart.
   *
   * Symmetric with `uninstall --deep`'s gateway-restart, which has been live
   * since v4.12.0. Without this on the install side, an upgrade of the npm
   * package leaves the running gateway with the old plugin in memory until
   * something else triggers a restart — observed on Edith 2026-04-25 where
   * the npm package was on 4.12.5 but the plugin loaded was still 4.12.2,
   * silently producing zero memories.
   */
  restartGateway?: boolean;
}

export async function installOpenClawHook(options: OpenClawInstallOptions = {}): Promise<void> {
  const hooksDirs = findAllHooksDirs();

  if (hooksDirs.length === 0) {
    const home = resolveUserHome();
    console.error('Could not find OpenClaw or Claude Code config directory.');
    console.error('');
    console.error('Debug info:');
    console.error(`  Home directory: ${home}`);
    console.error(`  ~/.openclaw/ exists: ${fs.existsSync(path.join(home, '.openclaw'))}`);
    console.error(`  ~/.claude/ exists: ${fs.existsSync(path.join(home, '.claude'))}`);
    console.error(`  OpenClaw binary found: ${isOpenClawInstalled()}`);
    console.error('');
    console.error('If OpenClaw is installed, try running directly:');
    console.error('  openclaw skills install shieldcortex');
    console.error('  openclaw plugins install @drakon-systems/shieldcortex-realtime');
    console.error('');
    console.error('Or install OpenClaw first:');
    console.error('  npm install -g openclaw');
    process.exit(1);
  }

  if (!fs.existsSync(HOOK_SOURCE)) {
    console.error('Hook source files not found. Package may be corrupted.');
    process.exit(1);
  }

  // Clean up legacy plugin entry that caused config validation errors
  cleanupLegacyPlugin();

  // Docker / container: warn about environment
  if (isDockerEnvironment()) {
    console.warn('⚠  Docker/container environment detected.');
    console.warn('   Hook and plugin installation may behave differently in containers.');
    console.warn('   Use --no-plugins to skip plugin install, or --no-hooks to skip hooks.');
    console.warn('');
  }

  let installed = 0;
  let migratedLegacy = 0;

  if (!options.noHooks) {
    // Install to ALL detected hook directories
    for (const hooksDir of hooksDirs) {
      const destDir = preferredHookDir(hooksDir);
      try {
        // Clean up legacy paths BEFORE installing to avoid duplicate hooks
        const legacyDirsBeforeInstall = detectLegacyHookVariants(hooksDir);
        if (legacyDirsBeforeInstall.length > 0) {
          console.log(`Detected legacy OpenClaw hook layout in ${hooksDir} — migrating to ${destDir}`);
        }
        for (const removedDir of removeLegacyHookVariants(hooksDir)) {
          console.log(`Removed legacy cortex-memory hook from ${removedDir}`);
          migratedLegacy++;
        }

        copyHookFiles(HOOK_SOURCE, destDir);

        console.log(`Installed cortex-memory hook to ${destDir}`);
        installed++;
      } catch (err) {
        const code = (err as NodeJS.ErrnoException).code;
        const framework = destDir.includes(`${path.sep}.claude${path.sep}`)
          ? 'Claude Code'
          : destDir.includes(`${path.sep}.openclaw${path.sep}`)
            ? 'OpenClaw'
            : null;
        if (code === 'EACCES' || code === 'EPERM') {
          if (framework === 'Claude Code') {
            console.warn(`  Skipped ${framework} hook install at ${destDir} (permission denied).`);
            console.warn('    This only affects Claude Code memory-sync. OpenClaw integration is unaffected.');
            console.warn(`    To fix: sudo chown -R "$USER":"$USER" ~/.claude`);
          } else if (framework === 'OpenClaw') {
            console.warn(`  Skipped ${framework} hook install at ${destDir} (permission denied).`);
            console.warn('    OpenClaw memory capture will not run until this is fixed.');
            console.warn(`    To fix: sudo chown -R "$USER":"$USER" ~/.openclaw`);
          } else {
            console.warn(`  Skipped ${destDir} (permission denied)`);
          }
        } else {
          // Never throw — warn gracefully
          console.warn(`  Warning: Could not install hook to ${destDir}: ${(err as Error).message}`);
        }
      }
    }

    if (installed === 0) {
      console.warn('Could not install hooks to any directory (permission denied or error).');
      console.log('Try one of these:');
      console.log('  sudo "$(command -v shieldcortex)" openclaw install');
      console.log('  sudo chown -R "$USER":"$USER" ~/.openclaw ~/.claude');
      console.log('  shieldcortex openclaw install --no-hooks  # skip hook install');
      // Do not exit(1) — allow plugin install to continue
    }
  } else {
    console.log('Skipping hook installation (--no-hooks flag).');
    installed = hooksDirs.length; // pretend success so plugin install proceeds
  }

  // Install the real-time plugin to the extensions directory
  const pluginInstallMode = installPlugin({ noPlugins: options.noPlugins });

  console.log('');
  if (migratedLegacy > 0) {
    console.log(`Legacy OpenClaw hook cleanup completed (${migratedLegacy} old path${migratedLegacy === 1 ? '' : 's'} removed).`);
    console.log('');
  }
  console.log('What was installed:');
  if (!options.noHooks) {
    if (installed > 0) {
      console.log('  • cortex-memory hook (memory injection + "remember this:" trigger)');
      console.log('    Auto-save is optional: shieldcortex config --openclaw-auto-memory true');
    } else {
      console.log('  • cortex-memory hook: skipped (see warnings above)');
    }
  } else {
    console.log('  • cortex-memory hook: skipped (--no-hooks)');
  }
  if (pluginInstallMode !== 'skipped') {
    console.log('  • shieldcortex-realtime plugin (real-time LLM input scanning + optional output extraction)');
    if (pluginInstallMode === 'native-package') {
      console.log('    Installed through native OpenClaw package records.');
    } else if (pluginInstallMode === 'native-link') {
      console.log('    Installed through native OpenClaw linked plugin records.');
    } else if (pluginInstallMode === 'trusted-local-copy') {
      console.log('    Installed as a local fallback and trusted via plugins.allow.');
    } else if (pluginInstallMode === 'untrusted-local-copy') {
      console.log('    Installed as a local fallback, but trust pinning failed.');
    }
  } else {
    console.log('  • shieldcortex-realtime plugin: skipped');
  }
  console.log('');
  console.log('Native OpenClaw install is also supported:');
  console.log('  openclaw skills install shieldcortex');
  console.log('  openclaw plugins install @drakon-systems/shieldcortex-realtime');

  // Best-effort gateway restart so the new plugin/hook are picked up
  // immediately. Skipped only when the caller explicitly opts out, both
  // capability paths skipped (--no-hooks AND --no-plugins), or no work
  // landed (installed === 0 AND plugin skipped).
  const didInstallSomething = installed > 0 || pluginInstallMode !== 'skipped';
  const restartRequested = options.restartGateway !== false;
  if (restartRequested && didInstallSomething) {
    const { restartOpenClawGateway } = await import('./deep-clean.js');
    const result = await restartOpenClawGateway();
    console.log('');
    if (result.restarted) {
      console.log(`OpenClaw gateway restarted via ${result.method}.`);
    } else if (result.attempted) {
      console.warn(`OpenClaw gateway restart via ${result.method} failed: ${result.detail ?? 'unknown'}`);
      console.warn('Restart it manually so the new plugin/hook take effect:');
      console.warn(process.platform === 'linux'
        ? '  systemctl --user restart openclaw-gateway'
        : '  launchctl kickstart -k gui/$UID/ai.openclaw.gateway');
    } else {
      console.log('Restart your agent / OpenClaw gateway to activate.');
    }
  } else {
    console.log('');
    console.log('Restart your agent to activate.');
  }

  // Honest-state self-check (#74): after installing + reloading, verify the
  // plugin ACTUALLY loaded (present in OpenClaw's roster) and — with operator
  // consent — that it enforces. A security plugin must never report success
  // while silently dropped. We never print an "active/protected" all-clear
  // unless both proofs pass; a missing roster entry is a hard error.
  if (restartRequested && didInstallSomething && pluginInstallMode !== 'skipped') {
    try {
      const { runPluginSelfCheck } = await import('./openclaw-selfcheck.js');
      const home = resolveUserHome();
      const check = await runPluginSelfCheck(home, { expectedVersion: readSelfVersion() ?? undefined });
      console.log('');
      if (check.ok) {
        console.log('✓ Honest-state self-check: plugin confirmed loaded (roster), enforcing (live canary), version ≥ expected.');
      } else if (!check.rosterProof) {
        console.warn('✗ Honest-state self-check FAILED: the plugin is NOT in OpenClaw\'s loaded roster after restart.');
        console.warn('  Protection would report ON while actually OFF (issue #74). Reconcile the install:');
        console.warn('    SHIELDCORTEX_ALLOW_GATEWAY_RECONCILE=1 shieldcortex repair');
        process.exitCode = 1;
      } else if (!check.versionProof) {
        console.warn('✗ Honest-state self-check FAILED: the loaded plugin version is OLDER than expected (silent downgrade, #74).');
        console.warn('  Reinstall pinned to the expected version:');
        console.warn('    SHIELDCORTEX_ALLOW_GATEWAY_RECONCILE=1 SHIELDCORTEX_ALLOW_GATEWAY_RESTART=1 shieldcortex repair');
        process.exitCode = 1;
      } else {
        // Loaded + version OK, but enforcement not actively proven (the live
        // canary needs explicit consent to drive a real gateway tool call).
        console.log('• Plugin is loaded in the roster. Enforcement NOT actively proven — confirm the live canary with:');
        console.log('    SHIELDCORTEX_ALLOW_GATEWAY_CANARY=1 shieldcortex repair');
      }
    } catch {
      // Self-check is best-effort on layouts we can't read; never break install.
    }
  }
}

export async function uninstallOpenClawHook(): Promise<void> {
  const hooksDirs = findAllHooksDirs();

  if (hooksDirs.length === 0) {
    console.log('Neither Claude Code nor OpenClaw is installed on this system.');
    return;
  }

  let removed = 0;

  for (const hooksDir of hooksDirs) {
    const destDir = preferredHookDir(hooksDir);
    if (removeHookDir(destDir)) {
      console.log(`Removed cortex-memory hook from ${destDir}`);
      removed++;
    }

    for (const removedDir of removeLegacyHookVariants(hooksDir)) {
      console.log(`Removed legacy cortex-memory hook from ${removedDir}`);
      removed++;
    }
  }

  // Remove the real-time plugin
  uninstallPlugin();

  // Clean up legacy plugin entry if present
  cleanupLegacyPlugin();

  if (removed === 0) {
    console.log('cortex-memory hook is not installed.');
  }
}

export async function openClawHookStatus(): Promise<void> {
  const hooksDirs = findAllHooksDirs();

  if (hooksDirs.length === 0) {
    console.log('Claude Code / OpenClaw: not detected');
    return;
  }

  console.log('Claude Code / OpenClaw: detected');
  console.log('');

  for (const hooksDir of hooksDirs) {
    const destDir = preferredHookDir(hooksDir);
    const installed = hasRequiredHookFiles(destDir);
    const legacyDirs = legacyHookDirs(hooksDir).filter(dir => fs.existsSync(dir));

    console.log(`  ${hooksDir}`);
    console.log(`    cortex-memory: ${installed ? 'installed' : 'not installed'}`);
    if (legacyDirs.length > 0) {
      if (installed) {
        console.log(`    legacy duplicates: ${legacyDirs.map(dir => path.relative(hooksDir, dir)).join(', ')} — rerun \`shieldcortex openclaw install\` to clean up`);
      } else {
        console.log(`    legacy install: ${legacyDirs.map(dir => path.relative(hooksDir, dir)).join(', ')} — rerun \`shieldcortex openclaw install\` to migrate`);
      }
    }
  }

  console.log('');
  const plugin = pluginStatus();
  const configState = pluginConfigStatus();
  const anyConfig = configState.inAllow || configState.inLegacyInstalls || configState.inEntries;

  if (!plugin.installed && !anyConfig) {
    console.log('  Real-time plugin: not installed');
    return;
  }

  if (!plugin.installed && anyConfig) {
    // Config says yes, disk says no — the drift case that caused #20.
    const refs = [
      configState.inAllow ? 'plugins.allow' : null,
      configState.inLegacyInstalls ? 'plugins.installs (legacy — will be cleaned on next install)' : null,
      configState.inEntries ? 'plugins.entries' : null,
    ].filter(Boolean).join(' + ');
    console.log(`  Real-time plugin: config references (${refs}) but no files on disk — run \`openclaw plugins install @drakon-systems/shieldcortex-realtime\` to reinstall`);
    return;
  }

  const trust = localPluginTrustStatus(plugin.path);
  const trustSuffix =
    trust === 'trusted'
      ? 'trusted via plugins.allow'
      : trust === 'untrusted'
        ? 'local install not yet trusted'
        : 'native or unknown trust source';
  const entrySuffix = plugin.entry ? ` [${plugin.entry}]` : '';
  console.log(`  Real-time plugin: installed (${plugin.path})${entrySuffix} — ${trustSuffix}`);

  // Surface any config/disk drift even when installed. A legacy `installs`
  // entry alone is not sufficient for OpenClaw to load the plugin — it needs
  // `allow` + `entries[id].enabled` — so don't count `inLegacyInstalls` here.
  if (!configState.inEntries && !configState.inAllow) {
    console.log('    warning: on disk but missing from openclaw.json — OpenClaw may not load it');
  }
  if (configState.inLegacyInstalls) {
    console.log('    note: legacy `plugins.installs` entry detected — will be cleaned on next `shieldcortex openclaw install`');
  }
}

/**
 * `shieldcortex openclaw repair` (v4.25.5).
 *
 * Diagnoses and fixes the duplicate-plugin-id mess that `shieldcortex doctor`'s
 * "OpenClaw dup installs" check surfaces. Two distinct cases:
 *
 *   1. **Sticky hooks/ duplicate** — when a copy sits at `~/.openclaw/hooks/
 *      shieldcortex-realtime/`, plain `rm -rf` reverts on the next
 *      `openclaw plugins update` because OpenClaw's hook-pack install
 *      tracking re-creates it. The only reliable purge is a full
 *      `openclaw plugins uninstall` + `plugins install @latest` round-trip,
 *      which clears every tracking record at once. Customer-side config
 *      under `~/.openclaw/openclaw.json` → `plugins.entries.shieldcortex-
 *      realtime` (interceptor severity actions, cloudApiKey, autoMemory
 *      thresholds, the enabled flag, allowlist membership) is wiped by
 *      `plugins uninstall`, so this function snapshots it first and
 *      restores it after reinstall.
 *
 *   2. **Extensions/ leftovers** — legacy install locations and
 *      `.trash-*` / `*.disabled-*` directories. No sticky state — a simple
 *      `rm -rf` suffices.
 *
 * Memory data at `~/.shieldcortex/` is never touched.
 *
 * If something fails between uninstall and restore, the snapshot is also
 * written to `~/.openclaw/openclaw.json.repair-backup-<ts>` so the user
 * can recover manually.
 */
/** This package's own version (the shieldcortex lib the realtime plugin should
 * run against), read from the package root. */
function readSelfVersion(): string | null {
  try {
    const root = path.resolve(__dirname, '..', '..');
    const pkg = JSON.parse(fs.readFileSync(path.join(root, 'package.json'), 'utf-8')) as { version?: unknown };
    return typeof pkg.version === 'string' ? pkg.version : null;
  } catch {
    return null;
  }
}

export type ManagedPinRepairStatus = 'not-installed' | 'clean' | 'healed' | 'failed';
export interface ManagedPinRepairResult {
  status: ManagedPinRepairStatus;
  message: string;
}

/**
 * Heal the OpenClaw `EOVERRIDE` trap that silently disables the realtime plugin
 * on `openclaw update` (upstream openclaw/openclaw#91772).
 *
 * OpenClaw pins shared deps in the plugin's generated project manifest's
 * `dependencies` (managed peers) but never advances them, while it re-imports
 * its bundled workspace `overrides` each release. When the two drift to
 * different versions for the same package, npm's `assertRootOverrides` throws
 * and OpenClaw disables the plugin. The heal: strip the drifted dependency pins
 * (OpenClaw's reinstall re-derives them at the override version, so they match),
 * advance the stale `shieldcortex` lib pin to the running version, re-enable the
 * plugin if it was auto-disabled, and reinstall so the manifest recomputes
 * consistently. Validated by hand on a real box; mirrors that exact sequence.
 *
 * Returns a structured result; prints progress so `shieldcortex openclaw repair`
 * reads coherently.
 */
export async function repairOpenClawManagedPins(homeArg?: string): Promise<ManagedPinRepairResult> {
  const home = homeArg ?? resolveUserHome();
  const pluginId = 'shieldcortex-realtime';
  const pluginSpec = '@drakon-systems/shieldcortex-realtime@latest';

  const projectDir = resolveRealtimeProjectDir(home);
  const manifest = readRealtimeProjectManifest(home);
  if (!projectDir || !manifest) {
    return { status: 'not-installed', message: 'Realtime plugin not installed; no managed pins to reconcile.' };
  }

  const risks = findEoverrideRiskPins(manifest);
  // Strip-set: every managed peer co-present in overrides (latent EOVERRIDE),
  // not just the currently-mismatched ones. OpenClaw refreshes the override
  // from its bundled workspace mid-install while preserving the stale dep pin,
  // so a manifest that looks clean at rest still throws EOVERRIDE on reinstall
  // (edith, 2026-06-14). Stripping the co-present dep pin lets the reinstall
  // re-derive it at the current override version.
  const latentPins = findLatentEoverridePins(manifest);
  const disabled = isRealtimePluginDisabledInConfig(home);
  const selfVersion = readSelfVersion();
  const deps = (typeof manifest.dependencies === 'object' && manifest.dependencies
    ? manifest.dependencies
    : {}) as Record<string, unknown>;
  const staleShieldcortex =
    typeof deps.shieldcortex === 'string' && !!selfVersion && deps.shieldcortex !== selfVersion;

  if (risks.length === 0 && !disabled && !staleShieldcortex) {
    return { status: 'clean', message: 'Realtime plugin pins are consistent and the plugin is enabled. Nothing to reconcile.' };
  }

  console.log('Reconciling OpenClaw managed plugin pins (EOVERRIDE guard):');
  if (risks.length) console.log(`  - version-drifted now: ${risks.map((r) => `${r.name} (${r.dependencyVersion}→${r.overrideVersion})`).join(', ')}`);
  if (latentPins.length) console.log(`  - stripping override-shadowed peer pin(s): ${latentPins.join(', ')} (re-derived at the current override on reinstall)`);
  if (staleShieldcortex) console.log(`  - stale shieldcortex lib pin: ${String(deps.shieldcortex)} → ${selfVersion}`);
  if (disabled) console.log('  - plugin is disabled in config (auto-disabled after a failed update)');

  // 1. Backup the project manifest before touching it.
  const manifestPath = path.join(projectDir, 'package.json');
  const ts = new Date().toISOString().replace(/[:.]/g, '-');
  try {
    fs.writeFileSync(`${manifestPath}.repair-backup-${ts}`, JSON.stringify(manifest, null, 2));
    console.log(`  - safety backup: ${`${manifestPath}.repair-backup-${ts}`.replace(home, '~')}`);
  } catch { /* best-effort */ }

  // 2. Strip co-present (latent) pins from deps AND managedPeerDependencies so
  //    the reinstall re-derives them at the CURRENT override version, then
  //    advance the stale shieldcortex lib pin. `deps` is the same object the
  //    strip mutates in place; shieldcortex is never override-shadowed so it
  //    survives the strip.
  stripManagedPinsFromManifest(manifest as Record<string, unknown>, latentPins);
  if (staleShieldcortex && selfVersion) deps.shieldcortex = selfVersion;
  (manifest as Record<string, unknown>).dependencies = deps;
  try {
    fs.writeFileSync(manifestPath, JSON.stringify(manifest, null, 2) + '\n');
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    return { status: 'failed', message: `Could not write the project manifest (${msg}). Backup left at ${manifestPath}.repair-backup-${ts}.` };
  }

  // 3. Resolve the openclaw binary.
  let openclawBin: string;
  try {
    openclawBin = execSync('which openclaw', { encoding: 'utf-8', timeout: 5000 }).trim();
    if (!openclawBin || !fs.existsSync(openclawBin)) throw new Error('not on PATH');
  } catch {
    return { status: 'failed', message: 'Manifest reconciled, but `openclaw` is not on PATH to reinstall. Run `openclaw plugins install --force ' + pluginSpec + '` then `openclaw gateway restart`.' };
  }
  const spawnEnv = { ...process.env, HOME: home };

  // 4. Re-enable if it was auto-disabled.
  if (disabled) {
    spawnSync(openclawBin, ['plugins', 'enable', pluginId], { encoding: 'utf-8', env: spawnEnv, timeout: 30000 });
  }

  // 5. Reinstall so OpenClaw recomputes a consistent manifest (re-derives the
  //    stripped pins at the override version — no more drift).
  console.log(`  - reinstalling: openclaw plugins install --force ${pluginSpec}`);
  const reinstall = spawnSync(openclawBin, ['plugins', 'install', '--force', pluginSpec], { encoding: 'utf-8', env: spawnEnv, timeout: 180000 });
  if (reinstall.status !== 0) {
    const out = `${reinstall.stderr ?? ''}${reinstall.stdout ?? ''}`.trim().split('\n').slice(-4).join('\n');
    return { status: 'failed', message: `Reinstall failed after reconciling the manifest:\n${out}\nManifest backup: ${manifestPath}.repair-backup-${ts}` };
  }

  // 6. Verify no residual drift.
  const after = readRealtimeProjectManifest(home);
  const residual = after ? findEoverrideRiskPins(after) : [];
  if (residual.length > 0) {
    return { status: 'failed', message: `Reinstall succeeded but pins still drift: ${residual.map((r) => r.name).join(', ')}. Backup: ${manifestPath}.repair-backup-${ts}` };
  }

  const parts = [`Reconciled ${latentPins.length} override-shadowed pin(s)`];
  if (staleShieldcortex) parts.push(`advanced shieldcortex to ${selfVersion}`);
  if (disabled) parts.push('re-enabled the plugin');
  return { status: 'healed', message: `${parts.join(', ')}. Restart to load it: openclaw gateway restart` };
}

export async function repairOpenClawPlugin(): Promise<void> {
  const home = resolveUserHome();
  const openclawDir = path.join(home, '.openclaw');
  const configPath = path.join(openclawDir, 'openclaw.json');
  const pluginId = 'shieldcortex-realtime';

  if (!fs.existsSync(openclawDir)) {
    console.log('OpenClaw not detected (~/.openclaw missing). Nothing to repair.');
    return;
  }

  // #74 first concern: reconcile conflicted install metadata (installs.json ↔
  // SQLite index ↔ config) and the silent-drop / version-regression states the
  // managed-pin + duplicate-dir logic below does not cover. Diagnosis is always
  // safe; execution requires SHIELDCORTEX_ALLOW_GATEWAY_RECONCILE=1 (it reloads
  // the gateway). Honest-state self-check runs after any remediation.
  try {
    const selfVersion = readSelfVersion();
    if (selfVersion) {
      const { reconcileOpenClawPluginState, formatReconcileReport } = await import('./openclaw-reconcile.js');
      const result = await reconcileOpenClawPluginState({ home, expectedVersion: selfVersion });
      if (result.verdict.state !== 'healthy' || result.applied) {
        for (const line of formatReconcileReport(result)) console.log(`  ${line}`);
        console.log('');
        if (result.applied && !result.ok) process.exitCode = 1;
      }
    }
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    console.log(`  ✗ metadata reconcile errored — ${msg}`);
    console.log('');
  }

  // Next concern: reconcile managed-pin drift / re-enable a plugin that
  // OpenClaw auto-disabled after an EOVERRIDE on update (openclaw#91772).
  try {
    const pinResult = await repairOpenClawManagedPins(home);
    if (pinResult.status === 'healed') {
      console.log(`  ✓ ${pinResult.message}`);
      console.log('');
    } else if (pinResult.status === 'failed') {
      console.log(`  ✗ ${pinResult.message}`);
      console.log('');
    }
    // 'clean' / 'not-installed' → stay quiet and fall through to the dup check.
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    console.log(`  ✗ managed-pin reconcile errored — ${msg}`);
    console.log('');
  }

  // Find duplicate install locations (same scan as the doctor check).
  const dupCandidates: string[] = [];
  for (const subdir of ['extensions', 'hooks']) {
    const dir = path.join(openclawDir, subdir);
    if (!fs.existsSync(dir)) continue;
    let entries: fs.Dirent[];
    try {
      entries = fs.readdirSync(dir, { withFileTypes: true });
    } catch {
      continue;
    }
    for (const entry of entries) {
      if (!entry.isDirectory()) continue;
      if (!entry.name.includes(pluginId)) continue;
      const manifest = path.join(dir, entry.name, 'openclaw.plugin.json');
      if (fs.existsSync(manifest)) {
        dupCandidates.push(path.join(dir, entry.name));
      }
    }
  }

  if (dupCandidates.length === 0) {
    console.log('No duplicate shieldcortex-realtime installs detected. Nothing to repair.');
    return;
  }

  const hooksDirPrefix = path.join(openclawDir, 'hooks') + path.sep;
  const hasHooksDup = dupCandidates.some((p) => p.startsWith(hooksDirPrefix));
  const displayPaths = dupCandidates.map((p) => p.replace(home, '~'));

  console.log(`Found ${dupCandidates.length} duplicate install(s):`);
  for (const p of displayPaths) console.log(`  - ${p}`);
  console.log('');

  if (!hasHooksDup) {
    // Simple case: extensions/ leftovers only. No sticky state — just rm.
    console.log('All duplicates are in ~/.openclaw/extensions/ (no sticky state). Removing:');
    for (const p of dupCandidates) {
      try {
        fs.rmSync(p, { recursive: true, force: true });
        console.log(`  ✓ removed ${p.replace(home, '~')}`);
      } catch (err) {
        const msg = err instanceof Error ? err.message : String(err);
        console.log(`  ✗ failed to remove ${p.replace(home, '~')} — ${msg}`);
      }
    }
    console.log('');
    console.log('Repair complete. Restart the OpenClaw gateway to apply.');
    return;
  }

  // Sticky case: ~/.openclaw/hooks/<id>/ duplicate present. Need the full
  // uninstall+reinstall round-trip with config preservation.

  // Step 1: Snapshot the customer's plugin config from openclaw.json.
  let configSnapshot: {
    entry: unknown;
    allowed: boolean;
    raw: Record<string, unknown> | null;
  } = { entry: null, allowed: false, raw: null };

  if (fs.existsSync(configPath)) {
    try {
      const raw = JSON.parse(fs.readFileSync(configPath, 'utf-8')) as Record<string, unknown>;
      const plugins = (raw.plugins ?? {}) as { entries?: Record<string, unknown>; allow?: unknown[] };
      const entry = plugins.entries?.[pluginId] ?? null;
      const allowed = Array.isArray(plugins.allow) && plugins.allow.includes(pluginId);
      configSnapshot = { entry, allowed, raw };
      console.log('Snapshotted customer plugin config:');
      console.log(`  - plugins.entries.${pluginId}: ${entry ? 'present' : '(none — defaults will apply)'}`);
      console.log(`  - plugins.allow membership: ${allowed ? 'yes' : 'no'}`);

      // Also write a backup file so the user can manually restore if the
      // restore step at the end fails for any reason.
      const ts = new Date().toISOString().replace(/[:.]/g, '-');
      const backupPath = `${configPath}.repair-backup-${ts}`;
      try {
        fs.writeFileSync(backupPath, JSON.stringify(raw, null, 2), 'utf-8');
        console.log(`  - safety backup: ${backupPath.replace(home, '~')}`);
      } catch { /* best-effort */ }
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      console.log(`Warning: could not read ${configPath.replace(home, '~')} — ${msg}`);
      console.log('Continuing without snapshot. Customer config may be reset to defaults.');
    }
  } else {
    console.log('No ~/.openclaw/openclaw.json present. Nothing to snapshot.');
  }
  console.log('');

  // Step 2: Resolve openclaw binary.
  let openclawBin: string;
  try {
    openclawBin = execSync('which openclaw', { encoding: 'utf-8', timeout: 5000 }).trim();
    if (!openclawBin || !fs.existsSync(openclawBin)) {
      throw new Error('not on PATH');
    }
  } catch {
    console.error('Cannot run repair: `openclaw` binary not found on PATH.');
    console.error('Install OpenClaw first, or run `shieldcortex openclaw install` to set up the integration.');
    process.exit(1);
  }

  const spawnEnv = { ...process.env, HOME: home };

  // Step 3: Uninstall the plugin. The uninstall command requires interactive
  // confirmation by default; pipe `y\n` via stdin to auto-confirm.
  console.log('Step 1/3: openclaw plugins uninstall shieldcortex-realtime');
  const uninstallResult = spawnSync(openclawBin, ['plugins', 'uninstall', pluginId], {
    encoding: 'utf-8',
    env: spawnEnv,
    input: 'y\n',
    timeout: 60000,
  });
  if (uninstallResult.status !== 0) {
    console.error('  ✗ uninstall failed:');
    if (uninstallResult.stderr) console.error(uninstallResult.stderr);
    if (uninstallResult.stdout) console.error(uninstallResult.stdout);
    console.error('');
    console.error('Aborting — no destructive change has been made.');
    process.exit(1);
  }
  console.log('  ✓ uninstall succeeded');
  console.log('');

  // Step 4: rm -rf any duplicate locations the uninstall didn't touch.
  // Field discovery (mac, 2026-05-27): `openclaw plugins uninstall` removes
  // only the ~/.openclaw/npm/node_modules/<scope>/<id>/ directory + the
  // openclaw.json `plugins.entries.<id>` entry — it does NOT remove
  // ~/.openclaw/hooks/<id>/ or ~/.openclaw/extensions/<id>/. If those
  // lingering copies are left in place, the next install short-circuits
  // and leaves them intact, so the duplicate persists.
  console.log('Step 2/3: clear lingering duplicate install paths + hook-pack tracking');
  let cleared = 0;
  for (const p of dupCandidates) {
    try {
      fs.rmSync(p, { recursive: true, force: true });
      console.log(`  ✓ removed ${p.replace(home, '~')}`);
      cleared++;
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      console.log(`  ✗ failed to remove ${p.replace(home, '~')} — ${msg}`);
    }
  }
  if (cleared === 0) {
    console.log('  (no duplicate paths required cleanup)');
  }

  // ALSO purge `hooks.internal.installs.<id>` from openclaw.json — this
  // is the legacy-version pin (typically @4.18.3) that drives the
  // hook-pack reinstall on every `openclaw plugins update`. `plugins
  // uninstall` does NOT touch this entry on macOS (confirmed via state
  // inspection 2026-05-27). With the entry removed AND the disk dirs
  // gone, the next install runs against a true clean slate.
  if (fs.existsSync(configPath)) {
    try {
      const current = JSON.parse(fs.readFileSync(configPath, 'utf-8')) as Record<string, unknown>;
      const hooks = (current.hooks ?? {}) as { internal?: { installs?: Record<string, unknown> } };
      const installs = hooks.internal?.installs;
      if (installs && Object.prototype.hasOwnProperty.call(installs, pluginId)) {
        delete installs[pluginId];
        const tmp = `${configPath}.tmp`;
        fs.writeFileSync(tmp, JSON.stringify(current, null, 2), 'utf-8');
        fs.renameSync(tmp, configPath);
        console.log(`  ✓ cleared hooks.internal.installs.${pluginId} (legacy 4.18.3 hook-pack pin)`);
      } else {
        console.log(`  (no hooks.internal.installs.${pluginId} entry to clear)`);
      }
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      console.log(`  ✗ could not edit openclaw.json — ${msg} (proceeding anyway)`);
    }
  }
  console.log('');

  // Step 5: Reinstall from npm.
  console.log('Step 3/3: openclaw plugins install @drakon-systems/shieldcortex-realtime@latest');
  const installResult = spawnSync(
    openclawBin,
    ['plugins', 'install', '@drakon-systems/shieldcortex-realtime@latest'],
    { encoding: 'utf-8', env: spawnEnv, timeout: 120000 },
  );
  if (installResult.status !== 0) {
    console.error('  ✗ install failed:');
    if (installResult.stderr) console.error(installResult.stderr);
    if (installResult.stdout) console.error(installResult.stdout);
    console.error('');
    console.error('CRITICAL: uninstall succeeded but reinstall failed. The plugin is currently uninstalled.');
    if (configSnapshot.raw) {
      console.error('Your previous OpenClaw config has been backed up — see the safety backup line above.');
    }
    console.error('Try again with: openclaw plugins install @drakon-systems/shieldcortex-realtime@latest');
    process.exit(1);
  }
  console.log('  ✓ install succeeded');
  console.log('');

  // Step 5: Restore the customer's plugin config snapshot.
  if (configSnapshot.entry || configSnapshot.allowed) {
    try {
      const current = JSON.parse(fs.readFileSync(configPath, 'utf-8')) as Record<string, unknown>;
      const plugins = (current.plugins ?? {}) as {
        entries?: Record<string, unknown>;
        allow?: string[];
      };
      plugins.entries = plugins.entries ?? {};
      plugins.allow = Array.isArray(plugins.allow) ? plugins.allow : [];

      // Restore the customer's entries.<id> subtree (preserves config,
      // enabled flag, anything else they had set).
      if (configSnapshot.entry !== null) {
        plugins.entries[pluginId] = configSnapshot.entry;
      }
      // Restore allowlist membership.
      if (configSnapshot.allowed && !plugins.allow.includes(pluginId)) {
        plugins.allow.push(pluginId);
      }
      current.plugins = plugins;

      // Atomic write.
      const tmp = `${configPath}.tmp`;
      fs.writeFileSync(tmp, JSON.stringify(current, null, 2), 'utf-8');
      fs.renameSync(tmp, configPath);
      console.log('Restored customer plugin config:');
      if (configSnapshot.entry) console.log(`  ✓ plugins.entries.${pluginId} restored`);
      if (configSnapshot.allowed) console.log(`  ✓ plugins.allow membership restored`);
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      console.error(`Warning: could not restore config — ${msg}`);
      console.error('Your previous config is in the safety backup file (see snapshot section above).');
    }
  }
  console.log('');

  console.log('Repair complete. Restart the OpenClaw gateway to load the fresh plugin install.');
}

export async function handleOpenClawCommand(subcommand: string, extraArgs: string[] = []): Promise<void> {
  const noHooks = extraArgs.includes('--no-hooks');
  const noPlugins = extraArgs.includes('--no-plugins');
  const restartGateway = !extraArgs.includes('--no-gateway-restart');

  switch (subcommand) {
    case 'install':
      await installOpenClawHook({ noHooks, noPlugins, restartGateway });
      break;
    case 'uninstall':
      await uninstallOpenClawHook();
      break;
    case 'status':
      await openClawHookStatus();
      break;
    case 'repair':
      await repairOpenClawPlugin();
      break;
    default:
      console.log('Usage: shieldcortex openclaw <install|uninstall|status|repair>');
      console.log('');
      console.log('Install options:');
      console.log('  --no-hooks              Skip hook installation (useful in Docker/CI)');
      console.log('  --no-plugins            Skip plugin installation (useful in Docker/CI)');
      console.log('  --no-gateway-restart    Skip the auto gateway restart after install');
      console.log('');
      console.log('Repair: diagnose + safely fix duplicate-plugin-id state surfaced by');
      console.log('`shieldcortex doctor`. Preserves the customer\'s OpenClaw-side plugin');
      console.log('config (interceptor settings, cloud API key, allowlist) across the');
      console.log('uninstall+reinstall round-trip needed for sticky cases.');
      process.exit(1);
  }
}
