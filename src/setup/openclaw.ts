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

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const HOOK_NAME = 'cortex-memory';

// Hook source is in hooks/openclaw/cortex-memory/ relative to project root
// From dist/setup/, go up two levels to project root
const HOOK_SOURCE = path.resolve(__dirname, '..', '..', 'hooks', 'openclaw', HOOK_NAME);

// Plugin compiled output in plugins/openclaw/dist/ relative to project root
const PLUGIN_SOURCE = path.resolve(__dirname, '..', '..', 'plugins', 'openclaw', 'dist');
const PLUGIN_PACKAGE_SOURCE = path.resolve(__dirname, '..', '..', 'plugins', 'openclaw');
const PLUGIN_DIR_NAME = 'shieldcortex-realtime';
const HOOK_FILES = ['HOOK.md', 'handler.ts', 'runtime.mjs'] as const;
const OPENCLAW_SKIP_NATIVE_INSTALL_ENV = 'SHIELDCORTEX_SKIP_NATIVE_OPENCLAW_INSTALL';

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
 * Remove the shieldcortex-realtime plugin entry from openclaw.json
 * if it exists. Earlier versions incorrectly registered a plugin
 * that caused OpenClaw config validation errors.
 */
function cleanupLegacyPlugin(): void {
  const home = resolveUserHome();
  const configPath = path.join(home, '.openclaw', 'openclaw.json');
  if (!fs.existsSync(configPath)) return;

  try {
    const raw = fs.readFileSync(configPath, 'utf-8');
    const config = JSON.parse(raw);
    let changed = false;

    // Remove legacy entries (old format before native installs)
    if (config.plugins?.entries?.['shieldcortex-realtime']) {
      delete config.plugins.entries['shieldcortex-realtime'];
      if (Object.keys(config.plugins.entries).length === 0) delete config.plugins.entries;
      changed = true;
    }

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

function trustLocalPlugin(installDir: string, version: string): boolean {
  const configPath = openClawConfigPath();
  const configDir = path.dirname(configPath);
  const pluginId = PLUGIN_DIR_NAME; // "shieldcortex-realtime"

  try {
    if (!fs.existsSync(configDir)) {
      fs.mkdirSync(configDir, { recursive: true });
    }

    const raw = fs.existsSync(configPath) ? fs.readFileSync(configPath, 'utf-8') : '{}';
    const config = JSON.parse(raw);
    const plugins = typeof config.plugins === 'object' && config.plugins !== null ? config.plugins : {};
    const allow = Array.isArray((plugins as { allow?: unknown }).allow)
      ? ((plugins as { allow?: string[] }).allow ?? [])
      : [];

    // Remove any stale full-path entries for this plugin
    const cleaned = allow.filter(
      (e: string) => !e.includes(PLUGIN_DIR_NAME) || e === pluginId,
    );
    if (!cleaned.includes(pluginId)) {
      cleaned.push(pluginId);
    }

    // Add installs entry so OpenClaw recognises the plugin
    const installs = typeof plugins.installs === 'object' && plugins.installs !== null
      ? plugins.installs
      : {};
    (installs as Record<string, unknown>)[pluginId] = {
      source: 'path',
      installPath: installDir,
      version,
      installedAt: new Date().toISOString(),
    };

    // Add entries to enable the plugin
    const entries = typeof plugins.entries === 'object' && plugins.entries !== null
      ? plugins.entries
      : {};
    if (!(entries as Record<string, unknown>)[pluginId]) {
      (entries as Record<string, unknown>)[pluginId] = { enabled: true };
    }

    config.plugins = {
      ...plugins,
      allow: cleaned,
      installs,
      entries,
    };

    fs.writeFileSync(configPath, JSON.stringify(config, null, 2) + '\n', 'utf-8');
    return true;
  } catch {
    return false;
  }
}

function tryNativeOpenClawPluginInstall(): PluginInstallMode | null {
  if (process.env[OPENCLAW_SKIP_NATIVE_INSTALL_ENV] === '1') return null;
  if (!isOpenClawInstalled()) return null;

  const env = { ...process.env, HOME: resolveUserHome() };
  const attempts: Array<{ args: string[]; label: string }> = [
    { args: ['plugins', 'install', '@drakon-systems/shieldcortex-realtime'], label: 'package install' },
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

    const requiredFiles = ['index.js', 'openclaw.plugin.json'];
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

    // Verify readability
    try {
      fs.accessSync(indexDest, fs.constants.R_OK);
    } catch {
      console.warn(`  Warning: ${indexDest} copied but not readable`);
    }

    // Read plugin version from manifest
    let pluginVersion = 'unknown';
    try {
      const manifest = JSON.parse(fs.readFileSync(path.join(destDir, 'openclaw.plugin.json'), 'utf-8'));
      pluginVersion = manifest.version ?? pluginVersion;
    } catch {
      // Fall back to package.json version
      try {
        const pkg = JSON.parse(fs.readFileSync(path.join(packageRoot, 'package.json'), 'utf-8'));
        pluginVersion = pkg.version ?? pluginVersion;
      } catch { /* keep "unknown" */ }
    }

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
    fs.rmSync(destDir, { recursive: true });
    console.log(`Removed real-time plugin from ${destDir}`);
    return true;
  } catch {
    return false;
  }
}

/**
 * Check whether the plugin is installed in the extensions directory.
 */
function pluginStatus(): { installed: boolean; path?: string } {
  const extensionsDir = findExtensionsDir();
  if (!extensionsDir) return { installed: false };

  const destDir = path.join(extensionsDir, PLUGIN_DIR_NAME);
  const indexPath = path.join(destDir, 'index.js');
  if (fs.existsSync(indexPath)) {
    return { installed: true, path: destDir };
  }
  return { installed: false };
}

function localPluginTrustStatus(pluginPath: string | undefined): 'trusted' | 'untrusted' | 'unknown' {
  if (!pluginPath) return 'unknown';
  const indexPath = path.join(pluginPath, 'index.js');
  const configPath = openClawConfigPath();
  if (!fs.existsSync(configPath)) return 'unknown';

  try {
    const config = JSON.parse(fs.readFileSync(configPath, 'utf-8'));
    const allow = config.plugins?.allow;
    if (Array.isArray(allow) && (allow.includes(PLUGIN_DIR_NAME) || allow.includes(indexPath))) {
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
    console.error('  openclaw hooks install shieldcortex');
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
        if (code === 'EACCES' || code === 'EPERM') {
          console.warn(`  Skipped ${destDir} (permission denied)`);
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
  console.log('  openclaw hooks install shieldcortex');
  console.log('  openclaw plugins install @drakon-systems/shieldcortex-realtime');
  console.log('');
  console.log('Restart your agent to activate.');
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
  if (!plugin.installed) {
    console.log('  Real-time plugin: not installed');
    return;
  }

  const trust = localPluginTrustStatus(plugin.path);
  const trustSuffix =
    trust === 'trusted'
      ? 'trusted via plugins.allow'
      : trust === 'untrusted'
        ? 'local install not yet trusted'
        : 'native or unknown trust source';
  console.log(`  Real-time plugin: installed (${plugin.path}) — ${trustSuffix}`);
}

export async function handleOpenClawCommand(subcommand: string, extraArgs: string[] = []): Promise<void> {
  const noHooks = extraArgs.includes('--no-hooks');
  const noPlugins = extraArgs.includes('--no-plugins');

  switch (subcommand) {
    case 'install':
      await installOpenClawHook({ noHooks, noPlugins });
      break;
    case 'uninstall':
      await uninstallOpenClawHook();
      break;
    case 'status':
      await openClawHookStatus();
      break;
    default:
      console.log('Usage: shieldcortex openclaw <install|uninstall|status>');
      console.log('');
      console.log('Install options:');
      console.log('  --no-hooks     Skip hook installation (useful in Docker/CI)');
      console.log('  --no-plugins   Skip plugin installation (useful in Docker/CI)');
      process.exit(1);
  }
}
