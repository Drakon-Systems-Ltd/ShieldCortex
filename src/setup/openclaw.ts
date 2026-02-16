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
import { execSync } from 'child_process';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const HOOK_NAME = 'cortex-memory';

// Hook source is in hooks/openclaw/cortex-memory/ relative to project root
// From dist/setup/, go up two levels to project root
const HOOK_SOURCE = path.resolve(__dirname, '..', '..', 'hooks', 'openclaw', HOOK_NAME);

// Plugin compiled output in plugins/openclaw/dist/ relative to project root
const PLUGIN_SOURCE = path.resolve(__dirname, '..', '..', 'plugins', 'openclaw', 'dist');
const PLUGIN_DIR_NAME = 'shieldcortex-realtime';

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
  return os.homedir();
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

  // If openclaw command exists but config dir doesn't, create it
  const openclawDir = path.join(home, '.openclaw');
  if (!fs.existsSync(openclawDir)) {
    try {
      execSync('which openclaw', { encoding: 'utf-8', timeout: 5000 });
      // openclaw is installed but config dir missing — create it
      fs.mkdirSync(openclawDir, { recursive: true });
    } catch {
      // openclaw not in PATH, skip
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
    if (!config.plugins?.entries?.['shieldcortex-realtime']) return;

    delete config.plugins.entries['shieldcortex-realtime'];
    if (Object.keys(config.plugins.entries).length === 0) delete config.plugins.entries;
    if (config.plugins && Object.keys(config.plugins).length === 0) delete config.plugins;

    fs.writeFileSync(configPath, JSON.stringify(config, null, 2) + '\n', 'utf-8');
    console.log('Cleaned up legacy plugin entry from openclaw.json');
  } catch {
    // Non-critical — don't fail the install
  }
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
function installPlugin(): boolean {
  if (!fs.existsSync(PLUGIN_SOURCE)) {
    console.warn('  Warning: Plugin source not found, skipping plugin install');
    return false;
  }

  const extensionsDir = findExtensionsDir();
  if (!extensionsDir) return false;

  const destDir = path.join(extensionsDir, PLUGIN_DIR_NAME);
  try {
    fs.mkdirSync(destDir, { recursive: true });

    for (const file of ['index.js', 'openclaw.plugin.json']) {
      const src = path.join(PLUGIN_SOURCE, file);
      const dest = path.join(destDir, file);
      if (fs.existsSync(src)) {
        fs.copyFileSync(src, dest);
      }
    }

    // Verify readability
    const indexDest = path.join(destDir, 'index.js');
    try {
      fs.accessSync(indexDest, fs.constants.R_OK);
    } catch {
      console.warn(`  Warning: ${indexDest} copied but not readable`);
    }

    console.log(`Installed real-time plugin to ${destDir}`);
    return true;
  } catch (err) {
    const code = (err as NodeJS.ErrnoException).code;
    if (code === 'EACCES' || code === 'EPERM') {
      console.warn(`  Skipped plugin install (permission denied on ${destDir})`);
    } else {
      console.warn(`  Warning: Could not install plugin: ${(err as Error).message}`);
    }
    return false;
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

// ==================== Commands ====================

export async function installOpenClawHook(): Promise<void> {
  const hooksDirs = findAllHooksDirs();

  if (hooksDirs.length === 0) {
    console.error('OpenClaw is not installed on this system.');
    console.log('Install it first: npm install -g openclaw');
    process.exit(1);
  }

  if (!fs.existsSync(HOOK_SOURCE)) {
    console.error('Hook source files not found. Package may be corrupted.');
    process.exit(1);
  }

  // Clean up legacy plugin entry that caused config validation errors
  cleanupLegacyPlugin();

  // Install to ALL detected hook directories
  let installed = 0;
  for (const hooksDir of hooksDirs) {
    const destDir = path.join(hooksDir, HOOK_NAME);
    try {
      fs.mkdirSync(destDir, { recursive: true });

      for (const file of ['HOOK.md', 'handler.ts']) {
        const src = path.join(HOOK_SOURCE, file);
        const dest = path.join(destDir, file);
        fs.copyFileSync(src, dest);

        try {
          fs.accessSync(dest, fs.constants.R_OK);
        } catch {
          console.error(`  Warning: ${dest} was copied but is not readable`);
        }
      }

      console.log(`Installed cortex-memory hook to ${destDir}`);
      installed++;
    } catch (err) {
      const code = (err as NodeJS.ErrnoException).code;
      if (code === 'EACCES' || code === 'EPERM') {
        console.warn(`  Skipped ${destDir} (permission denied)`);
      } else {
        throw err;
      }
    }
  }

  if (installed === 0) {
    console.error('Could not install to any hook directory (permission denied).');
    console.log('Try running with sudo, or fix permissions on your hooks directories.');
    process.exit(1);
  }

  // Install the real-time plugin to the extensions directory
  const pluginInstalled = installPlugin();

  console.log('');
  console.log('What was installed:');
  console.log('  • cortex-memory hook (auto-save, memory injection, "remember this:" trigger)');
  if (pluginInstalled) {
    console.log('  • shieldcortex-realtime plugin (real-time LLM input/output scanning)');
  }
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
    const destDir = path.join(hooksDir, HOOK_NAME);
    if (fs.existsSync(destDir)) {
      fs.rmSync(destDir, { recursive: true });
      console.log(`Removed cortex-memory hook from ${destDir}`);
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
    const destDir = path.join(hooksDir, HOOK_NAME);
    const installed = fs.existsSync(destDir);
    console.log(`  ${hooksDir}`);
    console.log(`    cortex-memory: ${installed ? 'installed' : 'not installed'}`);
  }

  console.log('');
  const plugin = pluginStatus();
  console.log(`  Real-time plugin: ${plugin.installed ? `installed (${plugin.path})` : 'not installed'}`);
}

export async function handleOpenClawCommand(subcommand: string): Promise<void> {
  switch (subcommand) {
    case 'install':
      await installOpenClawHook();
      break;
    case 'uninstall':
      await uninstallOpenClawHook();
      break;
    case 'status':
      await openClawHookStatus();
      break;
    default:
      console.log('Usage: shieldcortex openclaw <install|uninstall|status>');
      process.exit(1);
  }
}
