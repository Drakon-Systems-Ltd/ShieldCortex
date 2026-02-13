/**
 * Claude Code / OpenClaw hook installer.
 *
 * Copies the cortex-memory hook into the hooks directory.
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

/**
 * Resolve the real user's home directory.
 *
 * When run under sudo, os.homedir() returns /root/.
 * We check SUDO_USER first and resolve their actual home.
 */
function resolveUserHome(): string {
  const sudoUser = process.env.SUDO_USER;
  if (sudoUser) {
    try {
      const homeDir = execSync(`eval echo ~${sudoUser}`, {
        encoding: 'utf-8',
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

export async function installOpenClawHook(): Promise<void> {
  const hooksDirs = findAllHooksDirs();

  if (hooksDirs.length === 0) {
    console.error('Neither Claude Code nor OpenClaw is installed on this system.');
    console.log('Install Claude Code first: https://claude.ai/claude-code');
    process.exit(1);
  }

  if (!fs.existsSync(HOOK_SOURCE)) {
    console.error('Hook source files not found. Package may be corrupted.');
    process.exit(1);
  }

  // Install to ALL detected hook directories
  for (const hooksDir of hooksDirs) {
    const destDir = path.join(hooksDir, HOOK_NAME);
    fs.mkdirSync(destDir, { recursive: true });

    for (const file of ['HOOK.md', 'handler.ts']) {
      const src = path.join(HOOK_SOURCE, file);
      const dest = path.join(destDir, file);
      fs.copyFileSync(src, dest);

      // Verify the copied file is readable
      try {
        fs.accessSync(dest, fs.constants.R_OK);
      } catch {
        console.error(`  Warning: ${dest} was copied but is not readable`);
      }
    }

    console.log(`Installed cortex-memory hook to ${destDir}`);
  }

  console.log('  The hook will activate on next restart.');
  console.log('');
  console.log('  What it does:');
  console.log('  • Auto-saves important session context on /new');
  console.log('  • Injects past memories on session start');
  console.log('  • "remember this: ..." keyword trigger');
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

  if (removed === 0) {
    console.log('cortex-memory hook is not installed in any location.');
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
