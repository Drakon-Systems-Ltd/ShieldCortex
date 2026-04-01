#!/usr/bin/env node
/**
 * Postinstall script - prints setup instructions after global install.
 * Also detects existing OpenClaw installations and either auto-refreshes
 * them or prints a clear upgrade warning (Bug #15 fix).
 *
 * Does NOT auto-run setup when:
 *   - Running in CI
 *   - SHIELDCORTEX_SKIP_AUTO_OPENCLAW=1 is set
 *   - Running as a local/dev install (npm_config_global !== 'true')
 */
import { existsSync, copyFileSync, mkdirSync, readdirSync, readFileSync } from 'fs';
import { join, dirname } from 'path';
import { homedir } from 'os';
import { spawnSync } from 'child_process';
import { fileURLToPath } from 'url';

const isGlobal = process.env.npm_config_global === 'true';
const isCI = process.env.CI === 'true' || process.env.CONTINUOUS_INTEGRATION === 'true';
const skipAutoOpenClaw = process.env.SHIELDCORTEX_SKIP_AUTO_OPENCLAW === '1';

/**
 * Detect Docker/container environment — mirrors the logic in src/setup/openclaw.ts.
 * Postinstall must not crash the gateway in Umbrel/Docker installs (#16).
 */
function isDockerEnvironment() {
  try { if (existsSync('/.dockerenv')) return true; } catch { /* ignore */ }
  if (process.env.DOCKER === 'true' || process.env.DOCKER === '1') return true;
  if (process.env.container === 'docker') return true;
  try {
    const cgroup = readFileSync('/proc/1/cgroup', 'utf8');
    if (cgroup.includes('docker') || cgroup.includes('kubepods') || cgroup.includes('containerd')) return true;
  } catch { /* ignore */ }
  return false;
}

/**
 * Check whether OpenClaw is installed and whether ShieldCortex hooks/plugin exist.
 */
function getOpenClawState() {
  const home = homedir();
  const openclawDir = join(home, '.openclaw');
  const knownHook = join(openclawDir, 'hooks', 'cortex-memory');
  const knownPlugin = join(openclawDir, 'extensions', 'shieldcortex-realtime');

  return {
    openclawInstalled: existsSync(openclawDir),
    hookInstalled: existsSync(knownHook),
    pluginInstalled: existsSync(knownPlugin),
    pluginDir: knownPlugin,
  };
}

/**
 * Auto-copy updated plugin files into the existing extensions directory.
 * This ensures interceptor.js and other new files appear after upgrade (#15).
 */
function autoCopyPlugin(pluginDestDir, cliDistDir) {
  if (!existsSync(pluginDestDir)) return false;

  try {
    // Source: plugins/openclaw/dist/ inside this package
    const pluginSourceDir = join(dirname(fileURLToPath(import.meta.url)), '..', 'plugins', 'openclaw', 'dist');
    if (!existsSync(pluginSourceDir)) return false;

    let copied = 0;
    const files = readdirSync(pluginSourceDir);
    for (const file of files) {
      const src = join(pluginSourceDir, file);
      const dest = join(pluginDestDir, file);
      try {
        copyFileSync(src, dest);
        copied++;
      } catch {
        // Non-fatal — individual file copy failure
      }
    }
    return copied > 0;
  } catch {
    return false;
  }
}

/**
 * Run `shieldcortex openclaw install` to refresh the full hook+plugin.
 */
function refreshOpenClawInstall(cliPath) {
  if (!existsSync(cliPath)) return false;
  const result = spawnSync(process.execPath, [cliPath, 'openclaw', 'install'], {
    stdio: 'inherit',
    env: process.env,
  });
  return result.status === 0;
}

// ── Main postinstall logic ──

if (isGlobal && !isCI) {
  const __filename = fileURLToPath(import.meta.url);
  const __dirname = dirname(__filename);
  const cliPath = join(__dirname, '..', 'dist', 'index.js');

  const state = getOpenClawState();
  const inDocker = isDockerEnvironment();

  if (!skipAutoOpenClaw && state.openclawInstalled) {
    if (inDocker) {
      // Bug #16: Docker install — never auto-run, just warn
      console.log('');
      console.warn('[shieldcortex] ⚠  Docker/container environment detected.');
      console.warn('[shieldcortex] Skipping automatic OpenClaw hook/plugin refresh.');
      console.warn('[shieldcortex] To manually install after confirming OpenClaw support:');
      console.warn('[shieldcortex]   shieldcortex openclaw install --no-plugins');
    } else if (state.pluginInstalled) {
      // Bug #15: Plugin exists from a previous install — auto-copy new files
      console.log('');
      console.log('[shieldcortex] Existing plugin detected. Copying updated plugin files...');
      const copied = autoCopyPlugin(state.pluginDir, cliPath);
      if (copied) {
        console.log('[shieldcortex] Plugin files updated. Run full refresh for hook updates:');
        console.log('[shieldcortex]   shieldcortex openclaw install');
      } else {
        // Fall back to full refresh
        console.log('[shieldcortex] Auto-copy failed. Running full OpenClaw refresh...');
        const ok = refreshOpenClawInstall(cliPath);
        if (!ok) {
          console.warn('[shieldcortex] ⚠  OpenClaw auto-refresh failed (non-fatal).');
          console.warn('[shieldcortex] Run manually: shieldcortex openclaw install');
        }
      }
    } else if (state.hookInstalled) {
      // Hook exists but no plugin — run full refresh
      console.log('');
      console.log('[shieldcortex] OpenClaw hook detected. Refreshing to latest version...');
      const ok = refreshOpenClawInstall(cliPath);
      if (!ok) {
        console.warn('[shieldcortex] ⚠  OpenClaw auto-refresh skipped (non-fatal).');
        console.warn('[shieldcortex] Run manually: shieldcortex openclaw install');
      }
    }
    // else: openclaw installed but no previous shieldcortex — don't auto-install; let user run setup
  }

  console.log('');
  console.log('\x1b[36m╭───────────────────────────────────────────────────────╮\x1b[0m');
  console.log('\x1b[36m│\x1b[0m  \x1b[1mShieldCortex installed!\x1b[0m                              \x1b[36m│\x1b[0m');
  console.log('\x1b[36m│\x1b[0m                                                       \x1b[36m│\x1b[0m');
  console.log('\x1b[36m│\x1b[0m  \x1b[1mNext step:\x1b[0m                                          \x1b[36m│\x1b[0m');
  console.log('\x1b[36m│\x1b[0m  \x1b[33mshieldcortex setup\x1b[0m                                  \x1b[36m│\x1b[0m');
  console.log('\x1b[36m│\x1b[0m                                                       \x1b[36m│\x1b[0m');
  console.log('\x1b[36m│\x1b[0m  This adds persistent memory to Claude Code.         \x1b[36m│\x1b[0m');
  console.log('\x1b[36m│\x1b[0m  Your conversations will remember context across     \x1b[36m│\x1b[0m');
  console.log('\x1b[36m│\x1b[0m  sessions, compactions, and projects.                \x1b[36m│\x1b[0m');
  console.log('\x1b[36m╰───────────────────────────────────────────────────────╯\x1b[0m');
  console.log('');
}
