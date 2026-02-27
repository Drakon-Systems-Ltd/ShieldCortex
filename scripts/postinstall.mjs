#!/usr/bin/env node
/**
 * Postinstall script - prints setup instructions after global install.
 * Does NOT auto-run setup (can fail in CI, user might not have Claude Code).
 */
import { existsSync } from 'fs';
import { join, dirname } from 'path';
import { homedir } from 'os';
import { spawnSync } from 'child_process';
import { fileURLToPath } from 'url';

// Only show message for global installs (not local dev or CI)
const isGlobal = process.env.npm_config_global === 'true';
const isCI = process.env.CI === 'true' || process.env.CONTINUOUS_INTEGRATION === 'true';
const skipAutoOpenClaw = process.env.SHIELDCORTEX_SKIP_AUTO_OPENCLAW === '1';

function shouldRefreshOpenClaw() {
  const home = homedir();
  const openclawDir = join(home, '.openclaw');
  const knownHook = join(openclawDir, 'hooks', 'cortex-memory');
  const knownPlugin = join(openclawDir, 'extensions', 'shieldcortex-realtime');
  return existsSync(openclawDir) || existsSync(knownHook) || existsSync(knownPlugin);
}

function refreshOpenClawInstall() {
  const __filename = fileURLToPath(import.meta.url);
  const __dirname = dirname(__filename);
  const cliPath = join(__dirname, '..', 'dist', 'index.js');

  if (!existsSync(cliPath)) return;
  const result = spawnSync(process.execPath, [cliPath, 'openclaw', 'install'], {
    stdio: 'inherit',
    env: process.env,
  });
  if (result.status !== 0) {
    console.warn('[shieldcortex] OpenClaw auto-refresh skipped (non-fatal).');
  }
}

if (isGlobal && !isCI) {
  if (!skipAutoOpenClaw && shouldRefreshOpenClaw()) {
    console.log('\n[shieldcortex] OpenClaw detected. Refreshing hook/plugin to latest version...');
    refreshOpenClawInstall();
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
