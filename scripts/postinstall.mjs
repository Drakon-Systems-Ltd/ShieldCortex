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
import { existsSync, copyFileSync, mkdirSync, readdirSync, readFileSync, writeFileSync } from 'fs';
import { join, dirname } from 'path';
import { homedir } from 'os';
import { spawnSync } from 'child_process';
import { fileURLToPath } from 'url';
import { createRequire } from 'module';
import { getDashboardHint } from './lib/dashboard-hint.mjs';

const isGlobal = process.env.npm_config_global === 'true';
const isCI = process.env.CI === 'true' || process.env.CONTINUOUS_INTEGRATION === 'true';
const skipAutoOpenClaw = process.env.SHIELDCORTEX_SKIP_AUTO_OPENCLAW === '1';

/**
 * Write integration defaults for fresh installs only.
 * Returns true if defaults were written (fresh install), false if config already exists.
 *
 * Why: as of v4.13.x ShieldCortex ships flagship integrations ON by default for new
 * users so they see value within the first session. Existing users keep their current
 * settings — we never overwrite a config file that already exists.
 *
 * The v4.11.0 latency concern (200-500ms + 100-400 tokens/turn for proactive recall)
 * is real but only matters for fast OpenClaw agent loops; for interactive Claude Code
 * sessions the value > latency. Users can opt out via dashboard or CLI.
 */
function writeFreshInstallDefaults() {
  const configDir = join(homedir(), '.shieldcortex');
  const configFile = join(configDir, 'config.json');

  if (existsSync(configFile)) return false;

  try {
    mkdirSync(configDir, { recursive: true });
    const defaults = {
      openclawAutoMemory: true,
      proactiveRecall: true,
    };
    writeFileSync(configFile, JSON.stringify(defaults, null, 2) + '\n');
    return true;
  } catch {
    return false;
  }
}

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

// Smoke-test the better-sqlite3 native binding at install time so an ABI
// mismatch (Node newer than the prebuilds, no compiler) surfaces here with
// actionable guidance — not later as a bare `libc++abi ... Napi::Error`
// crash-loop with zero explanation. Never throws; warns and returns false.
function verifyNativeModule() {
  try {
    const require = createRequire(import.meta.url);
    const Database = require('better-sqlite3');
    const db = new Database(':memory:');
    db.exec('CREATE TABLE _sc_probe(x)');
    db.close();
    return true;
  } catch (err) {
    const detail = err && err.message ? err.message : String(err);
    console.log('');
    console.warn('\x1b[33m[shieldcortex] ⚠  Database engine (better-sqlite3) failed to load.\x1b[0m');
    console.warn(`[shieldcortex] Node ${process.version} (ABI ${process.versions.modules}) has no matching`);
    console.warn('[shieldcortex] prebuilt binary and it was not compiled locally.');
    console.warn('[shieldcortex] Fix one of these before running ShieldCortex:');
    console.warn('[shieldcortex]   • npm rebuild better-sqlite3   (needs a C/C++ toolchain)');
    console.warn('[shieldcortex]   • or run on Node LTS 20.x / 22.x (ships prebuilt binaries)');
    console.warn(`[shieldcortex] Underlying error: ${detail}`);
    return false;
  }
}

// ── Main postinstall logic ──

if (isGlobal && !isCI) {
  const __filename = fileURLToPath(import.meta.url);
  const __dirname = dirname(__filename);
  const cliPath = join(__dirname, '..', 'dist', 'index.js');

  verifyNativeModule();

  const isFreshInstall = writeFreshInstallDefaults();
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
      // Bug #15: Plugin exists from a previous install — auto-copy new files.
      console.log('');
      console.log('[shieldcortex] Existing plugin detected. Copying updated plugin files...');
      const copied = autoCopyPlugin(state.pluginDir, cliPath);
      if (copied) {
        console.log('[shieldcortex] Plugin files updated.');
      } else {
        console.warn('[shieldcortex] ⚠  Plugin auto-copy failed — full refresh will recopy it.');
      }

      // Task 6b: the hook is installed by file-copy and goes STALE on a
      // package bump unless something re-copies it. The plugin auto-copy
      // above only touches plugin files, leaving a stale handler.ts/runtime.mjs
      // in ~/.openclaw/hooks/cortex-memory/. Whenever the hook is present we
      // ALSO run the full refresh (it re-copies the hook AND re-registers the
      // plugin). The full install is idempotent, so re-running is safe even
      // right after the plugin auto-copy.
      if (state.hookInstalled) {
        console.log('[shieldcortex] Refreshing OpenClaw hook to latest version...');
        const ok = refreshOpenClawInstall(cliPath);
        if (!ok) {
          console.warn('[shieldcortex] ⚠  OpenClaw hook refresh failed (non-fatal).');
          console.warn('[shieldcortex] Run manually: shieldcortex openclaw install');
        }
      } else if (!copied) {
        // No hook installed AND the plugin copy failed — fall back to a full
        // refresh so the plugin still lands.
        console.log('[shieldcortex] Running full OpenClaw refresh...');
        const ok = refreshOpenClawInstall(cliPath);
        if (!ok) {
          console.warn('[shieldcortex] ⚠  OpenClaw auto-refresh failed (non-fatal).');
          console.warn('[shieldcortex] Run manually: shieldcortex openclaw install');
        }
      } else {
        console.log('[shieldcortex] No hook installed. Run full setup for hook + memory:');
        console.log('[shieldcortex]   shieldcortex openclaw install');
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
  if (isFreshInstall) {
    console.log('\x1b[2mFresh install — flagship integrations enabled by default:\x1b[0m');
    console.log('\x1b[2m  • OpenClaw Auto-Memory  — captures memories from agent LLM output\x1b[0m');
    console.log('\x1b[2m  • Proactive Recall      — injects relevant memory into prompts\x1b[0m');
    console.log('\x1b[2mTo opt out (e.g. for fast agent loops): dashboard Settings → Integrations, or:\x1b[0m');
    console.log('\x1b[2m  shieldcortex config --openclaw-auto-memory false\x1b[0m');
    console.log('\x1b[2m  shieldcortex config --proactive-recall false\x1b[0m');
  } else {
    console.log('\x1b[2mIntegration toggles preserved from your existing config.\x1b[0m');
    console.log('\x1b[2mManage in dashboard Settings → Integrations, or:\x1b[0m');
    console.log('\x1b[2m  shieldcortex config --openclaw-auto-memory true|false\x1b[0m');
    console.log('\x1b[2m  shieldcortex config --proactive-recall true|false\x1b[0m');
  }
  console.log('');

  // Dashboard discovery hint — only shown on non-headless systems where the
  // local dashboard isn't already running. Best-effort, never blocks install.
  try {
    const hint = await getDashboardHint();
    if (hint) {
      console.log(`\x1b[36m${hint.title}:\x1b[0m`);
      console.log(`  \x1b[33m${hint.command}\x1b[0m  \x1b[2m→ ${hint.url}\x1b[0m`);
      console.log(`  \x1b[2m${hint.detail}\x1b[0m`);
      if (hint.alwaysOnCommand) {
        console.log(`  \x1b[33m${hint.alwaysOnCommand}\x1b[0m  \x1b[2m${hint.alwaysOnDetail}\x1b[0m`);
      }
      console.log('');
    }
  } catch { /* never fail postinstall on a hint */ }
}
