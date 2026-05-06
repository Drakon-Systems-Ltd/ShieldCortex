#!/usr/bin/env node

/**
 * ShieldCortex - Brain-like Memory System for Claude Code
 *
 * This server provides persistent, intelligent memory for Claude Code,
 * solving the context compaction and session persistence problems.
 *
 * Usage (after `npm install -g shieldcortex`):
 *   shieldcortex                         # Start MCP server (default)
 *   shieldcortex --mode mcp              # Start MCP server
 *   shieldcortex --mode api              # Start visualization API server
 *   shieldcortex --mode both             # Start both servers
 *   shieldcortex --mode worker           # Start headless background worker
 *   shieldcortex --dashboard             # Start API + Dashboard (admin panel)
 *   shieldcortex --db /path/to.db        # Custom database path
 *   shieldcortex scan "text"             # Quick content scan (no MCP/ML)
 *   shieldcortex audit                   # Full security audit of agent environment
 *   shieldcortex audit --json            # Audit with JSON output
 *   shieldcortex audit --markdown        # Audit with Markdown output
 *   shieldcortex audit --ci              # Audit in CI mode (exit code reflects grade)
 *   shieldcortex status                  # Show database and system status
 *   shieldcortex quickstart              # Detect integrations and offer guided install
 *   shieldcortex quickstart --yes        # Install across all detected integrations
 *   shieldcortex setup                   # Configure Claude for proactive memory use
 *   shieldcortex install                 # Alias for setup
 *   shieldcortex install --with-stop-hook        # Opt in to the Stop hook (sampled per-turn extraction)
 *   shieldcortex install --with-session-end      # Opt in to the SessionEnd hook (final extraction on session exit)
 *   shieldcortex install --with-stop-hook --with-session-end   # Both at once
 *   shieldcortex hook pre-compact        # Run pre-compact hook (for settings.json)
 *   shieldcortex hook session-start      # Run session-start hook (for settings.json)
 *   shieldcortex hook session-end        # Run session-end hook (for settings.json)
 *   shieldcortex service install         # Install persistent ShieldCortex service
 *   shieldcortex service install --headless  # Recommended for always-on servers
 *   shieldcortex service repair          # Rebuild persistent service with current install path
 *   shieldcortex service uninstall       # Remove persistent service
 *   shieldcortex service status          # Check service status
 *   shieldcortex openclaw install        # Install OpenClaw hook/plugin (compatibility wrapper)
 *   shieldcortex openclaw uninstall      # Remove OpenClaw hook
 *   shieldcortex openclaw status         # Check OpenClaw hook status
 *   shieldcortex config --openclaw-auto-memory true   # Enable OpenClaw auto-memory extraction
 *   shieldcortex config --openclaw-auto-memory false  # Disable OpenClaw auto-memory extraction
 *   shieldcortex cloud sync --full      # Backfill local memories + graph to ShieldCortex Cloud
 *   shieldcortex review-copilot status  # Local AI Explainer status (Pro)
 *   shieldcortex copilot install         # Configure MCP server for VS Code + Cursor
 *   shieldcortex copilot uninstall       # Remove MCP server configuration
 *   shieldcortex copilot status          # Check MCP server configuration
 *   shieldcortex codex install           # Configure MCP server for Codex CLI + VS Code extension
 *   shieldcortex codex uninstall         # Remove Codex MCP configuration
 *   shieldcortex codex status            # Check Codex MCP configuration
 *   shieldcortex xray <target>           # Inspect package/file/plugin for hidden risk
 *   shieldcortex xray <path> --deep      # Deep scan (Pro) with full analysis
 *   shieldcortex xray <package> --json   # JSON output
 *   shieldcortex cortex capture      # Log a mistake with rule extraction
 *   shieldcortex cortex preflight    # Pre-flight check before a task
 *   shieldcortex cortex review       # Weekly pattern review
 *   shieldcortex cortex graduate     # Archive learned rules
 *   shieldcortex license activate <key>  # Activate a licence key
 *   shieldcortex license status          # Show current licence tier and features
 *   shieldcortex license deactivate      # Remove licence
 *   shieldcortex migrate                 # Migrate from Claude Cortex
 *   shieldcortex setup uninstall         # Remove hooks + CLAUDE.md block (requires confirmation)
 *   shieldcortex uninstall               # Full uninstall (requires confirmation)
 *   shieldcortex uninstall --confirm     # Full uninstall (non-interactive)
 *   shieldcortex uninstall --keep-logs   # Full uninstall but keep log files
 */

import { StdioServerTransport } from '@modelcontextprotocol/sdk/server/stdio.js';
import { spawn, ChildProcess } from 'child_process';
import { fileURLToPath } from 'url';
import http from 'http';
import path from 'path';
import fs from 'fs';
import { createServer } from './server.js';
import { startVisualizationServer } from './api/visualization-server.js';
import { handleServiceCommand } from './service/install.js';
import { setupClaudeMd } from './setup/claude-md.js';
import { handleHookCommand } from './setup/hooks.js';
import { handleOpenClawCommand } from './setup/openclaw.js';
import { handleCopilotCommand } from './setup/copilot.js';
import { handleCodexCommand } from './setup/codex.js';
import { createRequire } from 'module';
import { execSync } from 'child_process';
import { disposeModel, preloadModel } from './embeddings/index.js';
import { startDefaultWorker, stopDefaultWorker } from './worker/brain-worker.js';

const require = createRequire(import.meta.url);
const pkg = require('../package.json');

/**
 * Warn if running via npx cache with an outdated version.
 * Only prints for interactive CLI commands (not MCP server mode).
 */
function checkVersionStaleness(): void {
  // Skip for MCP server mode (no argv[2]) — stdout must stay clean for JSON-RPC
  if (!process.argv[2]) return;

  try {
    const globalVersion = execSync('npm ls -g shieldcortex --depth=0 --json 2>/dev/null', {
      encoding: 'utf-8',
      timeout: 3000,
    });
    const parsed = JSON.parse(globalVersion);
    const installed = parsed?.dependencies?.shieldcortex?.version;
    if (installed && installed !== pkg.version) {
      console.error(
        `\x1b[33m⚠ Running shieldcortex v${pkg.version} (npx cache) but v${installed} is globally installed.\x1b[0m`
      );
      console.error(
        `\x1b[33m  Use \`shieldcortex ${process.argv.slice(2).join(' ')}\` instead of \`npx shieldcortex\`.\x1b[0m`
      );
      console.error('');
    }
  } catch {
    // Not globally installed, or npm not available — no warning needed
  }
}

type ServerMode = 'mcp' | 'api' | 'both' | 'dashboard' | 'worker';

interface Args {
  dbPath?: string;
  mode: ServerMode;
}

// Get the directory of this file for relative paths
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

// Parse command line arguments
function parseArgs(): Args {
  const args = process.argv.slice(2);
  const result: Args = { mode: 'mcp' };

  for (let i = 0; i < args.length; i++) {
    if (args[i] === '--db' && args[i + 1]) {
      result.dbPath = args[i + 1];
      i++;
    } else if (args[i] === '--dashboard') {
      result.mode = 'dashboard';
    } else if (args[i] === '--mode' && args[i + 1]) {
      const mode = args[i + 1].toLowerCase();
      if (mode === 'mcp' || mode === 'api' || mode === 'both' || mode === 'dashboard' || mode === 'worker') {
        result.mode = mode as ServerMode;
      }
      i++;
    }
  }

  if (args[0] === 'dashboard') result.mode = 'dashboard';
  if (args[0] === 'api') result.mode = 'api';
  if (args[0] === 'worker') result.mode = 'worker';

  return result;
}

/**
 * Start MCP server for Claude Code integration
 */
async function startMcpServer(dbPath?: string): Promise<void> {
  // Create the MCP server
  const server = createServer(dbPath);
  const transport = new StdioServerTransport();

  // Register signal handlers BEFORE connect so cleanup runs even if connect() throws
  // Handle SIGINT gracefully — Claude Code sends this to idle MCP servers.
  // First SIGINT: log and stay alive (it may be a probe).
  // Second SIGINT within 5s: actually exit.
  let sigintCount = 0;
  let sigintResetTimer: ReturnType<typeof setTimeout> | null = null;
  process.on('SIGINT', async () => {
    sigintCount++;
    if (sigintCount === 1) {
      // First SIGINT — stay alive, reset counter after 5s
      sigintResetTimer = setTimeout(() => { sigintCount = 0; }, 5000);
      return;
    }
    // Second SIGINT — actually shut down
    if (sigintResetTimer) clearTimeout(sigintResetTimer);
    stopDefaultWorker();
    await server.close();
    await disposeModel();
    process.exit(0);
  });

  process.on('SIGTERM', async () => {
    stopDefaultWorker();
    await server.close();
    await disposeModel();
    process.exit(0);
  });

  // Connect via stdio transport
  await server.connect(transport);

  // Start the brain worker in MCP-lite profile so STM→LTM consolidation runs
  // even on hooks-only installs (no dashboard, no `service install`). Without
  // this, MCP-only deployments accumulate STM forever and never promote (#45).
  // The MCP profile uses a 15 min cadence and skips medium-tick + cloud-sync
  // work to keep total background load bounded across many open windows.
  // Disabled via SHIELDCORTEX_DISABLE_WORKER=1 for forensics / debugging.
  if (process.env.SHIELDCORTEX_DISABLE_WORKER !== '1') {
    try {
      startDefaultWorker({ profile: 'mcp' });
    } catch (err) {
      const msg = err instanceof Error ? err.message : String(err);
      console.error('[shieldcortex] Brain worker autostart failed (continuing without):', msg);
    }
  }

  // Preload embedding model in background so first tool call doesn't hang.
  // Fire-and-forget: failure is fine — searchMemories falls back to FTS-only.
  if (process.env.SHIELDCORTEX_SKIP_EMBEDDINGS !== '1') {
    preloadModel().catch(err => {
      console.error('[shieldcortex] Model preload failed (will retry on first use):', err.message);
    });
  }

  // Detect when the MCP client (mcporter) disconnects
  process.stdin.on('end', async () => {
    stopDefaultWorker();
    await server.close();
    await disposeModel();
    process.exit(0);
  });

  // Keepalive: send a JSON-RPC notification every 3 minutes to prevent
  // Claude Code from considering the connection idle and sending SIGINT.
  // See: https://github.com/Drakon-Systems-Ltd/ShieldCortex/issues/4
  // Routed through SDK transport to avoid stdout write races (#6).
  const KEEPALIVE_INTERVAL_MS = 3 * 60 * 1000; // 3 minutes
  const keepaliveTimer = setInterval(() => {
    try {
      // Send via SDK so writes are serialised with tool responses.
      // server.server is the underlying Protocol instance with notification().
      server.server.notification({ method: '$/ping' }).catch(() => {
        // Transport closed — let the stdin 'end' handler deal with it
      });
    } catch {
      // Server not connected — ignore
    }
  }, KEEPALIVE_INTERVAL_MS);

  // Clean up keepalive on exit
  process.on('exit', () => clearInterval(keepaliveTimer));
}

/**
 * Find the dashboard standalone server path
 * Tries multiple locations to support npm package, global install, and local dev
 */
function findDashboardPath(): { serverPath: string; cwd: string } | null {
  const fs = require('fs');

  // Candidate locations to check (in order of priority)
  // All paths are relative to __dirname (dist/) — no self-referencing require.resolve
  const candidates: Array<{ serverPath: string; cwd: string }> = [
    // Standard npm package structure (dist/ is in package root)
    {
      serverPath: path.resolve(__dirname, '..', 'dashboard', '.next', 'standalone', 'dashboard', 'server.js'),
      cwd: path.resolve(__dirname, '..', 'dashboard', '.next', 'standalone', 'dashboard'),
    },
    // Global npm install (some platforms put dist/ differently)
    {
      serverPath: path.resolve(__dirname, '..', '..', 'dashboard', '.next', 'standalone', 'dashboard', 'server.js'),
      cwd: path.resolve(__dirname, '..', '..', 'dashboard', '.next', 'standalone', 'dashboard'),
    },
  ];

  for (const candidate of candidates) {
    try {
      if (fs.existsSync(candidate.serverPath)) {
        return candidate;
      }
    } catch {
      // Ignore errors (e.g., require.resolve may fail)
    }
  }

  return null;
}

/**
 * Start the Next.js dashboard as a child process
 */
function startDashboard(): ChildProcess {
  const fs = require('fs');

  // Find dashboard server path
  const dashboardPath = findDashboardPath();
  const dashboardDir = path.resolve(__dirname, '..', 'dashboard');
  const useStandalone = dashboardPath !== null;

  console.log(`
╔══════════════════════════════════════════════════════════════╗
║             🧠 ShieldCortex Dashboard                        ║
╠══════════════════════════════════════════════════════════════╣
║  Starting Next.js dashboard...                               ║
║  Dashboard: http://localhost:3030                            ║
║  API:       http://localhost:3001                            ║
╚══════════════════════════════════════════════════════════════╝
  `);

  let dashboard: ChildProcess;

  if (useStandalone && dashboardPath) {
    // Use standalone server (npm package distribution)
    dashboard = spawn(process.execPath, ['server.js'], {
      cwd: dashboardPath.cwd,
      stdio: ['ignore', 'pipe', 'pipe'],
      env: { ...process.env, PORT: '3030', HOSTNAME: '0.0.0.0' },
    });
  } else {
    // Fall back to npm run start (local development)
    // Don't use shell: true — it fails on macOS Tahoe when /bin/zsh isn't accessible.
    // Instead, find the npm binary path and spawn it directly.
    const npmPath = process.platform === 'win32' ? 'npm.cmd' : 'npm';
    dashboard = spawn(npmPath, ['run', 'start'], {
      cwd: dashboardDir,
      stdio: ['ignore', 'pipe', 'pipe'],
    });
  }

  // Pipe dashboard output with prefix
  dashboard.stdout?.on('data', (data) => {
    const lines = data.toString().split('\n').filter((l: string) => l.trim());
    for (const line of lines) {
      console.log(`[dashboard] ${line}`);
    }
  });

  dashboard.stderr?.on('data', (data) => {
    const lines = data.toString().split('\n').filter((l: string) => l.trim());
    for (const line of lines) {
      console.error(`[dashboard] ${line}`);
    }
  });

  dashboard.on('error', (error) => {
    console.error('[dashboard] Failed to start:', error.message);
    if (error.message.includes('ENOENT') || error.message.includes('spawn')) {
      console.error(`
╔══════════════════════════════════════════════════════════════╗
║  ⚠️  Dashboard spawn failed (shell not found)                 ║
╠══════════════════════════════════════════════════════════════╣
║  This can happen on newer macOS versions (Tahoe+).           ║
║                                                              ║
║  Manual workaround:                                          ║
║    cd ${dashboardDir}
║    npm run start                                             ║
║                                                              ║
║  Then visit: http://localhost:3030                           ║
╚══════════════════════════════════════════════════════════════╝
      `);
    } else if (!useStandalone) {
      console.error('[dashboard] Make sure to run "npm run build" in the dashboard directory first.');
    }
  });

  dashboard.on('exit', (code, signal) => {
    if (signal) {
      console.log(`[dashboard] Killed by signal ${signal}`);
    } else if (code !== 0) {
      console.error(`[dashboard] Exited with code ${code}`);
    }
  });

  return dashboard;
}

async function startWorkerMode(dbPath?: string): Promise<void> {
  const { initDatabase } = await import('./database/init.js');
  const { startDefaultWorker } = await import('./worker/brain-worker.js');

  initDatabase(dbPath);
  startDefaultWorker();

  console.log(`
╔══════════════════════════════════════════════════════════════╗
║             ShieldCortex Worker Service                     ║
╠══════════════════════════════════════════════════════════════╣
║  Running headless background worker                         ║
║  Heartbeats keep this device online in ShieldCortex Cloud   ║
║  Sync retries and graph maintenance remain active           ║
╚══════════════════════════════════════════════════════════════╝
  `);

  const keepAlive = setInterval(() => {
    // Intentionally empty. BrainWorker timers are unref()'d, so the service
    // needs one referenced timer to remain alive as a daemon.
  }, 60 * 60 * 1000);

  const shutdown = (signal: string) => {
    console.log(`\nReceived ${signal}, stopping ShieldCortex worker...`);
    clearInterval(keepAlive);
    stopDefaultWorker();
    process.exit(0);
  };

  process.on('SIGINT', () => shutdown('SIGINT'));
  process.on('SIGTERM', () => shutdown('SIGTERM'));
}

function checkLocalHttp(url: string, expectedStatus: number[] = [200], timeoutMs = 1200): Promise<boolean> {
  return new Promise((resolve) => {
    const req = http.get(url, { timeout: timeoutMs }, (res) => {
      res.resume();
      resolve(Boolean(res.statusCode && expectedStatus.includes(res.statusCode)));
    });

    req.on('timeout', () => {
      req.destroy();
      resolve(false);
    });

    req.on('error', () => resolve(false));
  });
}

async function isLocalApiRunning(): Promise<boolean> {
  return checkLocalHttp('http://127.0.0.1:3001/api/health');
}

async function isLocalDashboardRunning(): Promise<boolean> {
  return checkLocalHttp('http://127.0.0.1:3030', [200, 307, 308]);
}

/**
 * Main entry point
 */
async function main() {
  // Warn if npx is serving a stale cached version
  checkVersionStaleness();
  const parsedArgs = parseArgs();

  // ── Trial welcome / expiry warning ──────────────────────
  // Only show for interactive CLI commands (not MCP server mode — stdout must stay clean for JSON-RPC)
  if (process.argv[2] && parsedArgs.mode !== 'mcp') {
    try {
      const { existsSync } = await import('fs');
      const { join } = await import('path');
      const { homedir } = await import('os');
      const { getTrialStatus } = await import('./license/trial.js');
      const { acknowledgeTrialWelcome } = await import('./license/trial.js');
      const { getLicense } = await import('./license/store.js');

      const licenseFile = join(homedir(), '.shieldcortex', 'license.json');
      const licenseFileExists = existsSync(licenseFile);
      const activeLicense = getLicense();

      // Only show trial messages when no paid license is active
      if (!activeLicense.valid) {
        const trial = getTrialStatus(licenseFileExists);

        if (trial?.justCreated) {
          // First ever run — show welcome message
          const expiryDate = new Date(trial.expiresAt).toLocaleDateString();
          const bold = '\x1b[1m';
          const reset = '\x1b[0m';
          const green = '\x1b[32m';
          const cyan = '\x1b[36m';
          const yellow = '\x1b[33m';

          console.log(`\n${bold}🎁 Welcome to ShieldCortex!${reset}\n`);
          console.log(`You have a ${yellow}14-day Pro trial${reset} — all Pro features are unlocked.\n`);
          console.log(`  ${green}✓${reset} Custom injection patterns (up to 50)`);
          console.log(`  ${green}✓${reset} Custom Iron Dome policies`);
          console.log(`  ${green}✓${reset} Custom firewall rules`);
          console.log(`  ${green}✓${reset} Audit export (JSON/CSV)`);
          console.log(`  ${green}✓${reset} Skill scanner deep mode`);
          console.log(`\nYour trial expires on ${bold}${expiryDate}${reset}. Upgrade anytime at:`);
          console.log(`  ${cyan}https://shieldcortex.ai/pricing${reset}`);
          console.log(`\nRun: shieldcortex license status\n`);

          acknowledgeTrialWelcome();

        } else if (trial?.active && trial.daysRemaining <= 3) {
          // Trial expiring soon — show warning
          const yellow = '\x1b[33m';
          const cyan = '\x1b[36m';
          const reset = '\x1b[0m';
          const days = trial.daysRemaining;

          console.error(`${yellow}⚠️  Pro trial expires in ${days} day${days !== 1 ? 's' : ''}. Upgrade to keep Pro features:${reset}`);
          console.error(`    shieldcortex license activate <key>`);
          console.error(`    ${cyan}https://shieldcortex.ai/pricing${reset}\n`);
        }
      }
    } catch {
      // Best effort — never let trial messaging crash the CLI
    }

    // Show stats banner (threats blocked etc.) for interactive CLI modes
    try {
      const { printStatsBanner } = await import('./cli/stats-banner.js');
      await printStatsBanner();
    } catch {
      // Never fail startup over stats
    }
  }

  // Handle --help / -h / help / unknown args
  if (process.argv[2] === '--help' || process.argv[2] === '-h' || process.argv[2] === 'help') {
    const bold = '\x1b[1m';
    const cyan = '\x1b[36m';
    const reset = '\x1b[0m';
    console.log(`
${bold}ShieldCortex${reset} v${pkg.version} — AI Agent Memory Security

${bold}USAGE${reset}
  shieldcortex [command] [options]

${bold}COMMANDS${reset}
  ${cyan}scan${reset} <text>           Scan text through the defence pipeline
  ${cyan}scan-skill${reset} <path>     Scan an agent instruction file for threats
  ${cyan}scan-skills${reset}           Scan all installed skills/hooks
  ${cyan}dashboard${reset}             Open the local security dashboard
  ${cyan}worker${reset}                Run headless background sync + heartbeat worker
  ${cyan}status${reset}                Show current protection status
  ${cyan}doctor${reset}                Diagnose installation issues
  ${cyan}quickstart${reset} [target]    Detect integrations and guide/install setup
  ${cyan}config${reset} [options]      Configure cloud sync and settings
  ${cyan}cloud${reset} sync --full     Backfill local memories + graph to ShieldCortex Cloud
  ${cyan}review-copilot${reset} <action> Local AI Explainer for quarantine review (Pro)
  ${cyan}cortex${reset} <command>       Mistake learning & pre-flight checks (Pro)
  ${cyan}license${reset} <action>      Manage licence key (activate, status, deactivate)
  ${cyan}iron-dome${reset} <action>    Manage behaviour protection layer
  ${cyan}audit${reset} [options]       Run a full security audit
  ${cyan}setup${reset}                 Install ShieldCortex into your project
                        Flags: --with-stop-hook (sampled per-turn extraction)
                               --with-session-end (extraction on session exit)
                               Pass either to opt in; re-run without to opt out.
  ${cyan}uninstall${reset}             Remove ShieldCortex from your project
  ${cyan}openclaw${reset} <action>     Manage OpenClaw hook integration
  ${cyan}copilot${reset} <action>      Set up VS Code / Cursor MCP integration
  ${cyan}codex${reset} <action>        Set up Codex CLI / VS Code MCP integration
  ${cyan}graph${reset} backfill        Backfill knowledge graph from memories
  ${cyan}hook${reset} <action>         Manage hooks (start, stop, status)
  ${cyan}service${reset} <action>      Manage background service

${bold}OPTIONS${reset}
  --version, -v        Show version
  --help, -h           Show this help message

${bold}EXAMPLES${reset}
  shieldcortex quickstart
  shieldcortex scan "ignore previous instructions"
  shieldcortex scan-skill ~/.claude/skills/my-skill/SKILL.md
  shieldcortex dashboard
  shieldcortex worker
  shieldcortex install --with-stop-hook --with-session-end
  shieldcortex cortex preflight --task "deploy site"
  shieldcortex license activate sc_pro_...
  shieldcortex config --cloud-enable --cloud-api-key <key>
  shieldcortex cloud sync --full
  shieldcortex review-copilot status

${bold}DOCS${reset}
  https://shieldcortex.ai/docs
`);
    return;
  }

  // Handle --version / -v
  if (process.argv[2] === '--version' || process.argv[2] === '-v') {
    console.log(pkg.version);
    // --version --debug: show resolution paths for diagnosing stale versions
    if (process.argv[3] === '--debug') {
      const { fileURLToPath } = await import('url');
      const indexPath = fileURLToPath(import.meta.url);
      console.log(`  entry:        ${indexPath}`);
      console.log(`  package.json: ${require.resolve('../package.json')}`);
      console.log(`  argv[1]:      ${process.argv[1]}`);
    }
    return;
  }

  // Handle "doctor" subcommand
  if (process.argv[2] === 'doctor') {
    const { runDoctor } = await import('./cli/doctor.js');
    await runDoctor();
    return;
  }

  // Handle "quickstart" subcommand
  if (process.argv[2] === 'quickstart') {
    const { handleQuickstartCommand } = await import('./setup/quickstart.js');
    await handleQuickstartCommand(process.argv[3]);
    return;
  }

  // Handle "setup" subcommand (alias: "install")
  if (process.argv[2] === 'setup' || process.argv[2] === 'install') {
    if (process.argv[3] === 'uninstall') {
      const { uninstallSetup } = await import('./setup/uninstall.js');
      await uninstallSetup();
      return;
    }
    const stopHook = process.argv.includes('--with-stop-hook');
    const sessionEnd = process.argv.includes('--with-session-end');
    await setupClaudeMd({ stopHook, sessionEnd });
    return;
  }

  // Handle "migrate" subcommand
  if (process.argv[2] === 'migrate') {
    const { handleMigrateCommand } = await import('./setup/migrate.js');
    await handleMigrateCommand();
    return;
  }

  // Handle "uninstall" subcommand
  if (process.argv[2] === 'uninstall') {
    const { uninstallAll } = await import('./setup/uninstall.js');
    await uninstallAll({
      keepLogs: process.argv.includes('--keep-logs'),
      deep: process.argv.includes('--deep'),
      restartGateway: !process.argv.includes('--no-gateway-restart'),
    });
    return;
  }

  // Handle "hook" subcommand
  if (process.argv[2] === 'hook') {
    await handleHookCommand(process.argv[3] || '');
    return;
  }

  // Handle "openclaw" subcommand (backward compat: "clawdbot" also accepted)
  if (process.argv[2] === 'openclaw' || process.argv[2] === 'clawdbot') {
    await handleOpenClawCommand(process.argv[3] || '', process.argv.slice(4));
    return;
  }

  // Handle "copilot" subcommand (VS Code + Cursor MCP setup)
  if (process.argv[2] === 'copilot') {
    await handleCopilotCommand(process.argv[3] || '');
    return;
  }

  // Handle "codex" subcommand (Codex CLI + VS Code MCP setup)
  if (process.argv[2] === 'codex') {
    await handleCodexCommand(process.argv[3] || '');
    return;
  }

  // Handle "service" subcommand before normal mode parsing
  if (process.argv[2] === 'service') {
    await handleServiceCommand(process.argv[3] || '', process.argv.slice(4));
    return;
  }

  // Handle "config" subcommand (cloud sync configuration)
  if (process.argv[2] === 'config') {
    const { handleCloudConfig } = await import('./cloud/cli.js');
    handleCloudConfig(process.argv.slice(3));
    return;
  }

  // Handle "cloud" subcommand
  if (process.argv[2] === 'cloud') {
    const { handleCloudCommand } = await import('./cloud/cli.js');
    await handleCloudCommand(process.argv.slice(3));
    return;
  }

  // Handle "review-copilot" subcommand (backwards-compatible Local AI Explainer command)
  if (process.argv[2] === 'review-copilot') {
    const { handleReviewCopilotCommand } = await import('./cli/review-copilot.js');
    await handleReviewCopilotCommand(process.argv.slice(3), parsedArgs.dbPath);
    return;
  }

  // Handle "memories" subcommand (memory database operations: migrate-legacy, ...)
  if (process.argv[2] === 'memories') {
    const { handleMemoriesCommand } = await import('./cli/migrate-legacy.js');
    await handleMemoriesCommand(process.argv.slice(3));
    return;
  }

  // Handle "status" subcommand
  if (process.argv[2] === 'status') {
    const { handleStatusCommand } = await import('./setup/status.js');
    await handleStatusCommand();
    return;
  }

  // Handle "update" subcommand
  if (process.argv[2] === 'update') {
    const { execSync } = await import('child_process');
    const fs = await import('fs');
    const { homedir } = await import('os');
    const home = homedir();
    const pkgPath = new URL('../package.json', import.meta.url);
    const currentVersion = JSON.parse(fs.readFileSync(pkgPath, 'utf-8')).version ?? 'unknown';

    console.log(`Current version: v${currentVersion}`);
    console.log('Checking for updates...');

    // Step 1 — update the npm package if a newer version exists.
    let mainUpdated = false;
    try {
      const latest = execSync('npm view shieldcortex version', { encoding: 'utf-8', timeout: 10000 }).trim();

      if (latest === currentVersion) {
        console.log(`✓ Main package already on v${latest}`);
      } else {
        console.log(`New version available: v${latest}`);
        console.log('Updating npm package...');
        execSync('npm install -g shieldcortex@latest', { stdio: 'inherit', timeout: 120000 });
        console.log(`✓ Updated to v${latest}`);
        mainUpdated = true;
      }
    } catch (error) {
      console.error(`npm update failed: ${(error as Error).message}`);
      console.error('Try manually: npm install -g shieldcortex@latest');
      // Continue — plugin + skill may still have their own updates available.
    }

    // Step 2 — always reconcile the OpenClaw plugin. Plugin and skill have their
    // own release cadences; skipping them when main is current caused v4.9 → v4.10
    // users to be stuck on v4.9 of the plugin until they manually removed the
    // extension dir and re-ran `openclaw plugins install`.
    //
    // OpenClaw 2026.5.5 added a guard that refuses `plugins install` when the
    // plugin is already present at ~/.openclaw/npm/node_modules/<scope>/<name>
    // and tells the caller to use `update` or `--force`. Our reconcile always
    // *wants* to overwrite — that's the entire point of the step — so we pass
    // --force unconditionally. Works for fresh installs too (no-op when no
    // existing plugin to replace).
    try {
      const extDir = path.join(home, '.openclaw', 'extensions', 'shieldcortex-realtime');
      const npmDir = path.join(home, '.openclaw', 'npm', 'node_modules', '@drakon-systems', 'shieldcortex-realtime');
      if (fs.existsSync(extDir) || fs.existsSync(npmDir)) {
        console.log('Reconciling OpenClaw plugin...');
        // Best-effort cleanup of the legacy extensions/ path so 2026.5.x doesn't
        // see two install records. The npm/node_modules/ path is owned by the
        // OpenClaw installer and `--force` will replace it.
        try { fs.rmSync(extDir, { recursive: true, force: true }); } catch { /* ignore */ }
        try {
          execSync('openclaw plugins install --force @drakon-systems/shieldcortex-realtime@latest', {
            stdio: 'inherit',
            timeout: 60000,
            env: { ...process.env, HOME: home },
          });
          console.log('✓ OpenClaw plugin reconciled');
        } catch {
          console.warn('⚠ OpenClaw plugin reinstall failed — run manually:');
          console.warn('  openclaw plugins install --force @drakon-systems/shieldcortex-realtime');
        }
      }
    } catch {
      // OpenClaw not installed — skip silently
    }

    // Step 3 — always reconcile the OpenClaw / ClawHub skill.
    try {
      const skillDirs = [
        path.join(home, '.openclaw', 'workspace', 'skills', 'shieldcortex'),
        path.join(home, '.openclaw', 'skills', 'shieldcortex'),
        path.join(home, 'clawd', 'skills', 'shieldcortex'),
        path.join(home, 'friday', 'skills', 'shieldcortex'),
      ];
      const existingSkill = skillDirs.find(d => fs.existsSync(d));
      if (existingSkill) {
        console.log('Reconciling OpenClaw skill...');
        try {
          execSync('openclaw skills install shieldcortex --force', {
            stdio: 'inherit',
            timeout: 60000,
            env: { ...process.env, HOME: home },
          });
          console.log('✓ OpenClaw skill reconciled');
        } catch {
          console.warn('⚠ OpenClaw skill update failed — run manually:');
          console.warn('  openclaw skills install shieldcortex --force');
        }
      }
    } catch {
      // Skill update is best-effort
    }

    // Step 4 — migrate Claude Code hooks if needed.
    try {
      const { setupHooks } = await import('./setup/settings-hooks.js');
      setupHooks();
    } catch {
      // Hook migration is best-effort
    }

    if (mainUpdated) {
      console.log('Restart Claude Code / OpenClaw gateway to use the new version.');
    }

    // One-time notice for users crossing the v4.11.0 default-changes boundary.
    // `currentVersion` was captured pre-update, so any main-updated run that
    // came from <4.11.0 has the migration message shown once.
    try {
      const crossed4_11 = mainUpdated && /^\d+\.\d+\.\d+/.test(currentVersion) && (() => {
        const [maj, min] = currentVersion.split('.').map(Number);
        return maj < 4 || (maj === 4 && min < 11);
      })();
      if (crossed4_11) {
        console.log('');
        console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
        console.log(' ShieldCortex v4.11.0 — default behaviour changes');
        console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
        console.log('');
        console.log(' • Proactive recall on prompt submit is now OFF by default.');
        console.log(' • Tool-call interceptor no longer blocks critical/high');
        console.log('   severity writes with an approval prompt (defence still');
        console.log('   denies on failurePolicy).');
        console.log(' • SessionStart preamble instruction block is now OFF.');
        console.log(' • SessionStart memory cap reduced 15 → 5.');
        console.log(' • PreCompact thresholds raised; auto-memories cap 5 → 2.');
        console.log('');
        console.log(' Why: fleet evidence showed per-turn memory-injection tax');
        console.log(' was net-negative on fast agent loops. The defence pipeline');
        console.log(' stays on; only the memory-injection side is now opt-in.');
        console.log('');
        console.log(' To restore pre-v4.11.0 behaviour:');
        console.log('   shieldcortex config --restore-4.10-defaults');
        console.log('');
        console.log(' See CHANGELOG: https://github.com/Drakon-Systems-Ltd/ShieldCortex/blob/main/CHANGELOG.md');
        console.log('━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━');
      }
    } catch { /* notice is best-effort */ }

    return;
  }

  // Handle "graph" subcommand
  if (process.argv[2] === 'graph') {
    const action = process.argv[3];
    if (action === 'backfill') {
      const { initDatabase } = await import('./database/init.js');
      const os = await import('os');
      const dbPath = process.env.CLAUDE_MEMORY_DB || path.join(os.homedir(), '.shieldcortex', 'memories.db');
      initDatabase(dbPath);

      const { backfillGraph } = await import('./graph/backfill.js');
      const force = process.argv.includes('--force');
      console.log(force
        ? 'Force backfilling knowledge graph from ALL memories...'
        : 'Backfilling knowledge graph from new/updated memories...');
      const result = backfillGraph({ force });
      console.log(`Done! Extracted ${result.entities} new entities, ${result.triples} new triples from ${result.memoriesProcessed} memories (${result.memoriesSkipped} skipped).`);
    } else {
      console.error('Unknown graph command. Available: backfill');
      process.exit(1);
    }
    return;
  }

  // Handle "license" subcommand (also "licence" for British spelling)
  if (process.argv[2] === 'license' || process.argv[2] === 'licence') {
    const { handleLicenseCommand } = await import('./license/cli.js');
    await handleLicenseCommand(process.argv.slice(3));
    return;
  }

  // Handle "stats" subcommand — detailed security report
  if (process.argv[2] === 'stats') {
    const { runStatsCommand } = await import('./cli/stats-command.js');
    await runStatsCommand();
    return;
  }

  // Handle "audit" subcommand — full security audit of agent environment
  if (process.argv[2] === 'audit') {
    const { handleAuditCommand } = await import('./cli/audit.js');
    await handleAuditCommand(process.argv.slice(3));
    return;
  }

  // Handle "iron-dome" subcommand — behaviour protection layer
  if (process.argv[2] === 'iron-dome') {
    const { handleIronDomeCommand } = await import('./cli/iron-dome.js');
    await handleIronDomeCommand(process.argv.slice(3));
    return;
  }

  // Handle "scan" subcommand — lightweight content scan (no MCP server, no ONNX model)
  if (process.argv[2] === 'scan') {
    const text = process.argv[3];
    if (!text) {
      console.error('Usage: shieldcortex scan "text to analyse"');
      console.error('  Runs the defence pipeline (firewall + trust + sensitivity).');
      console.error('  No MCP server or ML model required — works on ARM64.');
      process.exit(1);
    }

    // Init database for audit logging
    const os = await import('os');
    const dbPath = process.env.CLAUDE_MEMORY_DB || path.join(os.homedir(), '.shieldcortex', 'memories.db');
    const { initDatabase } = await import('./database/init.js');
    initDatabase(dbPath);

    const { runDefencePipeline } = await import('./defence/pipeline.js');
    const source = { type: 'cli' as const, identifier: 'shieldcortex-scan' };
    const result = runDefencePipeline(text, 'CLI Scan', source);

    const bold = '\x1b[1m';
    const reset = '\x1b[0m';
    const green = '\x1b[32m';
    const red = '\x1b[31m';
    const yellow = '\x1b[33m';

    const resultColor = result.firewall.result === 'ALLOW' ? green :
                        result.firewall.result === 'QUARANTINE' ? yellow : red;

    console.log(`\n${bold}ShieldCortex Scan Result${reset}`);
    console.log(`${'─'.repeat(50)}`);
    console.log(`  Result:      ${resultColor}${result.firewall.result}${reset}`);
    console.log(`  Trust:       ${result.trust.score.toFixed(2)}`);
    console.log(`  Sensitivity: ${result.sensitivity.level}`);
    console.log(`  Anomaly:     ${result.firewall.anomalyScore.toFixed(2)}`);
    console.log(`  Reason:      ${result.firewall.reason}`);

    if (result.firewall.threatIndicators.length > 0) {
      console.log(`  Threats:     ${result.firewall.threatIndicators.join(', ')}`);
    }
    if (result.firewall.blockedPatterns.length > 0) {
      console.log(`  Patterns:    ${result.firewall.blockedPatterns.join(', ')}`);
    }

    if (result.credentialScan && result.credentialScan.findings.length > 0) {
      console.log(`\n${bold}Credential Findings (${result.credentialScan.findings.length}):${reset}`);
      for (const f of result.credentialScan.findings) {
        const sColor = f.severity === 'critical' ? red : f.severity === 'high' ? red : yellow;
        console.log(`  ${sColor}[${f.severity.toUpperCase()}]${reset} ${f.provider ? f.provider + ' ' : ''}${f.type}: ${f.match} (${f.action})`);
      }
    }

    console.log();
    process.exit(result.allowed ? 0 : 1);
  }

  // Handle "scan-skill" subcommand — scan a single skill/instruction file
  if (process.argv[2] === 'scan-skill') {
    const filePath = process.argv[3];
    if (!filePath) {
      console.error('Usage: shieldcortex scan-skill <path>');
      console.error('  Scans an agent instruction file for threats.');
      console.error('  Supports: SKILL.md, HOOK.md, handler.js, .cursorrules,');
      console.error('  .windsurfrules, .clinerules, CLAUDE.md, copilot-instructions.md,');
      console.error('  .aider.conf.yml, .continue/config.json');
      process.exit(1);
    }
    const { scanSkill } = await import('./defence/skill-scanner/index.js');
    const result = scanSkill(filePath);

    // Coloured output
    const severityColor: Record<string, string> = {
      critical: '\x1b[31m', // red
      high: '\x1b[91m',     // bright red
      medium: '\x1b[33m',   // yellow
      low: '\x1b[36m',      // cyan
    };
    const reset = '\x1b[0m';
    const bold = '\x1b[1m';

    console.log(`\n${bold}Skill Scanner Report${reset}`);
    console.log(`${'─'.repeat(50)}`);
    console.log(`  Skill:   ${result.skillName}`);
    console.log(`  Format:  ${result.format}`);
    console.log(`  Risk:    ${result.safe ? '\x1b[32mSAFE\x1b[0m' : `${severityColor[result.riskLevel] ?? ''}${result.riskLevel.toUpperCase()}${reset}`}`);
    console.log(`  Time:    ${result.scanDurationMs}ms`);

    if (result.findings.length > 0) {
      console.log(`\n${bold}Findings (${result.findings.length}):${reset}`);
      for (const f of result.findings) {
        const color = severityColor[f.severity] ?? '';
        console.log(`  ${color}[${f.severity.toUpperCase()}]${reset} ${f.pattern}`);
        console.log(`         ${f.description}`);
        if (f.matchedText) {
          console.log(`         Match: "${f.matchedText}"`);
        }
      }
    } else {
      console.log(`\n  \x1b[32mNo threats detected.\x1b[0m`);
    }

    console.log(`\n${result.summary}\n`);
    process.exit(result.safe ? 0 : 1);
  }

  // Handle "env" subcommand — Environment Firewall (Phase 1: scan a URL)
  if (process.argv[2] === 'env') {
    const sub = process.argv[3];
    if (sub !== 'scan') {
      console.error('Usage: shieldcortex env scan <url> [--json | --markdown]');
      console.error('  Fetches the URL, scores provenance, detects hidden instructions,');
      console.error('  runs injection patterns against visible + hidden content, and returns a taint label.');
      process.exit(1);
    }
    const urlArg = process.argv[4];
    if (!urlArg) {
      console.error('Usage: shieldcortex env scan <url> [--json | --markdown]');
      process.exit(1);
    }
    const wantsJson = process.argv.includes('--json');
    const wantsMarkdown = process.argv.includes('--markdown');

    const { scanUrl } = await import('./environment/index.js');
    const { formatEnvScanReport, formatEnvScanMarkdown } = await import('./environment/index.js');
    const result = await scanUrl(urlArg);

    if (wantsJson) {
      console.log(JSON.stringify(result, null, 2));
    } else if (wantsMarkdown) {
      console.log(formatEnvScanMarkdown(result));
    } else {
      console.log(formatEnvScanReport(result));
    }

    const blocking = result.taint.label === 'hostile' ? 2 : result.taint.label === 'suspicious' ? 1 : 0;
    process.exit(blocking);
  }

  // Handle "scan-skills" subcommand — scan all installed skills/hooks
  if (process.argv[2] === 'scan-skills') {
    const { scanSkill, discoverSkillFiles } = await import('./defence/skill-scanner/index.js');

    const customDir = process.argv.indexOf('--dir') !== -1
      ? process.argv[process.argv.indexOf('--dir') + 1]
      : undefined;

    const filesToScan = discoverSkillFiles(customDir);

    if (filesToScan.length === 0) {
      console.log('\nNo agent instruction files found to scan.');
      console.log('Checked: Claude Code skills, OpenClaw hooks, .cursorrules, CLAUDE.md, and more.');
      console.log('Use --dir <path> to scan a custom directory.\n');
      process.exit(0);
    }

    const bold = '\x1b[1m';
    const reset = '\x1b[0m';
    console.log(`\n${bold}Scanning ${filesToScan.length} file(s)...${reset}\n`);

    let threatCount = 0;
    const results: Array<{ path: string; safe: boolean; riskLevel: string; summary: string }> = [];

    for (const fp of filesToScan) {
      const result = scanSkill(fp);
      results.push({ path: fp, safe: result.safe, riskLevel: result.riskLevel, summary: result.summary });
      if (!result.safe) threatCount++;

      const icon = result.safe ? '\x1b[32m✓\x1b[0m' : '\x1b[31m✗\x1b[0m';
      const risk = result.safe ? '\x1b[32msafe\x1b[0m' : `\x1b[31m${result.riskLevel}\x1b[0m`;
      console.log(`  ${icon} ${risk.padEnd(20)} ${fp}`);
      if (!result.safe) {
        for (const f of result.findings) {
          if (f.severity === 'high' || f.severity === 'critical') {
            console.log(`    \x1b[31m[${f.severity}]\x1b[0m ${f.description}`);
          }
        }
      }
    }

    console.log(`\n${bold}Summary:${reset} ${filesToScan.length} scanned, ${threatCount} with threats\n`);
    process.exit(threatCount > 0 ? 1 : 0);
  }


  // Handle "consolidate" subcommand (v4.0.0 — Dream Mode)
  if (process.argv[2] === 'consolidate') {
    const { initDatabase } = await import('./database/init.js');
    initDatabase();
    const { consolidateMemories } = await import('./memory/consolidate.js');
    console.log('🧠 Starting Dream Mode consolidation...');
    const result = consolidateMemories();
    console.log(`✅ Consolidation complete:`);
    console.log(`   Near-duplicates merged: ${result.nearDuplicatesMerged}`);
    console.log(`   Archival candidates:    ${result.archivalCandidates}`);
    console.log(`   Contradictions found:   ${result.contradictionsDetected}`);
    console.log(`   Total processed:        ${result.totalProcessed}`);
    process.exit(0);
  }

  // Handle "xray" subcommand — package/file/plugin risk inspector
  if (process.argv[2] === 'xray') {
    const { handleXRayCommand } = await import('./xray/index.js');
    await handleXRayCommand(process.argv.slice(3));
    process.exit(0);
  }

  // Handle "xray-preinstall" subcommand — lightweight pre-install safety check
  if (process.argv[2] === 'xray-preinstall') {
    const { handlePreinstallCheck } = await import('./xray/preinstall.js');
    await handlePreinstallCheck();
    process.exit(0);
  }

  // Handle "cortex" subcommand (Pro tier — mistake learning)
  if (process.argv[2] === 'cortex') {
    const { handleCortexCommand } = await import('./cortex/cli.js');
    await handleCortexCommand(process.argv.slice(3));
    process.exit(0);
  }

  // Guard: if an unknown subcommand was given, show help instead of silently starting MCP
  const knownCommands = new Set([

    'doctor', 'quickstart', 'setup', 'install', 'migrate', 'uninstall', 'hook', 'update',
    'openclaw', 'clawdbot', 'copilot', 'codex', 'service', 'config', 'status',
    'graph', 'license', 'licence', 'audit', 'iron-dome', 'scan', 'cloud', 'review-copilot',
    'scan-skill', 'scan-skills', 'dashboard', 'api', 'worker', 'stats', 'cortex', 'consolidate', 'xray', 'xray-preinstall',
  ]);
  const arg = process.argv[2];
  if (arg && !arg.startsWith('-') && !knownCommands.has(arg)) {
    console.error(`Unknown command: ${arg}`);
    console.error(`Run 'shieldcortex --help' for a list of commands.`);
    process.exit(1);
  }

  const { dbPath, mode } = parsedArgs;

  let dashboardProcess: ChildProcess | null = null;

  if (mode === 'api') {
    // API mode only - for dashboard visualization
    if (await isLocalApiRunning()) {
      console.log('ShieldCortex API is already running at http://localhost:3001');
      return;
    }
    console.log('Starting ShieldCortex in API mode...');
    startVisualizationServer(dbPath);
  } else if (mode === 'dashboard') {
    // Dashboard mode - API + Next.js dashboard
    console.log('Starting ShieldCortex with Dashboard...');
    const apiRunning = await isLocalApiRunning();
    const dashboardRunning = await isLocalDashboardRunning();

    if (apiRunning && dashboardRunning) {
      console.log('ShieldCortex dashboard is already running.');
      console.log('Dashboard: http://localhost:3030');
      console.log('API:       http://localhost:3001');
      return;
    }

    if (!apiRunning) {
      startVisualizationServer(dbPath);
    } else {
      console.log('Reusing existing local ShieldCortex API on http://localhost:3001');
    }

    if (!dashboardRunning) {
      dashboardProcess = startDashboard();
    } else {
      console.log('Dashboard UI is already running on http://localhost:3030');
    }

    // Kill dashboard child process on any exit (prevents orphans)
    const killDashboard = () => {
      if (dashboardProcess && !dashboardProcess.killed) {
        dashboardProcess.kill('SIGTERM');
      }
    };

    // Clean up on normal signals
    const shutdown = (signal: string) => {
      console.log(`\nReceived ${signal}, shutting down...`);
      killDashboard();
      process.exit(0);
    };

    process.on('SIGINT', () => shutdown('SIGINT'));
    process.on('SIGTERM', () => shutdown('SIGTERM'));

    // Clean up on any exit (catches crashes, EADDRINUSE, uncaught exceptions)
    process.on('exit', killDashboard);
    process.on('uncaughtException', (err) => {
      console.error('[ShieldCortex] Uncaught exception:', err.message);
      killDashboard();
      process.exit(1);
    });
  } else if (mode === 'both') {
    // Both modes - API in background, MCP in foreground
    console.log('Starting ShieldCortex in both modes...');
    if (!(await isLocalApiRunning())) {
      startVisualizationServer(dbPath);
    } else {
      console.log('Reusing existing local ShieldCortex API on http://localhost:3001');
    }
    await startMcpServer(dbPath);
  } else if (mode === 'worker') {
    console.log('Starting ShieldCortex in headless worker mode...');
    await startWorkerMode(dbPath);
  } else {
    // MCP mode (default) - for Claude Code integration
    await startMcpServer(dbPath);
  }
}

// ── Library re-exports (safe, no side effects) ────────────
// When imported as a library (`import { ... } from 'shieldcortex'`),
// only these exports are evaluated — no MCP server, no workers.
export * from './lib.js';

// ── CLI guard ──────────────────────────────────────────────
// Only run the CLI when executed directly (npx shieldcortex / node dist/index.js).
// Skip when imported as a module (`import 'shieldcortex'`).
const resolvedArgv = (() => {
  try { return process.argv[1] ? fs.realpathSync(process.argv[1]) : ''; }
  catch { return process.argv[1] || ''; }
})();
const thisFile = fileURLToPath(import.meta.url);

const isCLI =
  process.argv[1] &&
  (
    process.argv[1] === thisFile ||
    resolvedArgv === thisFile ||
    process.argv[1].endsWith('/shieldcortex/dist/index.js') ||
    process.argv[1].endsWith('\\shieldcortex\\dist\\index.js') ||
    path.basename(process.argv[1]) === 'shieldcortex'
  );

if (isCLI) {
  main().catch((error) => {
    // Log to stderr to avoid corrupting MCP protocol
    console.error('Failed to start shieldcortex server:', error);
    process.exit(1);
  });
}
