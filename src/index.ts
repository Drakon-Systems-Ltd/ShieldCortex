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
import { createRequire } from 'module';
import { execSync } from 'child_process';

// Heavy modules (MCP server, visualization API + express/cors/ws, embedding
// model, brain worker, installer handlers) are loaded lazily via `await import`
// inside the dispatch branch that needs them — keeping per-prompt hook startup
// and lightweight CLI commands (--version, --help, status, doctor) fast. See
// Phase 11 of the hardening plan: the `hook` path must not eagerly pull in any
// of these, nor run the npx-staleness check.

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

/**
 * Should the interactive stats banner print for this invocation?
 *
 * It must print for normal interactive CLI commands (status, scan, doctor,
 * audit, setup, …) but NEVER for:
 *   - the MCP stdio server path (bare `shieldcortex`, `shieldcortex --db x`,
 *     or `shieldcortex --mode mcp`) — stdout there is the JSON-RPC channel and
 *     any banner bytes corrupt the protocol;
 *   - the per-prompt `hook` path (dispatched + returned before this is reached).
 *
 * The previous guard was `argv[2] && mode !== 'mcp'`. That was broken because
 * `parseArgs()` defaults `mode` to `'mcp'` for EVERY command except the few
 * server modes (dashboard/api/worker/--mode) — so `status`, `scan`, `doctor`,
 * `audit` etc. all kept `mode === 'mcp'` and were silently excluded, and the
 * banner never showed for any normal command (Phase 11 reordered this block but
 * left the faulty condition).
 *
 * The reliable discriminator is a POSITIONAL command word: the MCP stdio launch
 * is only ever reached with no positional command (flags only). So we show the
 * banner when either (a) there's a positional first arg that isn't a flag, or
 * (b) a non-mcp server mode was selected. `mcp` as an explicit positional
 * subcommand IS an interactive CLI command (the MCP-config scanner) — it parses
 * to mode 'mcp' but is not the stdio server, and prints normal stdout, so it's
 * fine for it to show the banner.
 *
 * Exported for unit testing.
 */
export function shouldShowInteractiveBanner(argv: string[], mode: ServerMode): boolean {
  const first = argv[2];
  if (!first) return false; // bare invocation → MCP stdio server
  // A positional (non-flag) first arg means a CLI subcommand was given.
  const hasPositionalCommand = !first.startsWith('-');
  if (hasPositionalCommand) {
    // The only way a positional first arg lands on the stdio MCP server is the
    // explicit server-mode words, which select a non-mcp mode anyway — so any
    // positional command that resolves to mode 'mcp' is an interactive command
    // (e.g. `mcp`, `scan`, `status`). Always show for positional commands.
    return true;
  }
  // Flag-only invocation (e.g. `--db x`, `--mode mcp`, `--version`). Show only
  // when a non-mcp server mode was explicitly requested (dashboard/api/worker).
  return mode !== 'mcp';
}

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
  // MCP stdio contract: stdout is the JSON-RPC channel — NOTHING else may write
  // to it, or the client's transport hits a non-JSON byte and reports
  // "Connection closed". Route any stray console.log (ours, a lazily-imported
  // module's, or a dependency's — notably the in-process brain worker started
  // below) to stderr. The SDK's StdioServerTransport writes JSON-RPC via
  // process.stdout.write directly, so it is unaffected. Defence-in-depth: each
  // module also logs to stderr in its own right, but this guarantees the stream
  // stays clean even if a future code path forgets.
  console.log = (...args: unknown[]): void => { console.error(...args); };

  // Startup self-heal (#76): before we touch the database, make sure the
  // better-sqlite3 native binding actually loads. On an ABI mismatch (npm
  // version bump without `shieldcortex repair`) it wouldn't, and `createServer`
  // → `initDatabase` would throw, killing the process before the MCP handshake
  // — the client sees only a bare `-32000`. Attempt the documented repair
  // (reusing the `shieldcortex repair` machinery); if it can't heal, fail LOUDLY
  // to stderr + a breadcrumb naming the exact fix command, never a silent death.
  const { selfHealMcpNativeBinding } = await import('./setup/mcp-self-heal.js');
  const heal = await selfHealMcpNativeBinding();
  if (!heal.ok) {
    console.error(heal.message);
    if (heal.breadcrumbPath) console.error(`\nDetails written to: ${heal.breadcrumbPath}`);
    process.exit(1);
  }

  // Lazy-load heavy server/worker/embedding modules — only the actual MCP
  // server path needs them, so they stay out of fast CLI/hook startup.
  const { createServer } = await import('./server.js');
  const { disposeModel, preloadModel } = await import('./embeddings/index.js');
  const { startDefaultWorker, stopDefaultWorker } = await import('./worker/brain-worker.js');

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
      // #383: worker quarantines a corrupt on-disk weight and retries once.
      // If we still land here, the heal did not recover — operator should run doctor.
      console.error(
        '[shieldcortex] Model preload failed (worker heals a corrupt cache at most once per process; run `shieldcortex doctor` if this repeats):',
        err instanceof Error ? err.message : err,
      );
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
 * Controller returned from startDashboard. Exposes the same `killed` /
 * `kill()` surface that ChildProcess has, so caller code that supervises
 * the dashboard doesn't have to change. Internally, the controller may be
 * fronting a Next.js child that has been respawned one or more times after
 * an exit — the caller doesn't need to know.
 */
interface DashboardController {
  readonly killed: boolean;
  kill(signal?: NodeJS.Signals | number): boolean;
}

/**
 * Start the Next.js dashboard as a supervised child process.
 *
 * v4.27.1: if the child exits while the parent is still alive (crash, OOM,
 * port conflict at startup, etc.), respawn it with exponential backoff
 * (1 → 2 → 4 → 8 → 16 → 32 → 60 s, capped). Without this, a single child
 * crash leaves the parent serving only the API on :3001 while :3030 stays
 * silent — and launchd has no signal to restart the parent because the
 * parent itself is fine. Field-observed on Mac after a multi-day uptime.
 */
function startDashboard(): DashboardController {
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

  let current: ChildProcess | null = null;
  let restartCount = 0;
  let shuttingDown = false;
  let backoffTimer: NodeJS.Timeout | null = null;
  let lastSpawnAt = 0;

  const spawnChild = (): ChildProcess => {
    lastSpawnAt = Date.now();
    if (useStandalone && dashboardPath) {
      return spawn(process.execPath, ['server.js'], {
        cwd: dashboardPath.cwd,
        stdio: ['ignore', 'pipe', 'pipe'],
        env: { ...process.env, PORT: '3030', HOSTNAME: '127.0.0.1' },
      });
    }
    const npmPath = process.platform === 'win32' ? 'npm.cmd' : 'npm';
    return spawn(npmPath, ['run', 'start'], {
      cwd: dashboardDir,
      stdio: ['ignore', 'pipe', 'pipe'],
    });
  };

  const attach = (child: ChildProcess): void => {
    child.stdout?.on('data', (data) => {
      const lines = data.toString().split('\n').filter((l: string) => l.trim());
      for (const line of lines) console.log(`[dashboard] ${line}`);
    });

    child.stderr?.on('data', (data) => {
      const lines = data.toString().split('\n').filter((l: string) => l.trim());
      for (const line of lines) console.error(`[dashboard] ${line}`);
    });

    child.on('error', (error) => {
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

    child.on('exit', (code, signal) => {
      if (signal) {
        console.log(`[dashboard] Killed by signal ${signal}`);
      } else if (code !== 0) {
        console.error(`[dashboard] Exited with code ${code}`);
      } else {
        console.log('[dashboard] Exited normally');
      }

      if (shuttingDown) return;

      // Reset the restart counter if the child stayed up long enough
      // (>5 min) — this means it crashed long after a healthy start, not
      // a tight crash-loop. Lets backoff start from 1s on isolated faults.
      const uptimeMs = Date.now() - lastSpawnAt;
      if (uptimeMs > 5 * 60 * 1000) restartCount = 0;

      restartCount += 1;
      const delayMs = Math.min(60000, 1000 * Math.pow(2, Math.min(restartCount - 1, 6)));
      console.error(`[dashboard] Respawning in ${Math.round(delayMs / 1000)}s (attempt #${restartCount})`);

      backoffTimer = setTimeout(() => {
        backoffTimer = null;
        if (shuttingDown) return;
        current = spawnChild();
        attach(current);
      }, delayMs);
      backoffTimer.unref();
    });
  };

  current = spawnChild();
  attach(current);

  return {
    get killed(): boolean {
      // Match ChildProcess semantics — `killed` flips to true once a SIGTERM
      // has been delivered. We treat the controller as "killed" once the
      // caller has asked us to shut down, regardless of whether the child
      // happens to be mid-respawn at that moment.
      return shuttingDown || (current !== null && current.killed);
    },
    kill(signal: NodeJS.Signals | number = 'SIGTERM'): boolean {
      shuttingDown = true;
      if (backoffTimer) {
        clearTimeout(backoffTimer);
        backoffTimer = null;
      }
      if (current && !current.killed) {
        return current.kill(signal);
      }
      return false;
    },
  };
}

async function startWorkerMode(dbPath?: string): Promise<void> {
  const { initDatabase } = await import('./database/init.js');
  const { startDefaultWorker, stopDefaultWorker } = await import('./worker/brain-worker.js');

  initDatabase(dbPath);
  startDefaultWorker();

  // Resilience handlers (v4.14.8). Without these, any throw outside a tick's
  // try/catch — module load errors from optional integrations, fetch socket
  // errors that leak past best-effort wrappers, transient SQLite errors during
  // schema migration on startup — would crash the entire worker process and
  // leave a stale `worker.json` (pid recorded, no further ticks). systemd
  // would restart it under `service install`, but users running
  // `shieldcortex worker` interactively had no supervisor.
  process.on('uncaughtException', (err) => {
    console.error('[BrainWorker] uncaughtException — continuing:', err);
  });
  process.on('unhandledRejection', (reason) => {
    console.error('[BrainWorker] unhandledRejection — continuing:', reason);
  });
  // Ignore SIGHUP so SSH disconnect doesn't kill an interactive
  // `shieldcortex worker` session. systemd users get this for free, but
  // anyone running it from a terminal previously lost the worker the moment
  // they logged out.
  process.on('SIGHUP', () => {
    console.error('[BrainWorker] SIGHUP ignored — keeping worker alive');
  });

  console.log(`
╔══════════════════════════════════════════════════════════════╗
║             ShieldCortex Worker Service                     ║
╠══════════════════════════════════════════════════════════════╣
║  Running headless background worker                         ║
║  Heartbeats keep this device online in ShieldCortex Cloud   ║
║  Sync retries and graph maintenance remain active           ║
╚══════════════════════════════════════════════════════════════╝

  For persistence across reboots, run:
    shieldcortex service install --headless
  (otherwise this process dies when the parent shell exits)
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
  // Dispatch the "hook" subcommand FIRST — before checkVersionStaleness() and
  // the stats banner. Hooks fire on every UserPromptSubmit, so this path
  // must be as cheap as possible: no `npm ls -g` staleness probe (hooks were
  // migrated to the global binary, where the warning is meaningless) and no
  // stats banners. handleHookCommand is imported lazily so the rest of
  // the installer surface stays out of hook startup.
  if (process.argv[2] === 'hook') {
    const { handleHookCommand } = await import('./setup/hooks.js');
    await handleHookCommand(process.argv[3] || '');
    return;
  }

  // Warn if npx is serving a stale cached version
  checkVersionStaleness();
  const parsedArgs = parseArgs();

  // ── Interactive stats banner ─────────────────────────────
  // Only show for interactive CLI commands. shouldShowInteractiveBanner gates
  // out the MCP stdio server path (bare / --mode mcp / --db) where stdout is
  // the JSON-RPC channel; the per-prompt `hook` path already returned above.
  // (The trial welcome/expiry banner that used to render here was removed with
  // the auto Pro trial — every local feature is Free now.)
  if (shouldShowInteractiveBanner(process.argv, parsedArgs.mode)) {
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
  ${cyan}remember${reset} <title>       Write a memory (via the defence pipeline)
                        --content <text> or pipe via stdin; --importance, --tags
  ${cyan}memories${reset} import-native Import native Markdown once through full defence
                        (dry-run by default; --apply admits then archives)
  ${cyan}scan${reset} <text>           Scan text through the defence pipeline
  ${cyan}scan-skill${reset} <path>     Scan an agent instruction file for threats
                        (--accept to suppress a reviewed file; --forget to undo)
  ${cyan}scan-skills${reset}           Scan all installed skills/hooks
  ${cyan}dashboard${reset}             Open the local security dashboard
  ${cyan}worker${reset}                Run headless background sync + heartbeat worker
  ${cyan}status${reset}                Show current protection status
  ${cyan}doctor${reset}                Diagnose installation issues (exits 1 on a ❌; --strict also fails on ⚠️)
  ${cyan}vacuum${reset}                Compact the memory DB, reclaiming free pages (no sqlite3 CLI needed)
  ${cyan}sessions${reset} prune        Delete old session-capture events (dry-run; --days N, --execute)
  ${cyan}approve${reset} [hash]        Grant a one-shot Action Guard approval for one exact
                        command (no hash = list recent refusals; --ttl N minutes)
  ${cyan}allowlist${reset} [add|remove|verify|scan]
                        Pin a human-reviewed script (path + content hash)
                        so the guard stops folding its source; any edit re-gates it.
                        scan = discover cron-referenced scripts and TTY-batch-review new/changed
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
                               --without-stop-hook / --without-session-end (opt out)
                               (absent flags leave existing opt-ins unchanged)
                               Pass either to opt in; re-run without to opt out.
  ${cyan}uninstall${reset}             Remove ShieldCortex from your project
  ${cyan}openclaw${reset} <action>     Manage OpenClaw hook integration
  ${cyan}copilot${reset} <action>      Set up VS Code / Cursor MCP integration
  ${cyan}codex${reset} <action>        Set up Codex CLI / VS Code MCP integration (memory only)
  ${cyan}hermes${reset} <action>       Install the Hermes pre_tool_call Action Guard plugin
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
    await runDoctor(process.argv.slice(3));
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
    const { parseHookOptInFlags } = await import('./setup/settings-hooks.js');
    const { setupClaudeMd } = await import('./setup/claude-md.js');
    await setupClaudeMd(parseHookOptInFlags(process.argv));
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

  // NOTE: the "hook" subcommand is dispatched at the very top of main(),
  // before checkVersionStaleness() and the stats banner — it must stay
  // fast (fires on every UserPromptSubmit) and never run `npm ls -g`.

  // Handle "openclaw" subcommand (backward compat: "clawdbot" also accepted)
  if (process.argv[2] === 'openclaw' || process.argv[2] === 'clawdbot') {
    const { handleOpenClawCommand } = await import('./setup/openclaw.js');
    await handleOpenClawCommand(process.argv[3] || '', process.argv.slice(4));
    return;
  }

  // Handle "copilot" subcommand (VS Code + Cursor MCP setup)
  if (process.argv[2] === 'copilot') {
    const { handleCopilotCommand } = await import('./setup/copilot.js');
    await handleCopilotCommand(process.argv[3] || '');
    return;
  }

  // Handle "codex" subcommand (Codex CLI + VS Code MCP setup)
  if (process.argv[2] === 'codex') {
    const { handleCodexCommand } = await import('./setup/codex.js');
    await handleCodexCommand(process.argv[3] || '');
    return;
  }

  if (process.argv[2] === 'hermes') {
    const { handleHermesCommand } = await import('./setup/hermes.js');
    await handleHermesCommand(process.argv[3] || '');
    return;
  }

  // Handle "service" subcommand before normal mode parsing
  if (process.argv[2] === 'service') {
    const { handleServiceCommand } = await import('./service/install.js');
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

  // Handle "remember" subcommand (Phase 15c) — direct, non-hanging memory write
  // through the same defence pipeline + project scoping the MCP tool uses.
  // Content via --content or piped stdin; never blocks on a TTY (prints usage).
  if (process.argv[2] === 'remember') {
    const { handleRememberCommand } = await import('./cli/remember.js');
    await handleRememberCommand(process.argv.slice(3));
    return;
  }

  // Handle "import-jsonl" subcommand — import Claude Code session transcripts
  // into session_events for dashboard replay.
  if (process.argv[2] === 'import-jsonl') {
    const { handleImportJsonlCommand } = await import('./cli/import-jsonl.js');
    await handleImportJsonlCommand(process.argv.slice(3));
    return;
  }

  // Handle "sessions" subcommand (#110) — session-capture maintenance
  // (currently `sessions prune`, the retention valve for session_events).
  if (process.argv[2] === 'sessions') {
    const { handleSessionsCommand } = await import('./cli/sessions.js');
    await handleSessionsCommand(process.argv.slice(3));
    return;
  }

  // Handle "approve" subcommand (#118) — one-shot exact-command Action Guard
  // approvals. Granting requires a TTY; see src/cli/approve.ts for why.
  if (process.argv[2] === 'approve') {
    const { runApprove } = await import('./cli/approve.js');
    process.exitCode = runApprove(process.argv.slice(3));
    return;
  }

  // Handle "deny" subcommand (#143) — the sibling of "approve": reject a
  // pending Action Guard request. Same store, same TTY gate; see
  // src/cli/deny.ts. Exists so a notification transport can offer approve and
  // deny as equally cheap, one-tap affordances on the same hash.
  if (process.argv[2] === 'deny') {
    const { runDeny } = await import('./cli/deny.js');
    process.exitCode = runDeny(process.argv.slice(3));
    return;
  }

  // Handle "allowlist" subcommand (#189) — the reviewed-script allowlist:
  // standing, content-hash-pinned trust for human-reviewed scripts, where
  // approve/deny above are one-shot. TTY-gated on every mutating verb.
  if (process.argv[2] === 'allowlist') {
    const { runAllowlist } = await import('./cli/allowlist.js');
    // scan is async (TTY prompts); add/list/verify stay sync.
    process.exitCode = await Promise.resolve(runAllowlist(process.argv.slice(3)));
    return;
  }

  // Handle "freeze"/"unfreeze"/"lease" (#227) — the session action lease's
  // operator surface. freeze/unfreeze are TTY-gated inside the command (no
  // env escape hatch — an agent must not lift the freeze that binds it);
  // `lease status` is read-only and ungated.
  if (process.argv[2] === 'freeze') {
    const { runFreezeCommand } = await import('./cli/freeze.js');
    process.exitCode = runFreezeCommand(process.argv.slice(3));
    return;
  }
  if (process.argv[2] === 'unfreeze') {
    const { runUnfreezeCommand } = await import('./cli/freeze.js');
    process.exitCode = runUnfreezeCommand(process.argv.slice(3));
    return;
  }
  if (process.argv[2] === 'lease') {
    const { runLeaseStatusCommand } = await import('./cli/freeze.js');
    process.exitCode = runLeaseStatusCommand();
    return;
  }

  // Handle "status" subcommand
  if (process.argv[2] === 'status') {
    const { handleStatusCommand } = await import('./setup/status.js');
    await handleStatusCommand();
    return;
  }

  // Handle "update" subcommand — delegated to ./cli/update.ts which renders
  // a progress-style flow (animated spinners on TTY, captured npm/openclaw
  // output, per-step timings, version-delta header). Same underlying steps
  // as the previous inline implementation.
  if (process.argv[2] === 'update') {
    const { runUpdate } = await import('./cli/update.js');
    await runUpdate();
    return;
  }

  // Handle "repair" subcommand — heal a broken install in place (currently the
  // better-sqlite3 native binding: rebuild in the install dir + re-verify).
  if (process.argv[2] === 'repair') {
    const { runRepair } = await import('./cli/repair.js');
    await runRepair(process.argv.slice(3));
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

  // Handle "threat-graph" subcommand (docs/design/2026-08-11-threat-graph.md)
  if (process.argv[2] === 'threat-graph') {
    const action = process.argv[3];
    const KNOWN = ['rebuild', 'status', 'reset-source', 'campaigns', 'conflicts', 'resolve-conflict'];
    if (!KNOWN.includes(action)) {
      console.error(`Unknown threat-graph command. Available: ${KNOWN.join(', ')}`);
      process.exit(1);
    }
    const { initDatabase } = await import('./database/init.js');
    const os = await import('os');
    const dbPath = process.env.CLAUDE_MEMORY_DB || path.join(os.homedir(), '.shieldcortex', 'memories.db');
    initDatabase(dbPath);

    if (action === 'rebuild') {
      const { rebuildThreatGraph } = await import('./threat-graph/projector.js');
      const { defaultRealtimeAuditDir } = await import('./threat-graph/shared.js');
      console.log('Rebuilding the threat graph from both audit ledgers...');
      const result = rebuildThreatGraph({ realtimeDir: defaultRealtimeAuditDir() });
      console.log(
        `Done! Projected ${result.processed} audit rows (${result.eventNodes} notable events).` +
        (result.errors.length > 0 ? ` ${result.errors.length} note(s) recorded — see doctor.` : '')
      );
    } else if (action === 'status') {
      const { getDatabase } = await import('./database/init.js');
      const db = getDatabase();
      const state = db.prepare('SELECT * FROM threat_graph_state WHERE id = 1').get() as Record<string, unknown> | undefined;
      const maxAudit = (db.prepare('SELECT COALESCE(MAX(id), 0) as m FROM defence_audit').get() as { m: number }).m;
      const counts = db.prepare(
        'SELECT kind, COUNT(*) as c FROM threat_nodes GROUP BY kind ORDER BY kind'
      ).all() as Array<{ kind: string; c: number }>;
      console.log('Threat graph status:');
      console.log(`  cursor: ${state?.last_audit_id ?? 0} of ${maxAudit} audit rows`);
      console.log(`  realtime cursor: ${state?.last_rt_cursor || '(none)'}`);
      console.log(`  last run: ${state?.last_run_at ?? 'never'}`);
      if (state?.last_error) console.log(`  last error: ${state.last_error}`);
      for (const row of counts) console.log(`  ${row.kind}: ${row.c}`);
      const { listAllowances } = await import('./threat-graph/allowance.js');
      const allowances = listAllowances(Date.now());
      const active = allowances.filter(a => a.active).length;
      console.log(`  allowances: ${allowances.length} (${active} active)`);
      const campaignCount = (db.prepare("SELECT COUNT(*) AS c FROM threat_nodes WHERE kind = 'campaign'").get() as { c: number }).c;
      console.log(`  campaigns: ${campaignCount}`);
      const conflictCount = (db.prepare("SELECT COUNT(*) AS c FROM threat_nodes WHERE kind = 'event' AND key LIKE 'conflict:%'").get() as { c: number }).c;
      const disputedCount = (db.prepare('SELECT COUNT(*) AS c FROM triples WHERE disputed = 1').get() as { c: number }).c;
      console.log(`  conflicts: ${conflictCount} open (${disputedCount} disputed triples)`);
    } else if (action === 'campaigns') {
      const { getDatabase } = await import('./database/init.js');
      const { runCampaignDetection } = await import('./threat-graph/campaign.js');
      const r = runCampaignDetection({ nowMs: Date.now() });
      console.log(`Detected ${r.campaigns} campaign(s) across ${r.events} recent events.`);
      const db = getDatabase();
      const camps = db.prepare("SELECT key, label, attrs FROM threat_nodes WHERE kind = 'campaign' ORDER BY last_seen DESC").all() as Array<{ key: string; label: string; attrs: string }>;
      for (const c of camps) {
        const a = JSON.parse(c.attrs);
        console.log(`  ${c.key}  ${c.label}${a.entity_overlap ? ' · entity-corroborated' : ''}`);
        console.log(`    sources: ${a.sources.join(', ')}`);
        if (a.sessions?.length) console.log(`    sessions: ${a.sessions.join(', ')}`);
        if (a.patterns?.length) console.log(`    patterns: ${a.patterns.join(', ')}`);
      }
    } else if (action === 'reset-source') {
      const key = process.argv[4];
      if (!key) {
        console.error("Usage: shieldcortex threat-graph reset-source '<source-key>'  (e.g. 'agent:build-bot')");
        process.exit(1);
      }
      const { resetSourceRisk } = await import('./threat-graph/risk.js');
      const reviewedBy = process.env.USER || process.env.LOGNAME || 'operator';
      const result = resetSourceRisk(key, { reviewedBy });
      console.log(result.found
        ? `Reset accumulated risk for '${key}'. Recorded as an operator review by ${reviewedBy}. Risk re-accrues if the source keeps misbehaving.`
        : `No source '${key}' found in the threat graph — nothing to reset.`);
    } else if (action === 'conflicts') {
      const { getDatabase } = await import('./database/init.js');
      const { detectRelationConflicts } = await import('./threat-graph/conflict.js');
      const r = detectRelationConflicts({ nowMs: Date.now() });
      console.log(`${r.conflicts} open relation-channel conflict(s):`);
      const db = getDatabase();
      const nodes = db.prepare("SELECT key, attrs FROM threat_nodes WHERE kind = 'event' AND key LIKE 'conflict:%' ORDER BY last_seen DESC").all() as Array<{ key: string; attrs: string }>;
      for (const n of nodes) {
        const a = JSON.parse(n.attrs);
        console.log(`\n  ${n.key}  —  ${a.subject} ${a.predicate} (margin ${Number(a.detected_margin).toFixed(2)})`);
        for (const c of a.contenders as Array<Record<string, unknown>>) {
          const star = c.object_id === a.authoritative_object_id ? ' *authoritative' : '';
          console.log(`    → ${c.object}  [${c.writer_source ?? 'unknown'} @ trust ${c.eff_trust}]${star}`);
        }
      }
      if (nodes.length > 0) {
        console.log(`\nResolve with: shieldcortex threat-graph resolve-conflict '<key>' <keep-one|keep-both|reject-both> ['<object-to-keep>']`);
      }
    } else if (action === 'resolve-conflict') {
      const { getDatabase } = await import('./database/init.js');
      const { resolveConflict } = await import('./threat-graph/conflict.js');
      const key = process.argv[4];
      const modeArg = process.argv[5];
      const keptName = process.argv[6];
      const MODES: Record<string, 'keep_one' | 'keep_both' | 'reject_both'> = {
        'keep-one': 'keep_one', 'keep-both': 'keep_both', 'reject-both': 'reject_both',
      };
      const resolution = MODES[modeArg ?? ''];
      const m = /^conflict:(\d+):(.+)$/.exec(key ?? '');
      if (!m || !resolution) {
        console.error("Usage: shieldcortex threat-graph resolve-conflict '<conflict:SUBJECT_ID:predicate>' <keep-one|keep-both|reject-both> ['<object-to-keep>']");
        process.exit(1);
      }
      const subjectId = Number(m[1]);
      const predicate = m[2];
      const db = getDatabase();
      const node = db.prepare("SELECT attrs FROM threat_nodes WHERE kind = 'event' AND key = ?").get(key) as { attrs: string } | undefined;
      if (!node) {
        console.error(`No open conflict '${key}'. List them with: shieldcortex threat-graph conflicts`);
        process.exit(1);
      }
      let keptObjectId: number | undefined;
      if (resolution === 'keep_one') {
        const contenders = (JSON.parse(node.attrs).contenders ?? []) as Array<{ object: string; object_id: number }>;
        const match = contenders.filter(c => c.object === keptName);
        if (!keptName || match.length !== 1) {
          console.error(`keep-one needs exactly one matching object to keep. Contenders: ${contenders.map(c => c.object).join(', ')}`);
          process.exit(1);
        }
        keptObjectId = match[0].object_id;
      }
      const reviewedBy = process.env.USER || process.env.LOGNAME || 'operator';
      try {
        const res = resolveConflict({ subjectId, predicate, resolution, keptObjectId }, reviewedBy);
        console.log(`Resolved ${res.channelKey} as ${res.resolution} — ${res.suspended} edge(s) suspended. Recorded as an operator review by ${reviewedBy}.`);
      } catch (e) {
        // The open set can shift between listing and resolving (a fresh detection
        // pass, a concurrent edit). Surface the guided message, not a stack trace.
        console.error(`Could not resolve '${key}': ${e instanceof Error ? e.message : String(e)}`);
        console.error('Re-list current conflicts with: shieldcortex threat-graph conflicts');
        process.exit(1);
      }
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

  // Handle "mcp" subcommand (Phase 14) — scan configured MCP servers' tool
  // descriptions for poisoning / line-jumping and rug-pull drift.
  if (process.argv[2] === 'mcp') {
    const { handleMcpCommand } = await import('./cli/mcp.js');
    await handleMcpCommand(process.argv.slice(3));
    return;
  }

  // Handle "memory" subcommand (v4.25.0) — show / downvote / list a single
  // memory. Distinct from the existing "memories" (plural) command which
  // routes to migrate-legacy.
  if (process.argv[2] === 'memory') {
    const { handleMemoryCommand } = await import('./cli/memory.js');
    await handleMemoryCommand(process.argv.slice(3));
    return;
  }

  // Handle "inspect" subcommand (v4.25.0) — read the precompact ring buffer.
  if (process.argv[2] === 'inspect') {
    const { handleInspectCommand } = await import('./cli/inspect.js');
    await handleInspectCommand(process.argv.slice(3));
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
    // Hardcoded identity in this dispatch → attested by construction. Operator
    // decision (accept-with-soak): test BLOCKs accrue to cli:shieldcortex-scan;
    // the advisory soak absorbs it, and enforce stays off until FP-measured.
    const result = runDefencePipeline(text, 'CLI Scan', source, undefined, undefined, { sourceAttested: true });

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

    // Drain any in-flight cloud sync requests before exiting. Without this,
    // the fire-and-forget POST in syncToCloud() gets aborted when this
    // short-lived CLI process terminates — and on headless Linux servers
    // (no long-running dashboard daemon) every scan silently fails to sync.
    const { flushPendingCloudSync } = await import('./cloud/sync.js');
    await flushPendingCloudSync(8000);

    process.exit(result.allowed ? 0 : 1);
  }

  // Handle "scan-skill" subcommand — scan a single skill/instruction file
  if (process.argv[2] === 'scan-skill') {
    const filePath = process.argv[3];
    if (!filePath) {
      console.error('Usage: shieldcortex scan-skill <path> [--accept | --clear | --forget]');
      console.error('  Scans an agent instruction file for threats.');
      console.error('  Supports: SKILL.md, HOOK.md, handler.js, .cursorrules,');
      console.error('  .windsurfrules, .clinerules, CLAUDE.md, copilot-instructions.md,');
      console.error('  .aider.conf.yml, .continue/config.json');
      console.error('');
      console.error('  --accept / --clear   Mark this file (by content hash) as reviewed &');
      console.error('                       acceptable — suppresses re-flagging until it changes.');
      console.error('  --forget             Remove a previously recorded acceptance.');
      process.exit(1);
    }
    const { scanSkill, contentHash, recordVerdict, removeVerdict, getVerdict } =
      await import('./defence/skill-scanner/index.js');
    const { readFileSync } = await import('fs');

    const wantAccept = process.argv.includes('--accept') || process.argv.includes('--clear');
    const wantForget = process.argv.includes('--forget');

    const result = scanSkill(filePath);

    // Operator verdict management (issue #121) — stored by content hash so any
    // change to the file invalidates the acceptance and re-flags it.
    if (wantForget) {
      try {
        const hash = contentHash(readFileSync(filePath, 'utf-8'));
        const removed = removeVerdict(hash);
        console.log(removed
          ? `\nForgot the stored acceptance for ${result.skillName} (${filePath}).`
          : `\nNo stored acceptance found for the current content of ${filePath}.`);
        process.exit(0);
      } catch {
        console.error(`\nCould not read ${filePath} to forget its verdict.`);
        process.exit(1);
      }
    }
    if (wantAccept) {
      try {
        const hash = contentHash(readFileSync(filePath, 'utf-8'));
        recordVerdict(hash, {
          path: filePath,
          skillName: result.skillName,
          riskLevel: result.riskLevel,
          acceptedAt: new Date().toISOString(),
        });
        console.log(`\nAccepted ${result.skillName} (${filePath}).`);
        console.log('It will be suppressed in future scans until its content changes.');
        process.exit(0);
      } catch {
        console.error(`\nCould not read ${filePath} to accept it.`);
        process.exit(1);
      }
    }

    // Plain scan — note if the operator has already accepted this exact content.
    let accepted = false;
    try {
      accepted = !!getVerdict(contentHash(readFileSync(filePath, 'utf-8')));
    } catch { /* unreadable — handled by scan result */ }

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
    if (accepted && !result.safe) {
      console.log(`  Status:  \x1b[32maccepted by operator\x1b[0m (suppressed — re-flags if the file changes)`);
    }

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

    // Drain pending cloud sync — same reasoning as the `scan` subcommand.
    const { flushPendingCloudSync } = await import('./cloud/sync.js');
    await flushPendingCloudSync(8000);

    // An operator-accepted file exits clean even if findings remain.
    process.exit(result.safe || accepted ? 0 : 1);
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
    const { scanSkill, discoverSkillFiles, getFileVerdict, writeWarningsFile } =
      await import('./defence/skill-scanner/index.js');
    type FlaggedSkill = {
      skillName: string;
      path: string;
      riskLevel: string;
      summary: string;
    };

    const customDir = process.argv.indexOf('--dir') !== -1
      ? process.argv[process.argv.indexOf('--dir') + 1]
      : undefined;

    const filesToScan = discoverSkillFiles(customDir);

    if (filesToScan.length === 0) {
      console.log('\nNo agent instruction files found to scan.');
      console.log('Checked: Claude Code skills, OpenClaw hooks, .cursorrules, CLAUDE.md, and more.');
      console.log('Use --dir <path> to scan a custom directory.\n');
      // Nothing to scan → the workspace warnings file must not linger.
      writeWarningsFile(process.cwd(), []);
      process.exit(0);
    }

    const bold = '\x1b[1m';
    const reset = '\x1b[0m';
    console.log(`\n${bold}Scanning ${filesToScan.length} file(s)...${reset}\n`);

    let threatCount = 0;
    let acceptedCount = 0;
    const flagged: FlaggedSkill[] = [];

    for (const fp of filesToScan) {
      const result = scanSkill(fp);

      // Operator acceptance (issue #121): a reviewed file with unchanged content
      // is suppressed — it is not counted as a live threat.
      const accepted = !result.safe && !!getFileVerdict(fp);
      if (accepted) acceptedCount++;

      const flag = !result.safe && !accepted;
      if (flag) {
        threatCount++;
        flagged.push({
          skillName: result.skillName,
          path: fp,
          riskLevel: result.riskLevel,
          summary: result.summary,
        });
      }

      const icon = flag ? '\x1b[31m✗\x1b[0m' : '\x1b[32m✓\x1b[0m';
      const risk = flag
        ? `\x1b[31m${result.riskLevel}\x1b[0m`
        : accepted
          ? '\x1b[32maccepted\x1b[0m'
          : '\x1b[32msafe\x1b[0m';
      console.log(`  ${icon} ${risk.padEnd(20)} ${fp}`);
      if (flag) {
        for (const f of result.findings) {
          if (f.severity === 'high' || f.severity === 'critical') {
            console.log(`    \x1b[31m[${f.severity}]\x1b[0m ${f.description}`);
          }
        }
      }
    }

    // Regenerate the workspace warnings file so it always matches this scan.
    const action = writeWarningsFile(process.cwd(), flagged);

    const acceptedNote = acceptedCount > 0 ? `, ${acceptedCount} accepted` : '';
    console.log(`\n${bold}Summary:${reset} ${filesToScan.length} scanned, ${threatCount} with threats${acceptedNote}\n`);
    if (action === 'written') {
      console.log(`Wrote SHIELDCORTEX_WARNINGS.md to ${process.cwd()}\n`);
    }
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

  // Handle "vacuum" subcommand (alias "compact", 4.45.2) — reclaim DB file space.
  // consolidate/prune free *rows*, but SQLite keeps the freed pages in the file;
  // only VACUUM shrinks it on disk. Runs via the bundled better-sqlite3, so it
  // needs no standalone sqlite3 CLI — which minimal boxes (EDITH had none) lack,
  // and which the old doctor remedy wrongly assumed was present.
  if (process.argv[2] === 'vacuum' || process.argv[2] === 'compact') {
    const { initDatabase, getDatabase } = await import('./database/init.js');
    const { statSync } = await import('fs');
    initDatabase();
    const db = getDatabase();
    const dbFile = db.name;
    const sizeMB = (p: string): number => { try { return statSync(p).size / 1048576; } catch { return 0; } };
    const pageSize = db.pragma('page_size', { simple: true }) as number;
    const freelist = db.pragma('freelist_count', { simple: true }) as number;
    const before = sizeMB(dbFile);
    console.log(`🧹 Compacting ${dbFile}`);
    console.log(`   ${(freelist * pageSize / 1048576).toFixed(1)} MB of free pages to reclaim`);
    try {
      db.pragma('wal_checkpoint(TRUNCATE)'); // flush pending WAL so VACUUM sees everything
      db.exec('VACUUM');
      // In WAL mode VACUUM rewrites pages through the WAL, so the main file does NOT
      // shrink until the next checkpoint. Checkpoint again before measuring, or we'd
      // report "reclaimed 0 MB" while the file is still its old size on disk.
      db.pragma('wal_checkpoint(TRUNCATE)');
    } catch (err) {
      console.error(`❌ Vacuum failed: ${err instanceof Error ? err.message : String(err)}`);
      console.error('   The DB is likely locked by a running ShieldCortex process — stop it (or wait until idle) and retry.');
      process.exit(1);
    }
    const after = sizeMB(dbFile);
    console.log(`✅ ${before.toFixed(1)} MB → ${after.toFixed(1)} MB (reclaimed ${(before - after).toFixed(1)} MB)`);
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

    'doctor', 'quickstart', 'setup', 'install', 'migrate', 'uninstall', 'hook', 'update', 'repair',
    'openclaw', 'clawdbot', 'copilot', 'codex', 'hermes', 'service', 'config', 'status',
    'graph', 'license', 'licence', 'audit', 'mcp', 'iron-dome', 'scan', 'cloud', 'review-copilot',
    'scan-skill', 'scan-skills', 'dashboard', 'api', 'worker', 'stats', 'cortex', 'consolidate', 'xray', 'xray-preinstall',
    'memories', 'import-jsonl', 'remember', 'vacuum', 'compact', 'sessions', 'approve', 'deny', 'allowlist',
  ]);
  const arg = process.argv[2];
  if (arg && !arg.startsWith('-') && !knownCommands.has(arg)) {
    console.error(`Unknown command: ${arg}`);
    console.error(`Run 'shieldcortex --help' for a list of commands.`);
    process.exit(1);
  }

  const { dbPath, mode } = parsedArgs;

  let dashboardProcess: DashboardController | null = null;

  // Lazy-load the visualization server (pulls in express + cors + ws) only on
  // the modes that actually start it. mcp/worker never touch it.
  const needsVizServer = mode === 'api' || mode === 'dashboard' || mode === 'both';
  const startVisualizationServer = needsVizServer
    ? (await import('./api/visualization-server.js')).startVisualizationServer
    : undefined as never;

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
