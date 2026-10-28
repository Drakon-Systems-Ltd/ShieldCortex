/**
 * `shieldcortex mcp` CLI
 *
 * Phase 14 — tool-description poisoning + rug-pull drift detection.
 *
 * Usage:
 *   shieldcortex mcp scan                # scan all discovered MCP servers
 *   shieldcortex mcp scan --all          # explicit "scan everything"
 *   shieldcortex mcp scan <server-name>  # scan a single configured server
 *   shieldcortex mcp scan --json         # structured output (for CI / Phase 15b)
 *   shieldcortex mcp scan --ci           # structured output + exit non-zero on findings
 */

import {
  scanMcpTools,
  formatToolsReport,
  type ToolHashStore,
  type McpToolsScanReport,
} from '../audit/mcp-tools-scanner.js';
import { discoverMcpServers } from '../audit/mcp-config-scanner.js';
import { SqliteToolHashStore, migrateLegacyToolHashes } from '../audit/mcp-tool-hash-store.js';
import { toSarif } from '../xray/sarif.js';
import { stringifyJsonTerminalSafe } from './term-ui.js';

interface McpScanOptions {
  serverName?: string;
  all: boolean;
  json: boolean;
  sarif: boolean;
  ci: boolean;
}

function parseScanArgs(args: string[]): McpScanOptions {
  const options: McpScanOptions = { all: false, json: false, sarif: false, ci: false };
  for (const arg of args) {
    if (arg === '--all') options.all = true;
    else if (arg === '--json') options.json = true;
    else if (arg === '--sarif' || arg === '--format=sarif') options.sarif = true;
    else if (arg === '--ci') { options.ci = true; options.json = true; }
    else if (!arg.startsWith('-')) options.serverName = arg;
  }
  return options;
}

function printScanHelp(): void {
  console.log(`shieldcortex mcp scan — detect MCP tool-description poisoning + rug-pull drift

Connects to your configured MCP servers, lists the tools they advertise, and
scans every tool name / description / input-schema description for hidden
instructions (tool poisoning / line-jumping). Tracks a content hash per tool to
flag descriptions that changed since the last scan (rug-pull).

Usage:
  shieldcortex mcp scan [server-name] [--all] [--json] [--ci]

Options:
  --all     Scan every discovered server (default when no name is given)
  --json    Emit a structured JSON report
  --sarif   Emit SARIF 2.1.0 (GitHub Code Scanning)
  --ci      Like --json, but exit non-zero when findings are present
  -h,--help Show this help
`);
}

async function runScan(args: string[]): Promise<void> {
  if (args.includes('-h') || args.includes('--help')) {
    printScanHelp();
    return;
  }

  const options = parseScanArgs(args);

  // Init DB for the persistent hash store. If it fails, fall back to an
  // in-memory store so a scan still runs (drift just won't persist).
  let store: ToolHashStore;
  try {
    const os = await import('os');
    const path = await import('path');
    const dbPath = process.env.CLAUDE_MEMORY_DB || path.join(os.homedir(), '.shieldcortex', 'memories.db');
    const { initDatabase } = await import('../database/init.js');
    const db = initDatabase(dbPath);
    // Seed pre-scoping baselines into every source that defines the name (#925).
    migrateLegacyToolHashes(db, discoverMcpServers({ includeShadowed: true }));
    store = new SqliteToolHashStore(db);
  } catch (err) {
    if (!options.json && !options.sarif) {
      console.error(`\x1b[33m  ! Could not open hash store (${err instanceof Error ? err.message : String(err)}); drift will not persist.\x1b[0m`);
    }
    store = inMemoryStore();
  }

  const report: McpToolsScanReport = await scanMcpTools(store, options.all ? undefined : options.serverName);

  if (options.sarif) {
    // Pure SARIF JSON on stdout — uploadable straight to GitHub Code Scanning.
    console.log(stringifyJsonTerminalSafe(toSarif(report.findings), 2));
  } else if (options.json) {
    console.log(stringifyJsonTerminalSafe(report, 2));
  } else {
    console.log(formatToolsReport(report));
  }

  if (options.ci) {
    const blocking = report.findings.some((f) => f.severity === 'critical' || f.severity === 'high');
    process.exit(blocking ? 1 : 0);
  }
}

/** Throwaway store for the DB-unavailable fallback path. */
function inMemoryStore(): ToolHashStore {
  const map = new Map<string, string>();
  return {
    get: (server, tool) => map.get(`${server}\u0000${tool}`),
    set: (server, tool, hash) => { map.set(`${server}\u0000${tool}`, hash); },
  };
}

export async function handleMcpCommand(args: string[]): Promise<void> {
  const sub = args[0];
  if (!sub || sub === 'scan') {
    await runScan(args[0] === 'scan' ? args.slice(1) : args);
    return;
  }
  if (sub === '-h' || sub === '--help' || sub === 'help') {
    printScanHelp();
    return;
  }
  console.error(`Unknown mcp subcommand: ${sub}`);
  console.error(`Run 'shieldcortex mcp scan --help' for usage.`);
  process.exit(1);
}
