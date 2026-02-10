/**
 * Copilot / Cursor MCP server installer.
 *
 * Configures ShieldCortex as an MCP server for:
 * - VS Code (GitHub Copilot) — user-level mcp.json
 * - Cursor — global ~/.cursor/mcp.json
 */

import fs from 'fs';
import path from 'path';
import os from 'os';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const SERVER_NAME = 'shieldcortex-memory';

// MCP entry point: dist/index.js (one level up from dist/setup/)
const MCP_ENTRY = path.resolve(__dirname, '..', 'index.js');

// ── Helpers ──

interface McpConfig {
  [key: string]: unknown;
}

/**
 * Read a JSON file, returning {} if it doesn't exist or is invalid.
 */
function readJson(filePath: string): McpConfig {
  try {
    if (!fs.existsSync(filePath)) return {};
    const raw = fs.readFileSync(filePath, 'utf-8').trim();
    if (!raw) return {};
    return JSON.parse(raw);
  } catch {
    return {};
  }
}

/**
 * Write a JSON file, creating parent directories as needed.
 */
function writeJson(filePath: string, data: McpConfig): void {
  fs.mkdirSync(path.dirname(filePath), { recursive: true });
  fs.writeFileSync(filePath, JSON.stringify(data, null, 2) + '\n');
}

/**
 * Build the server entry for ShieldCortex MCP.
 */
function serverEntry(): McpConfig {
  return {
    type: 'stdio',
    command: 'node',
    args: [MCP_ENTRY],
  };
}

// ── VS Code ──

/**
 * Find VS Code user config directories (supports standard + Insiders).
 * Returns paths that exist on the filesystem.
 */
function findVsCodeDirs(): string[] {
  const home = os.homedir();
  const platform = process.platform;
  const dirs: string[] = [];

  const variants = ['Code', 'Code - Insiders'];

  for (const variant of variants) {
    let configDir: string;
    if (platform === 'darwin') {
      configDir = path.join(home, 'Library', 'Application Support', variant, 'User');
    } else if (platform === 'win32') {
      configDir = path.join(process.env.APPDATA ?? path.join(home, 'AppData', 'Roaming'), variant, 'User');
    } else {
      configDir = path.join(home, '.config', variant, 'User');
    }

    if (fs.existsSync(configDir)) {
      dirs.push(configDir);
    }
  }

  return dirs;
}

/**
 * Add ShieldCortex to a VS Code mcp.json file.
 * VS Code format: { "servers": { "name": { ... } } }
 */
function addToVsCode(configDir: string): boolean {
  const mcpPath = path.join(configDir, 'mcp.json');
  const config = readJson(mcpPath);

  if (!config.servers || typeof config.servers !== 'object') {
    config.servers = {};
  }

  const servers = config.servers as McpConfig;
  if (servers[SERVER_NAME]) {
    return false; // already configured
  }

  servers[SERVER_NAME] = serverEntry();
  writeJson(mcpPath, config);
  return true;
}

/**
 * Remove ShieldCortex from a VS Code mcp.json file.
 */
function removeFromVsCode(configDir: string): boolean {
  const mcpPath = path.join(configDir, 'mcp.json');
  const config = readJson(mcpPath);

  if (!config.servers || typeof config.servers !== 'object') return false;

  const servers = config.servers as McpConfig;
  if (!servers[SERVER_NAME]) return false;

  delete servers[SERVER_NAME];
  writeJson(mcpPath, config);
  return true;
}

// ── Cursor ──

/**
 * Find Cursor config directory.
 */
function findCursorDir(): string | null {
  const home = os.homedir();
  const cursorDir = path.join(home, '.cursor');
  return fs.existsSync(cursorDir) ? cursorDir : null;
}

/**
 * Add ShieldCortex to Cursor's mcp.json.
 * Cursor format: { "mcpServers": { "name": { ... } } }
 */
function addToCursor(cursorDir: string): boolean {
  const mcpPath = path.join(cursorDir, 'mcp.json');
  const config = readJson(mcpPath);

  if (!config.mcpServers || typeof config.mcpServers !== 'object') {
    config.mcpServers = {};
  }

  const servers = config.mcpServers as McpConfig;
  if (servers[SERVER_NAME]) {
    return false; // already configured
  }

  // Cursor doesn't use "type" field
  servers[SERVER_NAME] = {
    command: 'node',
    args: [MCP_ENTRY],
  };

  writeJson(mcpPath, config);
  return true;
}

/**
 * Remove ShieldCortex from Cursor's mcp.json.
 */
function removeFromCursor(cursorDir: string): boolean {
  const mcpPath = path.join(cursorDir, 'mcp.json');
  const config = readJson(mcpPath);

  if (!config.mcpServers || typeof config.mcpServers !== 'object') return false;

  const servers = config.mcpServers as McpConfig;
  if (!servers[SERVER_NAME]) return false;

  delete servers[SERVER_NAME];
  writeJson(mcpPath, config);
  return true;
}

// ── Public API ──

export async function installCopilot(): Promise<void> {
  // Verify MCP entry exists
  if (!fs.existsSync(MCP_ENTRY)) {
    console.error('ShieldCortex MCP entry point not found. Package may be corrupted.');
    console.error(`Expected: ${MCP_ENTRY}`);
    process.exit(1);
  }

  let installed = 0;

  // VS Code
  const vscodeDirs = findVsCodeDirs();
  for (const dir of vscodeDirs) {
    const variant = path.basename(path.dirname(dir)); // "Code" or "Code - Insiders"
    if (addToVsCode(dir)) {
      console.log(`  ✓ VS Code (${variant}) — added to ${path.join(dir, 'mcp.json')}`);
      installed++;
    } else {
      console.log(`  · VS Code (${variant}) — already configured`);
    }
  }

  if (vscodeDirs.length === 0) {
    console.log('  · VS Code — not found');
  }

  // Cursor
  const cursorDir = findCursorDir();
  if (cursorDir) {
    if (addToCursor(cursorDir)) {
      console.log(`  ✓ Cursor — added to ${path.join(cursorDir, 'mcp.json')}`);
      installed++;
    } else {
      console.log('  · Cursor — already configured');
    }
  } else {
    console.log('  · Cursor — not found');
  }

  console.log();
  if (installed > 0) {
    console.log(`Configured ShieldCortex MCP server (${SERVER_NAME}).`);
    console.log('Restart your editor for changes to take effect.');
    console.log();
    console.log('What it provides:');
    console.log('  • Persistent memory across sessions (remember, recall, forget)');
    console.log('  • Defence pipeline (firewall, trust scoring, audit trail)');
    console.log('  • Knowledge graph queries');
    console.log('  • Memory consolidation');
  } else if (vscodeDirs.length === 0 && !cursorDir) {
    console.error('Neither VS Code nor Cursor was found on this system.');
    process.exit(1);
  } else {
    console.log('ShieldCortex MCP server was already configured in all detected editors.');
  }
}

export async function uninstallCopilot(): Promise<void> {
  let removed = 0;

  // VS Code
  const vscodeDirs = findVsCodeDirs();
  for (const dir of vscodeDirs) {
    const variant = path.basename(path.dirname(dir));
    if (removeFromVsCode(dir)) {
      console.log(`  ✓ VS Code (${variant}) — removed`);
      removed++;
    }
  }

  // Cursor
  const cursorDir = findCursorDir();
  if (cursorDir) {
    if (removeFromCursor(cursorDir)) {
      console.log('  ✓ Cursor — removed');
      removed++;
    }
  }

  if (removed === 0) {
    console.log('ShieldCortex MCP server was not configured in any editor.');
  } else {
    console.log(`\nRemoved ShieldCortex MCP server from ${removed} editor(s).`);
  }
}

export async function copilotStatus(): Promise<void> {
  console.log(`MCP entry point: ${MCP_ENTRY}`);
  console.log(`  Exists: ${fs.existsSync(MCP_ENTRY) ? 'yes' : 'no'}`);
  console.log();

  // VS Code
  const vscodeDirs = findVsCodeDirs();
  if (vscodeDirs.length === 0) {
    console.log('VS Code:  not found');
  }
  for (const dir of vscodeDirs) {
    const variant = path.basename(path.dirname(dir));
    const mcpPath = path.join(dir, 'mcp.json');
    const config = readJson(mcpPath);
    const servers = (config.servers ?? {}) as McpConfig;
    const installed = !!servers[SERVER_NAME];
    console.log(`VS Code (${variant}):  ${installed ? 'configured' : 'not configured'}`);
  }

  // Cursor
  const cursorDir = findCursorDir();
  if (!cursorDir) {
    console.log('Cursor:   not found');
  } else {
    const mcpPath = path.join(cursorDir, 'mcp.json');
    const config = readJson(mcpPath);
    const servers = (config.mcpServers ?? {}) as McpConfig;
    const installed = !!servers[SERVER_NAME];
    console.log(`Cursor:   ${installed ? 'configured' : 'not configured'}`);
  }
}

export async function handleCopilotCommand(subcommand: string): Promise<void> {
  console.log();
  switch (subcommand) {
    case 'install':
      await installCopilot();
      break;
    case 'uninstall':
      await uninstallCopilot();
      break;
    case 'status':
      await copilotStatus();
      break;
    default:
      console.log('Usage: shieldcortex copilot <install|uninstall|status>');
      console.log();
      console.log('  install    Configure ShieldCortex MCP server for VS Code and Cursor');
      console.log('  uninstall  Remove ShieldCortex MCP server configuration');
      console.log('  status     Check current configuration');
      process.exit(1);
  }
}
