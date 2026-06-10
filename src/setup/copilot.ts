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
import {
  readJsonConfigOrAbort,
  writeJsonConfigWithBackup,
  looksLikeShieldcortex,
  resolveMcpServerCommand,
} from './json-config.js';

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
 * Read a JSON config file. Missing → {}; existing-but-unparseable → THROWS.
 *
 * VS Code / Cursor `mcp.json` files are JSONC and may contain `//` comments
 * and trailing commas, which `JSON.parse` rejects. Aborting on that is the
 * CORRECT safe behaviour — silently treating an unparseable-but-present file
 * as `{}` and writing it back would delete every OTHER MCP server the user
 * configured. The thrown error (from readJsonConfigOrAbort) explains that
 * JSONC isn't supported so the user knows why the install stopped.
 */
function readJson(filePath: string): McpConfig {
  return readJsonConfigOrAbort(filePath) as McpConfig;
}

/**
 * Write a JSON config file, backing up any existing file first and creating
 * parent directories as needed.
 */
function writeJson(filePath: string, data: McpConfig): void {
  writeJsonConfigWithBackup(filePath, data);
}

/**
 * Read for the informational `status` command only: never throw. A JSONC/
 * unparseable file is reported as unreadable (null) instead of aborting the
 * whole status run. Mutating paths use readJson (which throws to abort).
 */
function readJsonForStatus(filePath: string): McpConfig | null {
  try {
    return readJson(filePath);
  } catch {
    return null;
  }
}

/**
 * Uninstall-side read: returns the parsed config, or `null` if the file is
 * unparseable. When it returns `null` for a file that ACTUALLY EXISTS (JSONC /
 * trailing comma), print a warning naming the path — otherwise a real
 * `shieldcortex` entry that can't be parsed is silently left in place while
 * uninstall reports "not configured." An absent file is silent (normal). The
 * caller treats `null` as a no-op (we never corrupt on parse failure).
 */
function readJsonForRemoval(filePath: string): McpConfig | null {
  const config = readJsonForStatus(filePath);
  if (config === null && fs.existsSync(filePath)) {
    console.warn(
      `  ! ${filePath} is JSONC/unparseable — could not auto-remove; ` +
        `remove the shieldcortex entry manually.`,
    );
  }
  return config;
}

/**
 * Build the VS Code server entry for ShieldCortex MCP.
 *
 * Resolves to the absolute global binary (or `node <absolute dist/index.js>`),
 * never `npx -y` — see resolveMcpServerCommand for why a re-resolving command
 * thrashes the editor's MCP-config hash. VS Code format includes `type`.
 */
function serverEntry(): McpConfig {
  const { command, args } = resolveMcpServerCommand(MCP_ENTRY);
  return {
    type: 'stdio',
    command,
    args,
  };
}

/**
 * Build the Cursor server entry. Same resolved command as VS Code, but Cursor's
 * schema omits the `type` field.
 */
function cursorServerEntry(): McpConfig {
  const { command, args } = resolveMcpServerCommand(MCP_ENTRY);
  return { command, args };
}

/**
 * Decide what to do with an EXISTING entry under our server name.
 *
 *  - not ours (looksLikeShieldcortex false) → leave it alone (`'foreign'`)
 *  - ours but the command/args already match the desired entry → `'current'`
 *  - ours but stale (old `node dist/index.js`, `npx -y shieldcortex`, a stale
 *    absolute path, …) → `'stale'`, caller refreshes it
 *
 * `SERVER_NAME` is ShieldCortex-specific (unlike the generic `memory` key in
 * ~/.claude.json), so a present entry under it is almost always ours — but we
 * still guard with looksLikeShieldcortex so a user who parked an unrelated
 * server under the same name isn't clobbered.
 */
function classifyExisting(existing: unknown, desired: McpConfig): 'foreign' | 'current' | 'stale' {
  if (!looksLikeShieldcortex(existing)) return 'foreign';
  const e = existing as { command?: unknown; args?: unknown };
  const sameCommand = e.command === desired.command;
  const desiredArgs = (desired.args as unknown[]) ?? [];
  const sameArgs =
    Array.isArray(e.args) &&
    e.args.length === desiredArgs.length &&
    e.args.every((v, i) => v === desiredArgs[i]);
  return sameCommand && sameArgs ? 'current' : 'stale';
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

/** Outcome of an add/refresh on one config file. */
type WriteOutcome = 'added' | 'refreshed' | 'unchanged' | 'foreign';

/**
 * Add (or refresh) ShieldCortex in a VS Code mcp.json file.
 * VS Code format: { "servers": { "name": { ... } } }
 *
 * On re-install, a stale ShieldCortex entry (e.g. an old `node dist/index.js`
 * path or an `npx -y` command from a previous version) is UPDATED to the
 * currently-resolved command rather than left in place — otherwise the editor
 * keeps launching the wrong/old server forever. A foreign entry parked under
 * our name is never touched.
 */
function addToVsCode(configDir: string): WriteOutcome {
  const mcpPath = path.join(configDir, 'mcp.json');
  const config = readJson(mcpPath);

  if (!config.servers || typeof config.servers !== 'object') {
    config.servers = {};
  }

  const servers = config.servers as McpConfig;
  const desired = serverEntry();

  if (servers[SERVER_NAME]) {
    const verdict = classifyExisting(servers[SERVER_NAME], desired);
    if (verdict === 'foreign') return 'foreign';
    if (verdict === 'current') return 'unchanged';
    servers[SERVER_NAME] = desired; // stale → refresh
    writeJson(mcpPath, config);
    return 'refreshed';
  }

  servers[SERVER_NAME] = desired;
  writeJson(mcpPath, config);
  return 'added';
}

/**
 * Remove ShieldCortex from a VS Code mcp.json file.
 *
 * If the file is unparseable (JSONC), leave it untouched and report nothing
 * removed — same "don't corrupt on parse failure" stance as readJson, but on
 * the uninstall side we degrade to a no-op rather than throwing through the
 * uninstaller loop. A present-but-unparseable file warns (via
 * readJsonForRemoval) so the user isn't told "not configured" while an entry
 * silently lingers.
 */
function removeFromVsCode(configDir: string): boolean {
  const mcpPath = path.join(configDir, 'mcp.json');
  const config = readJsonForRemoval(mcpPath);
  if (config === null) return false;

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
function addToCursor(cursorDir: string): WriteOutcome {
  const mcpPath = path.join(cursorDir, 'mcp.json');
  const config = readJson(mcpPath);

  if (!config.mcpServers || typeof config.mcpServers !== 'object') {
    config.mcpServers = {};
  }

  const servers = config.mcpServers as McpConfig;
  const desired = cursorServerEntry(); // Cursor schema omits "type"

  if (servers[SERVER_NAME]) {
    const verdict = classifyExisting(servers[SERVER_NAME], desired);
    if (verdict === 'foreign') return 'foreign';
    if (verdict === 'current') return 'unchanged';
    servers[SERVER_NAME] = desired; // stale → refresh
    writeJson(mcpPath, config);
    return 'refreshed';
  }

  servers[SERVER_NAME] = desired;
  writeJson(mcpPath, config);
  return 'added';
}

/**
 * Remove ShieldCortex from Cursor's mcp.json.
 *
 * Unparseable file → no-op (don't corrupt on parse failure), as in
 * removeFromVsCode; a present-but-unparseable file warns via readJsonForRemoval.
 */
function removeFromCursor(cursorDir: string): boolean {
  const mcpPath = path.join(cursorDir, 'mcp.json');
  const config = readJsonForRemoval(mcpPath);
  if (config === null) return false;

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

  // Report an add/refresh/unchanged/foreign outcome with the right glyph + text,
  // and count add+refresh toward `installed` (both mutate the config).
  const report = (outcome: WriteOutcome, label: string, target: string): void => {
    switch (outcome) {
      case 'added':
        console.log(`  ✓ ${label} — added to ${target}`);
        installed++;
        break;
      case 'refreshed':
        console.log(`  ↑ ${label} — refreshed stale entry in ${target}`);
        installed++;
        break;
      case 'unchanged':
        console.log(`  · ${label} — already configured`);
        break;
      case 'foreign':
        console.warn(`  ! ${label} — '${SERVER_NAME}' exists but is not ShieldCortex-owned; leaving it alone`);
        break;
    }
  };

  // VS Code
  const vscodeDirs = findVsCodeDirs();
  for (const dir of vscodeDirs) {
    const variant = path.basename(path.dirname(dir)); // "Code" or "Code - Insiders"
    report(addToVsCode(dir), `VS Code (${variant})`, path.join(dir, 'mcp.json'));
  }

  if (vscodeDirs.length === 0) {
    console.log('  · VS Code — not found');
  }

  // Cursor
  const cursorDir = findCursorDir();
  if (cursorDir) {
    report(addToCursor(cursorDir), 'Cursor', path.join(cursorDir, 'mcp.json'));
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
    const config = readJsonForStatus(mcpPath);
    if (config === null) {
      console.log(`VS Code (${variant}):  unreadable (not valid JSON — JSONC/comments not supported)`);
      continue;
    }
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
    const config = readJsonForStatus(mcpPath);
    if (config === null) {
      console.log('Cursor:   unreadable (not valid JSON — JSONC/comments not supported)');
    } else {
      const servers = (config.mcpServers ?? {}) as McpConfig;
      const installed = !!servers[SERVER_NAME];
      console.log(`Cursor:   ${installed ? 'configured' : 'not configured'}`);
    }
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
