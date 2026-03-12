/**
 * Codex MCP installer.
 *
 * Configures ShieldCortex as an MCP server for Codex by updating
 * ~/.codex/config.toml. Codex CLI and the Codex IDE extension share this
 * configuration, so one install covers both on the same machine.
 */

import fs from 'fs';
import os from 'os';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

const SERVER_NAME = 'shieldcortex-memory';
const MCP_ENTRY = path.resolve(__dirname, '..', 'index.js');

function getCodexConfigPath(): string {
  return path.join(os.homedir(), '.codex', 'config.toml');
}

function readConfig(): string {
  const configPath = getCodexConfigPath();
  if (!fs.existsSync(configPath)) return '';
  return fs.readFileSync(configPath, 'utf-8');
}

function writeConfig(content: string): void {
  const configPath = getCodexConfigPath();
  fs.mkdirSync(path.dirname(configPath), { recursive: true });
  fs.writeFileSync(configPath, content.endsWith('\n') ? content : `${content}\n`, 'utf-8');
}

function escapeTomlString(value: string): string {
  return value.replace(/\\/g, '\\\\').replace(/"/g, '\\"');
}

function buildServerBlock(): string {
  return [
    `[mcp_servers.${SERVER_NAME}]`,
    'command = "node"',
    `args = ["${escapeTomlString(MCP_ENTRY)}"]`,
    '',
  ].join('\n');
}

function hasServerBlock(content: string): boolean {
  return new RegExp(`^\\[mcp_servers\\.${SERVER_NAME}\\]`, 'm').test(content);
}

function upsertServerBlock(content: string): { content: string; changed: boolean } {
  const block = buildServerBlock();
  const sectionPattern = new RegExp(`^\\[mcp_servers\\.${SERVER_NAME}\\]\\n[\\s\\S]*?(?=^\\[|\\Z)`, 'm');

  if (sectionPattern.test(content)) {
    const nextContent = content.replace(sectionPattern, block);
    return { content: nextContent, changed: nextContent !== content };
  }

  const trimmed = content.trimEnd();
  return {
    content: trimmed.length > 0 ? `${trimmed}\n\n${block}` : block,
    changed: true,
  };
}

function removeServerBlock(content: string): { content: string; changed: boolean } {
  const sectionPattern = new RegExp(`^\\[mcp_servers\\.${SERVER_NAME}\\]\\n[\\s\\S]*?(?=^\\[|\\Z)`, 'm');
  if (!sectionPattern.test(content)) {
    return { content, changed: false };
  }

  const nextContent = content
    .replace(sectionPattern, '')
    .replace(/\n{3,}/g, '\n\n')
    .trimEnd();

  return { content: nextContent.length > 0 ? `${nextContent}\n` : '', changed: true };
}

export async function installCodex(): Promise<void> {
  if (!fs.existsSync(MCP_ENTRY)) {
    console.error('ShieldCortex MCP entry point not found. Package may be corrupted.');
    console.error(`Expected: ${MCP_ENTRY}`);
    process.exit(1);
  }

  const existing = readConfig();
  const result = upsertServerBlock(existing);
  writeConfig(result.content);

  if (result.changed) {
    console.log(`✓ Codex — configured ShieldCortex in ${getCodexConfigPath()}`);
  } else {
    console.log('· Codex — already configured');
  }

  console.log();
  console.log('This Codex config is shared by the Codex CLI and IDE extension.');
  console.log('Restart Codex / VS Code if it was already open.');
}

export async function uninstallCodex(): Promise<void> {
  const existing = readConfig();
  const result = removeServerBlock(existing);

  if (!result.changed) {
    console.log('ShieldCortex MCP server was not configured for Codex.');
    return;
  }

  writeConfig(result.content);
  console.log(`✓ Codex — removed ShieldCortex from ${getCodexConfigPath()}`);
}

export async function codexStatus(): Promise<void> {
  const content = readConfig();
  console.log(`Codex config: ${getCodexConfigPath()}`);
  console.log(`  Exists: ${content.length > 0 ? 'yes' : 'no'}`);
  console.log(`  Configured: ${hasServerBlock(content) ? 'yes' : 'no'}`);
  console.log(`  MCP entry: ${MCP_ENTRY}`);
  console.log(`  Entry exists: ${fs.existsSync(MCP_ENTRY) ? 'yes' : 'no'}`);
}

export async function handleCodexCommand(subcommand: string): Promise<void> {
  console.log();
  switch (subcommand) {
    case 'install':
      await installCodex();
      break;
    case 'uninstall':
      await uninstallCodex();
      break;
    case 'status':
      await codexStatus();
      break;
    default:
      console.log('Usage: shieldcortex codex <install|uninstall|status>');
      console.log();
      console.log('Configures ShieldCortex in ~/.codex/config.toml for Codex CLI');
      console.log('and the Codex VS Code extension.');
      process.exit(1);
  }
}
