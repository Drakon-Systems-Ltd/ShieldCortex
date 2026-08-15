/**
 * Hermes plugin installer.
 *
 * Copies plugins/hermes/shieldcortex into ~/.hermes/plugins/shieldcortex
 * and tells the operator what is actually bound: pre_tool_call via the
 * local Action Guard API. Not a conversation gate. Not a freeze plane
 * until Hermes consults DECISIONS.md (it does not, today).
 */

import fs from 'fs';
import os from 'os';
import path from 'path';
import { fileURLToPath } from 'url';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

function pluginSourceDir(): string {
  // dist/setup/hermes.js → repo-or-package root / plugins/hermes/shieldcortex
  return path.resolve(__dirname, '..', '..', 'plugins', 'hermes', 'shieldcortex');
}

function pluginDestDir(home: string = os.homedir()): string {
  return path.join(home, '.hermes', 'plugins', 'shieldcortex');
}

function copyDir(src: string, dest: string): void {
  fs.mkdirSync(dest, { recursive: true });
  for (const entry of fs.readdirSync(src, { withFileTypes: true })) {
    if (entry.name === '__pycache__' || entry.name === '.pytest_cache' || entry.name === 'tests') {
      continue;
    }
    const from = path.join(src, entry.name);
    const to = path.join(dest, entry.name);
    if (entry.isDirectory()) {
      copyDir(from, to);
    } else {
      fs.copyFileSync(from, to);
    }
  }
}

export function hermesPluginInstalled(home: string = os.homedir()): boolean {
  return fs.existsSync(path.join(pluginDestDir(home), 'plugin.yaml'));
}

export async function installHermes(home: string = os.homedir()): Promise<void> {
  const src = pluginSourceDir();
  if (!fs.existsSync(path.join(src, 'plugin.yaml'))) {
    console.error('Hermes plugin source not found. Package may be missing plugins/hermes.');
    console.error(`Expected: ${src}`);
    process.exit(1);
  }

  const dest = pluginDestDir(home);
  copyDir(src, dest);
  console.log(`✓ Hermes — plugin copied to ${dest}`);
  console.log();
  console.log('This is a tool gate (pre_tool_call → POST /api/v1/action-guard).');
  console.log('Enforce is ON by default. Opt out: SHIELDCORTEX_ENFORCE=0');
  console.log('Requires a running local API:  shieldcortex api   (http://127.0.0.1:3001)');
  console.log('Enable in Hermes:              hermes plugins enable shieldcortex');
  console.log('Conversation / freeze:         NOT bound on this plane.');
}

export async function uninstallHermes(home: string = os.homedir()): Promise<void> {
  const dest = pluginDestDir(home);
  if (!fs.existsSync(dest)) {
    console.log('Hermes plugin was not installed.');
    return;
  }
  fs.rmSync(dest, { recursive: true, force: true });
  console.log(`✓ Hermes — removed ${dest}`);
}

export async function hermesStatus(home: string = os.homedir()): Promise<void> {
  const src = pluginSourceDir();
  const dest = pluginDestDir(home);
  console.log(`Hermes plugin dest: ${dest}`);
  console.log(`  Installed: ${hermesPluginInstalled(home) ? 'yes' : 'no'}`);
  console.log(`  Source: ${src}`);
  console.log(`  Source present: ${fs.existsSync(path.join(src, 'plugin.yaml')) ? 'yes' : 'no'}`);
  console.log('  Tool gate: bound after `hermes plugins enable shieldcortex` + local API up');
  console.log('  Turn gate / freeze: not bound');
}

export async function handleHermesCommand(subcommand: string): Promise<void> {
  console.log();
  switch (subcommand) {
    case 'install':
      await installHermes();
      break;
    case 'uninstall':
      await uninstallHermes();
      break;
    case 'status':
      await hermesStatus();
      break;
    default:
      console.log('Usage: shieldcortex hermes <install|uninstall|status>');
      console.log();
      console.log('Installs the Hermes pre_tool_call plugin (Action Guard).');
      console.log('This is a deny plane. Codex/Cursor MCP install is not.');
      process.exit(1);
  }
}
